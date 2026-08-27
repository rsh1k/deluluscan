"""Tests for source-informed scanning (sourcescan.py)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json

from deluluscan.sourcescan import (SourceProvider, SourceAnalyzer,
                                candidates_to_probe_plan, load_mantis_findings)

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


VULN_ORDERBY = '''@Path("/v1/categories")
public class CategoryResource {
  @GET
  public Response list(@QueryParam("orderby") String orderBy) {
    return this.paginationUtil.getPage(req, user, filter, page, perPage, orderBy, direction);
  }
}
'''

SAFE_ORDERBY = '''@Path("/v1/containers")
public class ContainerResource {
  @GET
  public Response list(@QueryParam("orderby") String orderBy) {
    final String safe = SQLUtil.sanitizeSortBy(orderBy);
    return this.paginationUtil.getPage(req, user, filter, page, perPage, safe, direction);
  }
}
'''

BFLA_POST = '''@Path("/v1/roles")
public class RoleResource {
  @POST
  @Path("/{roleId}/layout")
  public Response addLayout(@PathParam("roleId") String roleId, LayoutForm form) {
    return Response.ok(roleAPI.addLayoutToRole(form, roleId)).build();
  }
}
'''

GUARDED_POST = '''@Path("/v1/roles")
public class RoleResource2 {
  @POST
  @Path("/{roleId}/secure")
  public Response secure(@PathParam("roleId") String roleId) {
    if (!APILocator.getRoleAPI().doesUserHaveRole(user, adminRole)) throw new DotSecurityException("no");
    return Response.ok().build();
  }
}
'''

COMMENT_ONLY_GUARD = '''@Path("/v1/things")
public class ThingResource {
  @DELETE
  @Path("/{id}")
  public Response del(@PathParam("id") String id) {
    // this used to call checkPermission but no longer does
    return Response.ok(api.delete(id)).build();
  }
}
'''

VELOCITY = '''@Path("/v1/template")
public class VTLResource {
  @POST
  @Path("/dynamic")
  public Response run(String body) {
    return Response.ok(VelocityUtil.eval(body)).build();
  }
}
'''


def _write(root, rel, content):
    p = os.path.join(root, "./app-src/main/java/com/example/rest", rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(content)


def _analyze(files):
    root = tempfile.mkdtemp(prefix="src_")
    for rel, content in files.items():
        _write(root, rel, content)
    return SourceAnalyzer(SourceProvider(local_root=root)).analyze()


def test_orderby_sqli_flagged_and_endpoint_resolved():
    cands = _analyze({"categories/CategoryResource.java": VULN_ORDERBY})
    hit = [c for c in cands if c.pattern_id == "orderby_sqli"]
    check("orderby SQLi flagged with correct endpoint",
          len(hit) == 1 and hit[0].endpoint_path == "/api/v1/categories", str([c.endpoint_path for c in hit]))


def test_guarded_orderby_not_flagged():
    cands = _analyze({"container/ContainerResource.java": SAFE_ORDERBY})
    check("orderby guarded by sanitizeSortBy is NOT flagged",
          not any(c.pattern_id == "orderby_sqli" for c in cands), str([c.pattern_id for c in cands]))


def test_bfla_post_flagged_with_method_path():
    cands = _analyze({"role/RoleResource.java": BFLA_POST})
    hit = [c for c in cands if c.pattern_id == "missing_authz"]
    check("BFLA POST flagged with method-level path",
          len(hit) == 1 and hit[0].endpoint_path == "/api/v1/roles/{roleId}/layout"
          and hit[0].http_methods == ("POST",), str([(c.endpoint_path, c.http_methods) for c in hit]))


def test_guarded_post_not_flagged():
    cands = _analyze({"role/RoleResource2.java": GUARDED_POST})
    check("state-changing method WITH a role/permission check is NOT flagged",
          not any(c.pattern_id == "missing_authz" for c in cands), str([c.pattern_id for c in cands]))


def test_comment_guard_does_not_suppress():
    # a comment mentioning checkPermission must NOT suppress a real missing-authz
    cands = _analyze({"things/ThingResource.java": COMMENT_ONLY_GUARD})
    check("comment mentioning a guard does not suppress the finding",
          any(c.pattern_id == "missing_authz" and c.endpoint_path == "/api/v1/things/{id}"
              for c in cands), str([(c.pattern_id, c.endpoint_path) for c in cands]))


def test_velocity_ssti_flagged():
    cands = _analyze({"template/TemplateResource.java": VELOCITY})
    hit = [c for c in cands if c.pattern_id == "velocity_ssti"]
    check("velocity eval flagged as SSTI/RCE candidate",
          len(hit) == 1 and hit[0].endpoint_path == "/api/v1/template/dynamic", str([c.endpoint_path for c in hit]))


def test_probe_plan_shape():
    cands = _analyze({"categories/CategoryResource.java": VULN_ORDERBY,
                      "role/RoleResource.java": BFLA_POST})
    plan = candidates_to_probe_plan(cands)
    ok = all({"pattern_id", "endpoint_path", "methods", "probe_kind"} <= set(p) for p in plan) and len(plan) == 2
    check("probe plan has the fields scanners need", ok, str(plan))


def test_github_fallback_uses_fetcher():
    # no local root -> uses the injected fetch_text over the seed file list
    calls = []
    def fake_fetch(url):
        calls.append(url)
        return VULN_ORDERBY if url.endswith("CategoryResource.java") else "class X {}"
    prov = SourceProvider(local_root=None, fetch_text=fake_fetch)
    cands = SourceAnalyzer(prov).analyze()
    check("github-fetch fallback invokes the fetcher and still finds candidates",
          len(calls) > 0 and any(c.pattern_id == "orderby_sqli" for c in cands),
          f"calls={len(calls)} cands={[c.pattern_id for c in cands]}")


GUARDED_MULTILINE = '''@Path("/v1/system/role")
public class RoleResource {
  @DELETE
  @Path("/layouts")
  public Response deleteRoleLayouts(final @Context HttpServletRequest request,
      final @Context HttpServletResponse response, final RoleLayoutForm form) {

    final InitDataObject initDataObject = new WebResource.InitBuilder()
        .requiredFrontendUser(false).rejectWhenNoUser(true)
        .requiredBackendUser(true).requiredPortlet("roles")
        .requestAndResponse(request, response).init();

    if (this.roleAPI.doesUserHaveRole(initDataObject.getUser(), this.roleAPI.loadCMSAdminRole())) {
      return Response.ok(doStuff()).build();
    }
    throw new DotSecurityException("nope");
  }
}
'''

GUARDED_SHORTHAND = '''@Path("/v1/foo")
public class FooResource {
  @POST
  public Response create(@Context HttpServletRequest req, @Context HttpServletResponse res) {
    final InitDataObject initData = webResource.init(req, res, true);
    return Response.ok().build();
  }
}
'''

UNGUARDED_PATHPARAM = '''@Path("/v1/bar")
public class BarResource {
  @POST
  @Path("/{id}/grant")
  public Response grant(@PathParam("id") String id, GrantForm form) {
    return Response.ok(api.grant(id, form)).build();
  }
}
'''


def test_multiline_initbuilder_guard_not_flagged():
    cands = _analyze({"role/RoleResource.java": GUARDED_MULTILINE})
    check("multi-line WebResource.InitBuilder auth chain is recognized (not flagged)",
          not any(c.pattern_id == "missing_authz" for c in cands),
          str([c.pattern_id for c in cands]))


def test_shorthand_init_guard_not_flagged():
    cands = _analyze({"foo/FooResource.java": GUARDED_SHORTHAND})
    check("shorthand webResource.init(req,res,true) is recognized (not flagged)",
          not any(c.pattern_id == "missing_authz" for c in cands),
          str([c.pattern_id for c in cands]))


def test_pathparam_braces_do_not_corrupt_endpoint():
    cands = _analyze({"bar/BarResource.java": UNGUARDED_PATHPARAM})
    hit = [c for c in cands if c.pattern_id == "missing_authz"]
    check("path-param braces in @Path don't corrupt the resolved endpoint",
          len(hit) == 1 and hit[0].endpoint_path == "/api/v1/bar/{id}/grant",
          str([c.endpoint_path for c in hit]))


def _write_finding(findings_dir, fid, **overrides):
    """A finding shaped like REAL Mantis output (google/mantis schema.json):
    status / attacker_position / privileges_required / user_interaction / impact
    are all REQUIRED there, and Deluluscan's ingest keys off several of them."""
    os.makedirs(findings_dir, exist_ok=True)
    finding = {
        "id": fid, "title": "SQL injection via orderby",
        "description": "orderBy reaches the query unsanitized.",
        "impact": "Arbitrary read of the categories table.",
        "severity": "CRITICAL", "cwe": "CWE-89",
        "code_paths": ["./app-src/main/java/com/example/rest/categories/CategoryResource.java:4"],
        "mitigation": "Route through SQLUtil.sanitizeSortBy.",
        "status": "VALID",
        "production_viability": "VIABLE",
        "attacker_position": "EXTERNAL",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "history": [],
    }
    finding.update(overrides)
    with open(os.path.join(findings_dir, f"{fid}.json"), "w") as fh:
        json.dump(finding, fh)
    return finding


def test_mantis_findings_resolve_endpoint_and_map_cwe():
    src_root = tempfile.mkdtemp(prefix="src_")
    _write(src_root, "categories/CategoryResource.java", VULN_ORDERBY)
    ws = tempfile.mkdtemp(prefix="mantis_ws_")
    _write_finding(os.path.join(ws, "findings"), "f1")
    cands = load_mantis_findings(ws, src_root)
    check("mantis finding resolves the live endpoint",
          len(cands) == 1 and cands[0].endpoint_path == "/api/v1/categories",
          str([(c.endpoint_path, c.pattern_id) for c in cands]))
    check("mantis finding maps CWE-89 to sqli",
          cands[0].probe_kind == "sqli" and cands[0].vuln_class == "sqli",
          str((cands[0].probe_kind, cands[0].vuln_class)))
    check("mantis finding carries provenance (source, severity, ai_verdict)",
          cands[0].source == "mantis" and cands[0].severity.value == "critical"
          and cands[0].ai_verdict == "confirmed",
          str((cands[0].source, cands[0].severity, cands[0].ai_verdict)))


def test_mantis_findings_skip_unreadable_file():
    src_root = tempfile.mkdtemp(prefix="src_")  # no CategoryResource.java written
    ws = tempfile.mkdtemp(prefix="mantis_ws_")
    _write_finding(os.path.join(ws, "findings"), "f2")
    cands = load_mantis_findings(ws, src_root)
    check("a finding whose file can't be re-read is skipped, not fabricated",
          cands == [], str(cands))


def test_mantis_findings_active_wins_over_archived_duplicate():
    src_root = tempfile.mkdtemp(prefix="src_")
    _write(src_root, "categories/CategoryResource.java", VULN_ORDERBY)
    ws = tempfile.mkdtemp(prefix="mantis_ws_")
    _write_finding(os.path.join(ws, "archive", "findings_pass_1"), "f3", severity="LOW")
    _write_finding(os.path.join(ws, "findings"), "f3", severity="CRITICAL")
    cands = load_mantis_findings(ws, src_root)
    check("active findings/ supersedes an archived duplicate with the same id",
          len(cands) == 1 and cands[0].severity.value == "critical",
          str([(c.pattern_id, c.severity) for c in cands]))


def test_mantis_findings_merge_into_probe_plan():
    src_root = tempfile.mkdtemp(prefix="src_")
    _write(src_root, "categories/CategoryResource.java", VULN_ORDERBY)
    ws = tempfile.mkdtemp(prefix="mantis_ws_")
    _write_finding(os.path.join(ws, "findings"), "f4")
    regex_cands = _analyze({"categories/CategoryResource.java": VULN_ORDERBY})
    mantis_cands = load_mantis_findings(ws, src_root)
    plan = candidates_to_probe_plan(regex_cands + mantis_cands)
    sources = sorted(p["source"] for p in plan)
    check("probe plan carries both sourcescan and mantis entries with correct 'source' tag",
          sources == ["mantis", "sourcescan"], str(sources))



def test_mantis_triage_verdicts_are_honoured():
    """Mantis spends 16 stages triaging. Ingesting findings it already rejected
    would queue live probes for known false positives."""
    src_root = tempfile.mkdtemp(prefix="src_")
    _write(src_root, "categories/CategoryResource.java", VULN_ORDERBY)
    ws = tempfile.mkdtemp(prefix="mantis_ws_")
    fdir = os.path.join(ws, "findings")
    _write_finding(fdir, "keep")
    _write_finding(fdir, "fp", status="FALSE_POSITIVE")
    _write_finding(fdir, "dupe", status="DUPLICATE")
    _write_finding(fdir, "testonly", production_viability="SAMPLE_OR_TEST")
    _write_finding(fdir, "nonviable", production_viability="NON_VIABLE")
    _write_finding(fdir, "physical", attacker_position="PHYSICAL_LONG_TERM")
    _write_finding(fdir, "local", attacker_position="LOCAL")
    cands = load_mantis_findings(ws, src_root)
    ids = sorted(c.pattern_id for c in cands)
    check("only the VALID, production-viable, remotely-reachable finding survives",
          ids == ["mantis:keep"], str(ids))
    from deluluscan.sourcescan import candidates_skipped
    check("withheld findings are counted, not silently dropped",
          candidates_skipped.get("triaged_out") == 2
          and candidates_skipped.get("not_production") == 2
          and candidates_skipped.get("not_remotely_testable") == 2,
          str(dict(candidates_skipped)))


def test_mantis_verdict_reflects_what_mantis_concluded():
    src_root = tempfile.mkdtemp(prefix="src_")
    _write(src_root, "categories/CategoryResource.java", VULN_ORDERBY)
    ws = tempfile.mkdtemp(prefix="mantis_ws_")
    fdir = os.path.join(ws, "findings")
    _write_finding(fdir, "repro", status="PROVISIONALLY_VALID", repro_status="reproduced")
    _write_finding(fdir, "research", status="NEEDS_RESEARCH")
    by = {c.pattern_id: c for c in load_mantis_findings(ws, src_root)}
    check("a reproduced PoC counts as confirmed even when triage is provisional",
          by["mantis:repro"].ai_verdict == "confirmed", by["mantis:repro"].ai_verdict)
    check("a finding still under research is NOT promoted to confirmed",
          by["mantis:research"].ai_verdict == "", by["mantis:research"].ai_verdict)


def test_mantis_risk_score_drives_order_and_identity_hint():
    src_root = tempfile.mkdtemp(prefix="src_")
    _write(src_root, "categories/CategoryResource.java", VULN_ORDERBY)
    ws = tempfile.mkdtemp(prefix="mantis_ws_")
    fdir = os.path.join(ws, "findings")
    _write_finding(fdir, "low", severity="CRITICAL", mantis_risk_score=2.0)
    _write_finding(fdir, "high", severity="HIGH", mantis_risk_score=9.4,
                   privileges_required="HIGH")
    cands = load_mantis_findings(ws, src_root)
    check("calibrated risk score outranks a bare severity label",
          cands[0].pattern_id == "mantis:high", str([c.pattern_id for c in cands]))
    check("privileges_required maps to the identity the probe should use",
          cands[0].identity_hint == "admin", cands[0].identity_hint)
    check("provenance carries Mantis's own calibration back into the report",
          cands[0].provenance.get("mantis_risk_score") == 9.4
          and cands[0].provenance.get("status") == "VALID",
          str(cands[0].provenance))


def test_mantis_walks_the_whole_dataflow_path():
    """code_paths is a data-flow PATH; the REST resource is often not entry 0."""
    src_root = tempfile.mkdtemp(prefix="src_")
    _write(src_root, "util/SqlHelper.java", "package com.x;\nclass SqlHelper {\n int f;\n}\n")
    _write(src_root, "categories/CategoryResource.java", VULN_ORDERBY)
    ws = tempfile.mkdtemp(prefix="mantis_ws_")
    _write_finding(os.path.join(ws, "findings"), "path", code_paths=[
        "util/SqlHelper.java:2",
        "./app-src/main/java/com/example/rest/categories/CategoryResource.java:4",
    ])
    cands = load_mantis_findings(ws, src_root)
    check("a later code_paths entry is used when the first resolves no endpoint",
          len(cands) == 1 and cands[0].endpoint_path == "/api/v1/categories",
          str([(c.file_path, c.endpoint_path) for c in cands]))



# --- static-analyzer precision (measured against the target source @94c5c8cf) --------

DOC_COMMENT_ONLY = """package com.example.rest.api.v1.cat;
/**
 * Url syntax:
 * api/v1/cat?filter=x&orderby=order-field-name&direction=asc
 */
@Path("/v1/cat")
public class CatResource {
    @GET
    public Response list(@Context HttpServletRequest req) {
        return Response.ok().build();
    }
}
"""


def test_orderby_in_javadoc_is_not_a_candidate():
    """A regex match inside a doc comment was reported as a CRITICAL SQLi.
    Measured on the real clone: 5/316 candidates were doc comments, including
    /api/v1/categories."""
    cands = _analyze({"cat/CatResource.java": DOC_COMMENT_ONLY})
    check("an orderby mentioned only in javadoc is not flagged",
          not any(c.pattern_id == "orderby_sqli" for c in cands),
          str([c.pattern_id for c in cands]))


def test_mask_comments_preserves_offsets():
    from deluluscan.sourcescan import SourceAnalyzer as SA
    src = "int a;\n/* orderby */\nint b;\n// orderby\nint c;\n"
    masked = SA._mask_comments(src)
    check("comment masking preserves length (so line numbers stay correct)",
          len(masked) == len(src), f"{len(masked)} vs {len(src)}")
    check("comment masking preserves newlines",
          masked.count("\n") == src.count("\n"), "newline count changed")
    check("comment bodies are blanked", "orderby" not in masked, masked)
    check("code outside comments survives", "int b;" in masked and "int c;" in masked, masked)


def test_downstream_guard_downgrades_rather_than_drops():
    """the target sanitizes in the Factory/Paginator layer, not the resource, so a
    method-local guard check called every such endpoint a critical SQLi (14/14
    were false positives). The candidate is DOWNGRADED, never silently dropped —
    only a live probe settles it."""
    import tempfile, os as _os
    from deluluscan.sourcescan import SourceProvider, SourceAnalyzer, analyzer_skipped
    root = tempfile.mkdtemp(prefix="dsg_")
    _write(root, "cat/CatResource.java", VULN_ORDERBY.replace(
        "public class", "// delegates to a paginator\n    private ThingPaginator pager;\n public class", 1)
        if "public class" in VULN_ORDERBY else VULN_ORDERBY)
    # the resource names ThingPaginator; that class applies the guard
    _write(root, "cat/CatResource.java", VULN_ORDERBY.replace(
        "@GET", "ThingPaginator pager;\n    @GET", 1))
    _write(root, "pag/ThingPaginator.java",
           "package com.example.util;\nclass ThingPaginator {\n"
           "  String go(String o){ return SQLUtil.sanitizeSortBy(o); }\n}\n")
    cands = SourceAnalyzer(SourceProvider(local_root=root), analyst=None,
                           use_ai=False).analyze(max_files=50)
    hits = [c for c in cands if c.pattern_id == "orderby_sqli"]
    check("candidate is retained (never silently dropped on a heuristic)",
          len(hits) >= 1, str([c.pattern_id for c in cands]))
    if hits:
        check("but downgraded out of CRITICAL when the guard is downstream",
              hits[0].severity.value == "low", hits[0].severity.value)
        check("and says WHERE the guard was found",
              "ThingPaginator" in hits[0].description, hits[0].description[-90:])
    check("the downgrade is counted, not silent",
          analyzer_skipped.get("guarded_downstream", 0) >= 1, str(dict(analyzer_skipped)))


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            try:
                fn()
            except Exception as e:
                _FAIL += 1
                print(f"FAIL  {fn.__name__}  [exception: {e}]")
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed")
    sys.exit(1 if _FAIL else 0)
