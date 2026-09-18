"""Tests for attack-chain correlation (deluluscan/correlate/)."""
import os, sys, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from deluluscan.correlate import correlate, chain_findings, objectives  # noqa: E402
from deluluscan.models import Finding, Severity, VulnClass  # noqa: E402
_PASS = 0; _FAIL = 0
def check(n, c, d=""):
    global _PASS, _FAIL
    if c: _PASS += 1; print(f"PASS  {n}")
    else: _FAIL += 1; print(f"FAIL  {n}  [{d}]")
def F(vc, title, ep="/x", desc="", sev=Severity.HIGH, detail=None):
    return Finding(vuln_class=vc, severity=sev, title=title, endpoint=ep, description=desc, detail=detail or {})
def ids(sugg): return {s.rule.id for s in sugg}

def test_ssrf_to_cloud_chain():
    fs = [F(VulnClass.SSRF, "Blind SSRF on fetch param"),
          F(VulnClass.INFO_LEAK, "AWS instance credentials reachable via metadata (SSRF->IMDS)",
            ep="169.254.169.254")]
    s = correlate(fs)
    check("SSRF + IMDS -> cloud-creds chain", "ssrf-to-cloud-creds" in ids(s))
    cf = chain_findings(fs)[0]
    check("chain finding is business_logic + critical",
          cf.vuln_class == VulnClass.BUSINESS_LOGIC and cf.severity == Severity.CRITICAL)
    check("chain finding stays tentative (not asserted proven)",
          cf.verdict == "inconclusive" and cf.confidence == "tentative")
    check("chain carries an agentic objective", "objective" in cf.detail and cf.detail["objective"])

def test_xss_session_chain():
    fs = [F(VulnClass.XSS, "Stored XSS in name"),
          F(VulnClass.MISCONFIG, "Insecure cookie flags: SESSIONID",
            desc="Cookie 'SESSIONID' is missing HttpOnly")]
    check("XSS + non-HttpOnly cookie -> session hijack chain", "xss-to-session-hijack" in ids(correlate(fs)))

def test_no_chain_when_only_one_member():
    fs = [F(VulnClass.SSRF, "Blind SSRF")]  # no IMDS finding
    check("SSRF alone does not form the cloud chain", "ssrf-to-cloud-creds" not in ids(correlate(fs)))

def test_single_finding_not_matched_twice():
    # a lone AUTHZ 'admin' finding must not satisfy both members of idor-to-privesc
    fs = [F(VulnClass.AUTHZ, "admin endpoint reachable", desc="privilege")]
    check("one finding cannot self-form a two-member chain",
          "idor-to-privesc" not in ids(correlate(fs)))

def test_objectives_for_agentic_engine():
    fs = [F(VulnClass.SSRF, "SSRF"),
          F(VulnClass.INFO_LEAK, "instance credentials via metadata", ep="169.254.169.254")]
    objs = objectives(fs)
    check("objectives produced for the agentic engine", objs and "objective" in objs[0])
    check("objective references the chain + members", objs[0]["chain"] == "ssrf-to-cloud-creds"
          and len(objs[0]["members"]) >= 1)

def test_works_on_plain_dicts():
    dicts = [{"vuln_class": "ssrf", "title": "SSRF", "endpoint": "/f", "description": "", "detail": {}},
             {"vuln_class": "info_leak", "title": "credentials via metadata IMDS", "endpoint": "169.254.169.254",
              "description": "", "detail": {}}]
    check("correlate accepts results.json dicts", "ssrf-to-cloud-creds" in ids(correlate(dicts)))

def test_shadow_env_crossenv_chain():
    fs = [F(VulnClass.AUTHZ, "Shadow environment drops authentication: staging.app.com",
            detail={"source": "shadowenv"}),
          F(VulnClass.IDOR, "IDOR via iterable numeric identifier", detail={"source": "idor_iter"})]
    check("shadow auth-drop + data finding -> cross-env chain",
          "shadow-env-crossenv-access" in ids(correlate(fs)))
    # the shadow finding alone (no data-bearing finding) does not form the chain
    check("shadow finding alone -> no chain",
          "shadow-env-crossenv-access" not in ids(correlate([fs[0]])))

def test_takeover_session_chain():
    fs = [F(VulnClass.MISCONFIG, "Dangling DNS takeover: blog.acme.com (AWS S3)",
            detail={"source": "recon.takeover"}),
          F(VulnClass.MISCONFIG, "Session cookie missing SameSite",
            desc="cookie lacks SameSite", detail={"source": "headers"})]
    check("subdomain takeover + cookie -> takeover-to-session chain",
          "takeover-to-session" in ids(correlate(fs)))

def test_cloud_id_ssrf_chain():
    fs = [F(VulnClass.INFO_LEAK, "GCP service-account identity disclosed",
            desc="svc@proj.iam.gserviceaccount.com", detail={"source": "passive"}),
          F(VulnClass.SSRF, "Blind SSRF on url param", detail={"source": "ssrf"})]
    check("cloud-id disclosure + SSRF -> cloud-id-to-ssrf chain",
          "cloud-id-to-ssrf" in ids(correlate(fs)))

def test_clean_findings_no_chains():
    fs = [F(VulnClass.MISCONFIG, "Missing HSTS"), F(VulnClass.INFO_LEAK, "Version disclosure via server")]
    check("unrelated findings produce no chains", correlate(fs) == [])

if __name__ == "__main__":
    for fn in [v for v in list(globals().values()) if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try: fn()
        except Exception as e:
            import traceback; _FAIL += 1; print(f"FAIL  {fn.__name__}  [exc: {e}]"); traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed"); sys.exit(1 if _FAIL else 0)
