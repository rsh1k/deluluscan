"""Evidence-derived reporting — the report must be a VIEW over captured evidence.

Regression context: the polished pentest report was previously produced by
hand-authoring prose strings into scripts/build_dashboard_data.py. That does
not reproduce, does not scale, and silently rots. deluluscan.reporting derives every
field from the RequestRecords a scanner actually captured.

Run: python3 -m tests.test_reporting
"""
from __future__ import annotations

import sys

from deluluscan.models import Finding, RequestRecord, Severity, VulnClass
from deluluscan.reporting import build_report, curl_for, attach_reports

_checks = 0
_failures: list[str] = []


def check(cond: bool, label: str) -> None:
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


def _rec(identity, status, method="GET", url="http://127.0.0.1:8080/api/v1/users/admin",
         req_headers=None, req_body=None):
    return RequestRecord(method=method, url=url, identity=identity, status=status,
                         elapsed_ms=12.3, req_headers=req_headers or {},
                         req_body=req_body, resp_headers={}, resp_body="{}", resp_len=2)


def _finding(**kw):
    base = dict(vuln_class=VulnClass.AUTHZ, severity=Severity.HIGH,
                title="BOLA on user read", endpoint="GET /api/v1/users/{userId}",
                description="desc", evidence=[], detail={})
    base.update(kw)
    return Finding(**base)


def test_curl_never_embeds_secrets():
    r = _rec("backend", 200, req_headers={"Authorization": "Bearer SUPERSECRET.JWT.VALUE",
                                          "Cookie": "JSESSIONID=abc123",
                                          "Content-Type": "application/json"})
    cmd = curl_for(r)
    check("SUPERSECRET" not in cmd, "curl does not embed the bearer token")
    check("JSESSIONID" not in cmd, "curl does not embed cookies")
    check("Content-Type: application/json" in cmd, "curl preserves meaningful headers")
    check("DELULUSCAN_BACKEND" in cmd, "curl references the identity credential by variable")
    check(cmd.startswith("# as backend"), "curl is annotated with the identity used")


def test_curl_reproduces_the_real_request():
    r = _rec("admin", 200, method="PUT",
             url="http://127.0.0.1:8080/api/roles/{id}/members",
             req_body='{"userIds": ["backend@example.com"]}')
    cmd = curl_for(r)
    check("-X PUT" in cmd, "curl carries the real HTTP method")
    check("/api/roles/{id}/members" in cmd, "curl carries the real URL")
    check("backend@example.com" in cmd, "curl carries the real request body")
    check("DELULUSCAN_ADMIN" in cmd, "curl references the admin credential")


def test_report_is_derived_from_evidence():
    f = _finding(evidence=[_rec("anonymous", 401), _rec("backend", 200), _rec("admin", 200)],
                 verdict="true_positive")
    rep = build_report(f)
    check(rep["observed"]["status_by_identity"] == {"anonymous": 401, "backend": 200,
                                                    "admin": 200},
          "status-by-identity is extracted from the evidence")
    check(rep["observed"]["requests_captured"] == 3, "captured request count is reported")
    # A prerequisites block precedes the per-exchange commands so a reader can
    # actually run them (the commands reference $DELULUSCAN_* credentials).
    cmds = [c for c in rep["reproduction"] if "curl" in c]
    check(len(cmds) == 3, "one reproduction command per captured exchange")
    check(rep["reproduction"][0].startswith("# Prerequisites"),
          "reproduction opens with the credential prerequisites block")
    check(all("observed: HTTP" in c for c in cmds),
          "every command states the status that was observed")
    check("anonymous" in rep["method"] and "backend" in rep["method"],
          "method names the identities actually probed")
    check(any("HTTP 401" in s for s in rep["steps"]), "steps cite real observed statuses")
    check("CONFIRMED." in rep["outcome"], "outcome leads with the verdict")
    check("denied" in rep["outcome"] and "served" in rep["outcome"],
          "outcome explains the differential in access-control terms")
    check(rep["generated"] == "derived-from-evidence", "block is marked evidence-derived")


def test_consistent_access_control_is_described_as_such():
    f = _finding(evidence=[_rec("anonymous", 403), _rec("backend", 403), _rec("admin", 403)],
                 verdict="false_positive")
    rep = build_report(f)
    check("consistent" in rep["outcome"],
          "identical responses across identities read as consistent access control")
    check("NOT REPRODUCED." in rep["outcome"], "false_positive verdict is stated plainly")


def test_violating_request_is_labelled():
    """A reader must not mistake a baseline 401 for a refutation of the finding.

    Real incident: a reviewer copied the frontend_user baseline command for the
    /api/v1/redis finding, saw the expected 401, and concluded the bug was
    invalid — the actual violator was 'backend'. Every command now states what
    it proves and the status observed.
    """
    f = _finding(evidence=[_rec("backend", 200), _rec("anonymous", 401),
                           _rec("frontend_user", 401), _rec("admin", 200)],
                 verdict="true_positive",
                 detail={"violating_identity": "backend"})
    cmds = [c for c in build_report(f)["reproduction"] if "curl" in c]
    viol = [c for c in cmds if "THE VIOLATION" in c]
    check(len(viol) == 1, "exactly one command is marked as THE VIOLATION")
    check("as backend" in viol[0], "the violating command is the backend one")
    denied = [c for c in cmds if "correctly denied" in c]
    check(len(denied) == 2, "both 401 baselines are labelled as correctly denied")
    check(any("proves auth IS enforced" in c for c in denied),
          "baseline label explains that a 401 supports the finding")
    check(any("entitled baseline" in c for c in cmds),
          "the admin exchange is labelled as entitled, not a violation")


def test_no_evidence_produces_no_invented_prose():
    f = _finding(evidence=[], verdict="not_tested")
    rep = build_report(f)
    check(rep["reproduction"] == [], "no evidence -> no fabricated reproduction commands")
    check(rep["observed"]["requests_captured"] == 0, "zero captured requests reported")
    check("NOT TESTED." in rep["outcome"], "untested findings say so in the outcome")


def test_attach_reports_is_idempotent_and_in_place():
    f = _finding(evidence=[_rec("anonymous", 401), _rec("backend", 200)],
                 verdict="true_positive",
                 detail={"code_paths": ["a/B.java:10"], "impact": "priv esc",
                         "remediation": "add role check", "cwe": "CWE-639"})
    attach_reports([f])
    r1 = f.detail["report"]
    check(r1["location"]["code_paths"] == ["a/B.java:10"], "code paths flow into location")
    check(r1["impact"] == "priv esc", "impact is carried through")
    check(r1["remediation"] == "add role check", "remediation is carried through")
    check("CWE-639" in r1["references"], "CWE reference is carried through")
    attach_reports([f])
    check(f.detail["report"] == r1, "regenerating from the same evidence is deterministic")


def test_explicit_labels_distinguish_violation_from_control():
    """One identity often sends BOTH the violating request and its control.

    Labelling by identity alone then marks the control as a second violation,
    which overstates the finding — the exact defect this locks down. An explicit
    per-exchange label list must win over the identity heuristic.
    """
    rec = lambda body, n: RequestRecord(
        method="GET", url=f"http://t/api/roles/checkuserroles/{n}", identity="readonly",
        status=200, elapsed_ms=5, req_headers={}, req_body=None, resp_headers={},
        resp_body=body, resp_len=len(body), error=None)
    f = Finding(
        vuln_class=VulnClass.IDOR, severity=Severity.MEDIUM,
        title="Cross-user role disclosure", endpoint="GET /api/roles/checkuserroles",
        description="x",
        evidence=[rec('{"checkRoles":true}', "victim"), rec('{"checkRoles":false}', "self")],
        detail={
            "violating_identity": "readonly",
            "evidence_labels": ["THE VIOLATION: learns the admin holds the role",
                                "CONTROL: the caller's own account returns the opposite"],
        })
    attach_reports([f])
    ex = f.detail["report"]["exchanges"]
    check(ex[0]["proves"].startswith("THE VIOLATION"), "explicit label used for the violating exchange")
    check(ex[1]["proves"].startswith("CONTROL"),
          "the control is labelled CONTROL, not a second violation")
    check("THE VIOLATION" not in ex[1]["proves"],
          "the control is never mislabelled as a violation")
    # Without explicit labels the identity heuristic still applies.
    f2 = Finding(
        vuln_class=VulnClass.IDOR, severity=Severity.MEDIUM, title="t", endpoint="e",
        description="x", evidence=[rec('{"a":1}', "v")],
        detail={"violating_identity": "readonly"})
    attach_reports([f2])
    check("VIOLATION" in f2.detail["report"]["exchanges"][0]["proves"],
          "identity heuristic still labels the violation when no explicit list is given")


def test_exchange_pairs_each_request_with_its_response():
    """A curl line without its response cannot be adjudicated by the reader."""
    empty = RequestRecord(
        method="GET", url="http://t/api/v1/ai/search/related", identity="anonymous",
        status=500, elapsed_ms=9, req_headers={}, req_body=None, resp_headers={},
        resp_body="", resp_len=0, error=None)
    f = Finding(vuln_class=VulnClass.ERROR_HANDLING, severity=Severity.LOW,
                title="500", endpoint="GET /api/v1/ai/search/related", description="x",
                evidence=[empty], detail={})
    attach_reports([f])
    ex = f.detail["report"]["exchanges"][0]
    check(ex["response"]["status"] == 500, "the observed status is carried on the exchange")
    check(ex["response"]["body_empty"] is True,
          "an empty 5xx body is flagged as empty, not rendered as a silent blank")
    check(ex["response"]["body_bytes"] == 0, "the true response length is recorded")


def main() -> int:
    print("== evidence-derived reporting ==")
    test_curl_never_embeds_secrets()
    test_curl_reproduces_the_real_request()
    test_report_is_derived_from_evidence()
    test_consistent_access_control_is_described_as_such()
    test_violating_request_is_labelled()
    test_no_evidence_produces_no_invented_prose()
    test_attach_reports_is_idempotent_and_in_place()
    test_explicit_labels_distinguish_violation_from_control()
    test_exchange_pairs_each_request_with_its_response()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks} checks:")
        for f in _failures:
            print("  -", f)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
