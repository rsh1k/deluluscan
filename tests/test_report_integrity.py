"""The report may only state what the scan observed.

Two defects this locks down, both in the published-report path:

1. FABRICATED EVIDENCE. _augment_evidence() invented an admin request/response
   for any finding lacking one — status, body, resp_len, and an elapsed_ms
   back-computed as anon.elapsed_ms * 0.9 so it looked measured. It was prepended
   to the evidence list, rendered identically to captured traffic, and read by
   buildAccessMatrix() as a real "admin was granted" observation.
   _normalize_evidence() did the same for findings with no evidence at all,
   defaulting backend=200 / anon=401 for anything whose title merely contained
   "idor" or "bfla".

2. HARDCODED NARRATIVE. renderPentestReport() asserted a specific
   roles/layouts -> _addtouser -> OSGi/Apps-RCE chain whenever ANY confirmed
   critical existed, plus a fixed "dominant theme" and conclusion — regardless of
   what the scan found. A lone SQLi produced a confident report about an
   escalation nobody tested.

The JS-execution checks need a JS engine and are skipped without one; the
Python-side checks always run.

Run: python3 -m tests.test_report_integrity
"""
from __future__ import annotations

import json
import re
import sys

from deluluscan import dashboard as d

_checks = 0
_failures: list[str] = []


def check(cond: bool, label: str) -> None:
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


# ---------------------------------------------------------------------------
# 1. No fabricated evidence
# ---------------------------------------------------------------------------
def test_finding_without_evidence_stays_without_evidence():
    findings = [{"title": "Possible horizontal IDOR on userId",
                 "endpoint": "GET /api/v1/users/{id}", "severity": "high",
                 "vuln_class": "authz", "verdict": "true_positive",
                 "description": "returned HTTP 200 to a backend user, HTTP 401 to anonymous",
                 "evidence": []}]
    out = d._normalize_evidence(findings)
    check(out[0]["evidence"] == [],
          "a finding with no evidence gets NO synthesised records")
    check(out[0].get("evidence_missing") is True,
          "and is flagged evidence_missing so the report can say so")


def test_idor_title_no_longer_conjures_a_backend_200():
    """The old heuristic: title contains 'idor' -> invent backend=200 + anon=401.
    That fabricated exactly the observation the access matrix reads to conclude
    privilege escalation."""
    findings = [{"title": "IDOR candidate", "endpoint": "GET /api/v1/thing/{id}",
                 "severity": "high", "vuln_class": "authz", "verdict": "true_positive",
                 "description": "no status codes mentioned at all", "evidence": []}]
    out = d._normalize_evidence(findings)
    ids = [e.get("identity") for e in out[0]["evidence"]]
    check(not ids, f"no identity records invented from an 'IDOR' title (got {ids})")


def test_admin_record_is_never_invented():
    """_augment_evidence() used to add an admin 200 whenever admin authenticated
    and the finding had an anonymous 401."""
    check(not hasattr(d, "_augment_evidence"),
          "_augment_evidence() is gone — an unprobed identity cannot be guessed")
    check(not hasattr(d, "_status_resp_body"),
          "_status_resp_body() is gone — no invented response bodies")
    check(not hasattr(d, "_extract_identity_status"),
          "_extract_identity_status() is gone — no status codes scraped from prose")

    result = {"meta": {"target": "http://127.0.0.1:8080",
                       "identities": {"admin": {"ok": True}}},
              "findings": [{"title": "Anonymous denied", "endpoint": "GET /api/v1/x",
                            "severity": "high", "vuln_class": "authz",
                            "verdict": "true_positive", "description": "d",
                            "evidence": [{"method": "GET", "url": "http://t/api/v1/x",
                                          "identity": "anonymous", "status": 401,
                                          "elapsed_ms": 20.0, "resp_body": "{}",
                                          "resp_len": 2}]}]}
    scans = d._build_scans(result)
    ev = scans[0]["findings"][0]["evidence"]
    idents = {e.get("identity") for e in ev}
    check(idents == {"anonymous"},
          f"only the identity actually probed appears in evidence (got {sorted(idents)})")


def test_real_evidence_is_preserved_and_redacted():
    findings = [{"title": "t", "endpoint": "GET /api/v1/x", "severity": "low",
                 "vuln_class": "info_leak", "verdict": "unverified", "description": "d",
                 "evidence": [{"method": "GET", "url": "http://t/api/v1/x",
                               "identity": "admin", "status": 200, "elapsed_ms": 5.0,
                               "req_headers": {"Authorization": "Bearer secret"},
                               "resp_headers": {"Set-Cookie": "JSESSIONID=DEADBEEFDEADBEEF01; HttpOnly"},
                               "body_snippet": "ok", "resp_len": 2}]}]
    out = d._normalize_evidence(findings)
    e = out[0]["evidence"][0]
    check(e["status"] == 200 and e["identity"] == "admin",
          "captured records pass through intact")
    check(e.get("resp_body") == "ok", "legacy body_snippet is still renamed to resp_body")
    check(e["req_headers"]["Authorization"] == "<redacted>",
          "credential headers are still redacted")
    check("DEADBEEF" not in e["resp_headers"]["Set-Cookie"],
          "session cookie values are still redacted")
    check("HttpOnly" in e["resp_headers"]["Set-Cookie"],
          "but cookie security attributes survive as evidence")
    check(out[0].get("evidence_missing") is not True,
          "a finding WITH evidence is not flagged as missing it")


def test_no_plausible_default_headers_are_invented():
    findings = [{"title": "t", "endpoint": "GET /api/v1/x", "severity": "low",
                 "vuln_class": "info_leak", "verdict": "unverified", "description": "d",
                 "evidence": [{"method": "GET", "url": "http://t/api/v1/x",
                               "identity": "admin", "status": 200, "elapsed_ms": 5.0}]}]
    e = d._normalize_evidence(findings)[0]["evidence"][0]
    check(e["req_headers"] == {} and e["resp_headers"] == {},
          "missing headers default to EMPTY, not an invented User-Agent/Accept trio")


# ---------------------------------------------------------------------------
# 2. No hardcoded narrative in the template
# ---------------------------------------------------------------------------
_HARDCODED = [
    ("chain reconnaissance step",
     "an unauthenticated request enumerates administrative layout identifiers"),
    ("chain RCE step", "the Apps secret-import deserialization path"),
    ("net-effect callout",
     "a single authenticated low-privilege account can obtain administrator-equivalent"),
    ("fixed dominant theme",
     "dominant theme is <b>broken function- and object-level authorization</b>"),
    ("fixed conclusion", "The target platform enforces authentication effectively"),
]


def test_template_carries_no_hardcoded_findings():
    tmpl = d._TMPL
    for name, needle in _HARDCODED:
        check(needle not in tmpl,
              f"template no longer hardcodes the {name}")


_CRITICAL = {
    "title": "SQL injection via 'orderby'", "endpoint": "GET /api/categories",
    "severity": "critical", "vuln_class": "sqli", "verdict": "true_positive",
    "exploitability": "exploitable", "confidence": "firm", "cwe": "CWE-89",
    "description": "desc", "detail": {"test": "sqli"},
    "evidence": [{"method": "GET", "url": "http://127.0.0.1:8080/api/categories",
                  "identity": "anonymous", "status": 200, "elapsed_ms": 12.0,
                  "req_headers": {}, "resp_headers": {}, "resp_body": "{}", "resp_len": 2}],
}


def test_shell_can_state_what_was_not_established():
    """The shell must carry the vocabulary for absence. Identifiers are minified in
    the built bundle, so assert on the user-visible STRINGS instead — those survive
    minification and are what a reader actually sees.

    The behavioural assertions (narrative derived from meta.escalation_pivot,
    status-0 excluded from the access matrix, destructive coverage rendered) live in
    dashboard/src/test/report-integrity.test.tsx, where the components are really
    rendered rather than grepped."""
    shell = d._TMPL
    for phrase, why in [
        ("No exploit chain was demonstrated", "can say no chain was found"),
        ("measured", "distinguishes a measured escalation from an inferred one"),
        ("inferred", "labels reasoned chains as reasoned"),
        ("Destructive operations", "reports destructive-pass coverage"),
        ("not probed", "can mark an identity/endpoint as untested"),
        ("no evidence captured", "can state that a finding has no evidence"),
        ("Untested is not the same as secure", "says absence is not assurance"),
        ("UNKNOWN", "marks unprobed destructive endpoints as unknown"),
    ]:
        check(phrase in shell, f"shell {why} ('{phrase}')")


def test_shell_reads_the_measured_pivot():
    shell = d._TMPL
    check("escalation_pivot" in shell,
          "the narrative is derived from meta.escalation_pivot (the MEASURED result)")
    check("destructive_pass" in shell,
          "coverage is derived from meta.destructive_pass")
    check("caused_outage" in shell,
          "an endpoint whose probe took the target down is reported as such")


def test_generated_page_is_self_contained():
    """The report is opened from file:// and served as a static artifact, so a
    reference to an external asset is a blank page, not a degraded one."""
    html = d.build_html({"meta": {"target": "http://127.0.0.1:8080"},
                         "findings": [dict(_CRITICAL)]})
    check(d._DATA_MARKER not in html, "the injection marker is consumed, not shipped")
    check("var SCANS=" in html, "the scan payload is embedded")
    check(not re.search(r'(?:src|href)="/?assets/', html),
          "no external asset references remain")
    check("SQL injection" in html, "the finding reached the payload")


def test_encrypted_page_contains_no_findings():
    pw = d.generate_password()
    html = d.build_html({"meta": {"target": "http://127.0.0.1:8080"},
                         "findings": [dict(_CRITICAL)]}, password=pw)
    check("var SCANS=null" in html, "plaintext payload is replaced by null")
    check("SQL injection" not in html,
          "the finding text genuinely is not in the file before decryption")
    check("/api/categories" not in html, "nor is the affected endpoint")
    blob = json.loads(re.search(r"var __ENC__=(\{.*?\});", html).group(1))
    check(d._decrypt_payload(blob, pw).find("SQL injection") > -1,
          "and the correct passphrase recovers it")


def main() -> int:
    print("== report integrity: only claim what was observed ==")
    test_finding_without_evidence_stays_without_evidence()
    test_idor_title_no_longer_conjures_a_backend_200()
    test_admin_record_is_never_invented()
    test_real_evidence_is_preserved_and_redacted()
    test_no_plausible_default_headers_are_invented()
    test_template_carries_no_hardcoded_findings()
    test_shell_can_state_what_was_not_established()
    test_shell_reads_the_measured_pivot()
    test_generated_page_is_self_contained()
    test_encrypted_page_contains_no_findings()
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
