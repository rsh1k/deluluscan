"""Offline tests for shadow-environment detection.

A synthetic fetch/resolver drives the scan with no network, and asserts the two
things that matter: (a) the posture diff catches a copy that is weaker than
production, and (b) the authorization boundary holds — an out-of-scope host is
reported as a lead but never actually requested.
"""
from __future__ import annotations

from deluluscan.shadowenv import ShadowEnvScan, derive_candidates
from deluluscan.models import VulnClass, Severity

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"PASS  {name}")
    else:
        _FAIL += 1
        print(f"FAIL  {name}  {detail}")


PROD_CSP = "default-src 'none'"


def test_derive_candidates():
    cands = derive_candidates("https://api.example.com")
    hosts = {c.split("://", 1)[1] for c in cands}
    check("derives staging.api.example.com", "staging.api.example.com" in hosts, hosts)
    check("derives staging-api.example.com", "staging-api.example.com" in hosts, hosts)
    check("derives apex-level staging.example.com", "staging.example.com" in hosts, hosts)
    check("never the target itself", "api.example.com" not in hosts)
    check("preserves scheme", all(c.startswith("https://") for c in cands))
    check("IP literal yields nothing", derive_candidates("http://10.0.0.1:8080") == [])


def _fetcher(responses: dict, calls: list):
    """responses: {host -> (status, headers, body)}; records every host fetched."""
    def fetch(url):
        from urllib.parse import urlparse
        host = urlparse(url).hostname
        calls.append(host)
        return responses.get(host, (0, {}, ""))
    return fetch


def test_auth_dropped_in_shadow():
    # production demands auth; the staging copy serves 200 anonymously.
    calls = []
    responses = {
        "app.example.com": (401, {"content-security-policy": PROD_CSP}, "sign in"),
        "staging.app.example.com": (200, {"content-security-policy": PROD_CSP}, "welcome admin"),
    }
    scan = ShadowEnvScan(
        fetch=_fetcher(responses, calls),
        resolve=lambda h: h in responses,                 # only these names exist
        authorized_hosts=["app.example.com", "staging.app.example.com"],
    )
    findings = scan.scan("https://app.example.com")
    drop = next((f for f in findings if f.vuln_class == VulnClass.AUTHZ), None)
    check("auth-drop detected", drop is not None, [f.title for f in findings])
    check("auth-drop is HIGH", drop and drop.severity == Severity.HIGH)
    check("auth-drop names the shadow host", drop and drop.detail.get("shadow_host") == "staging.app.example.com")
    check("auth-drop carries evidence", drop and len(drop.evidence) == 1)
    check("also flags reachable inventory",
          any(f.vuln_class == VulnClass.INVENTORY and f.detail.get("probed") for f in findings))


def test_headers_regressed_in_shadow():
    calls = []
    responses = {
        "example.com": (200, {"content-security-policy": PROD_CSP,
                              "x-frame-options": "DENY"}, "home"),
        "dev.example.com": (200, {}, "home"),             # dropped both headers
    }
    scan = ShadowEnvScan(fetch=_fetcher(responses, calls),
                         resolve=lambda h: h in responses,
                         authorized_hosts=["example.com", "dev.example.com"])
    findings = scan.scan("https://example.com")
    mis = next((f for f in findings if f.vuln_class == VulnClass.MISCONFIG), None)
    check("header regression detected", mis is not None, [f.title for f in findings])
    check("names the dropped headers",
          mis and "content-security-policy" in mis.detail.get("dropped_headers", []),
          mis and mis.detail.get("dropped_headers"))


def test_out_of_scope_is_a_lead_never_probed():
    # The shadow host resolves but is NOT authorized -> reported, never fetched.
    calls = []
    responses = {"example.com": (200, {}, "prod")}       # only the target is fetchable
    scan = ShadowEnvScan(
        fetch=_fetcher(responses, calls),
        resolve=lambda h: h in ("example.com", "staging.example.com"),
        authorized_hosts=["example.com"],                # staging.example.com NOT authorized
    )
    findings = scan.scan("https://example.com")
    lead = next((f for f in findings if f.detail.get("shadow_host") == "staging.example.com"), None)
    check("out-of-scope shadow reported as lead", lead is not None)
    check("lead is unprobed", lead and lead.detail.get("probed") is False)
    check("lead has no evidence (never requested)", lead and lead.evidence == [])
    check("SCOPE: out-of-scope host was never fetched",
          "staging.example.com" not in calls, calls)


def test_nonresolving_candidates_skipped():
    calls = []
    scan = ShadowEnvScan(fetch=_fetcher({"example.com": (200, {}, "x")}, calls),
                         resolve=lambda h: h == "example.com",   # no shadow names exist
                         authorized_hosts=["example.com"])
    findings = scan.scan("https://example.com")
    check("no findings when no shadow host resolves", findings == [], [f.title for f in findings])


def run():
    for fn in (test_derive_candidates, test_auth_dropped_in_shadow,
               test_headers_regressed_in_shadow, test_out_of_scope_is_a_lead_never_probed,
               test_nonresolving_candidates_skipped):
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    return _FAIL == 0


if __name__ == "__main__":
    import sys
    sys.exit(0 if run() else 1)
