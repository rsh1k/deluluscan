"""Unit tests for v0.8: injection/traversal classifiers and the chain analyzer.
Run: python -m tests.test_injection_chains
"""
from __future__ import annotations
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import RequestRecord, Finding, Severity, VulnClass
from deluluscan.active import injection as I
from deluluscan.verify.chains import ChainAnalyzer

results = []
def check(name, cond, extra=""):
    results.append((name, cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))

def rec(status=200, body="", headers=None):
    return RequestRecord(method="GET", url="http://h/x", identity="a", status=status,
                         elapsed_ms=10.0, resp_headers=headers or {}, resp_body=body, resp_len=len(body))


# ---- injection classifiers -------------------------------------------------
def test_traversal_hit():
    r = rec(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1")
    check("traversal confirmed on /etc/passwd signature",
          I.classify_traversal(r, "file", "../etc/passwd") is not None)

def test_traversal_no_fp():
    check("traversal: no FP on normal body",
          I.classify_traversal(rec(200, '{"ok":true}'), "file", "x") is None)

def test_ssti_hit():
    pl = "${1337*1331}"
    r = rec(200, f"result is {I._SSTI_PRODUCT} done")
    check("SSTI confirmed when expression evaluates and payload is gone",
          I.classify_ssti(r, "q", pl) is not None)

def test_ssti_no_fp_when_reflected_literally():
    pl = "${1337*1331}"
    r = rec(200, f"you searched for {pl}")   # payload echoed literally, not evaluated
    check("SSTI: no FP when payload only reflected literally",
          I.classify_ssti(r, "q", pl) is None)

def test_open_redirect_hit():
    r = rec(302, "", headers={"Location": "https://deluluscan-oob.example/"})
    check("open redirect confirmed via Location header",
          I.classify_open_redirect(r, "next", "https://deluluscan-oob.example/") is not None)

def test_open_redirect_no_fp_same_site():
    r = rec(302, "", headers={"Location": "https://localhost:8080/home"})
    check("open redirect: no FP on same-site redirect",
          I.classify_open_redirect(r, "next", "x") is None)

def test_crlf_hit():
    r = rec(200, "", headers={"X-Deluluscan-Injected": "pwned"})
    check("CRLF confirmed when injected header appears",
          I.classify_crlf(r, "q", I.CRLF_PAYLOAD) is not None)

def test_nosql_auth_bypass():
    base = rec(401, "denied")
    r = rec(200, '{"token":"abc","user":"admin"}')
    check("NoSQL auth bypass when denied->success via operator",
          I.classify_nosql(base, r, "user", '{"$gt":""}') is not None)

def test_host_header_reflected():
    r = rec(200, '<a href="https://deluluscan-oob.example/reset">reset</a>')
    check("host header injection when evil host reflected",
          I.classify_host_header(r, "deluluscan-oob.example") is not None)


# ---- chain analyzer --------------------------------------------------------
def _f(title, vc, test="", verdict="true_positive", desc=""):
    f = Finding(vuln_class=vc, severity=Severity.MEDIUM, title=title,
                endpoint="GET /x", description=desc, evidence=[], detail={"test": test})
    f.verdict = verdict
    return f

def test_chain_ssrf_metadata():
    findings = [
        _f("SSRF confirmed via OOB", VulnClass.SSRF, "ssrf_oob"),
        _f("Actuator/metadata endpoint reachable", VulnClass.MISCONFIG, "shadow_endpoint",
           desc="internal actuator metadata 169.254 reachable"),
    ]
    chains = ChainAnalyzer().analyze(findings)
    check("chain: SSRF + metadata -> critical credential-theft chain",
          any("SSRF" in c.title and c.severity == Severity.CRITICAL for c in chains),
          str([c.title for c in chains]))

def test_chain_upload_to_xss():
    findings = [
        _f("Unrestricted file upload accepted (deluluscan.svg)", VulnClass.MISCONFIG, "file_upload"),
        _f("Reflected content served", VulnClass.XSS, "reflected_xss",
           desc="uploaded asset is served and reflected as xss"),
    ]
    chains = ChainAnalyzer().analyze(findings)
    check("chain: file upload + served -> stored XSS/RCE",
          any("upload" in c.title.lower() for c in chains), str([c.title for c in chains]))

def test_chain_requires_two_distinct_findings():
    # a single SSRF alone must NOT form the SSRF+metadata chain
    findings = [_f("SSRF confirmed", VulnClass.SSRF, "ssrf_oob")]
    chains = ChainAnalyzer().analyze(findings)
    check("chain: single finding does not form a 2-part chain",
          not any("SSRF" in c.title for c in chains), str([c.title for c in chains]))

def test_chain_ignores_false_positives():
    findings = [
        _f("SSRF confirmed", VulnClass.SSRF, "ssrf_oob", verdict="false_positive"),
        _f("metadata reachable", VulnClass.MISCONFIG, "shadow_endpoint", desc="metadata 169.254"),
    ]
    chains = ChainAnalyzer().analyze(findings)
    check("chain: dismissed/false-positive constituents are not chained",
          not any("SSRF" in c.title for c in chains), str([c.title for c in chains]))

def test_chain_ignores_unconfirmed_candidates():
    # the reported FP: a 'manual SSRF review' candidate (verdict inconclusive) plus
    # an unrelated 500 must NOT form the SSRF->metadata chain.
    ssrf_candidate = _f("URL-accepting parameter 'callback' (manual SSRF review)",
                        VulnClass.SSRF, "ssrf_manual", verdict="inconclusive",
                        desc="url parameter may allow ssrf to internal/metadata; manual review")
    err = _f("Unhandled server error on malformed input", VulnClass.MISCONFIG,
             "server_error", verdict="true_positive", desc="500 on malformed json")
    chains = ChainAnalyzer().analyze([ssrf_candidate, err])
    check("chain: unconfirmed 'manual review' SSRF candidate is NOT chained",
          not any("SSRF" in c.title for c in chains), str([c.title for c in chains]))

def test_chain_sets_verdict():
    findings = [
        _f("No rate limiting on a sensitive flow", VulnClass.RATE_LIMIT, "no_rate_limit",
           desc="login flow no rate limit"),
        _f("login endpoint", VulnClass.AUTHZ, "authz", desc="authentication login"),
    ]
    chains = ChainAnalyzer().analyze(findings)
    check("chain findings carry a verdict + verification for the report",
          chains and chains[0].verdict and chains[0].detail.get("verification"),
          str([(c.title, c.verdict) for c in chains]))


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    total = len(results); passed = sum(1 for _, c in results if c)
    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)
