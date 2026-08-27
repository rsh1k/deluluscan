"""End-to-end test: run the REAL orchestrator (real HttpClient, discovery,
scanners, verifier) against the live loopback mock target. Proves the safety
gate accepts 127.0.0.1 and that verification separates true positives from the
planted false positives on a running server.
"""
from __future__ import annotations
import sys, os, threading, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_target import serve
from deluluscan.config import Config, ScanConfig
from deluluscan.models import Identity, IdentityRole
from deluluscan.orchestrator import Orchestrator

PORT = 8099


def main():
    threading.Thread(target=serve, args=(PORT,), daemon=True).start()
    time.sleep(0.5)

    cfg = Config(base_url=f"http://127.0.0.1:{PORT}", allow_remote=False,
                 verify_tls=False)
    cfg.identities = {"anonymous": Identity(role=IdentityRole.ANON)}
    cfg.scan = ScanConfig(rate_limit_rps=50.0, sqli_sleep_s=2,
                          scanners=["xss", "sqli", "idor", "owasp"], verify=True)
    cfg.ai.provider = "none"; cfg.ai.enabled = False

    result = Orchestrator(cfg).run()

    print(f"\nSafety gate: PASSED (loopback target accepted)\n")
    print(f"{'ENDPOINT':38} {'CLASS':6} {'VERDICT':22} {'EXPLOITABILITY':16} SEV")
    print("-" * 100)
    checks = []
    by_ep = {}
    for f in result["findings"]:
        v = f["detail"].get("verification", {})
        print(f"{f['endpoint']:38.38} {f['vuln_class']:6} "
              f"{f.get('verdict',''):22} {f.get('exploitability',''):16} {f['severity']}")
        by_ep.setdefault(f["endpoint"], []).append(f)

    def find(ep_substr, cls):
        for ep, fs in by_ep.items():
            if ep_substr in ep:
                for f in fs:
                    if f["vuln_class"] == cls:
                        return f
        return None

    def expect_absent(name, f):
        """Assert a finding class was NOT raised (a correct silence)."""
        ok = f is None
        checks.append((name, ok, "" if ok else f"unexpectedly present as {f.get('verdict')}"))

    def expect(name, f, verdict=None, expl=None):
        ok = f is not None
        if ok and verdict:
            ok = f.get("verdict") == verdict
        if ok and expl:
            ok = f.get("exploitability") == expl
        checks.append((name, ok, "" if ok else (f or {}).get("verdict", "MISSING")))

    expect("REAL reflected XSS -> true_positive/exploitable",
           find("/api/vuln/search", "xss"), "true_positive", "exploitable")
    expect("XSS behind strong CSP -> mitigated",
           find("/api/safe/search", "xss"), None, "mitigated")
    expect("REAL error-based SQLi -> true_positive",
           find("/api/vuln/item", "sqli"), "true_positive")
    # A verbose-error trap must NOT be reported as SQL injection at all. It used
    # to be raised as a sqli finding and then downgraded to false_positive by the
    # verifier; the scanner now discriminates up front by comparing the payload's
    # database error against a payload-free control value. Identical errors mean
    # the input never reached the statement, so it is reported as an
    # error-handling/SQL-disclosure defect instead of an injection claim.
    # (Live case that motivated this: /api/categories?orderby=... produced the
    # same "syntax error at or near ASC" for every rejected value because
    # sanitizeSortBy blanked it — two CRITICAL false positives.)
    expect_absent("verbose-error trap -> not reported as sqli at all",
                  find("/api/trap/item", "sqli"))
    expect("verbose-error trap -> reported as error_handling instead",
           find("/api/trap/item", "error_handling"), None, None)
    expect("REAL missing-auth roles -> reachable as anon",
           find("/api/vuln/roles", "authz"), None, None)

    print("\nExpectations:")
    allok = True
    for name, ok, extra in checks:
        allok = allok and ok
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  (got {extra})" if not ok else ""))

    m = result["meta"].get("verification", {})
    print(f"\nverification summary: {m}")
    print(f"total findings: {len(result['findings'])}")
    sys.exit(0 if allok else 1)


if __name__ == "__main__":
    main()
