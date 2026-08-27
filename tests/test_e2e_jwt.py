"""End-to-end: run the REAL orchestrator with the active `jwt` scanner against
the live loopback mock. The mock issues real HS256 tokens (weak secret) and its
/api/v1/users/current trusts claims without verifying the signature, and
/api/vuln/profile mass-assigns posted fields. Proves the tool logs in, extracts
the token, actively manipulates it, and confirms the bugs through the pipeline.
"""
from __future__ import annotations
import sys, os, threading, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_target import serve
from deluluscan.config import Config, ScanConfig
from deluluscan.models import Identity, IdentityRole
from deluluscan.orchestrator import Orchestrator

PORT = 8096


def main():
    threading.Thread(target=serve, args=(PORT,), daemon=True).start()
    time.sleep(0.5)

    cfg = Config(base_url=f"http://127.0.0.1:{PORT}", verify_tls=False)
    # a backend identity we control; the tool logs in to obtain its JWT
    cfg.identities = {
        "anonymous": Identity(role=IdentityRole.ANON),
        "backend": Identity(role=IdentityRole.BACKEND, username="editor", password="pw"),
    }
    cfg.scan = ScanConfig(rate_limit_rps=100.0, scanners=["jwt"], verify=True)
    cfg.ai.provider = "none"; cfg.ai.enabled = False

    result = Orchestrator(cfg).run()

    print("\nSafety gate: PASSED (loopback target accepted)\n")
    print(f"{'TITLE':52} {'VERDICT':20} {'EXPLOIT':13} SEV")
    print("-" * 100)
    tests_seen = set()
    for f in result["findings"]:
        v = f["detail"].get("verification", {})
        print(f"{f['title']:52.52} {f.get('verdict',''):20} "
              f"{f.get('exploitability',''):13} {f['severity']}")
        tests_seen.add(f["detail"].get("test", ""))

    checks = [
        ("JWT signature-not-verified / alg:none / claim tamper detected",
         any(t in tests_seen for t in ("alg_none:none", "strip_signature",
                                       "tamper_signature", "claim_tamper"))),
        ("weak JWT secret detected", "weak_secret" in tests_seen),
        ("mass assignment detected", "mass_assignment" in tests_seen),
    ]
    print("\nExpectations:")
    allok = True
    for name, ok in checks:
        allok = allok and ok
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\ntests observed: {sorted(t for t in tests_seen if t)}")
    print(f"total findings: {len(result['findings'])}")
    sys.exit(0 if allok else 1)


if __name__ == "__main__":
    main()
