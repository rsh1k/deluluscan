"""End-to-end: run the real orchestrator with the v0.5 breadth scanners against
the live mock, confirming authz-matrix bypass, excessive data exposure, verbose
error handling, missing rate limiting, and GraphQL introspection — and that the
token sequencer does NOT false-positive on the mock's random tokens.
"""
from __future__ import annotations
import sys, os, threading, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_target import serve
from deluluscan.config import Config, ScanConfig
from deluluscan.models import Identity, IdentityRole
from deluluscan.orchestrator import Orchestrator

PORT = 8095


def main():
    threading.Thread(target=serve, args=(PORT,), daemon=True).start()
    time.sleep(0.5)

    cfg = Config(base_url=f"http://127.0.0.1:{PORT}", verify_tls=False)
    cfg.identities = {
        "anonymous": Identity(role=IdentityRole.ANON),
        "backend": Identity(role=IdentityRole.BACKEND, username="editor", password="pw"),
        "admin": Identity(role=IdentityRole.ADMIN, username="admin-user", password="pw"),
    }
    cfg.scan = ScanConfig(rate_limit_rps=200.0,
                          scanners=["authmatrix", "bopla_miner", "sequencer",
                                    "faults", "flows", "graphql"],
                          verify=True, flow_burst=10)
    cfg.ai.provider = "none"; cfg.ai.enabled = False

    result = Orchestrator(cfg).run()

    tests_seen = {}
    for f in result["findings"]:
        t = f["detail"].get("test", "")
        tests_seen.setdefault(t, []).append(f)
    print(f"\n{'TEST':24} {'VERDICT':16} {'EXPLOIT':13} SEV  TITLE")
    print("-" * 100)
    for f in result["findings"]:
        print(f"{f['detail'].get('test',''):24.24} {f.get('verdict',''):16} "
              f"{f.get('exploitability',''):13} {f['severity']:4} {f['title'][:34]}")

    checks = [
        ("authz matrix bypass (BOLA/BFLA, A01)", "authz_matrix_bypass" in tests_seen),
        ("excessive data exposure (BOPLA/API3)", "excessive_data" in tests_seen),
        ("verbose error / A10 mishandling", "verbose_error" in tests_seen),
        ("missing rate limit (API4/API6)", "no_rate_limit" in tests_seen),
        ("graphql introspection exposed", "graphql_introspection" in tests_seen),
        ("sequencer did NOT false-positive on random tokens",
         "token_predictable" not in tests_seen and "token_weak" not in tests_seen),
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
