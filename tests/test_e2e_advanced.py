"""End-to-end: v0.6 advanced scanners through the real orchestrator against the
mock — supply-chain/artifact exposure, shadow endpoints, HTTP verb tampering,
and deep GraphQL abuse (batching / alias amplification / missing depth limit).
"""
from __future__ import annotations
import sys, os, threading, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_target import serve
from deluluscan.config import Config, ScanConfig
from deluluscan.models import Identity, IdentityRole
from deluluscan.orchestrator import Orchestrator

PORT = 8094


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
                          scanners=["content_discovery", "verbtamper", "graphql_adv"],
                          verify=True)
    cfg.ai.provider = "none"; cfg.ai.enabled = False

    result = Orchestrator(cfg).run()

    seen = {}
    for f in result["findings"]:
        seen.setdefault(f["detail"].get("test", ""), []).append(f)
    print(f"\n{'TEST':28} {'VERDICT':16} {'EXPLOIT':13} SEV  TITLE")
    print("-" * 100)
    for f in result["findings"]:
        print(f"{f['detail'].get('test',''):28.28} {f.get('verdict',''):16} "
              f"{f.get('exploitability',''):13} {f['severity']:4} {f['title'][:32]}")

    checks = [
        ("supply-chain artifact exposure (.git/.env)", "artifact_exposure" in seen),
        ("shadow/undocumented endpoint (API9)", "shadow_endpoint" in seen),
        ("HTTP verb tampering bypass (API5/A01)", "verb_tamper" in seen),
        ("GraphQL query batching", "graphql_batching" in seen),
        ("GraphQL alias amplification", "graphql_alias_amplification" in seen),
        ("GraphQL missing depth limit", "graphql_no_depth_limit" in seen),
    ]
    print("\nExpectations:")
    allok = True
    for name, ok in checks:
        allok = allok and ok
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\ntests observed: {sorted(t for t in seen if t)}")
    print(f"total findings: {len(result['findings'])}")
    sys.exit(0 if allok else 1)


if __name__ == "__main__":
    main()
