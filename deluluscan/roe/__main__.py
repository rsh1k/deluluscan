"""CLI: parse a Rules-of-Engagement doc and check targets/tests against it.

    python3 -m deluluscan.roe --file roe.yaml                 # show the parsed policy
    python3 -m deluluscan.roe --file roe.yaml --check https://app.example.com
    python3 -m deluluscan.roe --file roe.yaml --scanner sqli  # is this test permitted?
"""
from __future__ import annotations

import argparse
import json
import sys

from .parse import load_roe


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.roe", description="Rules-of-Engagement governance")
    ap.add_argument("--file", required=True, help="RoE document (YAML/JSON/text)")
    ap.add_argument("--check", metavar="TARGET", help="check whether a target URL/host is in scope")
    ap.add_argument("--scanner", metavar="NAME", help="check whether a test/scanner is permitted")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        pol = load_roe(a.file)
    except Exception as e:
        raise SystemExit(f"[roe] could not read {a.file}: {e}")

    result = {"policy": pol.to_dict()}
    exit_code = 0
    if a.check:
        allowed, reason = pol.target_in_scope(a.check)
        result["target"] = {"target": a.check, "in_scope": allowed, "reason": reason}
        exit_code = 0 if allowed else 3
    if a.scanner:
        result["scanner"] = {"name": a.scanner, "permitted": pol.scanner_allowed(a.scanner)}

    if a.json:
        print(json.dumps(result, indent=2, default=str))
        return exit_code
    print(f"[roe] {a.file}")
    print(f"  in-scope     : {pol.in_scope or '(none)'}")
    print(f"  out-of-scope : {pol.out_of_scope or '(none)'}")
    print(f"  excluded     : {sorted(pol.excluded_tests) or '(none)'}")
    if pol.window_start:
        print(f"  window       : {pol.window_start}-{pol.window_end}  (now within: {pol.within_window()})")
    if pol.rate_limit_rps:
        print(f"  rate limit   : {pol.rate_limit_rps} rps")
    print(f"  allow_remote={pol.allow_remote}  allow_destructive={pol.allow_destructive}")
    if a.check:
        r = result["target"]
        print(f"\n  target {a.check}: {'IN SCOPE' if r['in_scope'] else 'OUT OF SCOPE'} — {r['reason']}")
    if a.scanner:
        print(f"  scanner '{a.scanner}': {'permitted' if result['scanner']['permitted'] else 'PROHIBITED by RoE'}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
