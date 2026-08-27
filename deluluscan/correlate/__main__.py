"""CLI: correlate a results.json into attack-chain suggestions.

    python3 -m deluluscan.correlate --results deluluscan-out/results.json [--json]
"""
from __future__ import annotations

import argparse, json, sys
from .engine import correlate


def main(argv=None):
    p = argparse.ArgumentParser(prog="deluluscan.correlate", description="attack-chain correlation")
    p.add_argument("--results", required=True, help="a results.json / assess payload")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    with open(a.results) as fh:
        payload = json.load(fh)
    findings = payload.get("findings", payload if isinstance(payload, list) else [])
    sugg = correlate(findings)
    if a.json:
        print(json.dumps([s.to_finding().to_dict() for s in sugg], indent=2, default=str)); return 0
    print(f"[correlate] {len(sugg)} attack chain(s) from {len(findings)} finding(s)")
    for s in sugg:
        print(f"  [{s.rule.severity.value:>8}] {s.rule.name}")
        print(f"            objective: {s.rule.objective}")
        for m in s.members:
            print(f"            └─ {getattr(m,'title','')}  ({getattr(m,'endpoint','')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
