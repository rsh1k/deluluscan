"""CLI: scan a source tree for dangerous patterns + secrets.

    python3 -m deluluscan.sast --path ./src [--no-secrets] [--json]
"""
from __future__ import annotations

import argparse, json, sys
from .engine import SastScan


def main(argv=None):
    p = argparse.ArgumentParser(prog="deluluscan.sast", description="source-code SAST + secret scan")
    p.add_argument("--path", required=True, help="file or directory to scan")
    p.add_argument("--no-secrets", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--sarif", metavar="OUT_DIR",
                   help="write a SARIF report (results.sarif) into OUT_DIR — for GitHub "
                        "code-scanning / any SARIF-consuming CI. Language-agnostic.")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                   help="exit non-zero if any finding is at or above this severity (for CI gating)")
    a = p.parse_args(argv)
    fs = SastScan(secrets=not a.no_secrets).scan_path(a.path)
    if a.sarif:
        from ..reporting.sarif import write_sarif
        result = {"findings": [f.to_dict() for f in fs],
                  "meta": {"target": a.path, "tool": "deluluscan-sast"}}
        path = write_sarif(result, a.sarif)
        print(f"[sast] wrote SARIF: {path} ({len(fs)} finding(s))")
    if a.fail_on:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        gate = order[a.fail_on]
        worst = min((order.get(f.severity.value, 9) for f in fs), default=9)
        if worst <= gate:
            print(f"[sast] failing: a finding at or above '{a.fail_on}' was found")
            return 1
    if a.sarif:
        return 0
    if a.json:
        print(json.dumps([f.to_dict() for f in fs], indent=2, default=str)); return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fs.sort(key=lambda f: order.get(f.severity.value, 9))
    print(f"[sast] {a.path}: {len(fs)} finding(s)")
    for f in fs:
        print(f"  [{f.severity.value:>8}] {f.endpoint:<40} {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
