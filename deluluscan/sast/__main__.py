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
    a = p.parse_args(argv)
    fs = SastScan(secrets=not a.no_secrets).scan_path(a.path)
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
