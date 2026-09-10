"""CLI: python3 -m deluluscan.cicd --path . [--json]

Scans .github/workflows/*.yml for GitHub Actions security issues (script
injection, pwn requests, unpinned actions, broad permissions, pipe-to-shell).
Static, offline; runs on a repo you own."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import CicdScan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.cicd", description="CI/CD (GitHub Actions) security scan")
    ap.add_argument("--path", default=".", help="repo root or a workflow file")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    finds = CicdScan().scan_path(a.path)
    if a.json:
        print(json.dumps([f.to_dict() for f in finds], indent=2, default=str))
        return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    finds.sort(key=lambda f: order.get(f.severity.value, 9))
    print(f"[cicd] {a.path}: {len(finds)} finding(s)")
    for f in finds:
        print(f"  [{f.severity.value.upper():8}] {f.endpoint:40} {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
