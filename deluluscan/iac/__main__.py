"""CLI: python3 -m deluluscan.iac --path ./infra [--json]

Scans a tree for Terraform (.tf) + CloudFormation (.yaml/.json/.template)
misconfigurations. Static, offline; runs on source you own."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import IacScan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.iac", description="Terraform/CloudFormation IaC scanner")
    ap.add_argument("--path", default=".", help="file or directory to scan")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    finds = IacScan().scan_path(a.path)
    if a.json:
        print(json.dumps([f.to_dict() for f in finds], indent=2, default=str))
        return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    finds.sort(key=lambda f: order.get(f.severity.value, 9))
    print(f"[iac] {a.path}: {len(finds)} finding(s)")
    for f in finds:
        print(f"  [{f.severity.value.upper():8}] {f.endpoint:40} {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
