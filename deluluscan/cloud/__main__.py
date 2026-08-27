"""CLI: cloud posture checks over a collected inventory, and metadata exposure.

    python3 -m deluluscan.cloud --inventory aws.json --provider aws
    python3 -m deluluscan.cloud --inventory all.json          # auto-detect providers
    python3 -m deluluscan.cloud --check-imds                  # run ON a cloud instance
"""
from __future__ import annotations

import argparse
import json
import sys

from .engine import CloudScan


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="deluluscan.cloud", description="cloud posture (CSPM) checks")
    p.add_argument("--inventory", help="JSON inventory file (aws/gcp/azure describe-* export)")
    p.add_argument("--provider", choices=["aws", "gcp", "azure"], help="force a provider")
    p.add_argument("--check-imds", action="store_true",
                   help="probe THIS host's instance metadata for reachable credentials")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if not args.inventory and not args.check_imds:
        p.error("provide --inventory and/or --check-imds")

    scan = CloudScan()
    findings = []
    if args.inventory:
        findings += scan.scan_file(args.inventory, args.provider)
    if args.check_imds:
        findings += scan.check_metadata_exposure()

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
        return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity.value, 9))
    print(f"[cloud] {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f.severity.value:>8}] {f.title:<48} {f.endpoint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
