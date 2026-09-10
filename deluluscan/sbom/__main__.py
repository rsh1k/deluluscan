"""CLI: python3 -m deluluscan.sbom --file bom.json [--json]

Analyzes a CycloneDX or SPDX SBOM for known-vulnerable components + integrity
gaps. Static, offline."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import SbomScan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.sbom", description="SBOM (CycloneDX/SPDX) analyzer")
    ap.add_argument("--file", required=True, help="SBOM JSON file")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    finds = SbomScan().scan_file(a.file)
    if a.json:
        print(json.dumps([f.to_dict() for f in finds], indent=2, default=str))
        return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    finds.sort(key=lambda f: order.get(f.severity.value, 9))
    print(f"[sbom] {a.file}: {len(finds)} finding(s)")
    for f in finds:
        print(f"  [{f.severity.value.upper():8}] {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
