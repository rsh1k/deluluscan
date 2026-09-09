"""CLI: python3 -m deluluscan.depconfusion --path ./ [--json]

Scans dependency manifests for packages absent from their public registry
(dependency-confusion candidates). Makes read-only registry lookups; runs on
source you own, so no target-authorization gate applies."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import DepConfusionScan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.depconfusion",
                                 description="dependency-confusion / namespace-squatting detection")
    ap.add_argument("--path", default=".", help="source tree to scan (default: .)")
    ap.add_argument("--max-lookups", type=int, default=200)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    finds = DepConfusionScan(max_lookups=a.max_lookups).scan_path(a.path)
    if a.json:
        print(json.dumps([f.to_dict() for f in finds], indent=2, default=str))
        return 0
    print(f"[depconfusion] {a.path}: {len(finds)} candidate(s)")
    for f in finds:
        print(f"  [{f.severity.value.upper():6}] {f.detail['package']} ({f.detail['ecosystem']}) "
              f"— absent from public registry [{f.detail['manifest']}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
