"""CLI: scan a git repo's full history for committed secrets.

    python3 -m deluluscan.githistory --repo . [--json]

Reads all history blobs (read-only) and flags secret-shaped strings, incl. ones
removed from the current tree. Runs on a repo you own; no target gate applies."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import GitSecretScan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.githistory",
                                 description="secret scanning across git history")
    ap.add_argument("--repo", default=".", help="path to the git repo (default: .)")
    ap.add_argument("--max-blobs", type=int, default=20000)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    finds = GitSecretScan(max_blobs=a.max_blobs).scan_repo(a.repo)
    if a.json:
        print(json.dumps([f.to_dict() for f in finds], indent=2, default=str))
        return 0
    print(f"[githistory] {a.repo}: {len(finds)} unique secret(s) in history")
    for f in finds:
        locs = ", ".join(f.detail.get("history_locations", [])[:3])
        print(f"  [{f.severity.value.upper():8}] {f.detail.get('rule')}: {f.detail.get('masked')}  "
              f"({locs})")
    if finds:
        print("\n  ROTATE any real credential above — deleting it from HEAD does not "
              "remove it from history.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
