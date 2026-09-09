"""CLI: audit a JWT offline (structural weaknesses + HS* secret cracking).

    python3 -m deluluscan.jwtaudit --token eyJ... [--json]
    python3 -m deluluscan.jwtaudit --file captured.txt      # extract + audit all JWTs
    echo "...Bearer eyJ..." | python3 -m deluluscan.jwtaudit --stdin
"""
from __future__ import annotations

import argparse
import json
import sys

from .audit import audit_token, find_and_audit


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.jwtaudit", description="offline JWT audit")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--token", help="a single JWT to audit")
    g.add_argument("--file", help="a file to extract + audit all JWTs from")
    g.add_argument("--stdin", action="store_true", help="read text from stdin and audit JWTs in it")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.token:
        finds = audit_token(a.token.strip(), source="cli")
    else:
        text = sys.stdin.read() if a.stdin else open(a.file, encoding="utf-8", errors="replace").read()
        finds = find_and_audit(text, source=a.file or "stdin")
    if a.json:
        print(json.dumps([f.to_dict() for f in finds], indent=2, default=str))
        return 0
    print(f"[jwtaudit] {len(finds)} finding(s)")
    for f in sorted(finds, key=lambda x: x.severity.rank, reverse=True):
        print(f"  [{f.severity.value.upper():8}] {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
