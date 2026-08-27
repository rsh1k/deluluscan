"""CLI: HTTP security-header / CORS / cookie posture check.

    python3 -m deluluscan.headers --url https://127.0.0.1:8443/
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from urllib.parse import urlparse

from .engine import HeaderScan


def _is_local(url: str) -> bool:
    try:
        h = urlparse(url).hostname or ""
        return ipaddress.ip_address(socket.gethostbyname(h)).is_loopback or \
               ipaddress.ip_address(socket.gethostbyname(h)).is_private
    except Exception:
        return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="deluluscan.headers", description="security header/CORS/cookie check")
    p.add_argument("--url", required=True)
    p.add_argument("--allow-remote", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if not _is_local(args.url) and not args.allow_remote:
        raise SystemExit(f"[scope] {args.url} is not loopback/RFC1918; use --allow-remote if authorized.")
    findings = HeaderScan().scan(HeaderScan.default_fetch, args.url)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2, default=str)); return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity.value, 9))
    print(f"[headers] {args.url}: {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f.severity.value:>8}] {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
