"""CLI: passive analysis of a single URL (fetches it once) or piped body.

    python3 -m deluluscan.passive --url http://127.0.0.1:8080/
    cat response.html | python3 -m deluluscan.passive --stdin --url http://x/
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from urllib.parse import urlparse

from .engine import PassiveScan


def _is_local(url: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(urlparse(url).hostname or ""))
        return ip.is_loopback or ip.is_private
    except Exception:
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.passive", description="passive response analysis")
    ap.add_argument("--url", required=True)
    ap.add_argument("--stdin", action="store_true", help="read the response body from stdin")
    ap.add_argument("--allow-remote", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.stdin:
        status, headers, body = 200, {}, sys.stdin.read()
    else:
        if not _is_local(args.url) and not args.allow_remote:
            raise SystemExit(f"[scope] {args.url} is not loopback/RFC1918. Use --allow-remote "
                             "only if authorized (or pass --stdin to analyze saved output).")
        import urllib.request
        try:
            with urllib.request.urlopen(args.url, timeout=10) as r:
                status, headers, body = r.status, dict(r.headers), r.read(200_000).decode("utf-8", "replace")
        except Exception as e:
            raise SystemExit(f"[fetch] {e}")

    findings = PassiveScan().analyze(status, args.url, headers, body)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
        return 0
    print(f"[passive] {args.url}: {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f.severity.value.upper():8}] {f.title}  ({f.detail.get('rule', f.detail.get('rule',''))})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
