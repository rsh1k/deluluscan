"""CLI: deeper web/API surface checks (GraphQL introspection).

    python3 -m deluluscan.webapi --graphql http://127.0.0.1:8080/graphql
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from urllib.parse import urlparse

from .engine import WebApiScan


def _is_local(url: str) -> bool:
    try:
        h = urlparse(url).hostname or ""
        return ipaddress.ip_address(socket.gethostbyname(h)).is_loopback or \
               ipaddress.ip_address(socket.gethostbyname(h)).is_private
    except Exception:
        return False


def _default_fetch(url, body):
    import requests
    r = requests.post(url, json=body, timeout=15, headers={"content-type": "application/json"})
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="deluluscan.webapi", description="deeper web/API surface checks")
    p.add_argument("--graphql", help="GraphQL endpoint URL")
    p.add_argument("--allow-remote", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if not args.graphql:
        p.error("provide --graphql <url>")
    if not _is_local(args.graphql) and not args.allow_remote:
        raise SystemExit(f"[scope] {args.graphql} is not loopback/RFC1918; use --allow-remote if authorized.")

    surf, findings = WebApiScan().graphql_surface(_default_fetch, args.graphql)
    if args.json:
        print(json.dumps({"surface": surf.to_dict(),
                          "findings": [f.to_dict() for f in findings]}, indent=2, default=str))
        return 0
    print(f"[webapi] GraphQL {args.graphql}: introspection={'ON' if surf.introspection_enabled else 'off'} "
          f"({surf.type_count} types, {len(surf.queries)} queries, {len(surf.mutations)} mutations)")
    for f in findings:
        print(f"  [{f.severity.value:>8}] {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
