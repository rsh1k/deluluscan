"""CLI: scan a page and its JS for exposed secrets.

    python3 -m deluluscan.secrets --url https://127.0.0.1:8443/
"""
from __future__ import annotations

import argparse, ipaddress, json, socket, sys
from urllib.parse import urlparse
from .engine import SecretScan


def _is_local(url):
    try:
        h = urlparse(url).hostname or ""
        return ipaddress.ip_address(socket.gethostbyname(h)).is_loopback or \
               ipaddress.ip_address(socket.gethostbyname(h)).is_private
    except Exception:
        return False


def main(argv=None):
    p = argparse.ArgumentParser(prog="deluluscan.secrets", description="secret exposure scan")
    p.add_argument("--url", required=True)
    p.add_argument("--allow-remote", action="store_true")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    if not _is_local(a.url) and not a.allow_remote:
        raise SystemExit(f"[scope] {a.url} is not loopback/RFC1918; use --allow-remote if authorized.")
    fs = SecretScan().scan_site(SecretScan.default_fetch, a.url)
    if a.json:
        print(json.dumps([f.to_dict() for f in fs], indent=2, default=str)); return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    fs.sort(key=lambda f: order.get(f.severity.value, 9))
    print(f"[secrets] {a.url}: {len(fs)} exposed secret(s)")
    for f in fs:
        print(f"  [{f.severity.value:>8}] {f.title:<40} {f.detail['masked']}  ({f.endpoint})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
