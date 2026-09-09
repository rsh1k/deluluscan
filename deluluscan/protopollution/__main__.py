"""CLI: client-side prototype-pollution test (needs the optional playwright dep).

    python3 -m deluluscan.protopollution --url http://127.0.0.1:8080/app

Loads the page in a headless browser with __proto__ URL payloads and checks
whether Object.prototype was polluted. Active — gated to loopback/RFC1918 unless
you assert authorization with --allow-remote. Detection only."""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from urllib.parse import urlparse

from .engine import ProtoPollutionScan


def _is_local(url: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(urlparse(url).hostname or ""))
        return ip.is_loopback or ip.is_private
    except Exception:
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.protopollution",
                                 description="client-side prototype-pollution scanner")
    ap.add_argument("--url", required=True)
    ap.add_argument("--allow-remote", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if not _is_local(a.url) and not a.allow_remote:
        raise SystemExit(f"[scope] {a.url} is not loopback/RFC1918. Re-run with --allow-remote "
                         "only if you are authorized to test it.")
    try:
        res, findings = ProtoPollutionScan().run(a.url)
    except RuntimeError as exc:
        raise SystemExit(f"[protopollution] {exc}")
    if a.json:
        print(json.dumps({"hits": res.hits, "findings": [f.to_dict() for f in findings]},
                         indent=2, default=str))
        return 0
    print(f"[protopollution] {a.url}: {len(res.hits)} vector(s) polluted Object.prototype")
    for h in res.hits:
        print(f"    {h['label']}: {h['url']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
