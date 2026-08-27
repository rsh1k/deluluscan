"""CLI: edge & network recon on an authorized target.

    python3 -m deluluscan.netscan --url http://127.0.0.1:8080 [--no-ports] [--json]

Active passes (WAF probe, port scan) send traffic/open sockets to the target and
are gated to loopback/RFC1918 unless you assert authorization with --allow-remote.
Detection only.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from urllib.parse import urlparse

from .engine import NetScan


def _is_local(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_loopback or ip.is_private
    except Exception:
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.netscan",
                                 description="WAF/CDN/proxy detection + port/service + honeypot/IDS inference")
    ap.add_argument("--url", required=True)
    ap.add_argument("--no-ports", action="store_true")
    ap.add_argument("--no-waf", action="store_true")
    ap.add_argument("--allow-remote", action="store_true",
                    help="assert authorization for a non-local target")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not _is_local(args.url) and not args.allow_remote:
        raise SystemExit(f"[scope] {args.url} is not loopback/RFC1918. Re-run with "
                         "--allow-remote only if you are authorized to test it.")

    scan = NetScan(timeout=args.timeout)
    prof = scan.run(args.url, do_ports=not args.no_ports, do_waf=not args.no_waf)
    findings = scan.to_findings(prof)

    if args.json:
        print(json.dumps({"profile": prof.to_dict(),
                          "findings": [f.to_dict() for f in findings]},
                         indent=2, default=str))
        return 0

    print(f"[netscan] {args.url}")
    if prof.edges:
        print("  edge defence:")
        for e in prof.edges:
            b = " [BLOCKING]" if e.blocking else ""
            print(f"    - {e.name} ({e.kind}, {e.confidence}){b}: {'; '.join(e.signals[:3])}")
    else:
        print("  edge defence: none detected")
    if prof.ids_ips and prof.ids_ips.get("inline_drop_observed"):
        print("  IDS/IPS: inline drop inferred")
    if prof.ports:
        print(f"  open ports ({len(prof.ports)}):")
        for p in prof.ports:
            d = f"  <!> {p.dangerous}" if p.dangerous else ""
            print(f"    - {p.port:6} {p.service}{d}")
    for h in prof.honeypot_leads:
        print(f"  honeypot lead: {h.reason}")
    print(f"\n  findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
