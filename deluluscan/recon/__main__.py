"""CLI: reconnaissance on an authorized web target.

    python3 -m deluluscan.recon --url http://127.0.0.1:8080/ --domain example.test

Passive CT-log subdomain lookup uses public data; active fingerprint/content/DNS
passes send requests to the target and are gated to loopback/RFC1918 unless you
assert authorization with --allow-remote. Detection only.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from urllib.parse import urlparse

from .engine import ReconEngine


def _is_local(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return ipaddress.ip_address(socket.gethostbyname(host)).is_loopback or \
               ipaddress.ip_address(socket.gethostbyname(host)).is_private
    except Exception:
        return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="deluluscan.recon", description="web reconnaissance")
    p.add_argument("--url", required=True, help="base URL of the target")
    p.add_argument("--domain", help="registrable domain for CT-log subdomain enumeration")
    p.add_argument("--no-subdomains", action="store_true")
    p.add_argument("--no-content", action="store_true")
    p.add_argument("--no-resolve", action="store_true", help="don't DNS-resolve enumerated subdomains")
    p.add_argument("--max-paths", type=int, default=60)
    p.add_argument("--allow-remote", action="store_true", help="assert authorization for a non-local target")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    if not _is_local(args.url) and not args.allow_remote:
        raise SystemExit(f"[scope] {args.url} is not loopback/RFC1918. Re-run with "
                         "--allow-remote only if you are authorized to test it.")

    eng = ReconEngine(max_paths=args.max_paths)
    profile = eng.run(args.url, domain=args.domain,
                      do_subdomains=not args.no_subdomains, do_content=not args.no_content,
                      resolve_subs=not args.no_resolve)
    if args.json:
        print(json.dumps({"profile": profile.to_dict(),
                          "findings": [f.to_dict() for f in profile.to_findings()]},
                         indent=2, default=str))
        return 0
    print(f"[recon] {args.url}")
    print(f"  tech ({len(profile.techs)}):")
    for t in profile.techs:
        flag = f"  <!> {', '.join(v['id'] for v in t.vulnerabilities)}" if t.vulnerabilities else ""
        print(f"    - {t.name} {t.version or ''}{flag}")
    if profile.subdomains:
        live = [s['name'] for s in profile.subdomains if s.get('live')]
        print(f"  subdomains ({len(profile.subdomains)}, live={len(live)}): "
              f"{', '.join(s['name'] for s in profile.subdomains[:15])}"
              f"{' …' if len(profile.subdomains) > 15 else ''}")
    if profile.exposures:
        print(f"  exposures ({len(profile.exposures)}):")
        for e in profile.exposures:
            print(f"    [{e['status']}] {e['path']}  — {e['note']}")
    print(f"  -> {len(profile.to_findings())} finding(s) for the report")
    return 0


if __name__ == "__main__":
    sys.exit(main())
