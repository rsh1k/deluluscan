"""CLI: unified assessment -> merged multi-format LOCAL report.

    python3 -m deluluscan.assess --url http://127.0.0.1:8080/ \
        --formats md,html,json,sarif,csv --out-dir ./deluluscan-report

Writes report files to --out-dir. Nothing is uploaded or published.
"""
from __future__ import annotations

import argparse, ipaddress, socket, sys
from urllib.parse import urlparse
from .runner import run_web_assessment
from .report import write_reports


def _is_local(url):
    try:
        h = urlparse(url).hostname or ""
        return ipaddress.ip_address(socket.gethostbyname(h)).is_loopback or \
               ipaddress.ip_address(socket.gethostbyname(h)).is_private
    except Exception:
        return False


def main(argv=None):
    p = argparse.ArgumentParser(prog="deluluscan.assess",
                                description="unified assessment -> merged local report")
    p.add_argument("--url", required=True, help="target base URL")
    p.add_argument("--domain", help="registrable domain (enables CT-log subdomain recon)")
    p.add_argument("--graphql", help="GraphQL endpoint URL to include")
    p.add_argument("--sast-path", help="source tree/file to SAST-scan and include")
    p.add_argument("--spec", help="OpenAPI/Swagger spec file to security-lint and include")
    p.add_argument("--modules", help="comma list: recon,headers,secrets,webapi (default: all applicable)")
    p.add_argument("--formats", default="md,html,json,sarif",
                   help="comma list: json,md,html,sarif,csv,xlsx,junit")
    p.add_argument("--out-dir", default="./deluluscan-report")
    p.add_argument("--allow-remote", action="store_true")
    a = p.parse_args(argv)
    if not _is_local(a.url) and not a.allow_remote:
        raise SystemExit(f"[scope] {a.url} is not loopback/RFC1918; use --allow-remote if authorized.")
    mods = [m.strip() for m in a.modules.split(",")] if a.modules else None
    assessment = run_web_assessment(a.url, domain=a.domain, graphql_url=a.graphql, modules=mods,
                                    sast_path=a.sast_path, spec_path=a.spec)
    payload = assessment.payload()
    written = write_reports(payload, a.out_dir, [f for f in a.formats.split(",") if f.strip()])
    print(f"[assess] {a.url}: {payload['meta']['finding_count']} finding(s) "
          f"from modules {payload['meta']['modules']}")
    for fmt, path in written.items():
        print(f"  wrote {fmt:>6}: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
