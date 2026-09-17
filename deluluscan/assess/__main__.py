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
    p.add_argument("--sbom", help="CycloneDX/SPDX SBOM file to analyze and include")
    p.add_argument("--modules", help="comma list: recon,headers,secrets,netscan,passive,webapi "
                                     "(default: all applicable)")
    p.add_argument("--netscan-ports", action="store_true",
                   help="also run the netscan TCP port/service scan (opens sockets; loopback/RFC1918)")
    p.add_argument("--crawl", action="store_true",
                   help="run the dynamic headless-browser crawl (needs the optional playwright dep)")
    p.add_argument("--smuggling", action="store_true",
                   help="run the timing-only HTTP request-smuggling detector (touches shared infra)")
    p.add_argument("--adintel", action="store_true",
                   help="run SMB/LDAP posture detection on the target host (detection-only)")
    p.add_argument("--shadow", action="store_true",
                   help="detect staging/sandbox/dev copies of the target and diff their "
                        "security posture against production (scope-respecting)")
    p.add_argument("--shadow-authorize", default="",
                   help="comma-separated shadow hostnames you are authorized to actively probe")
    p.add_argument("--epss", action="store_true",
                   help="rank CVE findings by EPSS exploit probability (queries the FIRST.org API)")
    p.add_argument("--kev", action="store_true",
                   help="flag CVEs in the CISA Known-Exploited-Vulnerabilities catalog")
    p.add_argument("--depconfusion", action="store_true",
                   help="scan --sast-path deps for dependency-confusion (public-registry lookups)")
    p.add_argument("--formats", default="md,html,json,sarif",
                   help="comma list: json,md,html,sarif,csv,xlsx,junit")
    p.add_argument("--out-dir", default="./deluluscan-report")
    p.add_argument("--allow-remote", action="store_true")
    p.add_argument("--roe", help="Rules-of-Engagement doc (YAML/JSON/text): enforce scope, "
                                 "prohibited tests, and testing window")
    a = p.parse_args(argv)

    # Rules of Engagement: enforce scope + prohibited tests + window BEFORE anything runs.
    roe = None
    if a.roe:
        from ..roe import load_roe
        try:
            roe = load_roe(a.roe)
        except Exception as e:
            raise SystemExit(f"[roe] could not read {a.roe}: {e}")
        allowed, reason = roe.target_in_scope(a.url)
        if not allowed:
            raise SystemExit(f"[roe] {a.url} is not in scope per {a.roe} — {reason}. Refusing.")
        if roe.allow_remote:
            a.allow_remote = True          # RoE explicitly authorizes this in-scope target
        if not roe.within_window():
            raise SystemExit(f"[roe] outside the authorized testing window "
                             f"({roe.window_start}-{roe.window_end}). Refusing.")
        print(f"[roe] {a.url} in scope ({reason}); "
              f"prohibited tests: {sorted(roe.excluded_tests) or '(none)'}")

    if not _is_local(a.url) and not a.allow_remote:
        raise SystemExit(f"[scope] {a.url} is not loopback/RFC1918; use --allow-remote if authorized.")
    mods = [m.strip() for m in a.modules.split(",")] if a.modules else None
    # opt-in modules: append to the explicit list, or to the default set
    optin = [name for name, on in (("crawl", a.crawl), ("smuggling", a.smuggling),
                                   ("adintel", a.adintel), ("shadow", a.shadow)) if on]
    if optin:
        if mods is None:
            mods = (["recon", "headers", "secrets", "netscan", "passive"]
                    + (["webapi"] if a.graphql else []))
        mods = mods + [m for m in optin if m not in mods]
    # Drop any module the RoE prohibits (defaults resolve inside the runner, so
    # materialize them here first when the RoE needs to filter).
    if roe and roe.excluded_tests:
        if mods is None:
            mods = (["recon", "headers", "secrets", "netscan", "passive"]
                    + (["webapi"] if a.graphql else []))
        dropped = [m for m in mods if not roe.scanner_allowed(m)]
        if dropped:
            print(f"[roe] skipping prohibited module(s): {dropped}")
        mods = [m for m in mods if roe.scanner_allowed(m)]
    assessment = run_web_assessment(a.url, domain=a.domain, graphql_url=a.graphql, modules=mods,
                                    sast_path=a.sast_path, spec_path=a.spec, sbom_path=a.sbom,
                                    netscan_ports=a.netscan_ports, epss=a.epss, kev=a.kev,
                                    depconfusion=a.depconfusion,
                                    shadow_authorized_hosts=[h.strip() for h in
                                                             a.shadow_authorize.split(",") if h.strip()])
    payload = assessment.payload()
    written = write_reports(payload, a.out_dir, [f for f in a.formats.split(",") if f.strip()])
    print(f"[assess] {a.url}: {payload['meta']['finding_count']} finding(s) "
          f"from modules {payload['meta']['modules']}")
    for fmt, path in written.items():
        print(f"  wrote {fmt:>6}: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
