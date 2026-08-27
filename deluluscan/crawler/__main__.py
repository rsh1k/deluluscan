"""CLI: dynamic crawl of an authorized target (needs the optional Playwright dep).

    pip install playwright && playwright install chromium
    python3 -m deluluscan.crawler --url http://127.0.0.1:8080/ [--max-pages 40] [--json]

Drives a real headless browser against the target, so it is gated to loopback/
RFC1918 unless you assert authorization with --allow-remote. Detection only.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from urllib.parse import urlparse

from .engine import CrawlEngine
from .browser import PlaywrightDriver, PLAYWRIGHT_HINT


def _is_local(url: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(urlparse(url).hostname or ""))
        return ip.is_loopback or ip.is_private
    except Exception:
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.crawler",
                                 description="headless-browser dynamic crawl + API-surface discovery")
    ap.add_argument("--url", required=True)
    ap.add_argument("--max-pages", type=int, default=40)
    ap.add_argument("--max-depth", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--allow-remote", action="store_true")
    ap.add_argument("--headed", action="store_true", help="run the browser headed (debugging)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not _is_local(args.url) and not args.allow_remote:
        raise SystemExit(f"[scope] {args.url} is not loopback/RFC1918. Re-run with "
                         "--allow-remote only if you are authorized to test it.")

    driver = PlaywrightDriver(headless=not args.headed)
    try:
        engine = CrawlEngine(driver, max_pages=args.max_pages, max_depth=args.max_depth,
                             timeout=args.timeout)
        try:
            result = engine.crawl(args.url)
        except RuntimeError as exc:                   # Playwright not installed
            raise SystemExit(f"[crawler] {exc}")
    finally:
        driver.close()

    findings = result.to_findings()
    if args.json:
        print(json.dumps({"result": result.to_dict(),
                          "findings": [f.to_dict() for f in findings]}, indent=2, default=str))
        return 0
    print(f"[crawler] {args.url}: {len(result.pages)} page(s), "
          f"{len(result.api_endpoints)} API endpoint(s), {len(result.forms)} form(s)")
    for e in result.api_endpoints:
        print(f"    {e['method']:6} {e['path']}  [{e['resource_type'] or 'link'}]")
    if result.errors:
        print(f"  ({len(result.errors)} render error(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
