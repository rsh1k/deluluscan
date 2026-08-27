"""SPA / JS-aware crawler.

admin is an Angular SPA — most of its real API surface is only reachable by
watching what the app calls at runtime or by mining the JS bundles. Top hunters
(ZSeano's "make use of .js files" methodology) treat JS as the map of hidden
endpoints, parameters, and leaked secrets.

Two modes:
  * render (Playwright): load the app, capture every XHR/fetch the SPA makes, and
    read the rendered DOM — the ground truth of what the front end talks to.
  * static (always available): fetch HTML, follow <script src>, and mine the
    bundles for API paths, SSRF-prone endpoints, and leaked secrets.

Same-origin, authorized target only; bounded. No secret is exfiltrated — leaked
material is reported as a finding for the operator.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .jsrecon import extract_from_js, script_srcs

# high-signal secret patterns (ZSeano/JS-recon); reported, never used
_SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "generic_secret": re.compile(r"(?i)(?:api[_-]?key|secret|passwd|password|token)"
                                 r"['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{12,})['\"]"),
    "bearer": re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}"),
}
_FALSE_SECRET = re.compile(r"(?i)example|placeholder|xxxx|your[_-]?(?:api|key|token)|dummy|test")


@dataclass
class CrawlResult:
    paths: set[str] = field(default_factory=set)
    ssrf_candidates: set[str] = field(default_factory=set)
    secrets: list[tuple[str, str]] = field(default_factory=list)
    scripts_scanned: int = 0
    mode: str = "static"


def mine_secrets(text: str) -> list[tuple[str, str]]:
    out = []
    for kind, rx in _SECRET_PATTERNS.items():
        for m in rx.finditer(text or ""):
            val = m.group(0)
            if _FALSE_SECRET.search(val):
                continue
            out.append((kind, val[:60]))
    # de-dup
    seen, uniq = set(), []
    for k, v in out:
        if (k, v) not in seen:
            seen.add((k, v)); uniq.append((k, v))
    return uniq[:25]


class SpaCrawler:
    def __init__(self, fetch_text: Callable[[str], str], max_scripts: int = 25):
        # fetch_text(path)-> body text (goes through the safety-gated client)
        self.fetch_text = fetch_text
        self.max_scripts = max_scripts

    def static_crawl(self, roots=("/", "/admin/", "/html/")) -> CrawlResult:
        out = CrawlResult(mode="static")
        for root in roots:
            html = self.fetch_text(root) or ""
            p, s = extract_from_js(html)
            out.paths |= p; out.ssrf_candidates |= s
            out.secrets += mine_secrets(html)
            for src in script_srcs(html)[: self.max_scripts]:
                if not src.startswith(("/", "http")):
                    continue
                body = self.fetch_text(src) or ""
                out.scripts_scanned += 1
                pp, ss = extract_from_js(body)
                out.paths |= pp; out.ssrf_candidates |= ss
                out.secrets += mine_secrets(body)
        # de-dup secrets across all sources
        seen, uniq = set(), []
        for k, v in out.secrets:
            if (k, v) not in seen:
                seen.add((k, v)); uniq.append((k, v))
        out.secrets = uniq
        return out


def render_crawl(base_url: str, extra_headers: Optional[dict] = None,
                 timeout_s: float = 15.0) -> CrawlResult:
    """Playwright network-capture crawl: record every request the SPA issues.
    No-ops (returns empty static result) if Playwright/browser isn't available."""
    out = CrawlResult(mode="render")
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return out
    from urllib.parse import urlparse
    host = urlparse(base_url).hostname
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(ignore_https_errors=True,
                                      extra_http_headers=extra_headers or {})
            page = ctx.new_page()
            seen_urls: set[str] = set()

            def on_request(req):
                try:
                    u = urlparse(req.url)
                    if u.hostname == host and ("/api/" in u.path or "/dwr" in u.path
                                               or u.path.startswith("/html/")):
                        seen_urls.add(u.path)
                except Exception:
                    pass
            page.on("request", on_request)
            for start in (base_url, base_url.rstrip("/") + "/admin/"):
                try:
                    page.goto(start, timeout=int(timeout_s * 1000), wait_until="networkidle")
                    page.wait_for_timeout(800)
                except Exception:
                    continue
                out.secrets += mine_secrets(page.content() or "")
            out.paths |= seen_urls
            browser.close()
    except Exception:
        return out
    return out
