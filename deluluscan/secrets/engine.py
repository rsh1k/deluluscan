"""SecretScan — fetch a page and its same-origin JS, scan all for exposed secrets."""
from __future__ import annotations

import re
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

from ..models import Finding
from .scanner import scan_text

_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)


class SecretScan:
    def scan_urls(self, fetch: Callable, urls: list) -> list:
        out: list[Finding] = []
        for u in urls:
            try:
                _, text = fetch(u)
            except Exception:
                continue
            out += scan_text(text or "", source=u)
        return out

    def scan_site(self, fetch: Callable, base_url: str, max_js: int = 20) -> list:
        try:
            _, html = fetch(base_url)
        except Exception:
            html = ""
        out = scan_text(html or "", source=base_url)
        origin = urlparse(base_url)
        js_urls = []
        for src in _SRC_RE.findall(html or ""):
            full = urljoin(base_url, src)
            if urlparse(full).netloc == origin.netloc and full not in js_urls:
                js_urls.append(full)
        out += self.scan_urls(fetch, js_urls[:max_js])
        return out

    @staticmethod
    def default_fetch(url: str):
        import requests
        r = requests.get(url, timeout=15, headers={"user-agent": "deluluscan-secrets"})
        return r.status_code, r.text[:500000]
