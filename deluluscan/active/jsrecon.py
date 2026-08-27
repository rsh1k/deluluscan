"""JavaScript endpoint recon (LinkFinder-style).

Modern apps hide much of their server surface inside JS bundles — including
SSRF-prone and admin endpoints never linked from the UI. This module fetches
referenced scripts and extracts API-path-looking strings so discovery can test
them. Fetches only same-origin scripts on the authorized target; bounded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

# quoted path-like strings and fetch/axios/url calls
_PATH_RE = re.compile(r"""['"`](/(?:api|rest|v\d|graphql|admin|internal)[\w\-/.{}$:]*)['"`]""")
_FETCH_RE = re.compile(r"""(?:fetch|axios\.\w+|\.get|\.post|\.put|\.ajax|url\s*[:=])\s*\(?\s*['"`]([^'"`]+)['"`]""")
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+\.js[^'"]*)['"]""", re.I)
# URL-fetching endpoint names worth SSRF attention (from bug-bounty methodology)
_SSRF_HINTS = ("fetch", "proxy", "import", "preview", "unfurl", "avatar",
               "webhook", "remote", "loadurl", "url")


@dataclass
class JsRecon:
    paths: set[str] = field(default_factory=set)
    ssrf_candidates: set[str] = field(default_factory=set)
    scripts_scanned: int = 0


def extract_from_js(js: str) -> tuple[set[str], set[str]]:
    paths, ssrf = set(), set()
    for m in _PATH_RE.finditer(js):
        p = m.group(1)
        if 2 < len(p) < 120:
            paths.add(p)
    for m in _FETCH_RE.finditer(js):
        u = m.group(1)
        if u.startswith("/") and 2 < len(u) < 120:
            paths.add(u)
    for p in paths:
        if any(h in p.lower() for h in _SSRF_HINTS):
            ssrf.add(p)
    return paths, ssrf


def script_srcs(html: str) -> list[str]:
    return _SCRIPT_SRC_RE.findall(html or "")


class JsEndpointMiner:
    def __init__(self, fetch_text: Callable, max_scripts: int = 15):
        # fetch_text(path) -> body string
        self.fetch_text = fetch_text
        self.max_scripts = max_scripts

    def mine(self, root_html: str) -> JsRecon:
        out = JsRecon()
        srcs = script_srcs(root_html)[: self.max_scripts]
        # also mine inline scripts in the root HTML
        p, s = extract_from_js(root_html)
        out.paths |= p; out.ssrf_candidates |= s
        for src in srcs:
            if not src.startswith(("/", "http")):
                continue
            body = self.fetch_text(src) or ""
            out.scripts_scanned += 1
            p, s = extract_from_js(body)
            out.paths |= p
            out.ssrf_candidates |= s
        return out
