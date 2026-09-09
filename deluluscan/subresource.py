"""Subresource Integrity (SRI) + mixed-content analysis.

Two universal, observational classes on any HTML page:

  - Missing SRI: a cross-origin <script>/<style> loaded from a CDN without an
    `integrity` attribute — if that CDN (or its account) is compromised, it serves
    arbitrary code into this origin (a supply-chain XSS, the Polyfill.io class).
  - Mixed content: an HTTPS page pulling a sub-resource over http:// — a MITM can
    rewrite it; for a script/iframe that means code execution (active mixed
    content), for an image/style it's a downgrade/privacy leak (passive).

Pure HTML string analysis — offline, deterministic. Detection only.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import Finding, RequestRecord, Severity, VulnClass

_TAG = re.compile(r"<(script|link|iframe|img|audio|video|source)\b([^>]*)>", re.I)
_ATTR = lambda name: re.compile(rf"""\b{name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)
_SRC = _ATTR("src")
_HREF = _ATTR("href")
_REL = _ATTR("rel")
_INTEGRITY = _ATTR("integrity")


def _attr(pat, attrs: str) -> str:
    m = pat.search(attrs)
    if not m:
        return ""
    return m.group(1) or m.group(2) or m.group(3) or ""


def analyze_resources(url: str, body: str, *, source: str = "subresource") -> list:
    if not body or "<" not in body:
        return []
    page_https = urlparse(url).scheme == "https"
    page_host = urlparse(url).netloc.lower()
    out: list = []
    seen: set = set()
    rec = RequestRecord(method="GET", url=url, identity="anon", status=0, elapsed_ms=0.0)

    def add(vc, sev, title, desc, rule, res_url, cwe):
        key = (rule, res_url)
        if key in seen:
            return
        seen.add(key)
        out.append(Finding(vuln_class=vc, severity=sev, title=title, endpoint=url,
                           description=desc, evidence=[rec], confidence="firm",
                           detail={"rule": rule, "resource": res_url[:200], "cwe": cwe,
                                   "source": source}))

    for m in _TAG.finditer(body):
        tag = m.group(1).lower()
        attrs = m.group(2)
        rel = _attr(_REL, attrs).lower()
        res = _attr(_SRC, attrs) if tag != "link" else _attr(_HREF, attrs)
        if not res:
            continue
        r = res.strip()
        rl = r.lower()
        if rl.startswith(("data:", "blob:", "javascript:", "#", "mailto:")):
            continue

        # resolve scheme + host
        if r.startswith("//"):
            scheme, host = ("https" if page_https else "http"), urlparse("http:" + r).netloc.lower()
        elif "://" in r:
            pu = urlparse(r); scheme, host = pu.scheme.lower(), pu.netloc.lower()
        else:
            scheme, host = ("https" if page_https else "http"), page_host   # relative -> same origin
        cross_origin = bool(host) and host != page_host

        # ---- mixed content (HTTPS page, http resource) ----
        if page_https and scheme == "http":
            if tag in ("script", "iframe"):
                add(VulnClass.MISCONFIG, Severity.HIGH, "Active mixed content over HTTP",
                    f"The HTTPS page loads an active resource (<{tag}>) over http:// — a network "
                    f"attacker can rewrite it and run code in this origin: {r[:120]}",
                    "mixed-active", r, "CWE-311")
            else:
                add(VulnClass.MISCONFIG, Severity.LOW, "Passive mixed content over HTTP",
                    f"The HTTPS page loads a passive resource (<{tag}>) over http:// — downgrade / "
                    f"privacy exposure and a browser warning: {r[:120]}", "mixed-passive", r, "CWE-311")

        # ---- missing SRI on a cross-origin script/style ----
        is_stylesheet = tag == "link" and "stylesheet" in rel
        if cross_origin and scheme in ("http", "https") and (tag == "script" or is_stylesheet):
            if not _attr(_INTEGRITY, attrs):
                if tag == "script":
                    add(VulnClass.SUPPLY_CHAIN, Severity.MEDIUM,
                        "Cross-origin <script> without Subresource Integrity",
                        f"A third-party script from {host} has no integrity attribute — if that CDN "
                        f"is compromised it serves arbitrary code into this origin: {r[:120]}",
                        "sri-script", r, "CWE-353")
                else:
                    add(VulnClass.SUPPLY_CHAIN, Severity.LOW,
                        "Cross-origin stylesheet without Subresource Integrity",
                        f"A third-party stylesheet from {host} has no integrity attribute; a "
                        f"compromised CDN could inject CSS-based exfiltration/UI-redress: {r[:120]}",
                        "sri-style", r, "CWE-353")
    return out
