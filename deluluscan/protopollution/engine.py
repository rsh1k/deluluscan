"""Client-side prototype-pollution scanner.

For each URL vector, render the page in a real browser and check whether
`Object.prototype[marker]` actually got set — proof of a client-side gadget. The
`probe(full_url, marker) -> bool` function is INJECTED, so the engine is fully
offline-testable with a fake probe; the default drives Playwright (optional dep,
lazily imported, fail-soft). Active (it loads the page with a payload), so the
CLI gates it to loopback/RFC1918. Detection only — the payload sets one benign
marker property and nothing else.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass
from .payloads import vectors

PLAYWRIGHT_HINT = ("Playwright is not installed. Client-side prototype-pollution testing needs a "
                   "browser: pip install playwright && playwright install chromium")


@dataclass
class ProtoResult:
    base_url: str
    hits: list = field(default_factory=list)   # [{label, url, marker}]

    def to_findings(self) -> list:
        if not self.hits:
            return []
        rec = RequestRecord(method="GET", url=self.hits[0]["url"], identity="anon",
                            status=200, elapsed_ms=0.0)
        vecs = ", ".join(h["label"] for h in self.hits)
        return [Finding(
            vuln_class=VulnClass.MISCONFIG, severity=Severity.HIGH,
            title="Client-side prototype pollution",
            endpoint=self.base_url,
            description=("A client-side gadget merges attacker-controlled URL keys into an object "
                         "without guarding __proto__/constructor, so Object.prototype was polluted "
                         f"from the URL (confirmed in the live DOM). Vectors: {vecs}. This is often "
                         "a stepping stone to DOM XSS depending on the sink gadgets present."),
            evidence=[rec], confidence="firm", verdict="true_positive", exploitability="conditional",
            detail={"vectors": self.hits, "count": len(self.hits), "source": "protopollution",
                    "remediation": ("Reject/strip __proto__, constructor and prototype keys when "
                                    "merging untrusted input; use Object.create(null) maps, Map, or "
                                    "a hardened deep-merge; freeze Object.prototype where feasible.")})]


class ProtoPollutionScan:
    def __init__(self, probe: Optional[Callable] = None):
        self.probe = probe or _default_probe

    def scan(self, base_url: str) -> ProtoResult:
        marker = "dpp_" + secrets.token_hex(4)
        result = ProtoResult(base_url=base_url)
        for label, frag in vectors(marker):
            full = base_url + frag
            try:
                polluted = self.probe(full, marker)
            except Exception:
                continue
            if polluted:
                result.hits.append({"label": label, "url": full, "marker": marker})
        return result

    def run(self, base_url: str):
        r = self.scan(base_url)
        return r, r.to_findings()


def _default_probe(full_url: str, marker: str, timeout: int = 15) -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(PLAYWRIGHT_HINT) from exc
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_context(ignore_https_errors=True).new_page()
            page.goto(full_url, wait_until="networkidle", timeout=timeout * 1000)
            return bool(page.evaluate(
                "(m) => Object.prototype[m] !== undefined && Object.prototype[m] !== null", marker))
        finally:
            browser.close()
