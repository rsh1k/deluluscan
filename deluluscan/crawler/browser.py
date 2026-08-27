"""Browser-driver abstraction for the dynamic crawler.

The crawl engine talks to a `BrowserDriver` that renders a URL and reports back
what a real browser saw: the final HTML, the links, the forms, and — the whole
point of a headless crawl — the **network requests the page actually made** as
its JS ran (XHR/fetch). That network capture recovers dynamically-constructed API
calls that static JS parsing (recon/jsanalysis) cannot resolve.

The interface is injected, so the engine is fully testable with a fake driver and
no browser. `PlaywrightDriver` is the real implementation; Playwright is an
OPTIONAL dependency — importing it is lazy and its absence raises a clear,
actionable error (the CLI/engine degrade fail-soft rather than crashing a scan).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol


@dataclass
class NetworkRequest:
    method: str
    url: str
    resource_type: str = ""          # xhr | fetch | document | script | image | ...


@dataclass
class FormInfo:
    action: str
    method: str = "GET"
    inputs: list = field(default_factory=list)   # field names


@dataclass
class RenderedPage:
    url: str                          # final URL (after client redirects)
    status: int = 0
    html: str = ""
    links: list = field(default_factory=list)        # absolute hrefs
    requests: list = field(default_factory=list)      # NetworkRequest[]
    forms: list = field(default_factory=list)         # FormInfo[]
    error: str = ""


class BrowserDriver(Protocol):
    def render(self, url: str, timeout: int = 15) -> RenderedPage: ...
    def close(self) -> None: ...


PLAYWRIGHT_HINT = ("Playwright is not installed. The dynamic crawler is optional; "
                   "install it with:\n    pip install playwright\n    playwright install chromium")


class PlaywrightDriver:
    """Headless-Chromium driver (persistent browser across renders). Playwright is
    imported lazily so the package works without it."""

    def __init__(self, *, headless: bool = True, user_agent: str = "deluluscan-crawler"):
        self.headless = headless
        self.user_agent = user_agent
        self._pw = None
        self._browser = None

    def _ensure(self):
        if self._browser is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:                     # ImportError or driver missing
            raise RuntimeError(PLAYWRIGHT_HINT) from exc
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)

    def render(self, url: str, timeout: int = 15) -> RenderedPage:
        self._ensure()
        requests: list = []
        ctx = self._browser.new_context(user_agent=self.user_agent, ignore_https_errors=True)
        page = ctx.new_page()
        page.on("request", lambda r: requests.append(
            NetworkRequest(method=r.method, url=r.url, resource_type=r.resource_type)))
        status = 0
        error = ""
        try:
            resp = page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
            status = resp.status if resp else 0
            html = page.content()
            links = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)") or []
            forms = page.eval_on_selector_all(
                "form",
                "els => els.map(f => ({action: f.action, method: (f.method||'GET'), "
                "inputs: Array.from(f.querySelectorAll('input,select,textarea'))"
                ".map(i => i.name).filter(Boolean)}))") or []
        except Exception as exc:
            html, links, forms = "", [], []
            error = str(exc)[:200]
        finally:
            ctx.close()
        return RenderedPage(
            url=url, status=status, html=html, links=list(links),
            requests=requests,
            forms=[FormInfo(action=f.get("action", ""), method=(f.get("method") or "GET").upper(),
                            inputs=f.get("inputs", [])) for f in forms],
            error=error)

    def close(self) -> None:
        try:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        except Exception:
            pass
        self._browser = self._pw = None
