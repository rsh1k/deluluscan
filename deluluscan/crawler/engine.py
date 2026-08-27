"""CrawlEngine — a bounded, same-origin dynamic crawl driven by a BrowserDriver.

BFS over rendered pages: render a URL, harvest its links (to keep crawling) and —
the payoff — the API endpoints the page's JS actually called (captured XHR/fetch
network requests) plus its forms. Recovers the dynamic surface that a static
wordlist or JS parse misses.

Bounded by max_pages, max_depth, and a per-page timeout. Same-origin by default
(never wanders off the authorized target). Detection only — it renders pages, it
does not submit forms or exploit anything. Driver is injected, so the whole engine
is testable offline with a fake driver.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urldefrag, urljoin

from ..models import Finding, RequestRecord, Severity, VulnClass

_API_HINT = ("/api", "/rest", "/graphql", "/v1", "/v2", "/v3", "/internal",
             "/oauth", "/auth", "/webhook")
_ASSET_RE = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
             ".woff2", ".ttf", ".ico", ".map", ".mp4", ".webp", ".pdf")


@dataclass
class CrawlResult:
    start_url: str
    pages: list = field(default_factory=list)          # crawled page URLs
    api_endpoints: list = field(default_factory=list)   # [{method,url,path,resource_type}]
    forms: list = field(default_factory=list)           # [{action,method,inputs}]
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"start_url": self.start_url, "pages": self.pages,
                "api_endpoints": self.api_endpoints, "forms": self.forms,
                "errors": self.errors}

    def to_findings(self) -> list:
        out: list = []
        if self.api_endpoints:
            sample = ", ".join(sorted({e["path"] for e in self.api_endpoints})[:12])
            rec = RequestRecord(method="GET", url=self.start_url, identity="anon",
                                status=200, elapsed_ms=0.0)
            out.append(Finding(
                vuln_class=VulnClass.INVENTORY, severity=Severity.LOW,
                title=f"{len(self.api_endpoints)} API endpoint(s) observed via dynamic crawl",
                endpoint=self.start_url,
                description=("A headless browser rendered the app and captured the API calls its "
                             "JavaScript actually made (XHR/fetch). These dynamic endpoints are "
                             "often undocumented (OWASP API9) — enumerate and test each for auth "
                             f"and object-level access. Sample: {sample}."),
                evidence=[rec],
                detail={"endpoints": self.api_endpoints, "count": len(self.api_endpoints),
                        "pages_crawled": len(self.pages), "source": "crawler"},
                confidence="firm", verdict="true_positive", exploitability="conditional"))
        return out


def _norm(url: str) -> str:
    return urldefrag(url)[0]


def _is_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(_ASSET_RE)


def _looks_api(url: str, resource_type: str) -> bool:
    if resource_type in ("xhr", "fetch"):
        return True
    p = urlparse(url).path.lower()
    return any(h in p for h in _API_HINT)


class CrawlEngine:
    def __init__(self, driver, *, max_pages: int = 40, max_depth: int = 3,
                 same_origin: bool = True, timeout: int = 15):
        self.driver = driver
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.same_origin = same_origin
        self.timeout = timeout

    def crawl(self, start_url: str) -> CrawlResult:
        result = CrawlResult(start_url=start_url)
        origin = urlparse(start_url).netloc
        frontier: deque = deque([(_norm(start_url), 0)])
        visited: set = set()
        api_seen: set = set()
        form_seen: set = set()

        while frontier and len(result.pages) < self.max_pages:
            url, depth = frontier.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                page = self.driver.render(url, timeout=self.timeout)
            except Exception as exc:
                result.errors.append(f"{url}: {str(exc)[:160]}")
                continue
            result.pages.append(url)
            if page.error:
                result.errors.append(f"{url}: {page.error}")

            # 1) capture API endpoints from the page's network traffic
            for req in page.requests or []:
                if _is_asset(req.url) or not _looks_api(req.url, req.resource_type):
                    continue
                path = urlparse(req.url).path
                key = (req.method.upper(), path)
                if key in api_seen:
                    continue
                api_seen.add(key)
                result.api_endpoints.append(
                    {"method": req.method.upper(), "url": req.url, "path": path,
                     "resource_type": req.resource_type})

            # 2) record forms (surface for later auth/logic testing)
            for f in page.forms or []:
                action = urljoin(url, f.action or url)
                key = (f.method.upper(), urlparse(action).path, tuple(f.inputs))
                if key in form_seen:
                    continue
                form_seen.add(key)
                result.forms.append({"action": action, "method": f.method.upper(),
                                     "inputs": f.inputs})

            # 3) enqueue same-origin page links within depth
            if depth < self.max_depth:
                for href in page.links or []:
                    nu = _norm(urljoin(url, href))
                    if not nu.startswith(("http://", "https://")):
                        continue
                    if self.same_origin and urlparse(nu).netloc != origin:
                        continue
                    if _is_asset(nu) or nu in visited:
                        continue
                    frontier.append((nu, depth + 1))

        return result
