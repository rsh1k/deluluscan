"""Offline tests for the dynamic crawler — a fake BrowserDriver serves canned
rendered pages, so the engine runs with no Playwright and no browser."""
from __future__ import annotations

from deluluscan.crawler import CrawlEngine, CrawlResult
from deluluscan.crawler.browser import RenderedPage, NetworkRequest, FormInfo
from deluluscan.models import VulnClass

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  {detail}")


class FakeDriver:
    """pages: {url -> RenderedPage}. Records render() calls."""
    def __init__(self, pages):
        self.pages = pages
        self.rendered = []
    def render(self, url, timeout=15):
        self.rendered.append(url)
        return self.pages.get(url, RenderedPage(url=url, status=404))
    def close(self):
        pass


def test_captures_dynamic_api_and_crawls_links():
    pages = {
        "http://t/": RenderedPage(
            url="http://t/", status=200,
            html="<html>home</html>",
            links=["http://t/dashboard", "http://t/style.css", "http://evil.com/x"],
            requests=[NetworkRequest("GET", "http://t/api/v1/me", "xhr"),
                      NetworkRequest("GET", "http://t/main.js", "script")],
            forms=[]),
        "http://t/dashboard": RenderedPage(
            url="http://t/dashboard", status=200, html="<html>dash</html>",
            links=["http://t/"],
            requests=[NetworkRequest("POST", "http://t/api/v1/orders", "fetch")],
            forms=[FormInfo(action="http://t/api/v1/search", method="GET", inputs=["q"])]),
    }
    drv = FakeDriver(pages)
    res = CrawlEngine(drv, max_pages=10, max_depth=2).crawl("http://t/")
    paths = {e["path"] for e in res.api_endpoints}
    check("captured xhr endpoint", "/api/v1/me" in paths, paths)
    check("captured fetch endpoint from linked page", "/api/v1/orders" in paths, paths)
    check("script asset not counted as API", "/main.js" not in paths, paths)
    check("crawled same-origin link", "http://t/dashboard" in res.pages, res.pages)
    check("did NOT cross origin", not any("evil.com" in u for u in drv.rendered), drv.rendered)
    check("did NOT crawl css asset", not any(u.endswith(".css") for u in drv.rendered), drv.rendered)
    check("form captured", any(f["action"].endswith("/api/v1/search") for f in res.forms), res.forms)


def test_method_and_path_dedup():
    reqs = [NetworkRequest("GET", "http://t/api/x?id=1", "xhr"),
            NetworkRequest("GET", "http://t/api/x?id=2", "xhr"),
            NetworkRequest("POST", "http://t/api/x", "fetch")]
    pages = {"http://t/": RenderedPage(url="http://t/", status=200, links=[], requests=reqs)}
    res = CrawlEngine(FakeDriver(pages)).crawl("http://t/")
    keys = {(e["method"], e["path"]) for e in res.api_endpoints}
    check("query-only diffs dedup to one GET", ("GET", "/api/x") in keys)
    check("distinct method kept", ("POST", "/api/x") in keys)
    check("exactly two endpoints", len(res.api_endpoints) == 2, res.api_endpoints)


def test_bounds_respected():
    # a page that links to many others; max_pages must cap the crawl
    links = [f"http://t/p{i}" for i in range(50)]
    pages = {"http://t/": RenderedPage(url="http://t/", status=200, links=links, requests=[])}
    for i in range(50):
        pages[f"http://t/p{i}"] = RenderedPage(url=f"http://t/p{i}", status=200, links=[], requests=[])
    res = CrawlEngine(FakeDriver(pages), max_pages=5, max_depth=3).crawl("http://t/")
    check("max_pages caps crawl", len(res.pages) == 5, len(res.pages))


def test_depth_limit():
    pages = {
        "http://t/": RenderedPage(url="http://t/", status=200, links=["http://t/a"], requests=[]),
        "http://t/a": RenderedPage(url="http://t/a", status=200, links=["http://t/b"], requests=[]),
        "http://t/b": RenderedPage(url="http://t/b", status=200, links=["http://t/c"], requests=[]),
        "http://t/c": RenderedPage(url="http://t/c", status=200, links=[], requests=[]),
    }
    res = CrawlEngine(FakeDriver(pages), max_depth=1).crawl("http://t/")
    check("depth 1 reaches /a", "http://t/a" in res.pages)
    check("depth 1 does NOT reach /b", "http://t/b" not in res.pages, res.pages)


def test_findings_and_failsoft():
    pages = {"http://t/": RenderedPage(url="http://t/", status=200, links=[],
             requests=[NetworkRequest("GET", "http://t/api/data", "xhr")])}
    res = CrawlEngine(FakeDriver(pages)).crawl("http://t/")
    finds = res.to_findings()
    check("inventory finding emitted", any(f.vuln_class == VulnClass.INVENTORY for f in finds))
    check("no endpoints -> no finding",
          CrawlResult("http://t/").to_findings() == [])

    class BoomDriver:
        def render(self, url, timeout=15): raise RuntimeError("browser crashed")
        def close(self): pass
    res2 = CrawlEngine(BoomDriver()).crawl("http://t/")
    check("render error is fail-soft", res2.pages == [] and len(res2.errors) == 1, res2.errors)


def test_playwright_missing_is_actionable():
    # Without Playwright installed, PlaywrightDriver.render raises a clear hint.
    from deluluscan.crawler.browser import PlaywrightDriver, PLAYWRIGHT_HINT
    try:
        import playwright  # noqa: F401
        check("playwright present -> skip hint assert", True)
    except Exception:
        drv = PlaywrightDriver()
        try:
            drv.render("http://127.0.0.1:1/")
            check("expected RuntimeError", False)
        except RuntimeError as e:
            check("missing-playwright hint is actionable", "pip install playwright" in str(e))


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
