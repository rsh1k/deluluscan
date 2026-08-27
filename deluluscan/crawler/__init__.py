"""Dynamic (headless-browser) crawler — renders JS-heavy apps to discover the
API surface and forms a static parse misses. Playwright is an OPTIONAL dependency;
without it the module imports fine and the crawl degrades fail-soft."""
from .engine import CrawlEngine, CrawlResult
from .browser import (BrowserDriver, PlaywrightDriver, RenderedPage,
                      NetworkRequest, FormInfo, PLAYWRIGHT_HINT)

__all__ = ["CrawlEngine", "CrawlResult", "BrowserDriver", "PlaywrightDriver",
           "RenderedPage", "NetworkRequest", "FormInfo", "PLAYWRIGHT_HINT"]
