"""Browser-based XSS execution check.

Regex/reflection can't tell you whether JavaScript actually *executes* — a marker
may sit in an escaped context, a WAF block page, or a JSON field that's never
rendered. The reliable confirmation (the practitioner standard) is to load the
response in a real browser and see whether an injected marker fires.

This module uses Playwright when it's installed, loading the returned HTML and
checking whether ``window.__deluluscan_xss`` gets set by an injected marker script.
If Playwright isn't available, it degrades gracefully to a static context
verdict (executable vs escaped) using the response differ — never a false
"confirmed". Nothing is exfiltrated; the page is rendered in an isolated,
throwaway context with no stored credentials.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .differ import marker_context


@dataclass
class XssExecResult:
    executed: Optional[bool]     # True/False if a browser ran it; None if not attempted
    method: str                  # "playwright" | "static_context" | "unavailable"
    context: str = ""
    detail: str = ""


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


# A marker that sets a global only if it truly executes as script.
EXEC_MARKER_ID = "deluluscan_xss_probe"
def exec_payload(token: str) -> str:
    # inert beyond setting a flag; no network, no cookie access
    return f'<img src=x onerror="window.__deluluscan_xss=\'{token}\'">' \
           f'<script>window.__deluluscan_xss=\'{token}\'</script>'


def confirm_in_browser(html: str, token: str, timeout_ms: int = 3000) -> XssExecResult:
    """Render HTML headless and report whether the marker executed."""
    if not playwright_available():
        ctx = marker_context(html, token)
        executable = ctx in ("html", "attribute", "script")
        return XssExecResult(
            executed=None, method="static_context", context=ctx,
            detail=("no browser available; reflected marker sits in an executable "
                    f"context ({ctx}) — likely exploitable, confirm manually"
                    if executable else
                    f"marker in non-executable context ({ctx}); not confirmed"))
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_content(html, wait_until="load")
            try:
                page.wait_for_function("window.__deluluscan_xss !== undefined", timeout=timeout_ms)
                got = page.evaluate("window.__deluluscan_xss")
            except Exception:
                got = None
            browser.close()
            if got == token:
                return XssExecResult(True, "playwright", marker_context(html, token),
                                     "marker executed in a headless browser — XSS confirmed")
            return XssExecResult(False, "playwright", marker_context(html, token),
                                 "marker did not execute in a headless browser — not exploitable")
    except Exception as e:
        ctx = marker_context(html, token)
        return XssExecResult(None, "unavailable", ctx, f"browser check failed: {e}")
