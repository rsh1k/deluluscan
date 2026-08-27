"""HeaderScan — fetch a URL, run a CORS reflection probe, and analyze the
security posture of the response headers/cookies. `fetch(url, extra_headers) ->
(status, headers_dict)` is injected so it runs offline in tests."""
from __future__ import annotations

from typing import Callable, Optional

from ..models import Finding
from .analyzer import analyze_all

_PROBE_ORIGIN = "https://deluluscan-cors-probe.example"


class HeaderScan:
    def scan(self, fetch: Callable, url: str) -> list:
        status, headers = fetch(url, {})
        # CORS reflection probe: send a foreign Origin, see if it's reflected
        cors_probe = None
        try:
            _, ph = fetch(url, {"Origin": _PROBE_ORIGIN})
            phl = {str(k).lower(): v for k, v in (ph or {}).items()}
            cors_probe = {"sent_origin": _PROBE_ORIGIN,
                          "acao": phl.get("access-control-allow-origin"),
                          "acac": phl.get("access-control-allow-credentials")}
        except Exception:
            pass
        return analyze_all(status, headers, url, cors_probe=cors_probe)

    @staticmethod
    def default_fetch(url: str, extra_headers: dict):
        import requests
        r = requests.get(url, headers={"user-agent": "deluluscan-headers", **(extra_headers or {})},
                         timeout=15, allow_redirects=False)
        h = dict(r.headers)
        sc = r.raw.headers.get_all("Set-Cookie") if hasattr(r.raw.headers, "get_all") else None
        if sc:
            h["Set-Cookie"] = sc
        return r.status_code, h
