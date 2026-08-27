"""WAF / CDN / reverse-proxy detection (wafw00f-style).

Two passes, mirroring how wafw00f works:
  1. passive — a normal request; inspect the response surface (Server header,
     vendor headers like cf-ray / x-amz-cf-id / x-iinfo, cookie names, body) for
     vendor markers. Cheap and non-triggering.
  2. active  — one deliberately-suspicious request (an obvious attack pattern in a
     query param). If the response now blocks (403/406/429 + block body) or a
     vendor marker appears that was absent on the normal request, that confirms a
     WAF is inline. Gated by the caller's authorization boundary (it sends a
     probe to the target).

Confidence scales with the number of *independent* signals pointing at one
vendor. Detection only — the attack pattern is a harmless canary, never a working
exploit.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .signatures import EDGE_SIGS, BLOCK_STATUSES, BLOCK_BODY_RE

# A benign-but-suspicious string most WAFs flag, harmless to the app.
_PROBE_PARAM = "deluluscan_waf_probe"
_PROBE_VALUE = "1' OR '1'='1 <script>alert(1)</script> ../../etc/passwd"


@dataclass
class EdgeMatch:
    name: str
    kind: str
    signals: list = field(default_factory=list)
    blocking: bool = False           # observed to actively block a probe

    @property
    def score(self) -> float:
        return float(len(self.signals)) + (1.5 if self.blocking else 0.0)

    @property
    def confidence(self) -> str:
        s = self.score
        return "confirmed" if s >= 3 else "firm" if s >= 2 else "tentative"


def _norm_headers(headers) -> dict:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _cookie_names(headers: dict) -> str:
    # Set-Cookie may be folded; match against the whole blob.
    return headers.get("set-cookie", "")


def _match_vendor(sig, status: int, headers: dict, body: str) -> list:
    signals: list = []
    for hname, vre in sig.headers:
        if hname.lower() in headers:
            val = headers[hname.lower()]
            if not vre or re.search(vre, val):
                signals.append(f"header {hname}: {val[:50]}" if val else f"header {hname}")
    cookies = _cookie_names(headers)
    for cre in sig.cookies:
        if re.search(cre, cookies):
            signals.append(f"cookie ~ {cre}")
    if sig.server_re and re.search(sig.server_re, headers.get("server", "")):
        signals.append(f"Server: {headers.get('server','')[:50]}")
    if sig.body_re and body and re.search(sig.body_re, body):
        signals.append("block/challenge body matched")
    return signals


class WafScan:
    def __init__(self, fetch: Optional[Callable] = None, timeout: int = 10):
        self.fetch = fetch or _default_fetch
        self.timeout = timeout

    def detect(self, url: str, *, active: bool = True) -> list:
        """Return EdgeMatch[] (best first). active=False => passive only."""
        # 1) passive
        p_status, p_headers, p_body = self._get(url)
        p_headers = _norm_headers(p_headers)
        matches: dict = {}
        for sig in EDGE_SIGS:
            sigs = _match_vendor(sig, p_status, p_headers, p_body)
            if sigs:
                matches[sig.name] = EdgeMatch(sig.name, sig.kind, sigs)

        # 2) active probe (may reveal a WAF that stays invisible on clean traffic)
        if active:
            a_status, a_headers, a_body = self._get(
                url, params={_PROBE_PARAM: _PROBE_VALUE})
            a_headers = _norm_headers(a_headers)
            for sig in EDGE_SIGS:
                sigs = _match_vendor(sig, a_status, a_headers, a_body)
                if sigs:
                    m = matches.get(sig.name) or EdgeMatch(sig.name, sig.kind, [])
                    for s in sigs:
                        if s not in m.signals:
                            m.signals.append(s)
                    matches[sig.name] = m
            blocked = self._looks_blocked(p_status, a_status, a_body)
            if blocked:
                if matches:
                    # attribute the block to the highest-signal WAF-capable vendor
                    for m in matches.values():
                        if m.kind in ("waf", "both"):
                            m.blocking = True
                            break
                    else:
                        next(iter(matches.values())).blocking = True
                else:
                    matches["Generic WAF (unattributed)"] = EdgeMatch(
                        "Generic WAF (unattributed)", "waf",
                        [f"probe blocked: HTTP {a_status}"], blocking=True)

        return sorted(matches.values(), key=lambda m: m.score, reverse=True)

    def _looks_blocked(self, clean_status: int, probe_status: int, probe_body: str) -> bool:
        if probe_status in BLOCK_STATUSES and probe_status != clean_status:
            return True
        if probe_status in BLOCK_STATUSES and any(
                re.search(r, probe_body or "") for r in BLOCK_BODY_RE):
            return True
        return False

    def _get(self, url: str, params: Optional[dict] = None):
        u = url
        if params:
            sep = "&" if "?" in url else "?"
            from urllib.parse import urlencode
            u = url + sep + urlencode(params)
        try:
            return self.fetch(u)
        except Exception as exc:
            return 0, {}, f"__error__:{exc}"


def _default_fetch(url: str, method: str = "GET", timeout: int = 10):
    import urllib.request
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "deluluscan-netscan"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(120_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read(60_000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, {}, ""
