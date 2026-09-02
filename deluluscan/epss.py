"""EPSS enrichment — prioritize CVE findings by real-world exploit probability.

CVSS says how bad a CVE *could* be; EPSS (the FIRST.org Exploit Prediction Scoring
System) says how *likely* it is to be exploited in the next 30 days, learned from
real attack telemetry. Attaching EPSS to the version-gated CVE findings
(platforms/cves.py) lets the report rank "patch this first" by evidence, not just
by severity — a HIGH CVE with EPSS 0.02 waits behind a MEDIUM with EPSS 0.80.

The fetch is injected, so this is offline-testable; the default queries the public
FIRST.org EPSS API in one batched request and FAILS SOFT (no network, no API, bad
data -> findings are simply not annotated, never an error). No auth, no PII.
"""
from __future__ import annotations

import json
from typing import Callable, Optional

_EPSS_API = "https://api.first.org/data/v1/epss"
_HIGH = 0.10          # EPSS >= 10% is already well above the ~2% median -> "act soon"
_CRITICAL = 0.50


def _default_fetch(cves: list, timeout: int = 12) -> dict:
    import urllib.request
    import urllib.parse
    out: dict = {}
    # the API takes a comma-separated cve list; batch to keep URLs sane
    for i in range(0, len(cves), 80):
        chunk = cves[i:i + 80]
        url = _EPSS_API + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)})
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "deluluscan-epss"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read(1_000_000).decode("utf-8", "replace"))
            for row in data.get("data", []):
                cve = row.get("cve")
                if cve:
                    out[cve] = {"epss": float(row.get("epss", 0) or 0),
                                "percentile": float(row.get("percentile", 0) or 0)}
        except Exception:
            continue          # fail soft per chunk
    return out


class EpssClient:
    def __init__(self, fetch: Optional[Callable] = None, timeout: int = 12):
        self.fetch = fetch or _default_fetch
        self.timeout = timeout
        self._cache: dict = {}

    def scores(self, cves: list) -> dict:
        """Return {cve: {"epss": float, "percentile": float}} for known CVEs."""
        want = sorted({c for c in cves if c and c not in self._cache})
        if want:
            try:
                fetched = self.fetch(want, self.timeout) or {}
            except Exception:
                fetched = {}
            self._cache.update(fetched)
        return {c: self._cache[c] for c in cves if c in self._cache}


def _band(epss: float) -> str:
    if epss >= _CRITICAL:
        return "critical"
    if epss >= _HIGH:
        return "elevated"
    return "low"


def _cves_in(findings: list) -> list:
    cves = []
    for f in findings:
        d = getattr(f, "detail", None) or {}
        cve = d.get("cve")
        if cve:
            cves.append(cve)
    return cves


def attach_epss(findings: list, client: Optional[EpssClient] = None) -> int:
    """Annotate each CVE-bearing finding with detail['epss'] = {score, percentile,
    band}. Returns the number of findings enriched. Fail-soft: on any problem the
    findings are returned unchanged."""
    cves = _cves_in(findings)
    if not cves:
        return 0
    client = client or EpssClient()
    scores = client.scores(cves)
    if not scores:
        return 0
    n = 0
    for f in findings:
        d = getattr(f, "detail", None)
        if not isinstance(d, dict):
            continue
        s = scores.get(d.get("cve"))
        if not s:
            continue
        band = _band(s["epss"])
        d["epss"] = {"score": round(s["epss"], 5),
                     "percentile": round(s["percentile"], 5), "band": band}
        # a very high real-world exploit probability is worth flagging in text too
        if band == "critical" and "exploit-predicted" not in (f.title or ""):
            d.setdefault("epss_note",
                         f"EPSS {s['epss']*100:.1f}% — actively exploited in the wild is likely.")
        n += 1
    return n
