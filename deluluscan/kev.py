"""CISA KEV cross-reference — flag CVEs that are KNOWN to be exploited.

EPSS gives a probability; CISA's Known Exploited Vulnerabilities catalog gives a
binary, authoritative fact: this CVE has been observed exploited in the wild and
(for federal systems) carries a remediation due date. A finding whose CVE is in
KEV jumps to the top of the fix list regardless of its CVSS score.

The fetch is injected (offline-testable); the default pulls the public CISA KEV
JSON feed once and FAILS SOFT — no network, no feed, bad data => findings are
simply not annotated. No auth, no PII.
"""
from __future__ import annotations

import json
from typing import Callable, Optional

_KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _default_fetch(timeout: int = 15) -> dict:
    import urllib.request
    try:
        req = urllib.request.Request(_KEV_FEED, headers={"User-Agent": "deluluscan-kev"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(20_000_000).decode("utf-8", "replace"))
    except Exception:
        return {}
    out: dict = {}
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID")
        if not cve:
            continue
        out[cve] = {
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "name": v.get("vulnerabilityName", ""),
            "ransomware": (v.get("knownRansomwareCampaignUse", "") or "").lower() == "known",
        }
    return out


class KevCatalog:
    def __init__(self, fetch: Optional[Callable] = None, timeout: int = 15):
        self.fetch = fetch or _default_fetch
        self.timeout = timeout
        self._catalog: Optional[dict] = None

    def _load(self) -> dict:
        if self._catalog is None:
            try:
                self._catalog = self.fetch(self.timeout) or {}
            except Exception:
                self._catalog = {}
        return self._catalog

    def entry(self, cve: str) -> Optional[dict]:
        return self._load().get(cve)

    def __contains__(self, cve: str) -> bool:
        return cve in self._load()

    def __len__(self) -> int:
        return len(self._load())


def attach_kev(findings: list, catalog: Optional[KevCatalog] = None) -> int:
    """Annotate CVE-bearing findings whose CVE is in the CISA KEV catalog with
    detail['kev']. Returns the count annotated. Fail-soft."""
    cves = [(f, (getattr(f, "detail", None) or {}).get("cve")) for f in findings]
    cves = [(f, c) for (f, c) in cves if c]
    if not cves:
        return 0
    # NB: KevCatalog defines __len__, so an empty one is falsy — must use `is None`,
    # never `catalog or KevCatalog()`, or an injected/errored catalog gets silently
    # replaced by a live-fetching default.
    if catalog is None:
        catalog = KevCatalog()
    if len(catalog) == 0:
        return 0
    n = 0
    for f, cve in cves:
        e = catalog.entry(cve)
        if not e:
            continue
        d = f.detail
        d["kev"] = {"in_kev": True, "date_added": e["date_added"],
                    "due_date": e["due_date"], "ransomware": e["ransomware"]}
        note = "Listed in CISA KEV — confirmed exploited in the wild"
        if e["ransomware"]:
            note += "; linked to known ransomware campaigns"
        d["kev_note"] = note + "."
        n += 1
    return n
