"""Offline tests for EPSS enrichment (injected fetch — no network)."""
from __future__ import annotations

from deluluscan.epss import EpssClient, attach_epss, _band
from deluluscan.models import Finding, Severity, VulnClass

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def _cve_finding(cve):
    return Finding(vuln_class=VulnClass.SUPPLY_CHAIN, severity=Severity.HIGH, title="x",
                   endpoint="t", description="", detail={"cve": cve})


def _fetch(table):
    def fetch(cves, timeout=12):
        return {c: table[c] for c in cves if c in table}
    return fetch


def test_attach_scores():
    table = {"CVE-2021-44228": {"epss": 0.97, "percentile": 0.99},
             "CVE-2018-0001": {"epss": 0.03, "percentile": 0.40}}
    f1, f2 = _cve_finding("CVE-2021-44228"), _cve_finding("CVE-2018-0001")
    n = attach_epss([f1, f2], EpssClient(fetch=_fetch(table)))
    check("both enriched", n == 2, n)
    check("high score -> critical band", f1.detail["epss"]["band"] == "critical")
    check("low score -> low band", f2.detail["epss"]["band"] == "low")
    check("critical carries epss_note", "epss_note" in f1.detail)
    check("low has no epss_note", "epss_note" not in f2.detail)


def test_no_cve_findings_untouched():
    f = Finding(vuln_class=VulnClass.MISCONFIG, severity=Severity.LOW, title="z",
                endpoint="t", description="", detail={})
    n = attach_epss([f], EpssClient(fetch=_fetch({})))
    check("no CVE -> nothing enriched", n == 0 and "epss" not in f.detail)


def test_unknown_cve_left_alone():
    f = _cve_finding("CVE-9999-0000")
    n = attach_epss([f], EpssClient(fetch=_fetch({"CVE-2021-44228": {"epss": 0.9, "percentile": 0.9}})))
    check("unknown CVE not annotated", n == 0 and "epss" not in f.detail)


def test_failsoft_on_fetch_error():
    def boom(cves, timeout=12): raise OSError("no network")
    f = _cve_finding("CVE-2021-44228")
    n = attach_epss([f], EpssClient(fetch=boom))
    check("fetch error -> fail soft, unchanged", n == 0 and "epss" not in f.detail)


def test_caching_dedups_requests():
    calls = {"n": 0}
    def fetch(cves, timeout=12):
        calls["n"] += 1
        return {c: {"epss": 0.5, "percentile": 0.9} for c in cves}
    client = EpssClient(fetch=fetch)
    client.scores(["CVE-2021-44228"])
    client.scores(["CVE-2021-44228"])   # cached -> no second fetch
    check("cache avoids refetch", calls["n"] == 1, calls["n"])


def test_band_thresholds():
    check("0.60 critical", _band(0.60) == "critical")
    check("0.10 elevated", _band(0.10) == "elevated")
    check("0.05 low", _band(0.05) == "low")


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
