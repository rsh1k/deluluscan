"""Offline tests for KEV cross-reference + combined priority scoring."""
from __future__ import annotations

from deluluscan.kev import KevCatalog, attach_kev
from deluluscan.priority import compute_priority, attach_priority
from deluluscan.models import Finding, Severity, VulnClass

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def _f(sev, *, cve=None, verdict="unverified", exploit="unknown", detail=None):
    d = dict(detail or {})
    if cve:
        d["cve"] = cve
    return Finding(vuln_class=VulnClass.SUPPLY_CHAIN, severity=sev, title="t", endpoint="t",
                   description="", detail=d, verdict=verdict, exploitability=exploit)


# ---- KEV ----
def test_kev_annotation():
    cat = KevCatalog(fetch=lambda t=15: {
        "CVE-2021-44228": {"date_added": "2021-12-10", "due_date": "2021-12-24",
                           "name": "Log4Shell", "ransomware": True}})
    f = _f(Severity.HIGH, cve="CVE-2021-44228")
    g = _f(Severity.HIGH, cve="CVE-2000-0000")
    n = attach_kev([f, g], cat)
    check("one KEV match", n == 1, n)
    check("KEV flag set", f.detail["kev"]["in_kev"] is True)
    check("ransomware surfaced", f.detail["kev"]["ransomware"] is True)
    check("KEV note mentions ransomware", "ransomware" in f.detail["kev_note"])
    check("non-KEV untouched", "kev" not in g.detail)


def test_kev_empty_catalog_failsoft():
    f = _f(Severity.HIGH, cve="CVE-2021-44228")
    n = attach_kev([f], KevCatalog(fetch=lambda t=15: {}))
    check("empty catalog -> no annotation", n == 0 and "kev" not in f.detail)


def test_kev_fetch_error_failsoft():
    def boom(t=15): raise OSError("no net")
    f = _f(Severity.HIGH, cve="CVE-2021-44228")
    n = attach_kev([f], KevCatalog(fetch=boom))
    check("fetch error -> fail soft", n == 0 and "kev" not in f.detail)


# ---- priority ----
def test_priority_ordering():
    med = compute_priority(_f(Severity.MEDIUM, cve="X", verdict="true_positive", exploit="exploitable",
                              detail={"kev": {"in_kev": True, "ransomware": True}, "epss": {"score": 0.9}}))
    crit = compute_priority(_f(Severity.CRITICAL))
    check("exploited medium outranks theoretical critical", med["score"] > crit["score"],
          (med["score"], crit["score"]))
    check("exploited medium is critical band", med["band"] == "critical")
    check("factors explain the score", any("KEV" in x for x in med["factors"]))


def test_priority_false_positive_sinks():
    p = compute_priority(_f(Severity.CRITICAL, verdict="false_positive"))
    check("false positive -> score 0", p["score"] == 0 and p["band"] == "info")


def test_priority_mitigated_reduced():
    base = compute_priority(_f(Severity.HIGH))["score"]
    mit = compute_priority(_f(Severity.HIGH, exploit="mitigated"))["score"]
    check("mitigated lowers score", mit < base, (mit, base))


def test_attach_priority_all():
    fs = [_f(Severity.LOW), _f(Severity.HIGH, cve="X")]
    n = attach_priority(fs)
    check("priority set on all", n == 2 and all("priority" in x.detail for x in fs))
    check("scores are 0-100", all(0 <= x.detail["priority"]["score"] <= 100 for x in fs))


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
