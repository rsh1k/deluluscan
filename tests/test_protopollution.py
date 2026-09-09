"""Offline tests for client-side prototype-pollution (injected browser probe)."""
from __future__ import annotations

from deluluscan.protopollution import ProtoPollutionScan, vectors
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def test_vectors_carry_marker():
    v = vectors("MARK")
    check("6 vectors", len(v) == 6, len(v))
    check("all reference __proto__ or constructor",
          all("__proto__" in f or "constructor" in f for _, f in v))
    check("all carry the marker", all("MARK" in f for _, f in v))


def test_vulnerable_query_gadget():
    # app pollutes only via a query-string __proto__[k] gadget
    def probe(url, marker):
        return f"__proto__[{marker}]" in url and "?" in url.split("#")[0]
    res, finds = ProtoPollutionScan(probe=probe).run("http://t/app")
    check("query vectors hit", any("query __proto__[k]" == h["label"] for h in res.hits), res.hits)
    check("hash vector NOT hit by a query-only gadget",
          not any(h["label"].startswith("hash") for h in res.hits), res.hits)
    check("one HIGH MISCONFIG finding", len(finds) == 1 and finds[0].severity == Severity.HIGH
          and finds[0].vuln_class == VulnClass.MISCONFIG)
    check("finding is true_positive", finds[0].verdict == "true_positive")
    check("finding lists vectors", finds[0].detail["count"] == len(res.hits))


def test_not_vulnerable():
    res, finds = ProtoPollutionScan(probe=lambda url, marker: False).run("http://t/app")
    check("no pollution -> no hits", res.hits == [])
    check("no pollution -> no findings", finds == [])


def test_probe_error_is_failsoft():
    def boom(url, marker): raise RuntimeError("browser died")
    res, finds = ProtoPollutionScan(probe=boom).run("http://t/app")
    check("probe error -> no crash, no findings", res.hits == [] and finds == [])


def test_marker_is_unique_per_scan():
    seen = []
    def probe(url, marker): seen.append(marker); return False
    ProtoPollutionScan(probe=probe).run("http://t/a")
    ProtoPollutionScan(probe=probe).run("http://t/b")
    check("marker differs across scans", len(set(seen)) == 2, set(seen))


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
