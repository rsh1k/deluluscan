"""Offline tests for SBOM (CycloneDX/SPDX) analysis."""
from __future__ import annotations

from deluluscan.sbom import SbomScan, parse_sbom, analyze_components
from deluluscan.sbom.parse import detect_format, Component
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")

def rules(f): return {x.detail["rule"] for x in f}


def _cdx(components):
    return {"bomFormat": "CycloneDX", "components": components}


def test_detect_and_parse_cyclonedx():
    d = _cdx([{"name": "x", "version": "1.0", "purl": "pkg:npm/x@1.0", "hashes": [{"alg": "SHA-256", "content": "a"}]}])
    check("cyclonedx detected", detect_format(d) == "cyclonedx")
    c = parse_sbom(d)
    check("component parsed w/ ecosystem+hash", c[0].name == "x" and c[0].ecosystem == "npm" and c[0].has_hash)


def test_detect_and_parse_spdx():
    d = {"spdxVersion": "SPDX-2.3", "packages": [
        {"name": "log4j-core", "versionInfo": "2.14.1",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:maven/x/log4j-core@2.14.1"}],
         "checksums": [{"algorithm": "SHA256", "checksumValue": "a"}]}]}
    check("spdx detected", detect_format(d) == "spdx")
    c = parse_sbom(d)
    check("spdx component parsed", c and c[0].name == "log4j-core" and c[0].version == "2.14.1" and c[0].has_hash)


def test_known_vulnerable_log4shell():
    f = SbomScan().scan_data(_cdx([{"name": "log4j-core", "version": "2.14.1",
        "purl": "pkg:maven/x/log4j-core@2.14.1", "hashes": [{"alg": "SHA-256", "content": "a"}]}]))
    kv = next((x for x in f if x.detail["rule"] == "sbom-known-vuln"), None)
    check("Log4Shell flagged CRITICAL supply_chain", kv and kv.severity == Severity.CRITICAL
          and kv.vuln_class == VulnClass.SUPPLY_CHAIN, rules(f))
    check("CVE recorded", kv and kv.detail["cve"] == "CVE-2021-44228")


def test_fixed_version_not_flagged():
    f = SbomScan().scan_data(_cdx([{"name": "log4j-core", "version": "2.17.1",
        "purl": "pkg:maven/x/log4j-core@2.17.1", "hashes": [{"alg": "SHA-256", "content": "a"}]}]))
    check("patched log4j not flagged", "sbom-known-vuln" not in rules(f), rules(f))


def test_integrity_and_version_gaps():
    f = analyze_components([Component("a", "1.0", has_hash=False), Component("b", "", has_hash=False),
                            Component("c", "1.0", has_hash=False)])
    check("no-hash aggregate flagged", "sbom-no-hash" in rules(f), rules(f))
    check("no-version flagged", "sbom-no-version" in rules(f), rules(f))


def test_empty_sbom():
    check("empty SBOM flagged", "sbom-empty" in rules(SbomScan().scan_data(_cdx([]))))


def test_clean_sbom():
    f = SbomScan().scan_data(_cdx([{"name": "safe", "version": "2.0.0", "purl": "pkg:npm/safe@2.0.0",
                                    "hashes": [{"alg": "SHA-256", "content": "a"}], "supplier": {"name": "ACME"}}]))
    check("clean SBOM -> no findings", f == [], [x.title for x in f])


def test_non_sbom_ignored():
    check("random json -> no findings", SbomScan().scan_data({"hello": "world"}) == [])


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
