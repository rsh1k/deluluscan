"""Offline tests for MITRE ATT&CK technique tagging."""
from __future__ import annotations

from deluluscan.attack import (techniques_for, attach_attack, CLASS_TECHNIQUES,
                               SOURCE_TECHNIQUES, Technique)
from deluluscan.models import Finding, Severity, VulnClass

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def _f(vc, source=None):
    d = {"source": source} if source else {}
    return Finding(vuln_class=vc, severity=Severity.HIGH, title="t", endpoint="t",
                   description="", detail=d)


def ids(f):
    return {t["id"] for t in f.detail.get("attack", [])}


def test_class_mapping():
    f = _f(VulnClass.SSRF)
    attach_attack([f])
    check("SSRF -> T1190 + IMDS", ids(f) == {"T1190", "T1552.005"}, ids(f))
    fx = _f(VulnClass.XSS); attach_attack([fx])
    check("XSS -> JS + steal cookie", ids(fx) == {"T1059.007", "T1539"}, ids(fx))
    fl = _f(VulnClass.SUPPLY_CHAIN); attach_attack([fl])
    check("supply_chain -> T1195", "T1195" in ids(fl))


def test_source_refines_class():
    # a MISCONFIG from the TLS scanner should map to sniffing/AiTM, not generic T1190
    f = _f(VulnClass.CRYPTO, "netscan.tls")
    attach_attack([f])
    check("TLS source -> T1040 + T1557", ids(f) == {"T1040", "T1557"}, ids(f))
    smb = _f(VulnClass.MISCONFIG, "netscan.adintel"); attach_attack([smb])
    check("SMB/LDAP -> relay + account discovery", ids(smb) == {"T1557.001", "T1087"}, ids(smb))
    dns = _f(VulnClass.MISCONFIG, "recon.dnsintel"); attach_attack([dns])
    check("DNS -> phishing-for-info", "T1598" in ids(dns), ids(dns))


def test_generic_misconfig_falls_back_to_class():
    f = _f(VulnClass.MISCONFIG, "headers")  # unknown source -> class map
    attach_attack([f])
    check("unknown source -> class T1190", "T1190" in ids(f), ids(f))


def test_technique_url_and_dict():
    t = Technique("Credential Access", "T1552.005", "Cloud Instance Metadata API")
    check("sub-technique URL", t.url == "https://attack.mitre.org/techniques/T1552/005/")
    tt = Technique("Initial Access", "T1190", "Exploit Public-Facing Application")
    check("top-level URL", tt.url == "https://attack.mitre.org/techniques/T1190/")
    d = t.to_dict()
    check("dict has tactic/id/name/url", all(k in d for k in ("tactic", "id", "name", "url")))


def test_attach_counts_and_skips():
    known = _f(VulnClass.SQLI)
    # a class with no mapping (none currently) — simulate via a finding whose class
    # value isn't in the map by using a detail-only object
    class Fake:
        vuln_class = type("V", (), {"value": "nonexistent"})()
        detail = {}
    n = attach_attack([known, Fake()])
    check("only mapped findings annotated", n == 1, n)
    check("unmapped finding untouched", "attack" not in Fake().detail)


def test_all_mappings_wellformed():
    for lst in list(CLASS_TECHNIQUES.values()) + list(SOURCE_TECHNIQUES.values()):
        for t in lst:
            check(f"{t.id} well-formed", t.id.startswith(("T1", "AML")) and t.tactic and t.name,
                  t.id)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
