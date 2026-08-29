"""Offline tests for SMB/LDAP posture detection (detection-only).

Injected probes exercise the finding logic with no network. Confirms we flag the
misconfigs and, importantly, do NOT flag a hardened host — and that the module is
detection-only (findings describe posture; there is no exploit path in the code)."""
from __future__ import annotations

from deluluscan.netscan.adintel import AdIntel
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")

def titles(f): return {x.title for x in f}


def test_smb_signing_not_required():
    ad = AdIntel(smb_probe=lambda h: {"reachable": True, "dialect": "0x311",
                                      "signing_required": False, "smbv1": False},
                 ldap_probe=lambda h: None)
    prof, finds = ad.run("10.0.0.5")
    f = next((x for x in finds if "signing not required" in x.title), None)
    check("SMB signing flagged", f is not None, titles(finds))
    check("SMB signing MEDIUM + misconfig", f and f.severity == Severity.MEDIUM
          and f.vuln_class == VulnClass.MISCONFIG)


def test_smbv1_enabled():
    ad = AdIntel(smb_probe=lambda h: {"reachable": True, "dialect": "0x0202",
                                      "signing_required": True, "smbv1": True},
                 ldap_probe=lambda h: None)
    prof, finds = ad.run("10.0.0.5")
    f = next((x for x in finds if "SMBv1" in x.title), None)
    check("SMBv1 flagged HIGH", f and f.severity == Severity.HIGH, titles(finds))
    check("signing NOT flagged when required", not any("signing not required" in t for t in titles(finds)))


def test_ldap_anonymous_bind():
    ad = AdIntel(smb_probe=lambda h: None,
                 ldap_probe=lambda h: {"reachable": True, "anonymous_bind": True,
                                       "naming_contexts": ["DC=corp,DC=local"]})
    prof, finds = ad.run("10.0.0.5")
    f = next((x for x in finds if "anonymous bind" in x.title), None)
    check("LDAP anon bind flagged", f is not None, titles(finds))
    check("LDAP anon is INFO_LEAK", f and f.vuln_class == VulnClass.INFO_LEAK)
    check("naming context surfaced", f and "DC=corp,DC=local" in f.detail.get("naming_contexts", []))


def test_hardened_host_clean():
    ad = AdIntel(smb_probe=lambda h: {"reachable": True, "dialect": "0x311",
                                      "signing_required": True, "smbv1": False},
                 ldap_probe=lambda h: {"reachable": True, "anonymous_bind": False,
                                       "naming_contexts": []})
    prof, finds = ad.run("10.0.0.5")
    check("hardened host -> no findings", finds == [], titles(finds))


def test_probe_failure_is_failsoft():
    def boom(h): raise OSError("refused")
    ad = AdIntel(smb_probe=boom, ldap_probe=boom)
    prof, finds = ad.run("10.0.0.5")
    check("probe error -> no crash, no findings", finds == [] and prof.smb is None)


def test_unreachable_no_findings():
    ad = AdIntel(smb_probe=lambda h: None, ldap_probe=lambda h: None)
    prof, finds = ad.run("10.0.0.5")
    check("no service -> no findings", finds == [])


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
