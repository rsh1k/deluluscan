"""Deluluscan security knowledge base — the standing per-class methodology (Deluluscan's
"skills"), and its wiring into the finding report.

Locks down: every security VulnClass has methodology; the deep-verification
discipline is captured (a reflection is a lead, not proof); and build_report
inherits verify steps + class remediation + taxonomy from the knowledge base
when the finding itself carries none.

Run: python3 -m tests.test_knowledge
"""
from __future__ import annotations

import sys

from deluluscan import knowledge as kb
from deluluscan.models import Finding, Severity, VulnClass

_checks = 0
_failures: list[str] = []


def check(cond, label):
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


# Identity roles are not vulnerability classes; everything else must have methodology.
_IDENTITY_ROLES = {"anonymous", "frontend_user", "backend", "admin", "readonly",
                   "content_editor", "publisher", "api_user"}


def test_every_security_class_has_methodology():
    missing = []
    for vc in VulnClass:
        if vc.value in _IDENTITY_ROLES:
            continue
        if kb.methodology_for(vc) is None:
            missing.append(vc.value)
    check(not missing, f"every security VulnClass has methodology (missing: {missing})")


def test_lookup_accepts_enum_value_and_str():
    check(kb.methodology_for(VulnClass.XSS) is not None, "lookup by enum")
    check(kb.methodology_for("xss") is not None, "lookup by string value")
    check(kb.methodology_for("does_not_exist") is None, "unknown class -> None")


def test_entries_are_complete_and_mapped():
    bad = []
    for key, k in kb.METHODOLOGY.items():
        if not (k.summary and k.how_tested and k.verify and k.remediation and k.owasp_2025):
            bad.append(key)
    check(not bad, f"every entry has summary/how_tested/verify/remediation/owasp (bad: {bad})")
    check(all(o.startswith("A") and ":2025" in o for o in
              (k.owasp_2025 for k in kb.METHODOLOGY.values())),
          "every owasp mapping is a 2025 identifier")


def test_deep_verify_discipline_is_encoded():
    # The hard-won rules must live in the methodology, not just in code comments.
    xss = kb.methodology_for("xss")
    check(any("precondition" in v.lower() and "execute" in v.lower() for v in xss.verify),
          "XSS methodology states reflection/JSON is a precondition, not execution")
    authz = kb.methodology_for("authz")
    check(any("fresh" in v.lower() and ("rme" in v.lower() or "rotat" in v.lower()) for v in authz.verify),
          "authz methodology warns about rme rotation / fresh credentials per probe")
    check(any("measure" in v.lower() for v in authz.verify),
          "authz methodology says to MEASURE escalation, not assume it")


def test_build_report_inherits_from_knowledge():
    from deluluscan.reporting.evidence_report import build_report
    # a finding with NO remediation/references of its own
    f = Finding(vuln_class=VulnClass.SQLI, severity=Severity.HIGH,
                title="SQLi via orderby", endpoint="GET /api/categories",
                description="db error on quote", verdict="true_positive",
                exploitability="exploitable")
    rep = build_report(f)
    check(rep["remediation"] and "arameter" in rep["remediation"],
          "report remediation inherited from knowledge base (parameterized queries)")
    check(rep.get("verify_steps") and len(rep["verify_steps"]) >= 2,
          "report carries verification steps from the knowledge base")
    check(any("CWE-89" in r for r in rep["references"]),
          "report references include the class CWE from the knowledge base")
    check(any("A05:2025" in r for r in rep["references"]),
          "report references include the OWASP 2025 mapping")


def test_finding_own_remediation_wins_over_knowledge():
    from deluluscan.reporting.evidence_report import build_report
    f = Finding(vuln_class=VulnClass.SQLI, severity=Severity.HIGH, title="t",
                endpoint="e", description="d",
                detail={"remediation": "Custom fix specific to this finding."})
    rep = build_report(f)
    check(rep["remediation"] == "Custom fix specific to this finding.",
          "a finding's own remediation is not overwritten by the knowledge base")


def main():
    print("== deluluscan knowledge base ==")
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks}:")
        for f in _failures:
            print("  -", f)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0



def test_sca_discipline_is_encoded():
    """The lesson that cost the most to learn this engagement: a vulnerable
    version on the classpath is not a finding. graphql-java 17.5 was genuinely
    the affected version AND on the classpath, yet CVE-2024-40094 did not
    reproduce — anonymous introspection was blocked and authenticated
    amplification measured FLAT at ~590x from 5 to 300 aliases."""
    sc = kb.methodology_for("supply_chain")
    v = " ".join(sc.verify).lower()
    check(any("lead, not a finding" in x.lower() for x in sc.verify),
          "supply_chain says a vulnerable version is a LEAD, not a finding")
    check("classpath" in v and "manifest" in v,
          "supply_chain requires checking the running classpath, not just the manifest")
    check("compensating control" in v,
          "supply_chain requires looking for a compensating control")
    check("amplification" in v and "flat" in v,
          "supply_chain requires MEASURING amplification (flat ratio != DoS)")
    check("reachability" in v or "caller" in v,
          "supply_chain states presence without a caller is not reachability")


def test_owasp_2025_codes_are_named_from_the_2025_list():
    """A ':2025' code must never be labelled with its 2021 meaning.

    The regression: two renderers each kept a private OWASP_NAME table and both
    held the 2021 list, so a finding classified A02:2025 (Security
    Misconfiguration) printed as "Cryptographic Failures" — the 2021 meaning of
    that code. A wrong category is a factual error about the finding, so the
    names live in one place and every code the methodology uses must have one.
    """
    used = {m.owasp_2025 for m in kb.METHODOLOGY.values() if m.owasp_2025}
    missing = sorted(used - set(kb.OWASP_2025_NAME))
    check(not missing, f"every OWASP 2025 code used by METHODOLOGY has a name (missing: {missing})")

    # The specific pairs the 2021 table got wrong.
    check(kb.OWASP_2025_NAME["A02:2025"] == "Security Misconfiguration",
          "A02:2025 is Security Misconfiguration, not the 2021 'Cryptographic Failures'")
    check(kb.OWASP_2025_NAME["A05:2025"] == "Injection",
          "A05:2025 is Injection, not the 2021 'Security Misconfiguration'")
    check(kb.OWASP_2025_NAME["A03:2025"] == "Software Supply Chain Failures",
          "A03:2025 is Software Supply Chain Failures, not the 2021 'Injection'")

    check(kb.owasp_2025_label("A05:2025") == "A05:2025 Injection",
          "owasp_2025_label pairs the code with its 2025 name")
    check(kb.owasp_2025_label("") == "", "an empty code yields an empty label")
    check(kb.owasp_2025_label("A99:2025") == "A99:2025",
          "an unknown code returns the bare code rather than a guessed name")

    # The classes reported in the target engagement, spot-checked end to end.
    for vuln_class, expected in [("rate_limit", "A02:2025 Security Misconfiguration"),
                                 ("log_injection", "A05:2025 Injection"),
                                 ("idor", "A01:2025 Broken Access Control"),
                                 ("error_handling", "A10:2025 Mishandling of Exceptional Conditions")]:
        m = kb.methodology_for(vuln_class)
        check(kb.owasp_2025_label(m.owasp_2025) == expected,
              f"{vuln_class} labels as {expected}")


if __name__ == "__main__":
    sys.exit(main())
