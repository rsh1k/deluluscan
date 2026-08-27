"""tests.test_compliance — audit-framework control mapping.

The risk this suite guards against is a mapping that looks authoritative and is
wrong: a plausible control ID beside a finding is harder to catch than a missing
one, because a reader assumes someone checked. So the tests assert the mapping
is COMPLETE (every class decided, one way or the other), CONSISTENT (same class,
same controls), and JUSTIFIED (every control carries a basis).

Run: python3 -m tests.test_compliance
"""
from __future__ import annotations

import sys

from deluluscan import compliance as cm
from deluluscan import knowledge as kb
from deluluscan.models import VulnClass


def known_classes() -> set[str]:
    """The real universe of vulnerability classes in this codebase.

    Deliberately the UNION of the VulnClass enum and the knowledge base's keys.
    They are not the same set: 'injection' is an umbrella class (command / LDAP /
    path / XXE) that exists in deluluscan.knowledge, in the scanner list and in the
    dashboard's OWASP table, but has no VulnClass member. Validating against the
    enum alone would reject a legitimate mapping.
    """
    return {v.value for v in VulnClass} | set(kb.METHODOLOGY)

_checks = 0
_failures: list[str] = []


def check(cond: bool, label: str) -> None:
    global _checks
    _checks += 1
    if cond:
        print(f"PASS  {label}")
    else:
        _failures.append(label)
        print(f"FAIL  {label}")


def test_every_class_is_decided():
    """No class may be silently unmapped — map it, or record why not."""
    check(set(kb.METHODOLOGY) - {v.value for v in VulnClass} == {"injection"},
          "the enum/knowledge-base divergence is exactly the known 'injection' umbrella class")
    known = known_classes()
    decided = set(cm.MAPPINGS) | set(cm.UNMAPPED)
    undecided = sorted(known - decided)
    check(not undecided,
          f"every VulnClass is either mapped or explicitly unmapped (undecided: {undecided})")

    unknown = sorted(decided - known)
    check(not unknown,
          f"no mapping references a class that does not exist (stale: {unknown})")


def test_every_control_is_justified():
    """A control with no stated basis is an assertion the reader cannot check."""
    for key, controls in cm.MAPPINGS.items():
        for c in controls:
            check(bool(c.basis and len(c.basis) > 20),
                  f"{key}/{c.control_id} states why the control is implicated")
            check(bool(c.title), f"{key}/{c.control_id} has a control title")
            check(c.framework in cm.frameworks(),
                  f"{key}/{c.control_id} names a known framework")


def test_unmapped_entries_give_a_reason():
    for key, reason in cm.UNMAPPED.items():
        check(len(reason) > 20, f"unmapped class '{key}' records a substantive reason")


def test_no_duplicate_control_within_a_class():
    """The same control listed twice for one class inflates a compliance table."""
    for key, controls in cm.MAPPINGS.items():
        seen = [(c.framework, c.control_id) for c in controls]
        check(len(seen) == len(set(seen)), f"{key} lists no duplicate control")


def test_lookup_accepts_enum_and_string():
    by_enum = cm.controls_for(VulnClass.SQLI)
    by_str = cm.controls_for("sqli")
    check(by_enum == by_str, "controls_for accepts a VulnClass and its string value alike")
    check(len(by_enum) >= 2, "sqli maps to multiple frameworks")


def test_unknown_class_returns_nothing_rather_than_guessing():
    check(cm.controls_for("not_a_real_class") == [],
          "an unknown class maps to nothing rather than a guess")
    block = cm.mapping_for_report("not_a_real_class")
    check(block["frameworks"] == {}, "report block for an unknown class is empty")
    check("unmapped_reason" in block,
          "an empty mapping states that nothing is asserted, rather than being blank")


def test_report_block_shape():
    block = cm.mapping_for_report("rate_limit")
    check("frameworks" in block and block["frameworks"], "rate_limit produces a report block")
    for fw, entries in block["frameworks"].items():
        for e in entries:
            check({"id", "title", "basis"} <= set(e),
                  f"{fw} entry carries id, title and basis")
    check("unmapped_reason" not in block,
          "a class that maps does not also carry an unmapped reason")


def test_grouping_matches_flat_list():
    flat = cm.controls_for("authz")
    grouped = cm.controls_by_framework("authz")
    check(sum(len(v) for v in grouped.values()) == len(flat),
          "grouping by framework loses no controls")


def test_coverage_summary_dedupes_across_classes():
    """Two classes citing one control must not double-count it."""
    summary = cm.coverage_summary(["sqli", "xss", "ssti"])
    pci = summary.get(cm.PCI, [])
    check(pci.count("6.2.4") == 1,
          "a control implicated by several classes appears once in the summary")
    check(pci == sorted(pci), "coverage summary is sorted for stable report output")


def test_findings_from_this_engagement_map_sensibly():
    """The classes actually reported against the target resolve to real controls."""
    expected = {
        "rate_limit": ("8.3.4", "authentication attempt limiting"),
        "log_injection": ("10.2.1", "audit log integrity"),
        "info_leak": ("3.3.1", "unnecessary data exposure"),
        "idor": ("7.2.1", "access control model"),
        "bopla": ("7.3.1", "least privilege"),
    }
    for vc, (pci_id, why) in expected.items():
        ids = [c.control_id for c in cm.controls_for(vc) if c.framework == cm.PCI]
        check(pci_id in ids, f"{vc} maps to PCI {pci_id} ({why})")


def test_describe_is_renderable():
    text = cm.describe()
    check("Deluluscan compliance mapping" in text, "describe() renders a header")
    check(cm.PCI in text and cm.SOC2 in text and cm.ISO in text,
          "describe() names all three frameworks")
    check("No mapping and no recorded reason" not in text,
          "describe() reports no undecided classes")


def main() -> int:
    print("== compliance mapping ==")
    test_every_class_is_decided()
    test_every_control_is_justified()
    test_unmapped_entries_give_a_reason()
    test_no_duplicate_control_within_a_class()
    test_lookup_accepts_enum_and_string()
    test_unknown_class_returns_nothing_rather_than_guessing()
    test_report_block_shape()
    test_grouping_matches_flat_list()
    test_coverage_summary_dedupes_across_classes()
    test_findings_from_this_engagement_map_sensibly()
    test_describe_is_renderable()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks} checks:")
        for f in _failures:
            print("  -", f)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
