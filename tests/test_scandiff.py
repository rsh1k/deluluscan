"""tests.test_scandiff — cross-scan finding comparison.

Two failure modes this guards against, both of which make a diff worse than
useless because they look plausible:

1. **Everything reads as NEW.** Finding ids are minted per scan, and titles
   carry per-run randomness (canary markers, generated ids, "×N endpoints").
   If any of that reaches the fingerprint, every scan reports a full slate of
   new findings and the diff gets ignored.
2. **FIXED is trusted when coverage shrank.** "No longer present" and "no longer
   tested" are indistinguishable from the finding list alone, and closing a
   ticket on the second is how a real issue gets lost.

Run: python3 -m tests.test_scandiff
"""
from __future__ import annotations

import copy
import sys

from deluluscan import scandiff as sd

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


def f(fid, title, cls="sqli", endpoint="GET /api/v1/x", severity="medium",
      verdict="true_positive", exploitability="exploitable", detail=None):
    return {"id": fid, "title": title, "vuln_class": cls, "endpoint": endpoint,
            "severity": severity, "verdict": verdict,
            "exploitability": exploitability, "confidence": "firm",
            "description": "", "detail": detail or {}}


def payload(findings, *, probed=100, discovered=100, target="http://t", date="d"):
    return {"target": target, "date": date,
            "meta": {"coverage": {"endpoints_probed": probed,
                                  "endpoints_discovered": discovered}},
            "findings": findings}


def test_identical_scans_are_all_unchanged():
    p = payload([f("a", "One"), f("b", "Two", cls="xss")])
    r = sd.diff(p, copy.deepcopy(p))
    check(r["summary"] == {"new": 0, "fixed": 0, "unchanged": 2, "changed": 0},
          "an identical re-scan reports everything unchanged")


def test_random_ids_do_not_make_findings_look_new():
    """The core regression: ids are per-scan and must not enter the fingerprint."""
    base = payload([f("aaaaaaaaaa", "One")])
    cur = payload([f("zzzzzzzzzz", "One")])
    r = sd.diff(base, cur)
    check(r["summary"]["new"] == 0 and r["summary"]["unchanged"] == 1,
          "a changed finding id alone does not make a finding NEW")


def test_per_run_markers_are_normalised_out():
    """Canary markers, uuids and counts vary every run by design."""
    pairs = [
        ("Stored XSS via marker deluluscan9mv9clz8", "Stored XSS via marker deluluscanvk7dygyr"),
        ("Verbose error (×3 endpoints)", "Verbose error (×14 endpoints)"),
        ("Leak at 550e8400-e29b-41d4-a716-446655440000",
         "Leak at 6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
        ("Log injection marker abc123def456", "Log injection marker 987654321fed"),
    ]
    for a, b in pairs:
        check(sd.normalise_title(a) == sd.normalise_title(b),
              f"per-run noise normalised: {a[:40]!r} == {b[:40]!r}")
    r = sd.diff(payload([f("a", pairs[0][0])]), payload([f("b", pairs[0][1])]))
    check(r["summary"]["unchanged"] == 1,
          "a finding whose title differs only by a canary marker is unchanged")


def test_genuinely_different_findings_do_not_collide():
    r = sd.diff(payload([f("a", "Hidden reflected parameter: 'page'")]),
                payload([f("b", "Hidden reflected parameter: 'limit'")]))
    check(r["summary"]["new"] == 1 and r["summary"]["fixed"] == 1,
          "different parameters are different findings, not one unchanged finding")


def test_same_endpoint_different_class_is_distinct():
    ep = "POST /api/v1/graphql"
    p = payload([f("a", "Introspection", cls="graphql", endpoint=ep),
                 f("b", "Batching", cls="graphql", endpoint=ep)])
    r = sd.diff(p, copy.deepcopy(p))
    check(r["summary"]["unchanged"] == 2,
          "two findings on one endpoint stay distinct across scans")


def test_detail_discriminators_separate_same_titled_findings():
    a = f("a", "Log injection", detail={"slot": "param:page"})
    b = f("b", "Log injection", detail={"slot": "param:limit"})
    check(sd.fingerprint(a) != sd.fingerprint(b),
          "detail discriminators separate findings that share a title")


def test_new_and_fixed_detected():
    base = payload([f("a", "Stays"), f("b", "Goes", cls="xss")])
    cur = payload([f("c", "Stays"), f("d", "Arrives", cls="idor")])
    r = sd.diff(base, cur)
    check(r["summary"] == {"new": 1, "fixed": 1, "unchanged": 1, "changed": 0},
          "new, fixed and unchanged are each classified")
    check(r["new"][0]["title"] == "Arrives", "the new finding is named")
    check(r["fixed"][0]["title"] == "Goes", "the fixed finding is named")


def test_severity_and_verdict_movement_is_changed_not_new():
    base = payload([f("a", "One", severity="medium")])
    cur = payload([f("a", "One", severity="critical")])
    r = sd.diff(base, cur)
    check(r["summary"]["changed"] == 1, "a severity move is CHANGED")
    check(r["changed"][0]["changes"]["severity"] == {"from": "medium", "to": "critical"},
          "the movement records both endpoints of the change")


def test_disposition_move_is_a_change():
    """Reported -> observation matters even when severity is identical."""
    base = payload([f("a", "One")])
    cur = payload([f("a", "One", detail={"observation": True})])
    r = sd.diff(base, cur)
    check(r["summary"]["changed"] == 1, "a reported finding becoming an observation is a change")
    check("disposition" in r["changed"][0]["changes"],
          "the disposition move is named explicitly")


def test_cvss_movement_detected():
    base = payload([f("a", "One", detail={"report": {"cvss": {"base_score": 4.3}}})])
    cur = payload([f("a", "One", detail={"report": {"cvss": {"base_score": 7.5}}})])
    r = sd.diff(base, cur)
    check(r["changed"][0]["changes"].get("cvss_score") == {"from": 4.3, "to": 7.5},
          "a CVSS score movement is reported")


def test_reduced_coverage_flags_fixed_as_unverified():
    base = payload([f("a", "One")], probed=745)
    cur = payload([], probed=500)
    r = sd.diff(base, cur)
    check(r["summary"]["fixed"] == 1, "the finding is absent from the current scan")
    check(r["coverage"]["fixed_verified"] is False,
          "FIXED is flagged unverified when the current scan probed less")
    check("not tested" in r["coverage"]["note"],
          "the warning says absence may mean 'not tested'")


def test_equal_coverage_trusts_fixed():
    r = sd.diff(payload([f("a", "One")], probed=745), payload([], probed=745))
    check(r["coverage"]["fixed_verified"] is True,
          "equal coverage means FIXED is not explained by reduced scope")


def test_missing_coverage_metadata_does_not_crash():
    r = sd.diff({"findings": [f("a", "One")]}, {"findings": []})
    check(r["summary"]["fixed"] == 1, "a payload without coverage metadata still diffs")
    check(r["coverage"]["fixed_verified"] is True,
          "unknown coverage does not raise a false warning")


def test_retest_targets_are_new_and_changed_only():
    base = payload([f("a", "Stays"), f("b", "Moves", severity="low")])
    cur = payload([f("a", "Stays"), f("b", "Moves", severity="high"),
                   f("c", "Arrives", cls="idor", endpoint="GET /api/v1/y")])
    targets = sd.retest_targets(sd.diff(base, cur))
    titles = {t["title"] for t in targets}
    check("Arrives" in titles and "Moves" in titles, "new and changed findings are retest targets")
    check("Stays" not in titles, "an unchanged finding is not re-tested")


def test_retest_targets_dedupe_per_endpoint():
    cur = payload([f("a", "One", endpoint="GET /api/v1/z"),
                   f("b", "Two", endpoint="GET /api/v1/z")])
    targets = sd.retest_targets(sd.diff(payload([]), cur))
    check(len(targets) == 1, "one endpoint is probed once even with several findings")


def test_render_is_readable_and_warns():
    text = sd.render(sd.diff(payload([f("a", "One")], probed=745),
                             payload([], probed=100)))
    check("Scan diff" in text, "render produces a header")
    check("COVERAGE WARNING" in text, "render surfaces the coverage warning prominently")
    check("FIXED" in text, "render names the fixed bucket")


def test_endpoint_ids_normalised():
    a = f("a", "Leak", endpoint="GET /api/v1/user/550e8400-e29b-41d4-a716-446655440000")
    b = f("b", "Leak", endpoint="GET /api/v1/user/6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    check(sd.fingerprint(a) == sd.fingerprint(b),
          "concrete ids in an endpoint normalise to the same template")


def main() -> int:
    print("== scan diff ==")
    for fn in (test_identical_scans_are_all_unchanged,
               test_random_ids_do_not_make_findings_look_new,
               test_per_run_markers_are_normalised_out,
               test_genuinely_different_findings_do_not_collide,
               test_same_endpoint_different_class_is_distinct,
               test_detail_discriminators_separate_same_titled_findings,
               test_new_and_fixed_detected,
               test_severity_and_verdict_movement_is_changed_not_new,
               test_disposition_move_is_a_change,
               test_cvss_movement_detected,
               test_reduced_coverage_flags_fixed_as_unverified,
               test_equal_coverage_trusts_fixed,
               test_missing_coverage_metadata_does_not_crash,
               test_retest_targets_are_new_and_changed_only,
               test_retest_targets_dedupe_per_endpoint,
               test_render_is_readable_and_warns,
               test_endpoint_ids_normalised):
        fn()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks} checks:")
        for x in _failures:
            print("  -", x)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
