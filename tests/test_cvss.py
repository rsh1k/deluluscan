"""tests.test_cvss — CVSS v3.1 base scoring.

The reference vectors below are published CVSS v3.1 base scores (NVD / FIRST
calculator output for well-known CVEs plus the spec's own examples). They are
the whole point of this suite: a scoring bug that silently shifts every finding
by a few tenths would be invisible without an external oracle to check against.

Run: python3 -m tests.test_cvss
"""
from __future__ import annotations

import unittest

from deluluscan.cvss import (Cvss31, CvssError, derive, evaluate, parse_vector,
                        privileges_required, score, severity_of)


class TestReferenceVectors(unittest.TestCase):
    """Score published vectors and compare against their published values."""

    # (vector, expected_base_score, expected_severity)
    CASES = [
        # Maximum severity — every metric at worst.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
        # Scope-changed maximum (e.g. Log4Shell CVE-2021-44228).
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
        # Spring4Shell CVE-2022-22965.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
        # Unauthenticated info disclosure, confidentiality-only, low impact.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"),
        # Authenticated (low priv) confidentiality-only, low impact.
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, "medium"),
        # Authenticated low-priv, low confidentiality, scope unchanged, DoS-free.
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.7, "low"),
        # Availability-only, unauthenticated, low.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3, "medium"),
        # Local, high complexity, requires UI — classic low.
        ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.2, "low"),
        # No impact at all must score exactly zero.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"),
        # Physical access, high complexity, high privs — minimum non-zero.
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "low"),
    ]

    def test_reference_scores(self):
        for vector, expected_score, expected_sev in self.CASES:
            with self.subTest(vector=vector):
                result = evaluate(vector)
                self.assertAlmostEqual(
                    result.base_score, expected_score, places=1,
                    msg=f"{vector} scored {result.base_score}, expected {expected_score}")
                self.assertEqual(result.severity, expected_sev)

    def test_score_helper_matches_evaluate(self):
        for vector, expected_score, expected_sev in self.CASES:
            self.assertEqual(score(vector), (expected_score, expected_sev))


class TestScopeAffectsPrivilegeWeight(unittest.TestCase):
    """Scope:Changed must use the heavier PR weights, not the unchanged ones."""

    def test_changed_scope_scores_higher_for_same_impact(self):
        unchanged = evaluate("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        changed = evaluate("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
        self.assertGreater(changed.base_score, unchanged.base_score)
        self.assertTrue(changed.scope_changed)
        self.assertFalse(unchanged.scope_changed)


class TestRoundup(unittest.TestCase):
    """v3.1 rounds UP to one decimal; the spec's integer method avoids float drift."""

    def test_never_rounds_down(self):
        # Every reference score must be >= the unrounded arithmetic value.
        for vector, expected, _ in TestReferenceVectors.CASES:
            self.assertEqual(evaluate(vector).base_score, expected)

    def test_scores_have_one_decimal_place(self):
        for vector, _, _ in TestReferenceVectors.CASES:
            value = evaluate(vector).base_score
            self.assertAlmostEqual(value, round(value, 1), places=10)

    def test_scores_within_range(self):
        for vector, _, _ in TestReferenceVectors.CASES:
            value = evaluate(vector).base_score
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 10.0)


class TestSeverityBands(unittest.TestCase):
    """Boundary values land in the band the v3.1 rating scale prescribes."""

    def test_boundaries(self):
        self.assertEqual(severity_of(0.0), "none")
        self.assertEqual(severity_of(0.1), "low")
        self.assertEqual(severity_of(3.9), "low")
        self.assertEqual(severity_of(4.0), "medium")
        self.assertEqual(severity_of(6.9), "medium")
        self.assertEqual(severity_of(7.0), "high")
        self.assertEqual(severity_of(8.9), "high")
        self.assertEqual(severity_of(9.0), "critical")
        self.assertEqual(severity_of(10.0), "critical")


class TestVectorParsing(unittest.TestCase):
    """A malformed vector must fail loudly — never score as if it were valid."""

    def test_parses_all_eight_metrics(self):
        m = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(m, {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                             "S": "U", "C": "H", "I": "H", "A": "H"})

    def test_rejects_wrong_version_prefix(self):
        with self.assertRaises(CvssError):
            parse_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_rejects_missing_metric(self):
        with self.assertRaises(CvssError):
            parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")

    def test_rejects_invalid_value(self):
        with self.assertRaises(CvssError):
            parse_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_rejects_unknown_metric(self):
        with self.assertRaises(CvssError):
            parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F")

    def test_rejects_duplicate_metric(self):
        with self.assertRaises(CvssError):
            parse_vector("CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_rejects_empty(self):
        for bad in ("", "   ", None):
            with self.assertRaises(CvssError):
                parse_vector(bad)  # type: ignore[arg-type]

    def test_rejects_malformed_segment(self):
        with self.assertRaises(CvssError):
            parse_vector("CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


class TestResultShape(unittest.TestCase):
    def test_returns_frozen_dataclass_with_vector(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        result = evaluate(vector)
        self.assertIsInstance(result, Cvss31)
        self.assertEqual(result.vector, vector)
        with self.assertRaises(Exception):
            result.base_score = 1.0  # type: ignore[misc]


class TestPrivilegesRequiredDerivation(unittest.TestCase):
    """PR must come from the identities that actually reproduced the finding."""

    def test_anonymous_repro_is_pr_none(self):
        value, why = privileges_required(["anonymous"])
        self.assertEqual(value, "N")
        self.assertIn("unauthenticated", why)

    def test_anonymous_wins_even_when_admin_also_reproduced(self):
        # The LOWEST privilege that worked decides the metric.
        value, _ = privileges_required(["admin", "backend", "anonymous"])
        self.assertEqual(value, "N")

    def test_low_privilege_authenticated_is_pr_low(self):
        value, why = privileges_required(["backend", "readonly"])
        self.assertEqual(value, "L")
        self.assertIn("backend", why)

    def test_admin_only_is_pr_high(self):
        value, why = privileges_required(["admin"])
        self.assertEqual(value, "H")
        self.assertIn("already holds", why)

    def test_no_identity_defaults_to_most_restrictive(self):
        # Never overstate severity when nothing was observed.
        value, why = privileges_required([])
        self.assertEqual(value, "H")
        self.assertIn("rather than overstating", why)


class TestDeriveVector(unittest.TestCase):
    def test_derives_scored_vector_with_rationale_for_every_metric(self):
        out = derive(reproduced_by=["anonymous"], confidentiality="L",
                     integrity="N", availability="N",
                     impact_rationale="full API specification disclosed")
        self.assertEqual(out["vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        self.assertEqual(out["base_score"], 5.3)
        self.assertEqual(out["severity"], "medium")
        self.assertEqual(out["version"], "3.1")
        # Every metric in the vector must carry a stated justification.
        rationale_keys = " ".join(out["metric_rationale"].keys())
        for metric in ("AV:N", "AC:L", "PR:N", "UI:N", "S:U", "C:L"):
            self.assertIn(metric, rationale_keys)

    def test_privilege_lowers_score_for_authenticated_only_finding(self):
        anon = derive(reproduced_by=["anonymous"], confidentiality="L",
                      integrity="N", availability="N", impact_rationale="x")
        authed = derive(reproduced_by=["backend"], confidentiality="L",
                        integrity="N", availability="N", impact_rationale="x")
        self.assertGreater(anon["base_score"], authed["base_score"])

    def test_rejects_invalid_impact_values(self):
        for bad in ({"confidentiality": "X"}, {"integrity": "Z"}, {"availability": "Q"}):
            kwargs = {"confidentiality": "N", "integrity": "N",
                      "availability": "N", "impact_rationale": "x"}
            kwargs.update(bad)
            with self.assertRaises(CvssError):
                derive(reproduced_by=["anonymous"], **kwargs)

    def test_rejects_invalid_ac_ui_scope(self):
        base = dict(reproduced_by=["anonymous"], confidentiality="N",
                    integrity="N", availability="N", impact_rationale="x")
        with self.assertRaises(CvssError):
            derive(**base, attack_complexity="X")
        with self.assertRaises(CvssError):
            derive(**base, user_interaction="X")
        with self.assertRaises(CvssError):
            derive(**base, scope="X")

    def test_zero_impact_scores_zero(self):
        out = derive(reproduced_by=["anonymous"], confidentiality="N",
                     integrity="N", availability="N",
                     impact_rationale="nothing of value was disclosed")
        self.assertEqual(out["base_score"], 0.0)
        self.assertEqual(out["severity"], "none")


if __name__ == "__main__":
    unittest.main(verbosity=2)
