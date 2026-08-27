"""deluluscan.cvss — CVSS v3.1 base-score computation.

Deluluscan grades findings with `severity` / `exploitability` / `confidence`, which
describe what THIS scan observed. A pentest report also has to hand the reader a
portable, industry-standard number, and that number has to be reproducible: a
vector string anyone can paste into the FIRST calculator and get the same score.

This module implements the CVSS v3.1 Base Score exactly as specified in the
CVSS v3.1 Specification Document, section 8.1 (Base equations) and Appendix A
(the Roundup function). Only the Base metric group is implemented: Temporal and
Environmental metrics describe a specific deployment over time, and asserting
them from a single scan would be inventing evidence.

v3.1 rather than v4.0 on purpose: the v3.1 base formula is closed-form and can
be unit-tested against published reference vectors (see tests/test_cvss.py),
whereas v4.0 scoring is a MacroVector table lookup whose correctness we could
not independently verify here. The report states the version it used.

Usage:
    >>> score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    (10.0, 'critical')
"""
from __future__ import annotations

import math
from dataclasses import dataclass

# Metric weights — CVSS v3.1 spec, Table 14-18.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
# Privileges Required is scope-dependent.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_ALLOWED = {
    "AV": set(_AV), "AC": set(_AC), "PR": {"N", "L", "H"},
    "UI": set(_UI), "S": {"U", "C"},
    "C": set(_CIA), "I": set(_CIA), "A": set(_CIA),
}


class CvssError(ValueError):
    """Raised for a malformed or incomplete CVSS v3.1 base vector."""


@dataclass(frozen=True)
class Cvss31:
    """A parsed CVSS v3.1 base vector plus its computed score."""

    vector: str
    metrics: dict[str, str]
    base_score: float
    severity: str

    @property
    def scope_changed(self) -> bool:
        return self.metrics["S"] == "C"


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a 'CVSS:3.1/AV:N/...' base vector into {metric: value}.

    Raises CvssError if the prefix is wrong, a metric is unknown/duplicated,
    a value is invalid, or any of the eight base metrics is missing.
    """
    if not isinstance(vector, str) or not vector.strip():
        raise CvssError("empty CVSS vector")
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise CvssError(f"vector must start with 'CVSS:3.1', got {parts[0]!r}")

    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if part.count(":") != 1:
            raise CvssError(f"malformed metric segment {part!r}")
        key, _, value = part.partition(":")
        if key not in _ALLOWED:
            raise CvssError(f"unknown base metric {key!r}")
        if key in metrics:
            raise CvssError(f"duplicate metric {key!r}")
        if value not in _ALLOWED[key]:
            raise CvssError(f"invalid value {value!r} for metric {key!r}")
        metrics[key] = value

    missing = [m for m in _ORDER if m not in metrics]
    if missing:
        raise CvssError(f"missing base metric(s): {', '.join(missing)}")
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A Roundup — round UP to one decimal place.

    Implemented on scaled integers exactly as the spec prescribes, because
    naive float ceil() misrounds values that are only float-approximately
    at a boundary (the reason the spec replaced v3.0's math.ceil approach).
    """
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def severity_of(base_score: float) -> str:
    """CVSS v3.1 qualitative severity rating scale (spec section 5)."""
    if base_score == 0.0:
        return "none"
    if base_score < 4.0:
        return "low"
    if base_score < 7.0:
        return "medium"
    if base_score < 9.0:
        return "high"
    return "critical"


def evaluate(vector: str) -> Cvss31:
    """Parse and score a CVSS v3.1 base vector."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    iss = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]

    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base = _roundup(min(impact + exploitability, 10))

    return Cvss31(vector=vector.strip(), metrics=m,
                  base_score=base, severity=severity_of(base))


def score(vector: str) -> tuple[float, str]:
    """Convenience: (base_score, qualitative_severity) for a v3.1 base vector."""
    result = evaluate(vector)
    return result.base_score, result.severity


# ---------------------------------------------------------------------------
# Deriving a vector for a Deluluscan finding
# ---------------------------------------------------------------------------
# A CVSS vector in a pentest report has to be defensible metric by metric. We
# split it honestly:
#   * AV / PR are DERIVED FROM EVIDENCE — which identities actually reproduced
#     the finding is an observed fact, so the lowest privilege that worked sets
#     PR, and an HTTP API sets AV:N.
#   * C / I / A are ANALYST JUDGEMENT — they require deciding what the disclosed
#     or altered data is worth, which no scanner can observe. They must be passed
#     in explicitly, together with the reasoning that justified them.
# Every metric carries a rationale string so the report can show its working
# rather than asserting a number.

_ANON_IDENTITIES = {"anonymous", "anon", "unauthenticated", ""}
_ADMIN_IDENTITIES = {"admin", "administrator"}


def privileges_required(reproduced_by: list[str] | set[str]) -> tuple[str, str]:
    """PR metric derived from the identities that actually reproduced a finding.

    Returns (value, rationale). The LOWEST privilege that reproduced the issue
    decides the metric — an issue an anonymous caller can trigger is PR:N even
    if admin can trigger it too.
    """
    ids = {str(i).strip().lower() for i in (reproduced_by or [])}
    if not ids:
        return "H", ("no identity was observed reproducing this finding; "
                     "assuming the most restrictive PR:H rather than overstating")
    if ids & _ANON_IDENTITIES:
        return "N", "reproduced by an unauthenticated caller"
    if ids <= _ADMIN_IDENTITIES:
        return "H", ("only reproduced by the administrator identity, which already "
                     "holds the privilege in question")
    low = sorted(ids - _ADMIN_IDENTITIES)
    return "L", (f"reproduced by non-administrative authenticated identit"
                 f"{'y' if len(low) == 1 else 'ies'}: {', '.join(low)}")


def derive(*, reproduced_by: list[str] | set[str],
           confidentiality: str, integrity: str, availability: str,
           impact_rationale: str,
           attack_complexity: str = "L", user_interaction: str = "N",
           scope: str = "U",
           complexity_rationale: str = "single unauthenticated HTTP request, "
                                       "no race or precondition",
           ) -> dict[str, object]:
    """Build a scored, fully-rationalised CVSS v3.1 base vector for a finding.

    `confidentiality` / `integrity` / `availability` are the analyst's call and
    must be accompanied by `impact_rationale` explaining the evidence behind
    them. Raises CvssError if any metric value is invalid.
    """
    for name, value in (("C", confidentiality), ("I", integrity), ("A", availability)):
        if value not in _CIA:
            raise CvssError(f"invalid {name} impact {value!r}")
    if attack_complexity not in _AC:
        raise CvssError(f"invalid AC {attack_complexity!r}")
    if user_interaction not in _UI:
        raise CvssError(f"invalid UI {user_interaction!r}")
    if scope not in {"U", "C"}:
        raise CvssError(f"invalid S {scope!r}")

    pr, pr_why = privileges_required(reproduced_by)
    vector = (f"CVSS:3.1/AV:N/AC:{attack_complexity}/PR:{pr}/UI:{user_interaction}"
              f"/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}")
    result = evaluate(vector)
    return {
        "version": "3.1",
        "vector": result.vector,
        "base_score": result.base_score,
        "severity": result.severity,
        "metric_rationale": {
            "AV:N": "the affected surface is a remotely reachable HTTP API",
            f"AC:{attack_complexity}": complexity_rationale,
            f"PR:{pr}": pr_why,
            f"UI:{user_interaction}": ("no victim interaction is required"
                                       if user_interaction == "N"
                                       else "requires a victim to act"),
            f"S:{scope}": ("impact is confined to the vulnerable component"
                           if scope == "U"
                           else "impact reaches resources beyond the vulnerable component"),
            f"C:{confidentiality}/I:{integrity}/A:{availability}": impact_rationale,
        },
        "scored_by": "deluluscan.cvss (CVSS v3.1 Base, FIRST specification)",
    }
