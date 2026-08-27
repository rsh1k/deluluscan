"""Dataclasses produced by the verification layer.

These are serialized into ``Finding.detail["verification"]`` (and mirrored onto
two new top-level ``Finding`` fields, ``verdict`` and ``exploitability``, for
easy sorting/reporting). Keeping them here avoids a circular import with the
scanners.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


# ---- verdict vocabulary -----------------------------------------------------
# How confident are we that the finding is a REAL issue (not a scanner artifact)?
VERDICTS = [
    "true_positive",         # corroborated by >=1 independent benign signal
    "likely_true_positive",  # reproduces, but full corroboration not possible
    "inconclusive",          # can't decide without a channel we don't have (e.g. OOB)
    "likely_false_positive", # a known FP confounder explains the signal
    "false_positive",        # confounder confirmed (e.g. signal present in baseline)
]

# Given the controls actually in place, can it be exploited?
EXPLOITABILITY = [
    "exploitable",       # reachable and no control neutralizes it
    "conditional",       # exploitable only under a stated precondition (weak CSP, WAF-dependent, victim interaction)
    "mitigated",         # a compensating control substantially blocks real-world impact
    "not_exploitable",   # a control fully neutralizes it as-is
    "unknown",           # needs a channel/step we did not perform
]


@dataclass
class ControlObservation:
    """One compensating/mitigating control we looked for."""
    name: str                     # csp | waf | nosniff | frame_options | hsts | cookie_flags | auth_required | cors | rate_limit
    present: bool
    strength: str = "n/a"         # none | weak | moderate | strong | n/a
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verification:
    verdict: str = "inconclusive"
    exploitability: str = "unknown"
    confidence_score: float = 0.0          # 0..1, calibrated
    reasons: list[str] = field(default_factory=list)          # why this verdict
    corroborations: list[str] = field(default_factory=list)   # independent signals that agreed
    confounders: list[str] = field(default_factory=list)      # FP sources checked (found or ruled out)
    controls: list[ControlObservation] = field(default_factory=list)
    repro: str = ""                        # SAFE manual reproduction step for a human
    probes: int = 0                        # how many corroboration requests we sent
    ai_analysis: str = ""                  # optional AI root-cause explanation

    def confidence_label(self) -> str:
        s = self.confidence_score
        if s >= 0.85:
            return "confirmed"
        if s >= 0.5:
            return "firm"
        return "tentative"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["controls"] = [c if isinstance(c, dict) else c.to_dict() for c in self.controls]
        return d
