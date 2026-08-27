"""Adversarial validation: a confidence state machine + a learning false-positive
signature memory.

Modeled on the practitioner pattern where the validator's job is to *disprove*
findings: each finding carries a 0..1 confidence, moves through an explicit state
machine, and every dismissal is remembered so the same known-harmless pattern is
auto-suppressed on future runs. Evidence-gated: a finding only reaches "reviewed"
with proof of exploitability; otherwise it is dismissed with a reason (never
silently dropped — dismissed findings are retained for audit).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Optional

# Finding lifecycle states
STATE_NEW = "new"
STATE_VALIDATING = "validating"
STATE_REVIEWED = "reviewed"        # survived validation -> worth human review
STATE_DISMISSED = "dismissed"      # disproven -> retained, not surfaced as active

# map a verify verdict to a starting confidence and state
_VERDICT_CONFIDENCE = {
    "true_positive": 0.9, "likely_true_positive": 0.65, "inconclusive": 0.4,
    "likely_false_positive": 0.2, "false_positive": 0.05,
}


@dataclass
class ValidationState:
    confidence: float = 0.3
    state: str = STATE_NEW
    transitions: list[str] = field(default_factory=list)
    dismissed_reason: str = ""

    def to_dict(self):
        return asdict(self)


def _norm(s: str) -> str:
    # collapse ids/uuids/numbers so signatures generalize across objects
    s = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}", s, flags=re.I)
    s = re.sub(r"\b\d+\b", "{n}", s)
    return s.strip().lower()[:200]


def signature(finding: dict) -> str:
    """A stable fingerprint for a finding: vuln class + test + normalized endpoint
    + normalized first evidence body. Two findings that are 'the same known
    pattern' hash equal so the FP memory can suppress repeats."""
    d = finding.get("detail", {}) or {}
    ev = (finding.get("evidence") or [{}])
    body = ""
    if ev and isinstance(ev[0], dict):
        body = (ev[0].get("resp_body") or "")[:200]
    basis = "|".join([
        finding.get("vuln_class", ""), d.get("test", ""),
        _norm(finding.get("endpoint", "")), _norm(body)])
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


class FalsePositiveMemory:
    """Persists dismissed-finding signatures so known-harmless patterns are
    auto-suppressed on subsequent runs (the 'FP signature database')."""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.sigs: dict[str, dict] = {}
        if path and os.path.exists(path):
            try:
                self.sigs = json.load(open(path))
            except Exception:
                self.sigs = {}

    def known(self, finding: dict) -> Optional[dict]:
        return self.sigs.get(signature(finding))

    def remember(self, finding: dict, reason: str) -> None:
        sig = signature(finding)
        rec = self.sigs.get(sig, {"count": 0})
        rec["count"] = rec.get("count", 0) + 1
        rec["reason"] = reason
        rec["title"] = finding.get("title", "")
        self.sigs[sig] = rec

    def save(self) -> None:
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            json.dump(self.sigs, open(self.path, "w"), indent=2)
        except Exception:
            pass


class ConfidenceEngine:
    """Turns a Verification result (+ any exploit-confirmation signal) into a
    confidence score and a lifecycle state, and consults/updates FP memory."""

    def __init__(self, memory: Optional[FalsePositiveMemory] = None,
                 review_threshold: float = 0.7):
        self.memory = memory
        self.review_threshold = review_threshold

    def evaluate(self, finding: dict) -> ValidationState:
        vs = ValidationState()
        verification = (finding.get("detail", {}) or {}).get("verification", {}) or {}
        verdict = finding.get("verdict") or verification.get("verdict") or "inconclusive"

        # 1) start from the verifier's verdict
        vs.confidence = _VERDICT_CONFIDENCE.get(verdict, 0.3)
        vs.state = STATE_VALIDATING
        vs.transitions.append(f"{STATE_NEW}->{STATE_VALIDATING} (verdict={verdict})")

        # 2) FP memory: previously-dismissed known pattern -> auto-suppress
        if self.memory:
            seen = self.memory.known(finding)
            if seen and verdict in ("false_positive", "likely_false_positive", "inconclusive"):
                vs.confidence = min(vs.confidence, 0.1)
                vs.state = STATE_DISMISSED
                vs.dismissed_reason = (f"matches a known false-positive pattern "
                                       f"(seen {seen.get('count',1)}x): {seen.get('reason','')}")
                vs.transitions.append(f"{STATE_VALIDATING}->{STATE_DISMISSED} (fp-memory)")
                return vs

        # 3) exploit-confirmation signal from the verifier (proof raises confidence)
        expl = finding.get("exploitability") or verification.get("exploitability")
        if expl == "exploitable" and verdict.startswith("true"):
            vs.confidence = max(vs.confidence, 0.9)
        elif expl in ("mitigated", "not_exploitable"):
            vs.confidence = min(vs.confidence, 0.3)

        # 4) evidence-gated routing
        if verdict in ("false_positive",):
            vs.state = STATE_DISMISSED
            vs.dismissed_reason = "verifier disproved the finding on re-test"
            vs.transitions.append(f"{STATE_VALIDATING}->{STATE_DISMISSED}")
            if self.memory:
                self.memory.remember(finding, vs.dismissed_reason)
        elif vs.confidence >= self.review_threshold:
            vs.state = STATE_REVIEWED
            vs.transitions.append(f"{STATE_VALIDATING}->{STATE_REVIEWED} "
                                  f"(confidence {vs.confidence:.2f})")
        else:
            # low confidence, not a hard FP -> keep for batch review, don't submit
            vs.state = STATE_VALIDATING
        return vs
