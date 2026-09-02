"""Combined priority score — one "fix this first" number per finding.

Severity alone over-ranks theoretical bugs and under-ranks a medium that is
actively exploited. Modern vulnerability management (ASPM) blends four signals:

  - IMPACT        : the finding's severity
  - EXPLOITATION  : is it exploited in the wild? (CISA KEV = fact, EPSS = odds)
  - REACHABILITY  : did OUR live verifier confirm it, and is it exploitable?

`compute_priority` folds these into a 0-100 score with an explainable factor
list, so the report can order remediation by real risk and show *why*. It uses
whatever enrichment is present (detail['kev'], detail['epss']) plus the finding's
own severity / verdict / exploitability — it never fetches anything itself.
"""
from __future__ import annotations

from typing import Optional

_SEV_BASE = {"info": 5, "low": 20, "medium": 45, "high": 70, "critical": 90}
_EXPLOIT_ADJ = {"exploitable": 10, "conditional": 3, "unknown": 0,
                "mitigated": -15, "not_exploitable": -30}
# a live verdict that disproved the finding should sink it
_DEAD_VERDICTS = {"false_positive", "likely_false_positive"}


def _sev_value(f) -> str:
    s = getattr(f, "severity", None)
    return getattr(s, "value", s) or "info"


def _band(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def compute_priority(f) -> dict:
    """Return {score, band, factors} for one finding."""
    detail = getattr(f, "detail", None) or {}
    sev = _sev_value(f)
    verdict = getattr(f, "verdict", "") or ""
    exploit = getattr(f, "exploitability", "") or "unknown"
    factors: list = []

    if verdict in _DEAD_VERDICTS:
        return {"score": 0, "band": "info",
                "factors": [f"live re-test verdict: {verdict}"]}

    score = float(_SEV_BASE.get(sev, 5))
    factors.append(f"severity {sev} (+{_SEV_BASE.get(sev, 5)})")

    kev = detail.get("kev") or {}
    if kev.get("in_kev"):
        score += 30
        factors.append("CISA KEV: exploited in the wild (+30)")
        if kev.get("ransomware"):
            score += 5
            factors.append("linked to ransomware campaigns (+5)")

    epss = detail.get("epss") or {}
    es = epss.get("score")
    if isinstance(es, (int, float)) and es > 0:
        bonus = round(es * 20, 1)
        score += bonus
        factors.append(f"EPSS {es*100:.1f}% exploit probability (+{bonus})")

    adj = _EXPLOIT_ADJ.get(exploit, 0)
    if adj:
        score += adj
        factors.append(f"exploitability {exploit} ({adj:+d})")

    if verdict in ("true_positive",):
        score += 5
        factors.append("live-verified true positive (+5)")

    score = max(0.0, min(100.0, score))
    return {"score": round(score, 1), "band": _band(score), "factors": factors}


def attach_priority(findings: list) -> int:
    """Set detail['priority'] on every finding. Returns the count processed."""
    n = 0
    for f in findings:
        d = getattr(f, "detail", None)
        if not isinstance(d, dict):
            continue
        d["priority"] = compute_priority(f)
        n += 1
    return n
