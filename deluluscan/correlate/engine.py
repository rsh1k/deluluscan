"""Correlate findings into attack-chain suggestions + agentic objectives."""
from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Optional

from ..models import Finding, Severity, VulnClass
from .chains import CHAIN_RULES, ChainRule


@dataclass
class ChainSuggestion:
    rule: ChainRule
    members: list                    # list[Finding] (one representative per predicate)

    def to_finding(self) -> Finding:
        eps = ", ".join(sorted({getattr(m, "endpoint", "") for m in self.members if getattr(m, "endpoint", "")}))
        return Finding(
            vuln_class=VulnClass.BUSINESS_LOGIC, severity=self.rule.severity,
            title=f"Correlated attack chain: {self.rule.name}",
            endpoint=eps or "chain",
            description=self.rule.rationale + f" (derived from {len(self.members)} confirmed findings).",
            detail={"chain": self.rule.id, "objective": self.rule.objective,
                    "members": [{"title": getattr(m, "title", ""), "endpoint": getattr(m, "endpoint", ""),
                                 "vuln_class": (m.vuln_class.value if hasattr(m.vuln_class, "value") else m.vuln_class)}
                                for m in self.members],
                    "remediation": self.rule.remediation, "source": "correlate"},
            confidence="tentative", verdict="inconclusive", exploitability="conditional")

    def to_objective(self) -> dict:
        return {"objective": self.rule.objective, "chain": self.rule.id,
                "severity": self.rule.severity.value,
                "members": [getattr(m, "endpoint", "") for m in self.members]}


def _as_view(f):
    """Accept a Finding or a plain results.json dict; expose the attrs predicates use."""
    if isinstance(f, dict):
        vc = f.get("vuln_class")
        try:
            vc = VulnClass(vc) if not isinstance(vc, VulnClass) else vc
        except Exception:
            vc = None
        return SimpleNamespace(vuln_class=vc, title=f.get("title", ""),
                               description=f.get("description", ""), detail=f.get("detail", {}),
                               endpoint=f.get("endpoint", ""), id=f.get("id", ""),
                               severity=f.get("severity"))
    return f


def correlate(findings: list) -> list:
    views = [_as_view(f) for f in findings]
    views = [v for v in views if getattr(v, "vuln_class", None) is not None]
    out = []
    for rule in CHAIN_RULES:
        matched = []
        ok = True
        for pred in rule.members:
            hits = [v for v in views if pred(v)]
            if not hits:
                ok = False
                break
            matched.append(hits[0])
        if ok:
            # avoid a chain that is just one finding matching two predicates
            if len({id(m) for m in matched}) >= 2 or len(rule.members) == 1:
                out.append(ChainSuggestion(rule, matched))
    return out


def chain_findings(findings: list) -> list:
    return [s.to_finding() for s in correlate(findings)]


def objectives(findings: list) -> list:
    return [s.to_objective() for s in correlate(findings)]
