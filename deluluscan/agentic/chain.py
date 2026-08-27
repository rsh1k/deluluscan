"""AttackChain — an ordered, evidence-carrying record of an exploitation attempt.

A chain is what turns a *lead* into a *proven* finding: each step is one
allowlisted capability call with its observation and (where applicable) an HTTP
evidence record. The chain is only ``proven`` when a DETERMINISTIC objective
verifier says so — never because the model asserted it.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from ..models import Finding, RequestRecord, Severity, VulnClass


@dataclass
class ChainStep:
    n: int
    capability: str
    args: dict
    rationale: str = ""
    observation: str = ""
    ok: bool = True
    state_changing: bool = False
    status: str = "executed"          # executed | rejected | blocked | denied
    evidence: Optional[RequestRecord] = None

    def to_dict(self) -> dict:
        d = {"n": self.n, "capability": self.capability, "args": self.args,
             "rationale": self.rationale, "observation": self.observation[:500],
             "ok": self.ok, "state_changing": self.state_changing, "status": self.status}
        return d


@dataclass
class AttackChain:
    objective: str
    vuln_class: VulnClass = VulnClass.BUSINESS_LOGIC
    severity: Severity = Severity.HIGH
    steps: list = field(default_factory=list)     # list[ChainStep]
    proven: bool = False
    reason: str = ""
    created_at: float = field(default_factory=time.time)

    def add(self, step: ChainStep) -> ChainStep:
        self.steps.append(step)
        return step

    def evidence_records(self) -> list:
        return [s.evidence for s in self.steps if s.evidence is not None]

    def to_dict(self) -> dict:
        return {"objective": self.objective, "vuln_class": self.vuln_class.value,
                "proven": self.proven, "reason": self.reason,
                "steps": [s.to_dict() for s in self.steps]}

    def to_finding(self) -> Optional[Finding]:
        """A proven chain becomes a confirmed finding; an unproven one is not
        emitted (the report may only assert what was demonstrated)."""
        if not self.proven:
            return None
        executed = [s for s in self.steps if s.status == "executed"]
        return Finding(
            vuln_class=self.vuln_class, severity=self.severity,
            title=f"Exploit chain: {self.objective}",
            endpoint=(executed[0].evidence.url if executed and executed[0].evidence else "chain"),
            description=(f"Demonstrated exploitation chain ({len(executed)} steps): "
                         + " -> ".join(s.capability for s in executed) + f". {self.reason}"),
            evidence=self.evidence_records()[:4],
            detail={"objective": self.objective, "steps": [s.to_dict() for s in self.steps],
                    "source": "agentic.exploit_chain"},
            confidence="confirmed", verdict="true_positive", exploitability="exploitable")
