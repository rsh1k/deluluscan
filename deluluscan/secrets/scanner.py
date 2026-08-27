"""Scan text (HTTP responses, JS) for exposed secrets — matches masked, never stored."""
from __future__ import annotations

from typing import Optional

from ..models import Finding, Severity, VulnClass
from .patterns import RULES, shannon_entropy, mask

_SEV = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
        "critical": Severity.CRITICAL}


def scan_text(text: str, source: str = "response") -> list:
    if not text:
        return []
    seen = set()
    out: list[Finding] = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            secret = m.group(rule.group) if rule.group else m.group(0)
            if not secret:
                continue
            if rule.min_entropy and shannon_entropy(secret) < rule.min_entropy:
                continue
            key = (rule.name, secret)
            if key in seen:
                continue
            seen.add(key)
            cls = VulnClass.CRYPTO if "Private Key" in rule.name else VulnClass.INFO_LEAK
            out.append(Finding(
                vuln_class=cls, severity=_SEV[rule.severity],
                title=f"Exposed secret: {rule.name}", endpoint=source,
                description=(f"A {rule.provider} {rule.name} was found in {source}. "
                             f"Masked value: {mask(secret)}. Rotate it and remove it from the "
                             "client-reachable surface."),
                detail={"provider": rule.provider, "rule": rule.name, "masked": mask(secret),
                        "source": source, "note": "secret value redacted"},
                confidence="confirmed", verdict="true_positive", exploitability="conditional"))
    return out
