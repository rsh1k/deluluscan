"""deluluscan.compliance — map findings to audit-framework controls.

A finding says "this is broken". A control ID says "this is the obligation it
breaks". Security teams are routinely asked the second question by auditors,
and answering it by hand for every report is where mapping errors creep in.

This module maps Deluluscan's vulnerability classes to controls in three frameworks:

    PCI-DSS v4.0.1        payment-card environments
    SOC 2 (2017 TSC)      the Common Criteria series
    ISO/IEC 27001:2022    Annex A controls

Design notes, in the spirit of the rest of the codebase:

* Mapping is **per vulnerability class**, not per finding. The same class of
  issue must always map to the same controls, for the same reason the OWASP
  taxonomy lives in `deluluscan.knowledge` rather than being assigned ad hoc.
* A mapping is an **advisory pointer, not an audit opinion**. Whether a control
  is actually failed depends on scope, compensating controls and the assessor's
  judgement — none of which a scanner observes. Every mapping carries a
  `basis` string saying why the control is implicated, so a reader can disagree.
* Classes with **no honest mapping return nothing**. An empty result is correct
  and useful; inventing a plausible-looking control ID to fill a column is the
  compliance equivalent of a false positive.

Inspect the table:  python3 -m deluluscan.compliance
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import VulnClass


@dataclass(frozen=True)
class Control:
    """One control in one framework, and why a class implicates it."""

    framework: str
    control_id: str
    title: str
    basis: str

    def label(self) -> str:
        return f"{self.framework} {self.control_id} — {self.title}"


PCI = "PCI-DSS v4.0.1"
SOC2 = "SOC 2 (2017 TSC)"
ISO = "ISO/IEC 27001:2022"


def _c(framework: str, control_id: str, title: str, basis: str) -> Control:
    return Control(framework=framework, control_id=control_id, title=title, basis=basis)


# --- per-class control mappings -------------------------------------------
# Keyed by VulnClass value. Every entry states the basis; a class that cannot be
# mapped honestly is simply absent from this table.
MAPPINGS: dict[str, list[Control]] = {
    "authz": [
        _c(PCI, "7.2.1", "Access control model defined and enforced",
           "a privileged operation served to an identity outside its role is an "
           "access-control model that is defined but not enforced"),
        _c(PCI, "7.3.1", "Access control system enforces least privilege by default",
           "the operation was reachable without the entitlement it requires"),
        _c(SOC2, "CC6.1", "Logical access security — authorization",
           "authorization did not restrict the operation to entitled principals"),
        _c(SOC2, "CC6.3", "Access removal and role-appropriate entitlement",
           "role membership did not determine what the identity could invoke"),
        _c(ISO, "A.5.15", "Access control",
           "the access-control rule for this operation was not applied"),
        _c(ISO, "A.8.2", "Privileged access rights",
           "an operation requiring privilege was reachable without it"),
    ],
    "idor": [
        _c(PCI, "7.2.1", "Access control model defined and enforced",
           "an object reference supplied by the client was trusted as proof of entitlement"),
        _c(SOC2, "CC6.1", "Logical access security — authorization",
           "object-level authorization was not enforced on the supplied identifier"),
        _c(ISO, "A.5.15", "Access control",
           "access to a specific object was not mediated by an authorization decision"),
        _c(ISO, "A.8.3", "Information access restriction",
           "data belonging to another subject was reachable by reference"),
    ],
    "bopla": [
        _c(PCI, "7.3.1", "Access control system enforces least privilege by default",
           "the response returned properties beyond those the caller is entitled to"),
        _c(SOC2, "CC6.1", "Logical access security — authorization",
           "property-level authorization was not applied to the response projection"),
        _c(ISO, "A.8.3", "Information access restriction",
           "the object projection was not restricted to the caller's need to know"),
    ],
    "info_leak": [
        _c(PCI, "3.3.1", "Sensitive data is masked or not stored/displayed unnecessarily",
           "data was disclosed to a principal with no need for it"),
        _c(SOC2, "CC6.1", "Logical access security — authorization",
           "information was disclosed outside the boundary authorization defines"),
        _c(ISO, "A.8.3", "Information access restriction",
           "information was returned beyond the caller's need to know"),
        _c(ISO, "A.5.34", "Privacy and protection of PII",
           "where the disclosed data identifies people, PII protection is implicated"),
    ],
    "sqli": [
        _c(PCI, "6.2.4", "Software engineering techniques prevent injection attacks",
           "input reached a query without parameterisation"),
        _c(SOC2, "CC8.1", "Change management — secure development",
           "the code path admits attacker-controlled query structure"),
        _c(ISO, "A.8.28", "Secure coding",
           "query construction did not separate code from data"),
    ],
    "injection": [
        _c(PCI, "6.2.4", "Software engineering techniques prevent injection attacks",
           "attacker-controlled input reached an interpreter"),
        _c(ISO, "A.8.28", "Secure coding",
           "input was not neutralised before reaching an interpreter"),
    ],
    "ssti": [
        _c(PCI, "6.2.4", "Software engineering techniques prevent injection attacks",
           "input was evaluated as template expression rather than data"),
        _c(ISO, "A.8.28", "Secure coding",
           "template rendering did not separate expression from data"),
    ],
    "xss": [
        _c(PCI, "6.2.4", "Software engineering techniques prevent injection attacks",
           "input was rendered into an execution context without encoding"),
        _c(ISO, "A.8.28", "Secure coding",
           "output encoding was absent for the render context"),
    ],
    "log_injection": [
        _c(PCI, "10.2.1", "Audit logs capture all individual user access and actions",
           "forged records make the audit log unable to evidence what occurred"),
        _c(PCI, "10.3.2", "Audit log files are protected from modification",
           "a caller can write arbitrary records into the log stream"),
        _c(SOC2, "CC7.2", "Monitoring — anomaly detection and log integrity",
           "log integrity cannot be assumed, so monitoring built on it is unreliable"),
        _c(ISO, "A.8.15", "Logging",
           "log records can be fabricated by an untrusted party"),
        _c(ISO, "A.8.16", "Monitoring activities",
           "monitoring derived from these logs may act on forged records"),
    ],
    "logging_failure": [
        _c(PCI, "10.2.1", "Audit logs capture all individual user access and actions",
           "a security-relevant action produced no audit record"),
        _c(SOC2, "CC7.2", "Monitoring — anomaly detection",
           "the action is invisible to monitoring"),
        _c(ISO, "A.8.15", "Logging",
           "the event was not logged"),
    ],
    "rate_limit": [
        _c(PCI, "8.3.4", "Invalid authentication attempts are limited",
           "authentication attempts were not effectively limited"),
        _c(SOC2, "CC6.1", "Logical access security — credential protection",
           "credential guessing is not constrained"),
        _c(SOC2, "CC7.2", "Monitoring — anomaly detection",
           "high-rate attempts consume no budget and raise no signal"),
        _c(ISO, "A.8.5", "Secure authentication",
           "the authentication mechanism does not throttle repeated failures"),
    ],
    "crypto": [
        _c(PCI, "8.3.2", "Strong cryptography protects authentication factors",
           "authentication material is protected by weak or predictable cryptography"),
        _c(SOC2, "CC6.1", "Logical access security — credential protection",
           "token or key material does not resist forgery"),
        _c(ISO, "A.8.24", "Use of cryptography",
           "the cryptographic mechanism does not meet its objective"),
    ],
    "misconfig": [
        _c(PCI, "2.2.1", "Configuration standards are applied to all system components",
           "the deployed configuration diverges from a hardened standard"),
        _c(SOC2, "CC6.6", "Boundary protection and secure configuration",
           "the component's configuration weakens its security boundary"),
        _c(ISO, "A.8.9", "Configuration management",
           "the secure configuration baseline is not enforced"),
    ],
    "inventory": [
        _c(PCI, "2.2.1", "Configuration standards are applied to all system components",
           "an undocumented or legacy surface is live outside the managed baseline"),
        _c(SOC2, "CC6.6", "Boundary protection",
           "the exposed surface is wider than the documented one"),
        _c(ISO, "A.5.9", "Inventory of information and other associated assets",
           "the live API surface is not fully reflected in the asset inventory"),
    ],
    "supply_chain": [
        _c(PCI, "6.3.3", "System components are protected from known vulnerabilities",
           "a component with a known vulnerability is deployed"),
        _c(SOC2, "CC7.1", "Vulnerability identification and remediation",
           "a known-vulnerable dependency is present in the running system"),
        _c(ISO, "A.8.8", "Management of technical vulnerabilities",
           "a published vulnerability affects a deployed component"),
        _c(ISO, "A.5.21", "Managing information security in the ICT supply chain",
           "risk is inherited from a third-party component"),
    ],
    "ssrf": [
        _c(PCI, "1.4.1", "Network security controls between trusted and untrusted networks",
           "the server can be induced to originate requests across a trust boundary"),
        _c(SOC2, "CC6.6", "Boundary protection",
           "an attacker directs server-side requests past the network boundary"),
        _c(ISO, "A.8.20", "Network security",
           "outbound destinations are attacker-controlled"),
    ],
    "error_handling": [
        _c(SOC2, "CC7.2", "Monitoring — anomaly detection",
           "unhandled conditions may mask failures that monitoring should surface"),
        _c(ISO, "A.8.28", "Secure coding",
           "exceptional conditions are not handled deliberately"),
    ],
    "business_logic": [
        _c(SOC2, "CC8.1", "Change management — secure development",
           "the workflow permits a sequence its design did not intend"),
        _c(ISO, "A.8.28", "Secure coding",
           "business rules are not enforced server-side"),
    ],
    "memory_disclosure": [
        _c(PCI, "2.2.1", "Configuration standards are applied to all system components",
           "a debug or diagnostic surface is reachable in a deployed configuration"),
        _c(ISO, "A.8.9", "Configuration management",
           "diagnostic interfaces are enabled outside a hardened baseline"),
    ],
    "graphql": [
        _c(PCI, "6.2.4", "Software engineering techniques prevent injection attacks",
           "query structure or depth is attacker-controlled"),
        _c(ISO, "A.8.28", "Secure coding",
           "query cost and field visibility are not constrained"),
    ],
}

# Classes deliberately left unmapped, with the reason. Recorded explicitly so an
# absent mapping reads as a decision rather than an oversight.
UNMAPPED: dict[str, str] = {
    "ai_llm": ("no established control in PCI-DSS v4, SOC 2 or ISO 27001:2022 "
               "addresses model-behaviour weaknesses directly; mapping one would "
               "be an invention"),
}


def controls_for(vuln_class) -> list[Control]:
    """Controls implicated by a vulnerability class, across all frameworks.

    Returns an empty list where no honest mapping exists.
    """
    key = getattr(vuln_class, "value", vuln_class)
    return list(MAPPINGS.get(str(key), []))


def controls_by_framework(vuln_class) -> dict[str, list[Control]]:
    """Same mapping, grouped by framework name."""
    grouped: dict[str, list[Control]] = {}
    for control in controls_for(vuln_class):
        grouped.setdefault(control.framework, []).append(control)
    return grouped


def frameworks() -> list[str]:
    """The frameworks this module maps to."""
    return [PCI, SOC2, ISO]


def mapping_for_report(vuln_class) -> dict:
    """A report-ready mapping block for one class.

    Shape:
        {"frameworks": {"PCI-DSS v4.0.1": [{"id","title","basis"}, ...], ...},
         "unmapped_reason": "..."}   # only when nothing maps
    """
    grouped = controls_by_framework(vuln_class)
    if grouped:
        return {
            "frameworks": {
                fw: [{"id": c.control_id, "title": c.title, "basis": c.basis}
                     for c in controls]
                for fw, controls in grouped.items()
            },
        }
    key = str(getattr(vuln_class, "value", vuln_class))
    reason = UNMAPPED.get(
        key, "no control mapping is defined for this class; none is asserted")
    return {"frameworks": {}, "unmapped_reason": reason}


def coverage_summary(vuln_classes) -> dict[str, list[str]]:
    """Framework -> sorted control IDs implicated by a set of classes.

    Used for the report's compliance-impact table: which controls does this
    engagement touch overall?
    """
    out: dict[str, set[str]] = {}
    for vc in vuln_classes:
        for control in controls_for(vc):
            out.setdefault(control.framework, set()).add(control.control_id)
    return {fw: sorted(ids) for fw, ids in sorted(out.items())}


def describe() -> str:
    """Human-readable dump of the whole mapping table."""
    lines = ["Deluluscan compliance mapping", "=" * 60,
             "Frameworks: " + ", ".join(frameworks()), ""]
    for key in sorted(MAPPINGS):
        lines.append(f"{key}")
        for fw, controls in controls_by_framework(key).items():
            for c in controls:
                lines.append(f"    {fw:22} {c.control_id:10} {c.title}")
        lines.append("")
    if UNMAPPED:
        lines.append("Deliberately unmapped:")
        for key, why in sorted(UNMAPPED.items()):
            lines.append(f"    {key}: {why}")
    mapped = set(MAPPINGS)
    known = {v.value for v in VulnClass}
    missing = sorted(known - mapped - set(UNMAPPED))
    if missing:
        lines.append("")
        lines.append("No mapping and no recorded reason (add one or record why):")
        lines.append("    " + ", ".join(missing))
    return "\n".join(lines)


if __name__ == "__main__":
    print(describe())
