"""Analyze a parsed SBOM: known-vulnerable components + integrity/provenance gaps.

The headline is cross-referencing components against a curated list of marquee
supply-chain CVEs (Log4Shell, Spring4Shell, Text4Shell, …) — because most orgs
generate an SBOM and never actually check it. Plus SBOM-quality signals that
undermine its value: components with no integrity hash (can't verify the artifact)
or no version (can't assess), and an SBOM with no components at all.
"""
from __future__ import annotations

from ..models import Finding, RequestRecord, Severity, VulnClass
from ..platforms.cves import version_in_range
from .known_vulns import KNOWN_VULN_PACKAGES

_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL}


def _rec(source, comp=""):
    return RequestRecord(method="SBOM", url=f"{source}:{comp}" if comp else source,
                         identity="anon", status=0, elapsed_ms=0.0)


def analyze_components(components: list, *, source: str = "sbom") -> list:
    out: list = []

    def add(vc, sev, title, desc, rule, comp, extra=None):
        out.append(Finding(vuln_class=vc, severity=sev, title=title,
                           endpoint=f"{source}:{comp}", description=desc, evidence=[_rec(source, comp)],
                           confidence="firm", verdict="likely_true_positive", exploitability="conditional",
                           detail={"rule": rule, "component": comp, "source": "sbom", **(extra or {})}))

    if not components:
        add(VulnClass.INVENTORY, Severity.LOW, "SBOM lists no components",
            "The SBOM contains no components — an empty/placeholder SBOM gives false assurance and "
            "no supply-chain visibility.", "sbom-empty", "-")
        return out

    no_hash = 0
    for c in components:
        cid = f"{c.name}@{c.version}" if c.version else c.name

        # ---- known-vulnerable component (the security payoff) ----
        nlow = (c.name or "").lower()
        for eco, pkg, spec, cve, sev, summary in KNOWN_VULN_PACKAGES:
            if nlow == pkg and c.version and version_in_range(c.version, spec):
                add(VulnClass.SUPPLY_CHAIN, _SEV[sev],
                    f"Known-vulnerable component: {c.name} {c.version} ({cve})",
                    f"{summary} {c.name} {c.version} is in the affected range ({spec}) per {cve}. "
                    "Upgrade to a fixed release.", "sbom-known-vuln", cid,
                    {"cve": cve, "affected": spec, "ecosystem": c.ecosystem or eco,
                     "remediation": f"Upgrade {c.name} out of {spec}."})
                break

        # ---- integrity / provenance quality ----
        if not c.has_hash:
            no_hash += 1
        if not c.version:
            add(VulnClass.INVENTORY, Severity.LOW, f"SBOM component without a version: {c.name}",
                f"'{c.name}' has no version in the SBOM — it can't be matched to vulnerabilities, "
                "defeating the point of the SBOM.", "sbom-no-version", c.name)

    # integrity gap reported once (aggregate) to stay low-noise
    if no_hash and no_hash >= max(1, len(components) // 5):
        add(VulnClass.SUPPLY_CHAIN, Severity.LOW,
            f"{no_hash}/{len(components)} SBOM components lack integrity hashes",
            "Many components carry no checksum/hash, so the SBOM can't be used to verify that the "
            "delivered artifact matches — weakens tamper detection.", "sbom-no-hash", "-",
            {"without_hash": no_hash, "total": len(components)})
    return out
