"""Known-vulnerable dependency scanner (SCA).

Runs once per scan, not per endpoint: it reads the target's build manifests and —
when the grey-box container view is available — the JARs actually on the running
target's classpath, then checks both against a vulnerability database.

Why the classpath view matters: measured on a real deployment, the manifest
declares `jdom 1.1.3` (XXE, CVE-2021-33813) while the image ALSO ships the fixed
`jdom2-2.0.6.1` — reporting from the manifest alone is a false alarm. Conversely
the image ships `poi-3.17` beside `poi-5.5.1`, so the vulnerable class really is
still loadable. Only the classpath settles it.

Grading discipline (deluluscan/knowledge.py, supply_chain): a vulnerable version on
the classpath is a reachable-code-path LEAD, not a demonstrated exploit. Confirmed
shipped -> firm / conditional. Manifest-only -> tentative / unknown. Neither ever
claims exploitation this scan did not observe.
"""
from __future__ import annotations

from typing import Iterable

from ..models import Endpoint, Finding, RequestRecord, Severity, VulnClass
from .base import Scanner

_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW, "UNKNOWN": Severity.INFO}


class DependencyScanner(Scanner):
    name = "dependency"
    vuln_classes = [VulnClass.SUPPLY_CHAIN.value]

    def __init__(self, client, auth, config, identities, osv_fetch=None):
        super().__init__(client, auth, config, identities)
        self._done = False
        self._osv_fetch = osv_fetch      # injected in tests; None = live OSV

    def applies_to(self, endpoint: Endpoint) -> bool:
        # Needs a source tree to read manifests from; the container view is a
        # bonus that upgrades confidence, not a requirement.
        return not self._done and bool(getattr(self.config, "source_root", ""))

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        self._done = True
        from .. import sca

        root = getattr(self.config, "source_root", "")
        declared = sca.parse_maven(root) + sca.parse_npm(root)
        if not declared:
            return

        obs = getattr(self.config, "observe", None)
        container = getattr(obs, "container", "") if obs else ""
        shipped = sca.jars_in_container(
            container, getattr(obs, "docker_path", "docker")) if container else []

        hits = sca.osv_query(declared, fetch=self._osv_fetch)
        if not hits:
            return
        details = {}
        for ids in hits.values():
            for vid in ids:
                if vid not in details:
                    details[vid] = sca.osv_detail(vid, fetch=self._osv_fetch)

        for h in sca.correlate(declared, shipped, hits, details):
            if h.severity in ("LOW", "UNKNOWN") and not h.shipped:
                continue           # keep the report to what is worth acting on
            label = ", ".join(h.cves) or h.vuln_id
            where = ("confirmed on the running target's classpath"
                     if h.shipped else "declared in the build manifest")
            rec = RequestRecord(
                method="SCA", url=h.dep.location or root, identity="n/a",
                status=0, elapsed_ms=0.0,
                resp_body=f"{h.dep.name} {h.dep.version} ({h.dep.ecosystem}) — {label}")
            yield Finding(
                vuln_class=VulnClass.SUPPLY_CHAIN,
                severity=_SEV.get(h.severity, Severity.INFO),
                title=f"Vulnerable dependency: {sca.artifact_of(h.dep.name)} "
                      f"{h.dep.version} ({label})",
                endpoint="(dependencies)",
                description=(
                    f"{h.dep.name} {h.dep.version} is affected by {label}"
                    f"{': ' + h.summary if h.summary else ''}. This version is {where}. "
                    f"{'Fixed in ' + ', '.join(h.fixed_in) + '. ' if h.fixed_in else ''}"
                    f"Presence of the vulnerable version is evidence of a reachable code "
                    f"path, not proof this scan exploited it — confirm the affected API "
                    f"is actually invoked before rating impact."),
                evidence=[rec],
                detail={"test": "sca", "package": h.dep.name, "version": h.dep.version,
                        "ecosystem": h.dep.ecosystem, "advisory": h.vuln_id,
                        "cves": h.cves, "fixed_in": h.fixed_in,
                        "shipped": h.shipped, "source": h.dep.location,
                        "remediation": (f"Upgrade to {h.fixed_in[0]} or later."
                                        if h.fixed_in else "Upgrade to a fixed release.")},
                verdict="likely_true_positive" if h.shipped else "unverified",
                exploitability="conditional" if h.shipped else "unknown",
                confidence="firm" if h.shipped else "tentative")

        # Stale copies left on the classpath after an upgrade keep the vulnerable
        # class loadable. Reported once, as hygiene.
        dupes = sca.duplicate_artifacts(shipped)
        if dupes:
            listing = "; ".join(f"{k} {v}" for k, v in sorted(dupes.items())[:20])
            yield Finding(
                vuln_class=VulnClass.SUPPLY_CHAIN, severity=Severity.LOW,
                title=f"{len(dupes)} artifact(s) ship at multiple versions on the classpath",
                endpoint="(dependencies)",
                description=(
                    "These artifacts are present at more than one version at the same "
                    "time, so an upgrade has left the older copy loadable and any "
                    "vulnerability in it still reachable depending on classpath order. "
                    f"Affected: {listing}."),
                evidence=[RequestRecord(method="SCA", url="(classpath)", identity="n/a",
                                        status=0, elapsed_ms=0.0, resp_body=listing)],
                detail={"test": "sca_duplicate_artifacts", "artifacts": dupes,
                        "remediation": "Exclude the superseded artifact from the build so "
                                       "only the fixed version ships."},
                verdict="true_positive", exploitability="conditional", confidence="firm")
