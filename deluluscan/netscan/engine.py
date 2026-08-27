"""NetScan — edge & network situational awareness for an authorized target.

Composes the passes into one picture and a set of Findings:
  - WAF/CDN/reverse-proxy detection (waf.WafScan)
  - port/service discovery + banner grab (ports.PortScan)
  - honeypot/deception heuristics (honeypot.assess)
  - IDS/IPS behavioural inference (a malicious probe that gets the connection
    reset/dropped while a clean request succeeds implies an inline IPS)

Findings are detection-only and evidence-backed. Network passes (ports, active
WAF probe) send traffic to the target, so the CLI gates them to loopback/RFC1918
unless the operator asserts authorization — same boundary as the rest of the tool.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse

from ..models import Finding, RequestRecord, Severity, VulnClass
from .waf import WafScan
from .ports import PortScan, COMMON_PORTS
from . import honeypot as _honeypot


@dataclass
class NetProfile:
    target: str
    edges: list = field(default_factory=list)        # list[EdgeMatch]
    ports: list = field(default_factory=list)         # list[PortResult]
    honeypot_leads: list = field(default_factory=list)
    ids_ips: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "edges": [{"name": e.name, "kind": e.kind, "confidence": e.confidence,
                       "blocking": e.blocking, "signals": e.signals} for e in self.edges],
            "ports": [{"port": p.port, "service": p.service, "banner": p.banner,
                       "dangerous": p.dangerous} for p in self.ports],
            "honeypot_leads": [{"reason": h.reason, "confidence": h.confidence,
                                "evidence": h.evidence, "matched": h.matched}
                               for h in self.honeypot_leads],
            "ids_ips": self.ids_ips,
        }


class NetScan:
    def __init__(self, fetch: Optional[Callable] = None, connect: Optional[Callable] = None,
                 timeout: int = 10):
        self.waf = WafScan(fetch=fetch, timeout=timeout)
        self.portscan = PortScan(connect=connect)
        self._fetch = self.waf.fetch

    def run(self, url: str, *, do_ports: bool = True, do_waf: bool = True,
            ports=COMMON_PORTS) -> NetProfile:
        host = urlparse(url).hostname or url
        prof = NetProfile(target=url)
        if do_waf:
            prof.edges = self.waf.detect(url, active=True)
            prof.ids_ips = self._infer_ids_ips(url)
        if do_ports:
            prof.ports = self.portscan.scan(host, ports=ports)
        # honeypot heuristics fold in whatever we gathered
        banners = [p.banner for p in prof.ports if p.banner]
        prof.honeypot_leads = _honeypot.assess(
            banners=banners, open_ports=[p.port for p in prof.ports])
        return prof

    def _infer_ids_ips(self, url: str) -> dict:
        """Clean request should succeed; a blatantly malicious one that gets the
        connection dropped (status 0 / reset) while the clean one didn't implies
        an inline IPS silently dropping traffic (distinct from a WAF's HTTP 403)."""
        clean = self.waf._get(url)
        mal = self.waf._get(url, params={"q": "'; DROP TABLE users;-- <script>"})
        clean_ok = clean[0] and clean[0] < 500
        probe_dropped = (mal[0] == 0) and clean_ok
        return {"inline_drop_observed": bool(probe_dropped),
                "clean_status": clean[0], "probe_status": mal[0],
                "note": ("A malicious probe was dropped at the connection level while a "
                         "clean request succeeded — consistent with an inline IDS/IPS."
                         if probe_dropped else
                         "No connection-level drop distinguishing an inline IPS was observed.")}

    # ---- findings --------------------------------------------------------
    def to_findings(self, prof: NetProfile) -> list:
        out: list = []
        base = prof.target

        for e in prof.edges:
            sev = Severity.INFO
            out.append(Finding(
                vuln_class=VulnClass.MISCONFIG, severity=sev,
                title=f"Edge defence detected: {e.name}" + (" (actively blocking)" if e.blocking else ""),
                endpoint=base,
                description=(f"A {e.kind.upper()} ({e.name}) sits in front of the target "
                             f"[{e.confidence}]. Signals: {'; '.join(e.signals[:4])}. "
                             "Not a vulnerability — it shapes how every other probe must be "
                             "interpreted (blocks/rate-limits may mask real findings)."),
                detail={"vendor": e.name, "kind": e.kind, "confidence": e.confidence,
                        "blocking": e.blocking, "signals": e.signals,
                        "source": "netscan.waf"},
                confidence="firm" if e.confidence != "tentative" else "tentative"))

        for p in prof.ports:
            if p.dangerous:
                out.append(Finding(
                    vuln_class=VulnClass.MISCONFIG, severity=Severity.HIGH,
                    title=f"High-risk service exposed: {p.service} (port {p.port})",
                    endpoint=f"{urlparse(base).hostname or base}:{p.port}",
                    description=p.dangerous + f" Banner: {p.banner[:80] or '(none)'}",
                    detail={"port": p.port, "service": p.service, "banner": p.banner,
                            "source": "netscan.ports"},
                    confidence="firm", verdict="likely_true_positive",
                    exploitability="conditional"))

        for h in prof.honeypot_leads:
            out.append(Finding(
                vuln_class=VulnClass.INFO_LEAK, severity=Severity.INFO,
                title=f"Deception/honeypot lead: {h.matched or 'heuristic'}",
                endpoint=base,
                description=h.reason + (f" ({h.evidence})" if h.evidence else "")
                            + " — TENTATIVE heuristic, verify before relying on it.",
                detail={"confidence": h.confidence, "evidence": h.evidence,
                        "matched": h.matched, "source": "netscan.honeypot"},
                confidence="tentative"))

        if prof.ids_ips and prof.ids_ips.get("inline_drop_observed"):
            out.append(Finding(
                vuln_class=VulnClass.MISCONFIG, severity=Severity.INFO,
                title="Inline IDS/IPS inferred (connection-level drop)",
                endpoint=base, description=prof.ids_ips["note"],
                detail={**prof.ids_ips, "source": "netscan.ids_ips"},
                confidence="tentative"))
        return out
