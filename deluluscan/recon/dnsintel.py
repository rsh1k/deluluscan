"""DNS & email intelligence (WSTG-INFO): the OSINT recon a pentest opens with.

Covers what CT-log subdomain enumeration doesn't — the domain's DNS posture and
the email-spoofing surface an attacker probes first:

  - SPF (TXT v=spf1): missing => spoofable; `+all` => anyone may send as you.
  - DMARC (_dmarc TXT v=DMARC1): missing => no anti-spoofing enforcement;
    `p=none` => monitor-only, spoofing still lands.
  - Zone transfer (AXFR): a nameserver that answers AXFR hands an attacker the
    entire internal DNS map — a classic high-impact misconfiguration.
  - MX / NS / A inventory, and email addresses harvested from the site body.

The resolver + zone-transfer functions are injected, so this runs fully offline
in tests. The default resolver uses dnspython if present, else `nslookup`/`dig`,
else fails soft. Detection only.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


@dataclass
class DnsProfile:
    domain: str
    records: dict = field(default_factory=dict)     # rtype -> [values]
    spf: Optional[str] = None
    dmarc: Optional[str] = None
    zone_transfer: Optional[list] = None            # records if AXFR succeeded
    emails: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"domain": self.domain, "records": self.records, "spf": self.spf,
                "dmarc": self.dmarc,
                "zone_transfer": (self.zone_transfer[:20] if self.zone_transfer else None),
                "emails": self.emails}


def _default_resolve(name: str, rtype: str) -> list:
    """Best-effort resolver: dnspython -> nslookup -> []."""
    try:
        import dns.resolver
        return [r.to_text().strip('"') for r in dns.resolver.resolve(name, rtype)]
    except Exception:
        pass
    try:
        out = subprocess.run(["nslookup", "-type=" + rtype, name],
                             capture_output=True, text=True, timeout=8).stdout
        vals = []
        for line in out.splitlines():
            line = line.strip()
            if rtype == "TXT" and "text =" in line:
                vals.append(line.split("text =", 1)[1].strip().strip('"'))
            elif rtype == "MX" and "mail exchanger" in line:
                vals.append(line.split("=", 1)[1].strip())
            elif rtype in ("A", "AAAA") and line.startswith("Address:") and "#" not in line:
                vals.append(line.split(":", 1)[1].strip())
            elif rtype == "NS" and "nameserver" in line:
                vals.append(line.split("=", 1)[1].strip())
        return vals
    except Exception:
        return []


def _default_axfr(domain: str, nameserver: str) -> Optional[list]:
    """Attempt a zone transfer. Returns records on success, None on refusal."""
    try:
        import dns.query
        import dns.zone
        z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=8))
        return [f"{n} {z[n].to_text(n)}" for n in z.nodes.keys()]
    except Exception:
        return None


class DnsIntel:
    def __init__(self, resolve: Optional[Callable] = None, axfr: Optional[Callable] = None):
        self.resolve = resolve or _default_resolve
        self.axfr = axfr or _default_axfr

    def gather(self, domain: str, *, page_body: str = "", try_axfr: bool = True) -> DnsProfile:
        prof = DnsProfile(domain=domain)
        for rtype in ("A", "MX", "NS", "TXT"):
            try:
                prof.records[rtype] = self.resolve(domain, rtype) or []
            except Exception:
                prof.records[rtype] = []
        # SPF lives in the domain's TXT records
        for txt in prof.records.get("TXT", []):
            if txt.lower().startswith("v=spf1"):
                prof.spf = txt
        # DMARC lives at _dmarc.<domain>
        try:
            for txt in (self.resolve(f"_dmarc.{domain}", "TXT") or []):
                if txt.lower().startswith("v=dmarc1"):
                    prof.dmarc = txt
        except Exception:
            pass
        # zone transfer against each nameserver
        if try_axfr:
            for ns in prof.records.get("NS", []):
                recs = self.axfr(domain, ns.rstrip("."))
                if recs:
                    prof.zone_transfer = recs
                    break
        if page_body:
            prof.emails = sorted(set(_EMAIL_RE.findall(page_body)))[:25]
        return prof

    def to_findings(self, prof: DnsProfile) -> list:
        out: list = []
        rec = RequestRecord(method="DNS", url=prof.domain, identity="anon", status=0, elapsed_ms=0.0)

        def add(vc, sev, title, desc, detail, conf="firm", verdict="likely_true_positive"):
            out.append(Finding(vuln_class=vc, severity=sev, title=title, endpoint=prof.domain,
                               description=desc, evidence=[rec], confidence=conf, verdict=verdict,
                               exploitability="conditional",
                               detail={**detail, "source": "recon.dnsintel"}))

        # SPF
        if prof.records.get("TXT") is not None:
            if prof.spf is None:
                add(VulnClass.MISCONFIG, Severity.LOW, "No SPF record",
                    f"{prof.domain} publishes no SPF record — anyone can send email spoofing "
                    "this domain. Publish an SPF record ending in -all.", {})
            elif re.search(r"(?:^|\s)\+all\b", prof.spf) or "+all" in prof.spf:
                add(VulnClass.MISCONFIG, Severity.MEDIUM, "SPF allows any sender (+all)",
                    f"The SPF record uses +all, authorizing any host to send as {prof.domain}: "
                    f"'{prof.spf}'. Use -all (hard fail).", {"spf": prof.spf})
        # DMARC
        if prof.dmarc is None and prof.records.get("TXT") is not None:
            add(VulnClass.MISCONFIG, Severity.MEDIUM, "No DMARC record",
                f"{prof.domain} has no DMARC policy — receivers can't reject spoofed mail, "
                "enabling phishing/BEC. Publish _dmarc with at least p=quarantine.", {})
        elif prof.dmarc and re.search(r"p\s*=\s*none", prof.dmarc, re.I):
            add(VulnClass.MISCONFIG, Severity.LOW, "DMARC policy is monitor-only (p=none)",
                f"DMARC is set to p=none, which only reports — spoofed mail is still delivered: "
                f"'{prof.dmarc}'. Move to p=quarantine or p=reject.", {"dmarc": prof.dmarc})
        # Zone transfer
        if prof.zone_transfer:
            add(VulnClass.INFO_LEAK, Severity.HIGH, "DNS zone transfer (AXFR) allowed",
                f"A nameserver for {prof.domain} answered a zone transfer, disclosing the full "
                f"DNS record set ({len(prof.zone_transfer)} records) — internal hosts, "
                "infrastructure map. Restrict AXFR to authorized secondaries.",
                {"record_count": len(prof.zone_transfer),
                 "sample": prof.zone_transfer[:8]}, verdict="true_positive")
        # Harvested emails
        if prof.emails:
            add(VulnClass.INFO_LEAK, Severity.INFO, f"{len(prof.emails)} email address(es) exposed on site",
                "Email addresses harvested from the site body — useful for phishing/OSINT. "
                f"Sample: {', '.join(prof.emails[:5])}.", {"emails": prof.emails},
                conf="firm", verdict="true_positive")
        return out

    def run(self, domain: str, *, page_body: str = "", try_axfr: bool = True):
        prof = self.gather(domain, page_body=page_body, try_axfr=try_axfr)
        return prof, self.to_findings(prof)
