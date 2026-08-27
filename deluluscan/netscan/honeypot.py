"""Honeypot / deception heuristics (deliberately conservative).

Honeypot detection is genuinely hard and error-prone; the research literature
treats it probabilistically (Shodan's Honeyscore). So this module emits only
*tentative* leads, never a hard verdict, from three honest signals:

  1. known deception-framework banners/markers (Cowrie/Kippo, Dionaea, Glastopf,
     Conpot) in a service banner, header, or body;
  2. an implausible service spread — a single host answering on many unrelated
     high-value ports (Dionaea-style multi-service emulation);
  3. banner/header inconsistency — e.g. a Server header that contradicts the
     stack seen elsewhere.

Everything is a heuristic and labelled as such. Detection only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .signatures import HONEYPOT_SIGS

# A real host rarely exposes this many *different* sensitive services at once.
_MULTISERVICE_THRESHOLD = 8
_SENSITIVE_SET = {21, 22, 23, 445, 1433, 3306, 5432, 6379, 9200, 27017, 3389, 11211}


@dataclass
class HoneypotLead:
    reason: str
    confidence: str                  # always tentative/low here
    evidence: str = ""
    matched: str = ""


def assess(*, banners: list = None, headers: dict = None, body: str = "",
           open_ports: list = None) -> list:
    """banners: list[str]; headers: dict; open_ports: list[int]. Returns leads."""
    leads: list = []
    banners = banners or []
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    open_ports = open_ports or []
    hay_banner = "\n".join(banners)
    hay_header = "\n".join(f"{k}: {v}" for k, v in headers.items())

    # 1) known deception signatures
    for sig in HONEYPOT_SIGS:
        hay = {"banner": hay_banner, "header": hay_header, "body": body}.get(sig.where, "")
        if sig.pattern and hay and re.search(sig.pattern, hay):
            leads.append(HoneypotLead(
                reason=f"Matches known deception marker: {sig.name}",
                confidence="tentative", evidence=sig.note, matched=sig.name))

    # 2) implausible multi-service spread
    sensitive_open = sorted(set(open_ports) & _SENSITIVE_SET)
    if len(sensitive_open) >= _MULTISERVICE_THRESHOLD:
        leads.append(HoneypotLead(
            reason=(f"{len(sensitive_open)} unrelated sensitive services answer on one "
                    "host — consistent with a multi-service honeypot (e.g. Dionaea)."),
            confidence="tentative",
            evidence=f"open sensitive ports: {sensitive_open}"))

    return leads
