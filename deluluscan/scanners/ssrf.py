"""SSRF detector (out-of-band).

The reliable way to detect blind SSRF is an out-of-band canary: feed a unique
collaborator hostname into any parameter that looks like it takes a URL/host,
then check whether the target server made a DNS/HTTP request to that host. If it
did, the server can be coerced into making requests on your behalf.

This module identifies URL-ish parameters and injects a per-endpoint unique
subdomain of the configured Interactsh domain. Correlation of callbacks happens
in integrations/interactsh.py. We only ever point the target at our own
collaborator -- never at cloud metadata endpoints or internal ranges -- so the
probe proves the capability without pivoting anywhere sensitive.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

from .base import Scanner
from ..models import (Endpoint, Finding, IdentityRole, Severity, VulnClass)

_URLISH = re.compile(r"(url|uri|host|endpoint|callback|webhook|target|src|"
                     r"feed|proxy|dest|redirect|image|fetch|remote)", re.IGNORECASE)


class SsrfScanner(Scanner):
    name = "ssrf"
    vuln_classes = [VulnClass.SSRF.value]

    def __init__(self, *args, oob=None, **kwargs):
        super().__init__(*args, **kwargs)
        # oob is an InteractshClient (or None if integration disabled).
        self.oob = oob

    def applies_to(self, endpoint: Endpoint) -> bool:
        if any(_URLISH.search(str(qp.get("name", ""))) for qp in endpoint.query_params):
            return True
        return _URLISH.search(endpoint.path) is not None

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        identity = self.identities.get(IdentityRole.BACKEND.value) \
            or self.identities.get(IdentityRole.ANON.value)
        targets = [qp["name"] for qp in endpoint.query_params
                   if _URLISH.search(str(qp.get("name", "")))]
        for param in targets[:4]:
            yield from self._probe(endpoint, identity, param)

    def _probe(self, endpoint, identity, param) -> Iterable[Finding]:
        if not self.oob:
            # No OOB channel: we can still flag the surface for manual review.
            yield Finding(
                vuln_class=VulnClass.SSRF, severity=Severity.INFO,
                title=f"URL-accepting parameter '{param}' (manual SSRF review)",
                endpoint=endpoint.key,
                description=(
                    f"Parameter '{param}' on {endpoint.key} appears to accept a "
                    f"URL/host. No out-of-band channel is configured, so this is "
                    f"flagged for manual SSRF testing. Enable the Interactsh "
                    f"integration for automated blind-SSRF detection."),
                evidence=[], detail={"param": param}, confidence="tentative")
            return

        token, _host, oob_url = self.oob.new_canary()
        rec = self.fetch(endpoint, identity, params={param: oob_url})
        # Give the server a moment, then poll for interactions.
        hits = self.oob.poll_for(token, timeout_s=8)
        if hits:
            yield Finding(
                vuln_class=VulnClass.SSRF, severity=Severity.CRITICAL,
                title=f"Out-of-band SSRF via '{param}'",
                endpoint=endpoint.key,
                description=(
                    f"After supplying the collaborator URL {oob_url} to '{param}', "
                    f"the target server initiated {len(hits)} out-of-band "
                    f"interaction(s) to the canary host. This confirms server-"
                    f"side request forgery. The probe targeted only the "
                    f"collaborator, not any internal/metadata endpoint."),
                evidence=[rec],
                detail={"param": param, "canary": oob_url,
                        "interactions": hits[:5]},
                confidence="confirmed")
