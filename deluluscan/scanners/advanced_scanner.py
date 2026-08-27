"""Scanner wrappers for the v0.6 advanced analyzers."""
from __future__ import annotations

from typing import Iterable

from .base import Scanner
from ..active.recon import (ParamMiner, ContentDiscovery, VersionEnumerator,
                            SupplyChainProbe)
from ..active.advanced import VerbTamper, RaceProbe, GraphQLAdvanced
from ..active.http_tools import RequestSpec, Repeater
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass


def _mk(vc, sev, title, endpoint, desc, evidence, detail, conf="firm", active=True):
    d = dict(detail)
    if active:
        d["active"] = True
    return Finding(vuln_class=vc, severity=sev, title=title, endpoint=endpoint,
                   description=desc, evidence=list(evidence), detail=d, confidence=conf)


def _anon_or_first(self):
    return self.identities.get(IdentityRole.ANON.value) or \
        next(iter(self.identities.values()), None)


# ---------------------------------------------------------------------------
# Content discovery + supply-chain exposure + version enumeration (API9/A03/A08)
# ---------------------------------------------------------------------------
class ContentDiscoveryScanner(Scanner):
    name = "content_discovery"
    vuln_classes = [VulnClass.INVENTORY.value, VulnClass.SUPPLY_CHAIN.value]

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._done = False

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if self._done:
            return
        self._done = True
        ident = _anon_or_first(self)
        label = ident.label() if ident else "anonymous"

        def send_path(p):
            return self.client.request("GET", p, identity_label=label)

        # shadow / undocumented endpoints (API9 improper inventory)
        for dp in ContentDiscovery().discover(send_path):
            yield _mk(VulnClass.INVENTORY, Severity.LOW,
                      f"Undocumented endpoint reachable: {dp.path}", f"GET {dp.path}",
                      f"{dp.detail}. Maintain an API inventory and retire shadow/"
                      f"debug/legacy endpoints.", [], {"test": "shadow_endpoint",
                      "path": dp.path, "status": dp.status})

        # supply-chain / integrity exposure (A03 / A08:2025)
        for ef in SupplyChainProbe().scan(send_path):
            sev = Severity.HIGH if ef.kind in ("vcs", "secrets", "backup") else Severity.MEDIUM
            yield _mk(VulnClass.SUPPLY_CHAIN, sev,
                      f"Sensitive artifact exposed: {ef.path}", f"GET {ef.path}",
                      f"{ef.detail}. Remove it from the web root / deny it at the edge.",
                      [], {"test": "artifact_exposure", "path": ef.path,
                           "kind": ef.kind, "status": ef.status})

        # API version enumeration (API9 deprecated/shadow versions)
        vf = VersionEnumerator().enumerate("/api/v1/users/current", send_path)
        if vf:
            yield _mk(VulnClass.INVENTORY, Severity.MEDIUM,
                      "Multiple API versions live", "/api/v{1..N}/users/current",
                      vf.detail, [], {"test": "version_sprawl", "live": vf.live_versions})


# ---------------------------------------------------------------------------
# Hidden parameter mining (Param Miner parity) — informational leads
# ---------------------------------------------------------------------------
class ParamMinerScanner(Scanner):
    name = "paramminer"
    vuln_classes = [VulnClass.MISCONFIG.value]

    def applies_to(self, e: Endpoint) -> bool:
        return e.method.upper() == "GET"

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = _anon_or_first(self)
        if ident is None:
            return
        baseline = self.fetch(endpoint, ident)

        def send_with_param(name, marker):
            return self.fetch(endpoint, ident, params={name: marker})

        for dp in ParamMiner().mine(send_with_param, baseline):
            # reflected params are the most useful (potential injection sinks)
            if dp.signal != "reflected":
                continue
            yield _mk(VulnClass.MISCONFIG, Severity.LOW,
                      f"Hidden reflected parameter: '{dp.name}'", endpoint.key,
                      f"{dp.detail}. Undocumented parameters widen the attack surface "
                      f"and may be injection sinks — review and lock down input handling.",
                      [], {"test": "hidden_param", "param": dp.name, "signal": dp.signal},
                      conf="tentative", active=False)


# ---------------------------------------------------------------------------
# HTTP verb / method tampering (function-level authz bypass, API5/A01)
# ---------------------------------------------------------------------------
class VerbTamperScanner(Scanner):
    name = "verbtamper"
    vuln_classes = [VulnClass.AUTHZ.value]

    def applies_to(self, e: Endpoint) -> bool:
        privileged = e.id_bearing or any(
            t in ("apps", "maintenance", "roles", "users", "system", "admin",
                  "workflow", "sites", "configuration") for t in e.tags)
        return privileged

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = _anon_or_first(self)
        label = ident.label() if ident else "anonymous"
        path = self.concrete_path(endpoint)

        def send(method, extra_headers):
            headers = dict(self.auth.headers_for(ident)) if ident else {}
            if extra_headers:
                headers.update(extra_headers)
            return self.client.request(method, path, identity_label=label, headers=headers)

        for vf in VerbTamper(send).test(endpoint.method):
            yield _mk(VulnClass.AUTHZ, Severity.HIGH,
                      f"HTTP method tampering bypass ({vf.technique})", endpoint.key,
                      f"{vf.detail}. Enforce authorization on the resource/action, not "
                      f"the HTTP verb, and reject unexpected methods.", [],
                      {"test": "verb_tamper", "technique": vf.technique,
                       "method": vf.method, "status": vf.status})


# ---------------------------------------------------------------------------
# Race conditions (business-logic TOCTOU, API6). Gated + bounded.
# ---------------------------------------------------------------------------
class RaceScanner(Scanner):
    name = "race"
    vuln_classes = [VulnClass.BUSINESS_LOGIC.value]

    _FLOW_WORDS = ("redeem", "coupon", "voucher", "purchase", "checkout", "order",
                   "transfer", "withdraw", "vote", "like", "follow", "apply",
                   "claim", "reset", "invite", "referral")

    def applies_to(self, e: Endpoint) -> bool:
        if not self.config.scan.allow_state_changing:
            return False
        if e.method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
            return False
        low = (e.path + " " + " ".join(e.tags)).lower()
        return any(w in low for w in self._FLOW_WORDS)

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = _anon_or_first(self)
        rep = Repeater(self.client)
        spec = RequestSpec(method=endpoint.method, path=self.concrete_path(endpoint),
                           headers=dict(self.auth.headers_for(ident)) if ident else {})
        label = ident.label() if ident else "anonymous"
        rf = RaceProbe().test(lambda: rep.send(spec, identity_label=label),
                              parallel=self.config.scan.race_parallel)
        if rf:
            yield _mk(VulnClass.BUSINESS_LOGIC, Severity.HIGH,
                      "Race condition / TOCTOU on a sensitive flow", endpoint.key,
                      f"{rf.detail}. Serialize the operation (idempotency keys, atomic "
                      f"checks, row locks) so it can't be won by parallel requests.",
                      [], {"test": "race_condition", "parallel": rf.parallel,
                           "successes": rf.successes})


# ---------------------------------------------------------------------------
# GraphQL deep abuse (batching / alias amplification / depth limit)
# ---------------------------------------------------------------------------
class GraphQLAdvScanner(Scanner):
    name = "graphql_adv"
    vuln_classes = [VulnClass.GRAPHQL.value]

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._done = False

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if self._done:
            return
        self._done = True
        ident = _anon_or_first(self)
        label = ident.label() if ident else "anonymous"
        for path in ("/api/graphql", "/graphql", "/api/v1/graphql"):
            probe_rec = self.client.request("POST", path, identity_label=label,
                                            headers={"Content-Type": "application/json"},
                                            data='{"query":"{__typename}"}')
            if probe_rec.status not in (200, 400):
                continue

            def send_body(raw):
                return self.client.request("POST", path, identity_label=label,
                                           headers={"Content-Type": "application/json"},
                                           data=raw)

            for gf in GraphQLAdvanced().test(send_body):
                sev = Severity.MEDIUM if gf.kind != "no_depth_limit" else Severity.LOW
                yield _mk(VulnClass.GRAPHQL, sev,
                          {"batching": "GraphQL query batching enabled",
                           "alias_amplification": "GraphQL alias amplification",
                           "no_depth_limit": "GraphQL missing depth/complexity limit"}[gf.kind],
                          f"POST {path}", f"{gf.detail}.", [],
                          {"test": f"graphql_{gf.kind}", "path": path})
            return
