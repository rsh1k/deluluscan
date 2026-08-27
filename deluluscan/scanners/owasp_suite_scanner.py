"""Scanner wrappers exposing the v0.5 OWASP-coverage analyzers to the pipeline.

Each is registered under its own name so it can be selected via config/CLI, and
each tags findings as active so the verification layer treats them as confirmed-
by-exercise rather than re-judging them with passive heuristics.
"""
from __future__ import annotations

import json
from typing import Iterable

from .base import Scanner
from ..active.owasp_suite import (AuthorizationMatrix, PropertyMiner, TokenSequencer,
                                  FaultProbe, FlowProbe, GraphQLProbe, malformed_probes)
from ..active.http_tools import RequestSpec, Repeater
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

_RANK = {IdentityRole.ANON.value: 0, IdentityRole.BACKEND.value: 1,
         IdentityRole.ADMIN.value: 2}


def _mk(vc, sev, title, endpoint, desc, evidence, detail, conf="firm"):
    detail = dict(detail); detail["active"] = True
    return Finding(vuln_class=vc, severity=sev, title=title, endpoint=endpoint,
                   description=desc, evidence=list(evidence), detail=detail, confidence=conf)


# ---------------------------------------------------------------------------
# API1 / API5 / A01 — authorization matrix (Autorize/AuthMatrix parity)
# ---------------------------------------------------------------------------
class AuthMatrixScanner(Scanner):
    name = "authmatrix"
    vuln_classes = [VulnClass.AUTHZ.value]

    def applies_to(self, e: Endpoint) -> bool:
        return e.method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE")

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if endpoint.method.upper() in ("DELETE", "PUT", "PATCH") and \
                not self.config.scan.allow_state_changing:
            return
        # Only endpoints that are supposed to be access-controlled — public
        # endpoints legitimately return the same content to everyone.
        privileged = endpoint.id_bearing or any(
            t in ("apps", "maintenance", "roles", "users", "system", "configuration",
                  "admin", "workflow", "sites") for t in endpoint.tags)
        if not privileged:
            return
        idents = {label: self.auth.headers_for(ident)
                  for label, ident in self.identities.items()}
        recs: dict = {}

        def send(_key, label, headers):
            rec = self.fetch(endpoint, self.identities[label])
            recs[label] = rec
            return rec

        matrix = AuthorizationMatrix(send, _RANK)
        res = matrix.test(endpoint.key, idents)
        if not res:
            return
        ev = [recs[res.reference_identity]] + [recs[b] for b in res.bypass_identities if b in recs]
        yield _mk(VulnClass.AUTHZ, Severity.HIGH,
                  "Broken access control (authorization matrix bypass)",
                  endpoint.key,
                  f"Access-control matrix shows a bypass: {res.detail} Reference "
                  f"identity: '{res.reference_identity}'. This is BOLA/BFLA — "
                  f"authorization must be enforced server-side per role and per object.",
                  ev, {"test": "authz_matrix_bypass",
                       "reference": res.reference_identity,
                       "bypass_identities": res.bypass_identities,
                       "matrix": [c.__dict__ for c in res.cells]})


# ---------------------------------------------------------------------------
# API3 / BOPLA — excessive data exposure + mass assignment
# ---------------------------------------------------------------------------
class BoplaMinerScanner(Scanner):
    name = "bopla_miner"
    vuln_classes = [VulnClass.BOPLA.value]

    def applies_to(self, e: Endpoint) -> bool:
        return e.method.upper() in ("GET", "POST", "PUT", "PATCH")

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)
        if ident is None:
            return
        rec = self.fetch(endpoint, ident)
        miner = PropertyMiner()
        # excessive data exposure (does the response leak sensitive properties?)
        for pf in miner.check_excessive_data(rec.resp_body, rec.status):
            yield _mk(VulnClass.BOPLA, Severity.HIGH,
                      f"Excessive data exposure: '{pf.field}'", endpoint.key,
                      f"{pf.detail}. Return role-scoped response schemas so callers "
                      f"only receive properties they're authorized to see.",
                      [rec], {"test": "excessive_data", "field": pf.field})
        # mass assignment on writes
        if endpoint.method.upper() in ("POST", "PUT", "PATCH") and \
                self.config.scan.allow_state_changing:
            try:
                readable = set(json.loads(rec.resp_body).keys()) if rec.resp_body else set()
            except Exception:
                readable = set()
            rep = Repeater(self.client)
            base = RequestSpec(method=endpoint.method,
                               path=self.concrete_path(endpoint),
                               headers=dict(self.auth.headers_for(ident)),
                               json_body={})

            def send_write(fieldname, value):
                spec = base.with_json_field(fieldname, value)
                return rep.send(spec, identity_label=ident.label())

            for pf in PropertyMiner(send_write).check_mass_assignment(readable | {"isadmin", "roleid"}):
                yield _mk(VulnClass.BOPLA, Severity.HIGH,
                          f"Mass assignment: '{pf.field}'", endpoint.key,
                          f"{pf.detail}. Bind writable fields with an explicit "
                          f"allowlist; never map the raw request body onto the model.",
                          [rec], {"test": "mass_assignment", "field": pf.field})


# ---------------------------------------------------------------------------
# Broken auth / A04 — token entropy (Burp Sequencer parity)
# ---------------------------------------------------------------------------
class SequencerScanner(Scanner):
    name = "sequencer"
    vuln_classes = [VulnClass.CRYPTO.value]

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._done = False

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if self._done:
            return
        self._done = True
        # Collect a bounded set of freshly issued tokens by re-authenticating.
        ident = self.identities.get(IdentityRole.BACKEND.value) or \
            self.identities.get(IdentityRole.ADMIN.value)
        if not ident or not ident.username:
            return
        tokens = []
        for _ in range(8):
            jwt = self.auth._login(ident)  # bounded re-login to sample tokens
            if jwt:
                tokens.append(jwt)
        report = TokenSequencer().analyze(tokens)
        if not report or report.verdict == "strong":
            return
        sev = Severity.HIGH if report.verdict == "predictable" else Severity.MEDIUM
        yield _mk(VulnClass.CRYPTO, sev,
                  f"Session token entropy is {report.verdict}", "(auth tokens)",
                  f"Analyzed {report.n} session tokens: {report.detail}. Predictable "
                  f"or low-entropy tokens enable session guessing/fixation.",
                  [], {"test": f"token_{report.verdict}", "report": report.__dict__},
                  conf="firm")


# ---------------------------------------------------------------------------
# A10:2025 — mishandling of exceptional conditions
# ---------------------------------------------------------------------------
class FaultScanner(Scanner):
    name = "faults"
    vuln_classes = [VulnClass.ERROR_HANDLING.value]

    def applies_to(self, e: Endpoint) -> bool:
        return e.method.upper() in ("GET", "POST", "PUT", "PATCH")

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)
        if ident is None:
            return
        auth_required = endpoint.id_bearing or any(
            t in ("apps", "maintenance", "roles", "users", "system") for t in endpoint.tags)
        probe = FaultProbe()
        seen = set()
        rep = Repeater(self.client)
        for name, payload in malformed_probes():
            spec = RequestSpec(method=endpoint.method,
                               path=self.concrete_path(endpoint),
                               headers=dict(self.auth.headers_for(ident)))
            if endpoint.method.upper() == "GET":
                spec.params = {"q": payload if isinstance(payload, str) else json.dumps(payload)}
            else:
                spec.json_body = payload if isinstance(payload, dict) else None
                if isinstance(payload, str):
                    spec.data = payload
            rec = rep.send(spec, identity_label=ident.label())
            for ff in probe.classify(name, rec, auth_required):
                if ff.kind in seen:
                    continue
                seen.add(ff.kind)
                sev = Severity.MEDIUM if ff.kind == "verbose_error" else (
                    Severity.HIGH if ff.kind == "fail_open" else Severity.LOW)
                yield _mk(VulnClass.ERROR_HANDLING, sev,
                          {"verbose_error": "Verbose error / stack trace disclosure",
                           "server_error": "Unhandled server error on malformed input",
                           "fail_open": "Possible fail-open on malformed input"}[ff.kind],
                          endpoint.key, f"{ff.detail} (probe: {ff.probe}). Fail closed, "
                          f"validate input, and return generic errors without internals.",
                          [rec], {"test": ff.kind, "probe": ff.probe})


# ---------------------------------------------------------------------------
# API4 / API6 — resource consumption + business-flow abuse (bounded & safe)
# ---------------------------------------------------------------------------
class FlowScanner(Scanner):
    name = "flows"
    vuln_classes = [VulnClass.RATE_LIMIT.value, VulnClass.BUSINESS_LOGIC.value]

    _SENSITIVE = ("authentication", "login", "register", "signup", "password",
                  "reset", "forgot", "token", "otp", "email", "sms")

    def applies_to(self, e: Endpoint) -> bool:
        low = (e.path + " " + " ".join(e.tags)).lower()
        return any(s in low for s in self._SENSITIVE) or bool(
            [p for p in e.query_params if p.get("name", "").lower() in ("limit", "size", "pagesize", "per_page")])

    @staticmethod
    def _has_ratelimit_header(rec) -> bool:
        if rec is None:
            return False
        for k in (rec.resp_headers or {}):
            kl = k.lower()
            if kl.startswith("x-dotratelimit") or kl.startswith("x-ratelimit") \
                    or kl.startswith("ratelimit") or kl == "retry-after" \
                    or kl == "x-rate-limit-limit":
                return True
        return False

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)
        if ident is None:
            return
        rep = Repeater(self.client)
        flow = FlowProbe()
        low = (endpoint.path + " " + " ".join(endpoint.tags)).lower()

        # rate limit on AUTHENTICATION flows only (login/token/reset/register/mfa).
        # Missing rate limiting is only security-relevant on credential/anti-
        # automation flows; on ordinary endpoints it is usually intentional. A
        # bounded burst also cannot *prove* absence, so we (a) only look at auth
        # flows and (b) skip entirely if the server exposes a rate-limit budget
        # header (it HAS a limiter; our small burst just didn't exhaust it).
        _AUTH_FLOW = ("authentication", "/login", "api-token", "jwt", "forgotpassword",
                      "forgot-password", "resetpassword", "reset-password", "/reset",
                      "/register", "signup", "/mfa", "/otp", "/2fa")
        if any(s in low for s in _AUTH_FLOW):
            spec = RequestSpec(method=endpoint.method, path=self.concrete_path(endpoint),
                               headers=dict(self.auth.headers_for(ident)))
            first = rep.send(spec, identity_label=ident.label())
            if not self._has_ratelimit_header(first):
                ff = flow.check_rate_limit(lambda: rep.send(spec, identity_label=ident.label()),
                                           burst=self.config.scan.flow_burst)
                if ff:
                    yield _mk(VulnClass.RATE_LIMIT, Severity.LOW,
                              "No rate limiting observed on an authentication flow", endpoint.key,
                              f"{ff.detail}. A bounded {self.config.scan.flow_burst}-request burst "
                              f"was not throttled and no rate-limit header was returned. This is a "
                              f"candidate only — a short burst cannot prove the absence of rate "
                              f"limiting (limits may apply at higher volumes, per-IP, or upstream). "
                              f"Confirm before reporting; add anti-automation (captcha, lockout, "
                              f"step-up) if genuinely absent.", [],
                              {"test": "no_rate_limit", **ff.detail_data})

        # pagination cap
        limit_param = next((p.get("name") for p in endpoint.query_params
                            if p.get("name", "").lower() in ("limit", "size", "pagesize", "per_page")), None)
        if limit_param:
            def send_with_limit(n):
                spec = RequestSpec(method=endpoint.method, path=self.concrete_path(endpoint),
                                   headers=dict(self.auth.headers_for(ident)),
                                   params={limit_param: n})
                return rep.send(spec, identity_label=ident.label())
            ff = flow.check_pagination_cap(send_with_limit)
            if ff:
                yield _mk(VulnClass.RATE_LIMIT, Severity.LOW,
                          "No server-side page-size cap", endpoint.key,
                          f"{ff.detail}. Enforce a maximum page size server-side.", [],
                          {"test": "no_pagination_cap", **ff.detail_data})


# ---------------------------------------------------------------------------
# GraphQL introspection
# ---------------------------------------------------------------------------
class GraphQLScanner(Scanner):
    name = "graphql"
    vuln_classes = [VulnClass.GRAPHQL.value]

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._done = False

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if self._done:
            return
        self._done = True
        ident = self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)
        probe = GraphQLProbe()
        for path in ("/api/graphql", "/graphql", "/api/v1/graphql"):
            rec = self.client.request("POST", path,
                                      identity_label=ident.label() if ident else "anonymous",
                                      headers={"Content-Type": "application/json"},
                                      data=probe.introspection_query())
            gf = probe.classify_introspection(rec)
            if gf:
                yield _mk(VulnClass.GRAPHQL, Severity.MEDIUM,
                          "GraphQL introspection enabled", f"POST {path}",
                          f"{gf.detail}. Disable introspection in production and enforce "
                          f"query depth/complexity limits to prevent schema disclosure "
                          f"and nested-query resource abuse.", [rec],
                          {"test": "graphql_introspection", "path": path})
                return
