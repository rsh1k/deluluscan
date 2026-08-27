"""Active JWT + authorization scanner.

Wraps the active workbench (jwt_lab, authz_probe) as a Scanner so its results
flow through the normal pipeline: verification, sorting, and reporting. It runs
the JWT validation battery once (server-wide) using a protected endpoint as the
oracle, and runs authorization manipulations per applicable endpoint.

Needs at least one authenticated identity carrying a JWT (bearer token or a
session established via login). With no credentials it is a no-op. Authorized
target only — the HttpClient safety gate applies to every request it sends.
"""
from __future__ import annotations

from typing import Iterable, Optional

from .base import Scanner
from ..ai.analyst import AIAnalyst
from ..active.http_tools import RequestSpec, Repeater
from ..active.jwt_lab import JwtLab
from ..active.authz_probe import AuthzProbe
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

# test name -> (severity, title prefix)
_JWT_SEV = {
    "alg_none": (Severity.CRITICAL, "JWT accepted with alg:none (no signature)"),
    "strip_signature": (Severity.CRITICAL, "JWT accepted with stripped signature"),
    "tamper_signature": (Severity.CRITICAL, "JWT signature not verified"),
    "alg_confusion_rs_to_hs": (Severity.CRITICAL, "JWT RS256->HS256 algorithm confusion"),
    "weak_secret": (Severity.HIGH, "JWT signed with a weak/guessable secret"),
    "claim_tamper": (Severity.CRITICAL, "JWT claim tampering / privilege escalation"),
}
_AUTHZ_SEV = {
    "missing_auth": (Severity.CRITICAL, "Protected resource served without authentication"),
    "identity_swap": (Severity.HIGH, "Resource reachable by a different identity (BFLA)"),
    "bola_id_swap": (Severity.HIGH, "Object reachable by id from another principal (BOLA)"),
    "mass_assignment": (Severity.HIGH, "Mass assignment: elevated field accepted on write"),
}


class JwtActiveScanner(Scanner):
    name = "jwt"
    vuln_classes = [VulnClass.AUTHZ.value]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._jwt_done = False
        self.repeater = Repeater(self.client)
        self.probe = AuthzProbe(self.client)
        try:
            self.ai = AIAnalyst(self.config.ai)
        except Exception:
            self.ai = None

    # --- helpers -----------------------------------------------------------
    def _auth_identity(self):
        for role in (IdentityRole.BACKEND, IdentityRole.ADMIN):
            ident = self.identities.get(role.value)
            if ident and (ident.username or ident.bearer_token):
                return ident
        return None

    def _bearer_token(self, ident) -> Optional[str]:
        headers = self.auth.headers_for(ident)
        auth = headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[len("Bearer "):]
        return ident.session_jwt or ident.bearer_token

    def applies_to(self, endpoint: Endpoint) -> bool:
        return endpoint.method.upper() in ("GET", "POST", "PUT", "PATCH")

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self._auth_identity()
        if not ident:
            return  # active auth testing needs credentials you control

        # -- JWT battery: run once, server-wide -----------------------------
        if not self._jwt_done:
            self._jwt_done = True
            yield from self._run_jwt(ident)

        # -- per-endpoint authorization manipulations -----------------------
        yield from self._run_authz(endpoint, ident)

    def _tag(self, f: Finding) -> Finding:
        f.detail["active"] = True
        return f

    # --- JWT ---------------------------------------------------------------
    def _run_jwt(self, ident) -> Iterable[Finding]:
        token = self._bearer_token(ident)
        if not token or token.count(".") < 2:
            return  # not a JWT we can manipulate

        oracle_path = "/api/v1/users/current"
        good = self.client.request("GET", oracle_path,
                                   identity_label=ident.label(),
                                   headers={"Authorization": f"Bearer {token}"})
        denied = self.client.request("GET", oracle_path, identity_label="anonymous")
        if good.status != 200:
            return  # can't establish an oracle to judge acceptance

        def send_with_token(tok: str):
            return self.client.request("GET", oracle_path,
                                       identity_label="jwt-test",
                                       headers={"Authorization": f"Bearer {tok}"})

        pub = getattr(self.config, "jwt_public_key", None)
        lab = JwtLab(send_with_token, good, denied, public_key_pem=pub)
        for r in lab.run(token):
            if not r.accepted:
                continue
            base = r.test.split(":")[0]
            sev, title = _JWT_SEV.get(base, (Severity.HIGH, f"JWT issue: {r.test}"))
            ev = send_with_token("<tampered-token-not-stored>")  # reproduce shape (no token leak)
            yield self._tag(Finding(
                vuln_class=VulnClass.AUTHZ, severity=sev,
                title=title, endpoint=f"GET {oracle_path}",
                description=(
                    f"The server accepted a tampered JWT ({r.detail}). This means "
                    f"token validation is broken: an attacker can mint or alter "
                    f"tokens the server will trust. Rotate keys, enforce a strict "
                    f"algorithm allowlist, and verify the signature and expiry."),
                evidence=[good, ev],
                detail={"test": r.test, "token_snippet": r.token_snippet,
                        "claim_changes": r.claim_changes,
                        "evidence_status": r.evidence_status},
                confidence="firm"))

    # --- active authorization ---------------------------------------------
    def _run_authz(self, endpoint: Endpoint, ident) -> Iterable[Finding]:
        headers = self.auth.headers_for(ident)
        spec = RequestSpec(method=endpoint.method,
                           path=self.concrete_path(endpoint),
                           headers=dict(headers))
        good = self.repeater.send(spec, identity_label=ident.label())
        if good.status not in (200, 201):
            return  # nothing authorized to compare against here

        # plan (AI-ordered when enabled; deterministic otherwise)
        plan = self.ai.plan_active({"endpoint": endpoint.key,
                                    "id_bearing": endpoint.id_bearing,
                                    "tags": endpoint.tags}) if self.ai else []

        # 1) missing auth — only meaningful on endpoints that should be gated
        #    (id-bearing or privileged); public endpoints legitimately need none.
        privileged = endpoint.id_bearing or any(
            t in ("apps", "maintenance", "roles", "users", "system", "configuration")
            for t in endpoint.tags)
        if privileged and (not plan or "authz_missing_auth" in plan):
            res = self.probe.test_missing_auth(spec, good)
            if res.granted:
                sev, title = _AUTHZ_SEV["missing_auth"]
                yield self._tag(self._authz_finding(endpoint, res, sev, title, good))

        # 2) identity swap to a lower-privilege identity
        other = self.identities.get(IdentityRole.ANON.value)
        lower = self.identities.get(IdentityRole.BACKEND.value)
        swap_target = None
        if ident.role is IdentityRole.ADMIN and lower:
            swap_target = (IdentityRole.BACKEND.value, self.auth.headers_for(lower))
        if swap_target and (not plan or "authz_identity_swap" in plan):
            res = self.probe.test_identity_swap(spec, good, swap_target[0], swap_target[1])
            if res.granted:
                sev, title = _AUTHZ_SEV["identity_swap"]
                yield self._tag(self._authz_finding(endpoint, res, sev, title, good))

        # 3) mass assignment on writes (report the first accepted field)
        if endpoint.method.upper() in ("POST", "PUT", "PATCH") and (
                not plan or "mass_assignment" in plan):
            for res in self.probe.test_mass_assignment(spec, ident.label(), headers):
                if res.granted:
                    sev, title = _AUTHZ_SEV["mass_assignment"]
                    yield self._tag(self._authz_finding(endpoint, res, sev, title, good))
                    break

    def _authz_finding(self, endpoint, res, sev, title, good) -> Finding:
        note = ""
        if self.ai and self.ai.enabled:
            note = self.ai.interpret_active({"test": res.test, "detail": res.detail,
                                             "endpoint": endpoint.key})
        return Finding(
            vuln_class=VulnClass.AUTHZ, severity=sev, title=title,
            endpoint=endpoint.key,
            description=(f"Active test '{res.test}': {res.detail}. Confirmed by "
                         f"replaying the request with the manipulation and "
                         f"observing that access was still granted."),
            evidence=[good], detail={"test": res.test, "status": res.status,
                                     "similarity": res.similarity,
                                     "changes": res.changes},
            confidence="firm", ai_notes=note)
