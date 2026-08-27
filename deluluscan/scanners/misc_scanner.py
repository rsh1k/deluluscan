"""Active CORS + CSRF checks (v0.9).

CORS: passive checks only see the headers on normal responses. The active check
sends a crafted ``Origin`` and observes whether the server *reflects* it with
credentials allowed — the exploitable configuration (a malicious site can read
authenticated responses).

CSRF: only meaningful for cookie/ambient-auth sessions. We flag a state-changing
endpoint when it is reachable with a cross-site ``Origin`` and no anti-CSRF token
while the session is cookie-based. Bearer-token (JWT-in-header) APIs are not
CSRF-able, so those are skipped to avoid false positives.
"""
from __future__ import annotations

from typing import Iterable

from .base import Scanner
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

_EVIL_ORIGIN = "https://evil.deluluscan-oob.example"


def _h(headers: dict, name: str):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


class CorsScanner(Scanner):
    name = "cors"
    vuln_classes = [VulnClass.MISCONFIG.value]

    def applies_to(self, e: Endpoint) -> bool:
        return e.method.upper() == "GET"

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self.identities.get(IdentityRole.BACKEND.value) or \
            self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)
        if ident is None:
            return
        path = self.concrete_path(endpoint)
        headers = dict(self.auth.headers_for(ident))
        headers["Origin"] = _EVIL_ORIGIN
        rec = self.client.request(endpoint.method, path,
                                  identity_label=ident.label(), headers=headers)
        if rec is None or rec.status == 0:
            return
        acao = _h(rec.resp_headers, "access-control-allow-origin") or ""
        acac = (_h(rec.resp_headers, "access-control-allow-credentials") or "").lower()

        reflects = acao == _EVIL_ORIGIN or (acao == "*" )
        if acao == _EVIL_ORIGIN and acac == "true":
            yield self._f(Severity.HIGH,
                "CORS reflects arbitrary Origin with credentials", endpoint, rec,
                f"The server reflected our attacker Origin ({_EVIL_ORIGIN}) in "
                f"Access-Control-Allow-Origin AND set Allow-Credentials: true. Any "
                f"malicious site can read this user's authenticated responses "
                f"cross-origin — sensitive data exposure / session-scoped theft.",
                "cors_reflect_credentials", "firm")
        elif acao == _EVIL_ORIGIN:
            yield self._f(Severity.MEDIUM,
                "CORS reflects arbitrary Origin", endpoint, rec,
                "The server reflects any supplied Origin in Access-Control-Allow-"
                "Origin. Without credentials the impact is limited, but it enables "
                "cross-origin reads of any non-credentialed data and is a "
                "misconfiguration.", "cors_reflect", "firm")

    def _f(self, sev, title, endpoint, rec, desc, test, conf):
        return Finding(vuln_class=VulnClass.MISCONFIG, severity=sev, title=title,
                       endpoint=endpoint.key, description=desc, evidence=[rec],
                       detail={"test": test, "active": True}, confidence=conf)


class CsrfScanner(Scanner):
    name = "csrf"
    vuln_classes = [VulnClass.MISCONFIG.value]

    def applies_to(self, e: Endpoint) -> bool:
        return e.method.upper() in ("POST", "PUT", "PATCH", "DELETE")

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if not self.config.scan.allow_state_changing:
            return
        ident = self.identities.get(IdentityRole.BACKEND.value) or \
            self.identities.get(IdentityRole.ADMIN.value)
        if ident is None:
            return
        headers = dict(self.auth.headers_for(ident))
        # CSRF only applies to ambient/cookie auth. If auth is a bearer token in a
        # header (not a cookie), the request is not CSRF-able -> skip (no FP).
        cookie_based = any(k.lower() == "cookie" for k in headers) and \
            not any(k.lower() == "authorization" for k in headers)
        if not cookie_based:
            return
        path = self.concrete_path(endpoint)
        headers["Origin"] = _EVIL_ORIGIN
        # strip common anti-CSRF headers to simulate a cross-site forged request
        for k in list(headers):
            if k.lower() in ("x-csrf-token", "x-xsrf-token", "csrf-token", "x-requested-with"):
                headers.pop(k)
        rec = self.client.request(endpoint.method, path,
                                  identity_label=ident.label(), headers=headers,
                                  json_body={})
        if rec is None:
            return
        from ..verify import evidence as E
        if E.classify_response(rec) == E.DISPOSITION_CONTENT and rec.status < 400:
            yield Finding(vuln_class=VulnClass.MISCONFIG, severity=Severity.MEDIUM,
                title="Possible CSRF: state-changing request accepted cross-site",
                endpoint=endpoint.key,
                description=("A cookie-authenticated, state-changing request succeeded "
                             f"with a cross-site Origin ({_EVIL_ORIGIN}) and no anti-CSRF "
                             "token. If the session rides on cookies with SameSite=None/"
                             "absent, this is exploitable via CSRF. Verify the SameSite "
                             "attribute and enforce a per-request CSRF token."),
                evidence=[rec], detail={"test": "csrf", "active": True},
                confidence="tentative")
