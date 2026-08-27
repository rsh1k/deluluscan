"""OAuth / SSO misconfiguration scanner — account-takeover class.

Bugcrowd VRT rates "OAuth Misconfiguration resulting in Account Takeover" as P1.
The classic bugs: an authorization/SSO endpoint that accepts an attacker-
controlled redirect_uri (so the auth code/token is delivered to the attacker),
and a missing/undbound `state` parameter (login CSRF). This scanner finds the
relevant endpoints and tests redirect manipulation + state presence.

Detection only — it never completes an OAuth dance or captures a real token; it
observes whether the endpoint would redirect a code/token off-domain.
"""
from __future__ import annotations

from urllib.parse import urlparse
from typing import Iterable

from .base import Scanner
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

_EVIL = "https://evil.deluluscan-oob.example/cb"
_OAUTH_HINTS = ("oauth", "authorize", "authorization", "sso", "saml", "openid",
                "connect", "login", "dotsaml", "idp")
_REDIRECT_PARAMS = ("redirect_uri", "redirecturi", "redirect", "returnurl",
                    "return_to", "relaystate", "callback", "next", "service",
                    "continue", "target_url", "goto")


def _h(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


class OAuthScanner(Scanner):
    name = "oauth"
    vuln_classes = [VulnClass.AUTHZ.value, VulnClass.MISCONFIG.value]

    def applies_to(self, e: Endpoint) -> bool:
        p = e.path.lower()
        if not any(h in p for h in _OAUTH_HINTS):
            return False
        return e.method.upper() in ("GET", "POST")

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)
        if ident is None:
            return
        path = self.concrete_path(endpoint)
        param_names = [(p.get("name") or "") for p in (endpoint.query_params or [])]
        redirect_params = [p for p in param_names if p.lower() in _REDIRECT_PARAMS]
        # even if not declared, try the common ones on OAuth-looking endpoints
        if not redirect_params:
            redirect_params = ["redirect_uri", "redirect", "RelayState"]

        for rp in redirect_params[:4]:
            sep = "&" if "?" in path else "?"
            target = f"{path}{sep}{rp}={_EVIL}"
            rec = self.client.request("GET", target, identity_label=ident.label(),
                                      headers=self.auth.headers_for(ident),
                                      allow_redirects=False)
            if rec is None:
                continue
            loc = _h(rec.resp_headers, "location") or ""
            body = rec.resp_body or ""
            evil_host = urlparse(_EVIL).hostname
            # redirect (or embedded link) sends the flow to the attacker host
            if evil_host in loc or (evil_host in body and ("code=" in body or "token" in body.lower())):
                yield Finding(
                    vuln_class=VulnClass.AUTHZ, severity=Severity.HIGH,
                    title="OAuth/SSO open redirect_uri — auth code/token theft (ATO)",
                    endpoint=endpoint.key,
                    description=(f"The authorization/SSO endpoint accepted an attacker-"
                                 f"controlled '{rp}' and redirected the flow to "
                                 f"{evil_host}. In an OAuth/SSO login this delivers the "
                                 f"authorization code or token to the attacker, enabling "
                                 f"account takeover. Enforce an exact-match allowlist of "
                                 f"registered redirect URIs server-side."),
                    evidence=[rec],
                    detail={"test": "oauth_redirect", "active": True, "param": rp,
                            "location": loc[:120]}, confidence="firm")
                return

        # missing/undbound state (login CSRF) on an authorize endpoint
        if "authorize" in path.lower() or "oauth" in path.lower():
            if "state" not in [p.lower() for p in param_names]:
                rec = self.client.request("GET", path, identity_label=ident.label(),
                                          headers=self.auth.headers_for(ident),
                                          allow_redirects=False)
                if rec is not None and rec.status in (301, 302, 303, 307, 308):
                    yield Finding(
                        vuln_class=VulnClass.MISCONFIG, severity=Severity.MEDIUM,
                        title="OAuth authorize endpoint without a 'state' parameter (login CSRF)",
                        endpoint=endpoint.key,
                        description=("The authorization endpoint does not appear to require a "
                                     "'state' parameter, so the OAuth flow is not bound to the "
                                     "user's session — enabling login CSRF / forced-login "
                                     "attacks. Require and validate a per-session 'state'."),
                        evidence=[rec], detail={"test": "oauth_state", "active": True},
                        confidence="tentative")
