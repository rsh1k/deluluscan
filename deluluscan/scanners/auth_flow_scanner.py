"""Authentication-flow scanner — password-reset / account-takeover classes.

HackerOne's top business-logic reports are dominated by account-takeover chains
via the password-reset and email-change flows. This scanner probes those flows
for the classic issues:
  * Host-header injection in the reset flow (poisoned reset link -> ATO).
  * Reset token leaked in the response body.
  * Email change without password re-authentication (ATO primitive).

Detection only — it triggers the flow with a benign/nonexistent account and a
canary host; it never takes over a real account.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

from .base import Scanner
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

_CANARY_HOST = "deluluscan-reset-canary.example"
_RESET_PATHS = ["/api/v1/forgotpassword", "/api/v1/users/forgotpassword",
                "/api/v1/forgot-password", "/api/v1/authentication/forgotpassword"]
_TOKEN_RE = re.compile(r"(?i)(reset[_-]?token|token|code)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})")


def _h(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


class AuthFlowScanner(Scanner):
    name = "authflow"
    vuln_classes = [VulnClass.AUTHZ.value, VulnClass.BUSINESS_LOGIC.value]

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._done = False

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if self._done:
            return
        self._done = True
        anon = self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)
        if anon is None:
            return
        yield from self._reset_flow(anon)
        yield from self._email_change()

    def _reset_flow(self, anon) -> Iterable[Finding]:
        bogus = "deluluscan-nouser@example.com"
        for path in _RESET_PATHS:
            headers = dict(self.auth.headers_for(anon))
            headers["Host"] = _CANARY_HOST
            headers["X-Forwarded-Host"] = _CANARY_HOST
            rec = self.client.request("POST", path, identity_label="anonymous",
                                      headers=headers, json_body={"email": bogus,
                                                                  "userId": bogus})
            if rec is None or rec.status in (0, 404):
                continue
            body = rec.resp_body or ""
            # host-header poisoning: canary reflected back (would land in the email link)
            if _CANARY_HOST in body or _CANARY_HOST in str(rec.resp_headers):
                yield self._f(Severity.HIGH,
                    "Password-reset host-header poisoning (account takeover vector)",
                    f"POST {path}", rec,
                    f"The reset flow reflects the attacker-controlled Host/X-Forwarded-Host "
                    f"({_CANARY_HOST}). If the reset email builds its link from this header, an "
                    f"attacker triggers a reset for a victim and receives the reset token when "
                    f"the victim clicks — full account takeover. Build reset links from a fixed, "
                    f"server-side base URL.", "reset_host_poisoning")
            # token leaked directly in the response
            m = _TOKEN_RE.search(body)
            if m and len(m.group(2)) >= 16:
                yield self._f(Severity.HIGH,
                    "Password-reset token disclosed in API response",
                    f"POST {path}", rec,
                    "The forgot-password response body contains what appears to be the reset "
                    "token/code. Anyone who can trigger a reset for a victim can read the token "
                    "and take over the account. The token must only be delivered out-of-band "
                    "(email), never in the API response.", "reset_token_leak")
            return  # a live reset endpoint was found and probed; stop

    def _email_change(self) -> Iterable[Finding]:
        if not self.config.scan.allow_state_changing:
            return
        ident = self.identities.get(IdentityRole.BACKEND.value)
        if ident is None:
            return
        import json
        headers = dict(self.auth.headers_for(ident))
        who = self.client.request("GET", "/api/v1/users/current",
                                  identity_label=ident.label(), headers=headers)
        if who is None or who.status != 200:
            return
        try:
            uid = json.loads(who.resp_body).get("userId") or \
                json.loads(who.resp_body).get("entity", {}).get("userId")
        except Exception:
            return
        if not uid:
            return
        # attempt to change email WITHOUT supplying currentPassword
        rec = self.client.request("PUT", "/api/v1/users/current",
                                  identity_label=ident.label(), headers=headers,
                                  json_body={"userId": uid, "email": "deluluscan-changed@example.com"})
        from ..verify import evidence as E
        if rec and rec.status < 400 and E.classify_response(rec) != E.DISPOSITION_DENIED \
                and "password" not in (rec.resp_body or "").lower():
            yield self._f(Severity.MEDIUM,
                "Email change without password re-authentication",
                "PUT /api/v1/users/current", rec,
                "The account email was updated without requiring the current password. Combined "
                "with a password-reset flow this enables account takeover of a hijacked session "
                "and weakens the identity binding. Require password (or step-up auth) for email "
                "changes. (Scanner set a benign placeholder email on its OWN account.)",
                "email_change_no_reauth")

    def _f(self, sev, title, endpoint, rec, desc, test):
        return Finding(vuln_class=VulnClass.AUTHZ, severity=sev, title=title,
                       endpoint=endpoint, description=desc, evidence=[rec],
                       detail={"test": test, "active": True}, confidence="tentative")
