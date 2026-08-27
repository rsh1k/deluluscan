"""BOPLA — Broken Object Property Level Authorization (OWASP API3:2023).

Two complementary checks, mapping to the two halves of API3:

1. **Excessive data exposure (read side, always-on, non-mutating).** For the
   same object, compare the JSON *fields* returned to admin vs to a lower-priv
   identity. If a lower-priv identity receives properties that look sensitive
   (password/hash/token/secret/ssn/key/salt/apikey), or receives the same rich
   field set an admin does, that's a property-level over-exposure candidate.

2. **Mass assignment (write side, OPT-IN + self-owned only).** On the
   authenticated identity's OWN object (e.g. /users/current), submit extra
   server-controlled properties the schema never invited — `admin: true`,
   `roles: [...]`, `active: true` — using clearly inert sentinel values, then
   read the object back. If the injected property is reflected/persisted, the
   endpoint binds unvetted client input (mass assignment). This only ever
   touches the tester's own object and only runs when allow_state_changing is
   set; it does NOT escalate privileges — it writes a recognizable sentinel and
   checks whether it stuck, then reports. Verification/cleanup is left to you.

Reference: OWASP API Security Top 10 (2023) API3:2023.
"""
from __future__ import annotations

import json
import re
from typing import Iterable

from .base import Scanner, canary
from ..models import (Endpoint, Finding, IdentityRole, Severity, VulnClass)

_SENSITIVE_FIELD = re.compile(
    r"(?i)(password|passwd|pwd|hash|salt|secret|token|api[_-]?key|"
    r"ssn|social.?security|private[_-]?key|access[_-]?key|client[_-]?secret)")

# server-controlled properties an attacker would try to set via mass assignment
_MASS_ASSIGN_PROBES = {
    "admin": True, "isAdmin": True, "roles": ["deluluscan-sentinel-role"],
    "active": True, "emailVerified": True,
}


class BoplaScanner(Scanner):
    name = "bopla"
    vuln_classes = [VulnClass.AUTHZ.value, VulnClass.INFO_LEAK.value]

    @staticmethod
    def _self_owned(endpoint: Endpoint) -> bool:
        """Write endpoints that act on the caller's OWN object — the only ones
        the mass-assignment probe will touch (never another user's data)."""
        p = endpoint.path.rstrip("/")
        return p.endswith(("/current", "/me", "/self"))

    def applies_to(self, endpoint: Endpoint) -> bool:
        m = endpoint.method.upper()
        # read side: id-bearing GETs; write side: PUT/POST to self-owned objects
        if m == "GET" and endpoint.id_bearing:
            return True
        if m in ("PUT", "POST") and self._self_owned(endpoint):
            return True
        return False

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if endpoint.method.upper() == "GET":
            yield from self._excessive_exposure(endpoint)
        else:
            yield from self._mass_assignment(endpoint)

    # ---- read side: excessive data exposure ------------------------------
    def _excessive_exposure(self, endpoint: Endpoint) -> Iterable[Finding]:
        admin = self.identities.get(IdentityRole.ADMIN.value)
        lower = (self.identities.get(IdentityRole.BACKEND.value)
                 or self.identities.get(IdentityRole.ANON.value))
        if not lower:
            return
        lo = self.fetch(endpoint, lower)
        if lo.status != 200 or not lo.resp_body.strip().startswith(("{", "[")):
            return
        # flag only sensitive-looking fields that carry a REAL, non-masked value —
        # a field named "token"/"apiKey" set to null/""/masked is not a leak.
        from ..active.owasp_suite import _flatten_items, _is_masked_value
        try:
            import json as _json
            sensitive = sorted({k for k, v in _flatten_items(_json.loads(lo.resp_body))
                                if _SENSITIVE_FIELD.search(k) and not _is_masked_value(v)})
        except Exception:
            sensitive = []
        if sensitive:
            yield Finding(
                vuln_class=VulnClass.INFO_LEAK, severity=Severity.HIGH,
                title=f"Sensitive properties exposed to {lower.label()}",
                endpoint=endpoint.key,
                description=(
                    f"The response to the {lower.label()} identity includes sensitive "
                    f"properties with real (non-masked) values: {', '.join(sensitive[:8])}. "
                    f"This caller likely shouldn't see them — broken object property-level "
                    f"authorization / excessive data exposure (API3:2023)."),
                evidence=[lo], detail={"sensitive_fields": sensitive},
                confidence="tentative")

        lo_keys = _json_keys(lo.resp_body)

        # field-count comparison vs admin (oversharing signal)
        if admin:
            ad = self.fetch(endpoint, admin)
            if ad.status == 200 and ad.resp_body.strip().startswith(("{", "[")):
                ad_keys = _json_keys(ad.resp_body)
                # lower-priv sees (almost) everything admin sees on a privileged obj
                if ad_keys and lo_keys and len(lo_keys & ad_keys) >= max(6, int(0.9 * len(ad_keys))) \
                        and lower.role is not IdentityRole.ADMIN:
                    yield Finding(
                        vuln_class=VulnClass.AUTHZ, severity=Severity.MEDIUM,
                        title=f"{lower.label()} sees same property set as admin",
                        endpoint=endpoint.key,
                        description=(
                            f"The {lower.label()} identity received {len(lo_keys)} "
                            f"of the admin response's {len(ad_keys)} properties on "
                            f"this object. If the object is not owned by the lower "
                            f"identity, the API may not be projecting fields by "
                            f"role (API3:2023). Verify ownership/intended fields."),
                        evidence=[lo, ad],
                        detail={"lower_fields": len(lo_keys),
                                "admin_fields": len(ad_keys)},
                        confidence="tentative")

    # ---- write side: mass assignment (gated, self-owned) -----------------
    def _mass_assignment(self, endpoint: Endpoint) -> Iterable[Finding]:
        if not self.config.scan.allow_state_changing:
            return
        identity = (self.identities.get(IdentityRole.BACKEND.value)
                    or self.identities.get(IdentityRole.ADMIN.value))
        if not identity:
            return
        headers = self.auth.headers_for(identity)
        # read current self object
        cur = self.client.request("GET", "/api/v1/users/current",
                                  identity_label=identity.label(), headers=headers)
        if cur.status != 200:
            return
        try:
            base = json.loads(cur.resp_body)
            base = base.get("entity", base)
            uid = base.get("userId")
        except Exception:
            return
        if not uid:
            return
        sentinel = canary("massassign")
        body = {"userId": uid, "givenName": base.get("givenName", "test"),
                "surname": base.get("surname", "test"),
                # the actual probe: a clearly-inert sentinel in a server field
                "additionalInfo": sentinel, **{
                    k: v for k, v in _MASS_ASSIGN_PROBES.items()}}
        put = self.client.request("PUT", "/api/v1/users/current",
                                  identity_label=identity.label(),
                                  headers=headers, json_body=body)
        if put.status not in (200, 202):
            return
        back = self.client.request("GET", "/api/v1/users/current",
                                   identity_label=identity.label(), headers=headers)
        # Confirm the injected VALUE actually PERSISTED — not merely that the
        # field NAME appears in the body. A normal user object already
        # contains "admin" (in the email), "roles", "active", "emailVerified",
        # so the old `k in back.resp_body` substring test fired on essentially
        # every run (a critical false positive). We parse the read-back and
        # require the injected value to be present AND to differ from the
        # pre-injection baseline (i.e. our write changed it).
        try:
            back_obj = json.loads(back.resp_body or "{}")
            back_obj = back_obj.get("entity", back_obj)
        except Exception:
            back_obj = {}
        if not isinstance(back_obj, dict):
            return
        persisted = []          # privileged fields that flipped to our value
        # the inert sentinel in a free-form field: strongest generic MA signal
        sentinel_stuck = back_obj.get("additionalInfo") == sentinel
        for k, injected in _MASS_ASSIGN_PROBES.items():
            if back_obj.get(k) == injected and base.get(k) != injected:
                persisted.append(k)
        if persisted or sentinel_stuck:
            changed = persisted + (["additionalInfo"] if sentinel_stuck else [])
            # A privileged field (admin/isAdmin/roles) flipping is HIGH; a bound
            # free-form field alone is a real but lower-impact mass assignment.
            priv = any(k in ("admin", "isAdmin", "roles", "active") for k in persisted)
            yield Finding(
                vuln_class=VulnClass.AUTHZ,
                severity=Severity.HIGH if priv else Severity.MEDIUM,
                title="Mass assignment: server-controlled fields accepted",
                endpoint="PUT /api/v1/users/current",
                description=(
                    f"After submitting unsolicited properties to the tester's OWN "
                    f"user object, the injected value(s) for ({', '.join(changed)}) "
                    f"PERSISTED in the read-back response (changed from the "
                    f"pre-injection baseline). The endpoint binds client input "
                    f"without a field allowlist (mass assignment, API3:2023). The "
                    f"probe used inert sentinel values on the tester's own account "
                    f"and did not attempt privilege escalation; verify the effect "
                    f"and reset the account fields manually."),
                evidence=[put, back],
                detail={"persisted_fields": changed, "sentinel": sentinel,
                        "sentinel_persisted": sentinel_stuck},
                confidence="firm")


def _json_keys(body: str) -> set[str]:
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        return set()
    if isinstance(obj, dict):
        obj = obj.get("entity", obj)
    keys: set[str] = set()

    def walk(o, depth=0):
        if depth > 4:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                keys.add(k)
                walk(v, depth + 1)
        elif isinstance(o, list) and o:
            walk(o[0], depth + 1)
    walk(obj)
    return keys
