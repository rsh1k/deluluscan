"""Active authorization & parameter-tampering probe.

Where the passive scanners *observe*, this module *acts*: it takes a request that
works for one identity and replays it with the credentials/parameters changed,
then checks whether the server still grants access. That is how you confirm
broken access control by exercising it (BOLA/IDOR, BFLA/privilege escalation,
missing auth, mass assignment) — the same moves you'd make by hand in Burp
Repeater, automated.

Authorized-target only (the HttpClient safety gate still applies). It proves the
issue by making the manipulated request succeed; it does not then use that
access to harvest data at scale.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .http_tools import Repeater, RequestSpec
from ..semantic_diff import structural_similarity
from ..verify import evidence as E

# Fields an attacker commonly injects to grant themselves privileges the API
# forgot to mask on write (mass assignment / BOPLA). These are *test* markers.
_MASS_ASSIGN_FIELDS = {
    "admin": True, "isAdmin": True, "is_admin": True, "roleId": "1",
    "role": "admin", "roles": ["admin"], "active": True, "approved": True,
    "emailVerified": True, "permissions": ["ADMIN"],
}


@dataclass
class AuthzResult:
    test: str
    granted: bool
    detail: str
    status: Optional[int] = None
    similarity: Optional[float] = None
    changes: dict = field(default_factory=dict)


def _looks_denied(rec) -> bool:
    # content-aware: empty result sets and permission-messages served as 200 are
    # denials, not "content served" (NIST 800-115 / OWASP WSTG 4.5).
    return E.classify_response(rec) != E.DISPOSITION_CONTENT


def _login_like(body: str) -> bool:
    low = (body or "").lower()
    return ("login" in low and "password" in low) or "j_security_check" in low


class AuthzProbe:
    def __init__(self, client):
        self.repeater = Repeater(client)

    # -- missing authentication --------------------------------------------
    def test_missing_auth(self, spec: RequestSpec, good) -> AuthzResult:
        # skip endpoints that are public by design (login/config/published)
        if E.is_public_by_design(spec.path):
            return AuthzResult("missing_auth", False,
                               "endpoint is public by design; anonymous access "
                               "is intended", None)
        stripped = spec.with_header("Authorization", None)
        stripped = stripped.with_header("Cookie", None)
        rec = self.repeater.send(stripped, identity_label="anonymous")
        # OWASP WSTG 4.5 oracle: the anonymous response must contain the SAME
        # protected data the authorized user gets — not merely a 200.
        res = E.served_protected_content(rec, good)
        return AuthzResult("missing_auth", res.served,
                           ("protected resource served to anonymous: " + res.reason)
                           if res.served else ("not a bypass: " + res.reason),
                           getattr(rec, "status", None), res.similarity)

    # -- horizontal / vertical privilege via identity swap -----------------
    def test_identity_swap(self, spec: RequestSpec, good, other_label: str,
                            other_headers: dict) -> AuthzResult:
        swapped = spec.with_header("Authorization", None).with_header("Cookie", None)
        for k, v in (other_headers or {}).items():
            swapped = swapped.with_header(k, v)
        rec = self.repeater.send(swapped, identity_label=other_label)
        res = E.served_protected_content(rec, good)
        return AuthzResult("identity_swap", res.served,
                           (f"'{other_label}' reached the same protected resource: {res.reason}"
                            if res.served else f"'{other_label}' did not: {res.reason}"),
                           getattr(rec, "status", None), res.similarity)

    # -- BOLA via object-id swap -------------------------------------------
    def test_bola_id(self, spec: RequestSpec, id_token: str, other_id: str,
                     identity_label: str, headers: dict) -> AuthzResult:
        """Replay the request as the SAME (lower-priv) identity but pointed at a
        different principal's object id. If a bogus id 404s and a real other id
        200s with an object, that's BOLA."""
        base = spec
        for k, v in (headers or {}).items():
            base = base.with_header(k, v)
        # control: a bogus id should NOT return an object
        bogus = "00000000-0000-0000-0000-0000000000ff" if "-" in id_token else "999999999"
        ctrl_spec = base.clone(); ctrl_spec.path = base.path.replace(id_token, bogus)
        ctrl = self.repeater.send(ctrl_spec, identity_label=identity_label)
        tgt_spec = base.clone(); tgt_spec.path = base.path.replace(id_token, other_id)
        target = self.repeater.send(tgt_spec, identity_label=identity_label)
        granted = (not _looks_denied(target)) and _looks_denied(ctrl)
        return AuthzResult("bola_id_swap", granted,
                           (f"object id {other_id} returned another principal's "
                            f"object while a bogus id did not" if granted
                            else "id swap did not yield object-scoped access"),
                           getattr(target, "status", None),
                           changes={"id": other_id})

    # -- mass assignment ---------------------------------------------------
    def test_mass_assignment(self, spec: RequestSpec, identity_label: str,
                             headers: dict) -> list[AuthzResult]:
        if spec.method.upper() not in ("POST", "PUT", "PATCH"):
            return []
        base = spec
        for k, v in (headers or {}).items():
            base = base.with_header(k, v)
        baseline = self.repeater.send(base, identity_label=identity_label)
        out: list[AuthzResult] = []
        for field_name, value in _MASS_ASSIGN_FIELDS.items():
            spec2 = base.with_json_field(field_name, value)
            rec = self.repeater.send(spec2, identity_label=identity_label)
            # signal: the elevated field is echoed back set, or status improved
            echoed = f'"{field_name}"' in (rec.resp_body or "") and (
                str(value).lower() in (rec.resp_body or "").lower())
            if echoed and rec.status < 400:
                out.append(AuthzResult(
                    "mass_assignment", True,
                    f"write accepted and reflected elevated field "
                    f"{field_name}={value}", rec.status, changes={field_name: value}))
        if not out:
            out.append(AuthzResult("mass_assignment", False,
                                   "no elevated field was accepted/reflected",
                                   getattr(baseline, "status", None)))
        return out
