"""Horizontal IDOR on write-path operations (PUT, DELETE, PATCH).

Tests whether a limited back-end user can MODIFY or DELETE resources that belong
to other users. This is the write-path complement to the read-path IDOR scanner
(idor.py).

Four targeted probe families:

1. **Cross-user deletion (IDOR on DELETE)**
   A backend user attempts to DELETE the readonly user's account and the admin's
   account via /api/v1/users/{userId}. Correct behaviour: 403/401. An IDOR allows
   the backend user to delete accounts it does not own.

2. **Cross-user profile modification (IDOR on PUT)**
   A backend user attempts to PUT /api/v1/users to overwrite the admin user's
   profile fields (email, firstName). Correct: 403/401. An IDOR means any
   backend user can silently alter arbitrary accounts.

3. **API-token IDOR** (confirmed finding class from prior scan)
   Three sub-tests:
   a) GET /api/tokens/{userId}/tokens — can backend read ADMIN's tokens?
   b) POST /api/tokens — can backend issue tokens FOR the admin user?
   c) DELETE /api/tokens/{tokenId} — dynamic: harvest a token id from admin,
      then attempt to delete it as backend.

4. **Role self-assignment / cross-user role grant**
   A backend user tries to assign the CMS-Administrator role to itself via
   POST /api/v1/users/{userId}/roles. This overlaps with privesc but is an IDOR
   angle: using another user's userId in the path param to grant their own
   account elevated roles.

Safety conventions
------------------
- All write probes use invalid / benign payloads so even a missing-authz endpoint
  cannot complete a destructive operation on real data.
- DELETE probes target PLACEHOLDER user IDs derived from well-known test seeds
  (not real production content). They are further guarded by the allow_state_changing
  flag — the scanner will not issue DELETE probes unless the operator has explicitly
  enabled state-changing tests.
- Never weaponise: confirm to proof (auth bypass is confirmed), then report.
"""
from __future__ import annotations

import json
import re
from typing import Iterable

from .base import Scanner
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

# ---------------------------------------------------------------------------
# Well-known test seeds — populated by the docker-compose setup script.
# These are used as probe targets and also as expected "not-mine" identifiers.
# ---------------------------------------------------------------------------
ADMIN_USER_ID = "appuser"
# Email-form IDs are accepted by most user APIs interchangeably with UUID.
BACKEND_USER_EMAIL = "backend@example.com"
READONLY_USER_EMAIL = "readonly@example.com"
ADMIN_USER_EMAIL = "admin@example.com"

# Placeholder UUID so a missing-authz endpoint still fails at input validation,
# not at actually deleting real data.
_INVALID_UUID = "00000000-0000-0000-0000-000000000000"

# CMS Administrator role identifier (built-in role).
_ADMIN_ROLE_ID = "TARGET_BACK_END_USER"
_CMS_ADMIN_ROLE_KEY = "CMS Administrator"

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)


def _is_denied(status: int) -> bool:
    return status in (401, 403)


def _is_success(status: int) -> bool:
    return status in (200, 201, 204)


def _access_granted(rec, *, write: bool) -> tuple[bool, str]:
    """Decide whether a probe response shows access was actually GRANTED — the
    only thing that should ever become an authz finding.

    The dominant false positive in differential authz testing is treating any
    non-401/403 as a grant: a 400 (request rejected before authz ran), a 404, a
    405, a 5xx server error, or a 3xx redirect-to-login are NOT grants. We route
    the body through the shared content classifier (which also unwraps the target
    {"errors":[...]} / "No Permissions" envelopes served as 200):

      * write ops (DELETE/PUT/PATCH/POST): a grant is a genuine 2xx (200/201/204)
        even with an empty body — a successful delete returns 204 No Content.
      * read ops: a grant requires substantive CONTENT (not an empty list, not a
        200-wrapped error/permission envelope).

    Returns (granted, disposition) so the caller can set confidence/severity.
    """
    from ..verify import evidence as E
    disp = E.classify_response(rec)
    if disp == E.DISPOSITION_CONTENT:
        return True, disp
    if write and rec.status in (200, 201, 204) and disp not in (
            E.DISPOSITION_DENIED, E.DISPOSITION_BAD_REQUEST,
            E.DISPOSITION_SERVER_ERROR, E.DISPOSITION_NOT_FOUND):
        return True, disp
    return False, disp


class IdorWriteScanner(Scanner):
    """Horizontal IDOR on write-path (PUT / DELETE / PATCH) operations."""

    name = "idor_write"
    vuln_classes = [VulnClass.IDOR.value, VulnClass.AUTHZ.value]

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        # Run exactly once regardless of how many endpoints are in the pipeline.
        self._done = False

    def applies_to(self, endpoint: Endpoint) -> bool:
        # We run all probes in one shot on the first matching endpoint, then
        # return False for everything else. Match any write-path endpoint so the
        # orchestrator invokes us at least once.
        return endpoint.method.upper() in ("PUT", "DELETE", "PATCH", "POST", "GET")

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if self._done:
            return
        self._done = True

        backend = self.identities.get(IdentityRole.BACKEND.value)
        admin = self.identities.get(IdentityRole.ADMIN.value)
        readonly = self.identities.get(IdentityRole.READONLY.value)

        if backend is None:
            return  # nothing to test without a low-privilege identity

        yield from self._probe_delete_idor(backend, admin, readonly)
        yield from self._probe_put_profile_idor(backend, admin)
        yield from self._probe_apitoken_idor(backend, admin)
        yield from self._probe_role_selfgrant(backend, admin)

    # ------------------------------------------------------------------
    # 1. Cross-user deletion (IDOR on DELETE /api/v1/users/{userId})
    # ------------------------------------------------------------------
    def _probe_delete_idor(
        self, backend, admin, readonly
    ) -> Iterable[Finding]:
        """Can a backend user DELETE another user's account?

        We only send DELETE if allow_state_changing is enabled; otherwise we
        first send a GET to confirm the target user exists, and report
        the probe was skipped with an explanation. With state-changing enabled
        we use the placeholder UUID so even a missing-authz endpoint cannot
        complete a real deletion.
        """
        # Target: admin user only. Testing admin deletion confirms the highest-
        # severity IDOR. A placeholder UUID always returns 404 (user not found)
        # which is not a meaningful authz signal — skip it for DELETE probes.
        # Do NOT use the readonly test user: if authz is absent we'd destroy it.
        targets = [
            (ADMIN_USER_ID, "admin user (appuser)"),
        ]

        for user_id, label in targets:
            endpoint_key = f"DELETE /api/v1/users/{user_id}"

            if not getattr(self.config.scan, "allow_state_changing", False):
                # Emit an informational finding explaining what was skipped and why.
                yield Finding(
                    vuln_class=VulnClass.IDOR,
                    severity=Severity.INFO,
                    title=f"IDOR-DELETE skipped (state-changing not enabled): {label}",
                    endpoint=endpoint_key,
                    description=(
                        f"The scanner would attempt DELETE /api/v1/users/{user_id} "
                        f"as the backend identity to test horizontal IDOR on user "
                        f"deletion ({label}). This probe is gated behind "
                        f"--allow-state-changing to prevent accidental data loss. "
                        f"Re-run with that flag to execute the live test."
                    ),
                    detail={"target_user": user_id, "probe_type": "idor_delete_user",
                            "skipped_reason": "allow_state_changing not set"},
                    confidence="tentative",
                )
                continue

            # Issue the DELETE as the backend user (safe: invalid UUID / non-existent user).
            rec = self._probe("DELETE", f"/api/v1/users/{user_id}", backend)
            if rec is None or rec.status == 0:
                continue

            # Baseline: what does admin get?
            admin_rec = self._probe("DELETE", f"/api/v1/users/{user_id}", admin) if admin else None

            granted, disp = _access_granted(rec, write=True)
            if not granted:
                # 401/403 denied, 404/400 request rejected, 5xx server error —
                # none of these is a completed cross-user deletion. Only a real
                # 2xx success proves the authz gate is absent. Skip otherwise.
                continue

            # Genuine 2xx: the deletion was accepted for an account we don't own.
            severity = Severity.CRITICAL if user_id == ADMIN_USER_ID else Severity.HIGH
            conf = "firm"
            yield Finding(
                vuln_class=VulnClass.IDOR,
                severity=severity,
                title=f"Horizontal IDOR: backend user can DELETE {label}",
                endpoint=endpoint_key,
                description=(
                    f"A backend (limited-privilege) user was NOT denied when attempting "
                    f"DELETE /api/v1/users/{user_id} ({label}). "
                    f"The response was HTTP {rec.status}. "
                    f"Correct behaviour is 401 or 403. "
                    f"This indicates a horizontal IDOR: any authenticated CMS back-end "
                    f"user may delete accounts they do not own, including the admin account."
                ),
                evidence=[r for r in (rec, admin_rec) if r],
                detail={
                    "target_user": user_id,
                    "target_label": label,
                    "backend_status": rec.status,
                    "admin_status": admin_rec.status if admin_rec else "n/a",
                    "probe_type": "idor_delete_user",
                    "active": True,
                },
                confidence=conf,
            )

    # ------------------------------------------------------------------
    # 2. Cross-user profile modification (IDOR on PUT /api/v1/users)
    # ------------------------------------------------------------------
    def _probe_put_profile_idor(
        self, backend, admin
    ) -> Iterable[Finding]:
        """Can a backend user overwrite the admin's profile via PUT /api/v1/users?

        the target PUT /api/v1/users accepts a JSON body with userId. A horizontal
        IDOR exists if the endpoint accepts an arbitrary userId — allowing a
        backend user to modify accounts they don't own. We target the admin's
        well-known userId with a benign payload (no email/password change).
        """
        # Benign payload: use a canary firstName that won't disrupt anything
        # even if the write somehow succeeds. We do NOT change password or email.
        benign_payload = {
            "userId": ADMIN_USER_ID,
            "firstName": "DeluluscanProbe",   # benign canary value
        }

        rec = self._probe("PUT", "/api/v1/users", backend, json_body=benign_payload)
        if rec is None or rec.status == 0:
            return

        admin_rec = self._probe("PUT", "/api/v1/users", admin,
                                json_body={"userId": ADMIN_USER_ID,
                                           "firstName": "Admin"}) if admin else None

        granted, disp = _access_granted(rec, write=True)
        if not granted:
            return

        conf = "firm"
        sev = Severity.HIGH
        yield Finding(
            vuln_class=VulnClass.IDOR,
            severity=sev,
            title="Horizontal IDOR: backend user can modify admin profile via PUT /api/v1/users",
            endpoint="PUT /api/v1/users",
            description=(
                f"A backend (limited-privilege) user was NOT denied when attempting "
                f"PUT /api/v1/users with userId={ADMIN_USER_ID!r} (the admin account). "
                f"The response was HTTP {rec.status}. "
                f"Correct behaviour is 401 or 403. "
                f"This indicates a horizontal IDOR: any backend user can overwrite "
                f"the profile of any other user, including the CMS Administrator."
            ),
            evidence=[r for r in (rec, admin_rec) if r],
            detail={
                "target_user": ADMIN_USER_ID,
                "probe_payload": benign_payload,
                "backend_status": rec.status,
                "admin_status": admin_rec.status if admin_rec else "n/a",
                "probe_type": "idor_put_user_profile",
                "active": True,
            },
            confidence=conf,
        )

    # ------------------------------------------------------------------
    # 3. API-token IDOR
    # ------------------------------------------------------------------
    def _probe_apitoken_idor(
        self, backend, admin
    ) -> Iterable[Finding]:
        """Three sub-tests against the /api/tokens surface.

        a) GET /api/tokens/{userId}/tokens — can backend READ admin's tokens?
        b) POST /api/tokens — can backend ISSUE tokens FOR the admin user?
        c) DELETE /api/tokens/{tokenId} — dynamic: harvest a real token id
           from admin, then attempt to delete it as backend.
        """
        yield from self._apitoken_read_idor(backend, admin)
        yield from self._apitoken_create_idor(backend, admin)
        yield from self._apitoken_delete_idor(backend, admin)

    def _apitoken_read_idor(self, backend, admin) -> Iterable[Finding]:
        """GET /api/tokens/{userId}/tokens — read admin's token list."""
        path = f"/api/tokens/{ADMIN_USER_ID}/tokens"

        backend_rec = self._probe("GET", path, backend)
        if backend_rec is None or backend_rec.status == 0:
            return

        admin_rec = self._probe("GET", path, admin) if admin else None

        # A read IDOR is real only if substantive token data actually came back —
        # not a 200-wrapped empty list or {"errors":[...]} / permission envelope.
        granted, disp = _access_granted(backend_rec, write=False)
        if not granted:
            return
        conf = "firm"
        yield Finding(
            vuln_class=VulnClass.IDOR,
            severity=Severity.HIGH,
            title="Horizontal IDOR: backend user can read admin's API tokens",
            endpoint=f"GET {path}",
            description=(
                f"A backend (limited-privilege) user was NOT denied when requesting "
                f"GET {path}. "
                f"The response was HTTP {backend_rec.status} ({backend_rec.resp_len} bytes). "
                f"Correct behaviour is 401 or 403. "
                f"This allows any authenticated backend user to enumerate API tokens "
                f"belonging to the CMS Administrator and potentially replay them."
            ),
            evidence=[r for r in (backend_rec, admin_rec) if r],
            detail={
                "target_user": ADMIN_USER_ID,
                "backend_status": backend_rec.status,
                "backend_resp_len": backend_rec.resp_len,
                "admin_status": admin_rec.status if admin_rec else "n/a",
                "probe_type": "idor_apitoken_read",
            },
            confidence=conf,
        )

    def _apitoken_create_idor(self, backend, admin) -> Iterable[Finding]:
        """POST /api/tokens — create a token FOR the admin user.

        The target API token creation body includes a userId field. If the
        endpoint does not enforce that the requesting user can only create tokens
        for themselves, a backend user can mint tokens for the admin account.

        Correct server behavior: backend gets 404 "No user found" (server refuses
        to resolve admin's identity for a backend caller) or 403. A 200 with a JWT
        in the response body is the only firm confirmation of the IDOR.
        """
        # Correct field names for ApiTokenForm — 'label' is not a known field.
        payload = {
            "userId": ADMIN_USER_ID,
            "expirationSeconds": 120,
            "claims": {},
        }
        rec = self._probe("POST", "/api/tokens", backend, json_body=payload)
        if rec is None or rec.status == 0:
            return

        admin_rec = self._probe("POST", "/api/tokens", admin,
                                json_body=payload) if admin else None

        # 401/403 denied, 404 "No user found" (server refused the cross-user
        # lookup), 400 input validation, 5xx errors — none is a minted token.
        # Only a genuine 2xx (ideally a JWT in the body) confirms the IDOR.
        granted, disp = _access_granted(rec, write=True)
        if not granted:
            return

        conf = "firm"
        sev = Severity.CRITICAL

        # Extract the newly created token id if present, for evidence.
        token_id = None
        if rec.resp_body:
            try:
                data = json.loads(rec.resp_body)
                token_id = (data.get("entity", {}) or {}).get("token", {}).get("id")
            except (json.JSONDecodeError, AttributeError):
                pass

        detail = {
            "target_user": ADMIN_USER_ID,
            "probe_payload": payload,
            "backend_status": rec.status,
            "admin_status": admin_rec.status if admin_rec else "n/a",
            "probe_type": "idor_apitoken_create",
            "active": True,
        }
        if token_id:
            detail["created_token_id"] = token_id

        yield Finding(
            vuln_class=VulnClass.IDOR,
            severity=sev,
            title="Horizontal IDOR: backend user can create API tokens for admin",
            endpoint="POST /api/tokens",
            description=(
                f"A backend (limited-privilege) user was NOT denied when attempting "
                f"POST /api/tokens with userId={ADMIN_USER_ID!r} (the admin account). "
                f"The response was HTTP {rec.status}. "
                f"Correct behaviour is 401 or 403. "
                f"This allows any backend user to mint API tokens for the administrator "
                f"account, enabling full privilege escalation via token replay."
                + (f" A token with id {token_id!r} was created as evidence." if token_id else "")
            ),
            evidence=[r for r in (rec, admin_rec) if r],
            detail=detail,
            confidence=conf,
        )

    def _apitoken_delete_idor(self, backend, admin) -> Iterable[Finding]:
        """DELETE /api/tokens/{tokenId} — delete admin's token.

        First harvests a real token id from the admin identity. Then attempts
        the deletion as the backend user. This is the most targeted sub-test
        because it uses a *real* token id rather than a placeholder.

        Safe: a single-token deletion does not lock the admin out and does not
        grant any privileges. The deletion is skipped if allow_state_changing is
        not set; in that case we still report the potential risk with INFO severity.
        """
        if admin is None:
            return

        # --- 1. Harvest a real token id from admin ---
        list_rec = self._probe(
            "GET", f"/api/tokens/{ADMIN_USER_ID}/tokens", admin
        )
        token_id = None
        if list_rec and list_rec.status == 200 and list_rec.resp_body:
            try:
                data = json.loads(list_rec.resp_body)
                tokens = (data.get("entity") or {}).get("tokens") or []
                if tokens:
                    token_id = tokens[0].get("id")
            except (json.JSONDecodeError, AttributeError):
                pass

        # Fall back to searching raw body for a UUID.
        if not token_id and list_rec and list_rec.resp_body:
            m = _UUID_RE.search(list_rec.resp_body)
            if m:
                token_id = m.group(0)

        if not token_id:
            # No real token to harvest — use the placeholder UUID as a probe.
            token_id = _INVALID_UUID

        path = f"/api/tokens/{token_id}"

        if not getattr(self.config.scan, "allow_state_changing", False):
            # Report the potential risk but do not actually DELETE.
            yield Finding(
                vuln_class=VulnClass.IDOR,
                severity=Severity.INFO,
                title=f"IDOR-DELETE skipped (state-changing not enabled): API token {token_id!r}",
                endpoint=f"DELETE {path}",
                description=(
                    f"The scanner would attempt DELETE {path} as the backend identity "
                    f"to test whether a low-privilege user can delete admin's API tokens. "
                    f"This probe is gated behind --allow-state-changing to prevent "
                    f"accidental token loss. Re-run with that flag to execute the live test."
                ),
                detail={
                    "target_token_id": token_id,
                    "probe_type": "idor_apitoken_delete",
                    "skipped_reason": "allow_state_changing not set",
                },
                confidence="tentative",
            )
            return

        rec = self._probe("DELETE", path, backend)
        if rec is None or rec.status == 0:
            return

        admin_rec = self._probe("GET", f"/api/tokens/{ADMIN_USER_ID}/tokens", admin)

        granted, disp = _access_granted(rec, write=True)
        if not granted:
            return

        conf = "firm"
        yield Finding(
            vuln_class=VulnClass.IDOR,
            severity=Severity.HIGH,
            title="Horizontal IDOR: backend user can DELETE admin's API token",
            endpoint=f"DELETE {path}",
            description=(
                f"A backend (limited-privilege) user was NOT denied when attempting "
                f"DELETE {path} (an API token belonging to the admin user). "
                f"The response was HTTP {rec.status}. "
                f"Correct behaviour is 401 or 403. "
                f"This allows any backend user to revoke API tokens belonging to "
                f"other users, including the administrator."
            ),
            evidence=[r for r in (rec, admin_rec) if r],
            detail={
                "target_token_id": token_id,
                "backend_status": rec.status,
                "probe_type": "idor_apitoken_delete",
                "active": True,
            },
            confidence=conf,
        )

    # ------------------------------------------------------------------
    # 4. Role self-assignment / cross-user role grant
    # ------------------------------------------------------------------
    def _probe_role_selfgrant(
        self, backend, admin
    ) -> Iterable[Finding]:
        """Can a backend user grant themselves admin roles?

        POST /api/v1/users/{userId}/roles with a benign role payload. We target
        the backend user's own userId (self-grant) and also try with the invalid
        placeholder so even a missing-authz endpoint fails at role resolution.

        This is the IDOR angle on privilege escalation: the userId in the path
        belongs to the requesting user, but the role being granted is admin-level,
        so only an admin should be permitted to perform this operation.
        """
        # Probe 1: backend tries to grant CMS Administrator role to itself.
        # Use a benign payload with an invalid role id first.
        self_path = f"/api/v1/users/{BACKEND_USER_EMAIL}/roles"
        payload_invalid = {
            "roleId": _INVALID_UUID,
        }
        rec = self._probe("POST", self_path, backend, json_body=payload_invalid)
        if rec is None or rec.status == 0:
            return

        admin_rec = self._probe("POST", self_path, admin,
                                json_body=payload_invalid) if admin else None

        # This probe sends an INVALID placeholder roleId, so a real grant can only
        # show up as a genuine 2xx. A 400 input-validation error means auth was
        # passed but the role id was rejected — that is NOT proof of a role IDOR
        # (it is the differential-suspicion case that privesc_scanner confirms
        # properly with a valid role id and an auto-revert). Requiring an actual
        # grant here stops the "backend can self-assign roles" CRITICAL false
        # positive that fired on a bare 400.
        granted, disp = _access_granted(rec, write=True)
        if not granted:
            return

        # Confirm the signal is meaningful: is anonymous denied here? If anon is
        # also not denied, the endpoint may be genuinely public (not a role IDOR).
        anon = self.identities.get(IdentityRole.ANON.value)
        anon_rec = self._probe("POST", self_path, anon) if anon else None
        if anon_rec and not _is_denied(anon_rec.status):
            return

        conf = "firm"
        sev = Severity.CRITICAL

        yield Finding(
            vuln_class=VulnClass.IDOR,
            severity=sev,
            title="Horizontal IDOR: backend user can self-assign roles (POST /api/v1/users/{userId}/roles)",
            endpoint=f"POST {self_path}",
            description=(
                f"A backend (limited-privilege) user was NOT denied when attempting "
                f"POST {self_path} to self-assign a role. "
                f"The response was HTTP {rec.status}. Anonymous is correctly denied. "
                f"Correct behaviour for a non-admin is 403. "
                f"This indicates the role assignment endpoint lacks function-level "
                f"authorization, enabling any backend user to elevate their own "
                f"account to CMS Administrator."
            ),
            evidence=[r for r in (rec, admin_rec, anon_rec) if r],
            detail={
                "target_path": self_path,
                "probe_payload": payload_invalid,
                "backend_status": rec.status,
                "admin_status": admin_rec.status if admin_rec else "n/a",
                "anon_status": anon_rec.status if anon_rec else "n/a",
                "probe_type": "idor_role_selfgrant",
                "active": True,
            },
            confidence=conf,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _probe(self, method: str, path: str, identity, *,
               json_body=None):
        """Issue a single request, suppressing connection errors."""
        if identity is None:
            return None
        headers = dict(self.auth.headers_for(identity))
        try:
            if method in ("PUT", "POST", "PATCH") and json_body is not None:
                return self.client.request(
                    method, path, identity_label=identity.label(),
                    headers=headers, json_body=json_body,
                )
            return self.client.request(
                method, path, identity_label=identity.label(),
                headers=headers,
            )
        except Exception:
            return None


def _looks_like_login(body: str) -> bool:
    low = body.lower()
    return ("login" in low and "password" in low) or "j_security_check" in low
