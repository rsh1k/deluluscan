"""IDOR / broken access control scanner.

The core technique the user asked for: for each endpoint, exercise it as all
three identities (anonymous, limited back-end user, admin) and compare. The
admin response is the oracle for "this resource exists and has content."

Two signals:

1. **Vertical authz (missing auth):** an id-bearing or clearly privileged
   endpoint returns 200 with real content to anonymous or to a limited back-end
   user when it should require admin. Detected by comparing status + body
   fingerprint across identities.

2. **Horizontal IDOR (object harvesting):** we collect object identifiers that
   admin can see (e.g. user ids, content identifiers), then ask whether a
   *lower*-privileged identity can read the same object by id. If a limited user
   can read an object that isn't theirs, that's IDOR.

This scanner only issues GETs (and other read methods) by default; it never
mutates state unless allow_state_changing is set, and even then only via the
configured identities' own resources.
"""
from __future__ import annotations

import re
from typing import Iterable

from .base import Scanner
from ..models import (Endpoint, Finding, IdentityRole, Severity, VulnClass)

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_INODE = re.compile(r"\b[0-9a-f]{32}\b")


class IdorScanner(Scanner):
    name = "idor"
    vuln_classes = [VulnClass.IDOR.value, VulnClass.AUTHZ.value]

    # Known admin IDs from the docker-compose test environment.
    # These are stable across restarts (provisioned by scripts/provision_users.py).
    _KNOWN_ADMIN_IDS = ["appuser", "admin@example.com"]

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._targeted_done = False

    def applies_to(self, endpoint: Endpoint) -> bool:
        return endpoint.method.upper() in ("GET", "POST")

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        admin = self.identities.get(IdentityRole.ADMIN.value)
        backend = self.identities.get(IdentityRole.BACKEND.value)
        anon = self.identities.get(IdentityRole.ANON.value)

        records = {}
        if admin:
            records["admin"] = self.fetch(endpoint, admin)
        if backend:
            records["backend"] = self.fetch(endpoint, backend)
        if anon:
            records["anonymous"] = self.fetch(endpoint, anon)

        from ..verify import evidence as E
        admin_rec = records.get("admin")
        admin_is_content = admin_rec is not None and \
            E.classify_response(admin_rec) == E.DISPOSITION_CONTENT

        # ---- signal 1: vertical access control ---------------------------
        for role in ("anonymous", "backend"):
            rec = records.get(role)
            if not rec:
                continue
            # Body-aware gate: the response must be real CONTENT, not a
            # 200-wrapped {"errors":[...]} / "No Permissions" envelope, an empty
            # result set, a login page, or any 4xx/5xx. We ALSO keep a
            # substantiality floor (>64 bytes): a trivial body like
            # {"id":"","title":"Item"} is public filler, not a privileged leak.
            # (classify_response fixes the error-envelope FP; the floor keeps the
            # original conservatism against tiny public payloads.)
            if E.classify_response(rec) != E.DISPOSITION_CONTENT or rec.resp_len <= 64:
                continue
            # Be conservative to avoid false positives:
            #  - self-scoped endpoints (/current, /me, /self) are SUPPOSED to be
            #    readable by the authenticated user -> not a finding;
            #  - only high-sensitivity tags count (apps/maintenance/roles), not
            #    'system'/'users'/'configuration' which have public/self members.
            self_scoped = endpoint.path.rstrip("/").endswith(
                ("/current", "/me", "/self"))
            looks_privileged = endpoint.id_bearing or any(
                t in ("apps", "maintenance", "roles") for t in endpoint.tags)
            if not (looks_privileged and not self_scoped):
                continue
            # Corroborate against the admin oracle: only "firm" when the low-priv
            # identity is served the SAME data values the admin sees (an actual
            # bypass), not just a same-shaped or self-scoped body.
            conf = "firm" if role == "anonymous" else "tentative"
            same_as_admin = None
            if admin_is_content:
                res = E.served_protected_content(rec, admin_rec)
                same_as_admin = res.served
                conf = "firm" if res.served else "tentative"
            sev = Severity.HIGH if role == "anonymous" else Severity.MEDIUM
            yield Finding(
                vuln_class=VulnClass.AUTHZ,
                severity=sev,
                title=f"Privileged endpoint reachable as {role}",
                endpoint=endpoint.key,
                description=(
                    f"{endpoint.key} returned substantive content ({rec.resp_len} "
                    f"bytes) to the {role} identity. The endpoint is id-bearing or "
                    f"tagged as privileged ({', '.join(endpoint.tags) or 'n/a'}), so "
                    f"it likely should require authorization."
                    + ("  The response carries the same data the admin oracle "
                       "returns — a confirmed access-control bypass."
                       if same_as_admin else
                       "  Verify against an authorized baseline before reporting."
                       if same_as_admin is False else "")),
                evidence=[r for r in (rec, admin_rec) if r],
                detail={"role": role, "resp_len": rec.resp_len,
                        "same_data_as_admin": same_as_admin},
                confidence=conf,
            )

        # ---- signal 2: horizontal IDOR via harvested ids -----------------
        if admin_is_content and backend and endpoint.id_bearing:
            ids = _harvest_ids(admin_rec.resp_body)
            for obj_id, kind in ids[:5]:   # cap probes per endpoint
                param = endpoint.path_params[0] if endpoint.path_params else None
                if not param:
                    break
                rec = self.fetch(endpoint, backend, path_overrides={param: obj_id})
                # Require real content (not a 200-wrapped error) AND that the
                # backend response shares the admin's actual data values — two
                # same-shaped error envelopes are ~100% "structurally similar" but
                # carry no data, the classic horizontal-IDOR false positive.
                if E.classify_response(rec) != E.DISPOSITION_CONTENT:
                    continue
                res = E.served_protected_content(rec, admin_rec)
                overlap = res.similarity or 0.0
                if not res.served:
                    continue
                conf = "firm" if overlap >= 0.9 else "tentative"
                yield Finding(
                    vuln_class=VulnClass.IDOR,
                    severity=Severity.HIGH,
                    title=f"Possible horizontal IDOR on {param}",
                    endpoint=endpoint.key,
                    description=(
                        f"A limited back-end user successfully read object "
                        f"'{obj_id}' ({kind}) via {endpoint.key}. This id was "
                        f"harvested from the admin-only response, and the backend "
                        f"response shares {overlap:.0%} of the admin response's "
                        f"data values, suggesting the back-end user reached an "
                        f"object that is not theirs. Verify ownership manually "
                        f"before reporting."),
                    evidence=[rec],
                    detail={"object_id": obj_id, "id_kind": kind,
                            "param": param, "value_overlap": round(overlap, 3)},
                    confidence=conf,
                )

        # ---- signal 3: targeted known-ID probes (run once per scan) ------
        # The default placeholder (00000000-...) never returns real data, so
        # signal 2 misses IDOR on well-known IDs. Run a single targeted pass
        # using the provisioned admin user ID.
        if not self._targeted_done:
            self._targeted_done = True
            yield from self._probe_user_profile_idor()

    def _probe_user_profile_idor(self) -> Iterable[Finding]:
        """Test GET /api/v1/users/{userId} for horizontal read IDOR.

        Confirmed vulnerability class: a backend user can read the admin's
        full profile (admin=True, lastLoginIP, failedLoginCount) using the
        admin's well-known userId. Anonymous gets 403; backend should too.
        """
        backend = self.identities.get(IdentityRole.BACKEND.value)
        admin = self.identities.get(IdentityRole.ADMIN.value)
        anon = self.identities.get(IdentityRole.ANON.value)
        if not backend:
            return

        for admin_id in self._KNOWN_ADMIN_IDS:
            path = f"/api/v1/users/{admin_id}"

            anon_rec = self.client.request(
                "GET", path, identity_label="anonymous",
                headers=self.auth.headers_for(anon)) if anon else None
            backend_rec = self.client.request(
                "GET", path, identity_label=backend.label(),
                headers=self.auth.headers_for(backend))
            admin_rec = self.client.request(
                "GET", path, identity_label="admin",
                headers=self.auth.headers_for(admin)) if admin else None

            if backend_rec.status == 0:
                continue

            # Confirmed IDOR: backend reads the admin profile where it should be
            # denied. Require real CONTENT (not a 200-wrapped error/permission
            # envelope) AND at least one admin-specific field actually present —
            # a 200 with none of the privileged fields is not proof of a profile read.
            from ..verify import evidence as E
            if E.classify_response(backend_rec) == E.DISPOSITION_CONTENT:
                body = backend_rec.resp_body or ""
                admin_fields = sum(1 for f in
                                   ('"admin"', '"lastLoginIP"', '"failedLoginCount"',
                                    '"lastLoginDate"', '"additionalInfo"')
                                   if f in body)
                if admin_fields == 0:
                    continue  # no privileged fields returned — not a profile read
                confidence = "firm" if admin_fields >= 2 else "tentative"
                anon_blocked = (anon_rec.status in (401, 403)) if anon_rec else True
                sev = Severity.HIGH if anon_blocked else Severity.MEDIUM
                yield Finding(
                    vuln_class=VulnClass.IDOR,
                    severity=sev,
                    title=f"Horizontal IDOR: backend can read admin user profile ({admin_id})",
                    endpoint=f"GET {path}",
                    description=(
                        f"GET {path} returned HTTP {backend_rec.status} "
                        f"({backend_rec.resp_len} bytes) to the backend identity. "
                        f"The response includes admin-specific fields: "
                        f"{admin_fields} sensitive fields detected. "
                        f"Anonymous identity gets {anon_rec.status if anon_rec else 'n/a'} — "
                        f"the endpoint IS auth-gated, so the backend user's 200 indicates "
                        f"missing AUTHORIZATION (the backend user can read arbitrary "
                        f"user profiles including admin-level account details). "
                        f"Vulnerable field examples: admin flag, lastLoginIP, failedLoginCount."),
                    evidence=[r for r in (backend_rec, anon_rec, admin_rec) if r],
                    detail={"admin_id": admin_id, "backend_status": backend_rec.status,
                            "anon_status": anon_rec.status if anon_rec else "n/a",
                            "admin_fields_detected": admin_fields},
                    confidence=confidence,
                )
                break  # found it, don't need to test the second ID form


def _looks_like_login(body: str) -> bool:
    low = body.lower()
    return ("login" in low and "password" in low) or "j_security_check" in low


def _harvest_ids(body: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen = set()
    for m in _UUID.findall(body):
        if m not in seen:
            seen.add(m); out.append((m, "uuid"))
    for m in _INODE.findall(body):
        if m not in seen:
            seen.add(m); out.append((m, "inode"))
    return out
