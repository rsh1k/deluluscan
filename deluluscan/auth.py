"""Authentication for the three the target trust levels.

the target accepts several auth mechanisms, checked in priority order: JWT bearer
(API token), Basic, the non-standard DOTAUTH header, and a session cookie issued
by POST /api/v1/authentication. This module turns each configured Identity into
a ready-to-use set of request headers.

Login flow (back-end / admin users):
    POST /api/v1/authentication  {"userId": "...", "password": "...", "rememberMe": false}
    -> sets a JWT access cookie; we also keep the bearer for header-based reuse.

If an Identity supplies an API access token directly (bearer_token), we use it
verbatim and skip the login round-trip.
"""
from __future__ import annotations

import base64
from typing import Optional

from .http_client import HttpClient
from .models import Identity, IdentityRole


class AuthManager:
    AUTH_ENDPOINT = "/api/v1/authentication"
    WHOAMI_ENDPOINT = "/api/v1/users/current"

    def __init__(self, client: HttpClient):
        self.client = client
        self._header_cache: dict[str, dict[str, str]] = {}

    def headers_for(self, identity: Identity) -> dict[str, str]:
        """Return auth headers for an identity, logging in once if needed."""
        if identity.role is IdentityRole.ANON:
            return dict(identity.extra_headers)

        cached = self._header_cache.get(identity.label())
        if cached is not None:
            return cached

        headers: dict[str, str] = dict(identity.extra_headers)

        if identity.bearer_token:
            headers["Authorization"] = f"Bearer {identity.bearer_token}"
        elif identity.username and identity.password:
            jwt = self._login(identity)
            if jwt:
                identity.session_jwt = jwt
                headers["Authorization"] = f"Bearer {jwt}"
            else:
                # Fall back to Basic auth, which the target also accepts.
                token = base64.b64encode(
                    f"{identity.username}:{identity.password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {token}"

        self._header_cache[identity.label()] = headers
        return headers

    def refresh(self, identity: Identity) -> dict[str, str]:
        """Drop cached headers and re-authenticate. A long scan (especially with
        --allow-state-changing) can invalidate an identity's session mid-run — a
        logout probe, a token rotation, a user mutation, or throttling — after
        which cached headers yield 401s. Verification calls this on an unexpected
        denial so it re-tests against a live session instead of scan-damaged
        state (otherwise genuine findings get buried as false positives)."""
        self._header_cache.pop(identity.label(), None)
        identity.session_jwt = None
        return self.headers_for(identity)

    def _login(self, identity: Identity) -> Optional[str]:
        # Bypass http_client.request() for the auth POST because request() clears
        # session cookies before returning, which prevents us from reading the JWT
        # out of the rme cookie.  We go directly to the underlying session so we
        # can read resp.cookies (the per-response jar) before it is discarded.
        url = self.client.url_for(self.AUTH_ENDPOINT)
        try:
            resp = self.client.session.request(
                "POST", url,
                json={
                    "userId": identity.username,
                    "password": identity.password,
                    "rememberMe": True,   # ensures the target always issues the rme JWT
                },
                timeout=self.client.timeout,
                verify=self.client.verify,
                allow_redirects=False,
            )
        except Exception:
            self.client.session.cookies.clear()
            return None

        if resp.status_code != 200:
            self.client.session.cookies.clear()
            return None

        # Read JWT from the per-response cookie jar (not the session jar, which
        # http_client.request() would have already cleared).
        jwt = None
        for cookie in resp.cookies:
            if cookie.name.lower() in ("rme", "access_token", "jwt", "jwtaccesstoken"):
                jwt = cookie.value
                break

        if not jwt:
            # Some target builds return the token in the JSON body instead.
            try:
                import json as _json
                entity = _json.loads(resp.text).get("entity", {})
                jwt = entity.get("token") or entity.get("jwt")
            except Exception:
                pass

        # Purge session cookies so they cannot bleed into subsequent requests
        # made under a different identity (e.g. anonymous probes).
        self.client.session.cookies.clear()
        return jwt

    def verify(self, identity: Identity) -> tuple[bool, str]:
        """Best-effort check that an identity is what it claims to be.

        Returns (ok, human_message). For ANON we just confirm the server is up.
        """
        headers = self.headers_for(identity)
        rec = self.client.request(
            "GET", self.WHOAMI_ENDPOINT,
            identity_label=identity.label(), headers=headers,
        )
        if identity.role is IdentityRole.ANON:
            return rec.status in (200, 401, 403), (
                f"server reachable (status {rec.status} on whoami)"
            )
        if rec.status == 200:
            return True, "authenticated; /users/current returned 200"
        return False, f"auth check failed: status {rec.status}"
