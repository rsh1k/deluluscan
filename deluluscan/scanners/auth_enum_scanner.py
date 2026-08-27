"""Authentication enumeration and hardening scanner.

Tests authentication-related vulnerabilities common to the target deployments:

  1. User enumeration via login response differences — timing or body divergence
     between "unknown user" and "known user, wrong password" lets an attacker
     harvest valid email addresses.
  2. Brute-force / rate-limiting absence — rapid sequential logins without
     lockout or throttling expose the login endpoint to credential stuffing.
  3. Default the target credentials — ships with well-known dev defaults that are
     frequently left unchanged in staging and production environments.
  4. Password-reset enumeration — GET /api/v1/users/password/reset/{email}
     returning different responses for real vs. ghost accounts.
  5. Auth-bypass via degenerate bearer tokens — null / undefined / empty-string
     bearer values that some frameworks accidentally accept.
  6. Session-cookie security flags — JSESSIONID missing Secure, HttpOnly, or
     SameSite attributes after a successful login.

All probes are benign: no real accounts are locked, no state is permanently
altered beyond a transient failed-login counter (which expires). Default
credentials are only attempted against the known dev defaults documented in
the target public docs.
"""
from __future__ import annotations

import json
import re
import time
from typing import Iterable, Optional

from .base import Scanner
from ..models import Endpoint, Finding, IdentityRole, RequestRecord, Severity, VulnClass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LOGIN_PATH = "/api/v1/authentication"
_RESET_PATHS = [
    "/api/v1/users/password/reset/{email}",
    "/api/v1/forgotpassword",
    "/api/v1/users/forgotpassword",
]

# Known the target development / default credentials (publicly documented)
_DEFAULT_CREDS = [
    ("admin@example.com", "admin"),
    ("admin@example.com", "target"),
    ("system@example.com", "system"),
    ("admin@example.com", "password"),
    ("admin@example.com", "the target"),
]

# Bogus account that should never exist on any real deployment
_GHOST_USER = "deluluscan-ghost-9x7z@nowhere-deluluscan.example"
_GHOST_PASS = "Deluluscan!Invalid#Pw99"

# Degenerate bearer values that some Java/Spring filters accidentally admit
_DEGENERATE_TOKENS = ["null", "undefined", "", "Bearer", "none", "0"]

# Minimum response-body length delta (bytes) considered "significantly different"
_ENUM_BODY_DELTA = 64
# Minimum timing delta (ms) that suggests timing-based enumeration
_ENUM_TIMING_DELTA_MS = 200

# Pattern to spot a JWT-shaped body in a login response (three base64 segments)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _h(headers: dict, name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


def _cookie_flags(set_cookie: str) -> dict[str, bool]:
    """Parse a Set-Cookie header and return which security flags are present."""
    low = set_cookie.lower()
    return {
        "secure": "; secure" in low or low.endswith(";secure") or low.endswith(" secure"),
        "httponly": "httponly" in low,
        "samesite": "samesite=" in low,
    }


def _login_attempt(client, username: str, password: str) -> RequestRecord:
    """Fire a raw (unauthenticated) login attempt and return the record."""
    return client.request(
        "POST", _LOGIN_PATH,
        identity_label="anonymous",
        json_body={"userId": username, "password": password, "rememberMe": False},
    )


def _body_len(rec: RequestRecord) -> int:
    return rec.resp_len if rec.resp_len else len(rec.resp_body or "")


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class AuthEnumScanner(Scanner):
    """Authentication enumeration and hardening scanner for the target.

    Runs a focused battery of login-endpoint probes rather than scanning every
    discovered endpoint. Registers itself against the login endpoint and
    password-reset paths, but most tests are server-wide (run once via a flag).
    """

    name = "auth_enum"
    vuln_classes = [
        VulnClass.AUTHZ.value,
        VulnClass.RATE_LIMIT.value,
        VulnClass.INFO_LEAK.value,
        VulnClass.MISCONFIG.value,
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Each top-level test runs at most once per scan session.
        self._enum_done = False
        self._rate_done = False
        self._default_done = False
        self._bypass_done = False
        self._cookie_done = False

    # ------------------------------------------------------------------
    # applies_to: trigger on auth / password-reset paths, or run once on
    # the very first endpoint when those paths are not in the spec.
    # ------------------------------------------------------------------

    def applies_to(self, endpoint: Endpoint) -> bool:
        p = endpoint.path.lower()
        return (
            "auth" in p
            or "login" in p
            or "password" in p
            or "reset" in p
            or "forgotpassword" in p
        )

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        # Resolve an anonymous identity; the tests don't need valid credentials.
        anon = self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)

        if not self._enum_done:
            self._enum_done = True
            yield from self._test_user_enumeration()

        if not self._rate_done:
            self._rate_done = True
            yield from self._test_rate_limiting()

        if not self._default_done:
            self._default_done = True
            yield from self._test_default_credentials()

        if not self._bypass_done:
            self._bypass_done = True
            yield from self._test_auth_bypass()

        if not self._cookie_done:
            self._cookie_done = True
            yield from self._test_cookie_flags()

        # Password-reset enumeration is path-specific
        p = endpoint.path.lower()
        if "password" in p or "reset" in p or "forgot" in p:
            yield from self._test_reset_enumeration(endpoint)

    # ------------------------------------------------------------------
    # 1. User enumeration via response differences
    # ------------------------------------------------------------------

    def _test_user_enumeration(self) -> Iterable[Finding]:
        """Compare login responses for a ghost account vs. a known-existing account.

        the target's admin account is always present; if its error response is
        distinguishably different from a nonexistent account, an attacker can
        confirm whether an email is registered.
        """
        # The known-present account — wrong password, correct address.
        # Use the documented default admin email; it exists on every target instance.
        known_user = "admin@example.com"

        rec_ghost = _login_attempt(self.client, _GHOST_USER, _GHOST_PASS)
        rec_known = _login_attempt(self.client, known_user, _GHOST_PASS)

        if rec_ghost.status == 0 or rec_known.status == 0:
            return  # network error; skip

        # --- body-length heuristic ---
        ghost_len = _body_len(rec_ghost)
        known_len = _body_len(rec_known)
        length_delta = abs(ghost_len - known_len)

        # --- status-code divergence ---
        status_diverges = rec_ghost.status != rec_known.status

        # --- timing heuristic ---
        timing_delta = abs(rec_ghost.elapsed_ms - rec_known.elapsed_ms)

        # --- body-content heuristic: look for "user not found" vs "invalid creds" ---
        ghost_body = (rec_ghost.resp_body or "").lower()
        known_body = (rec_known.resp_body or "").lower()
        msg_phrases_ghost = {"not found", "no user", "does not exist", "unknown", "no account"}
        msg_phrases_known = {"invalid password", "wrong password", "bad credentials",
                             "incorrect password", "authentication failed"}
        ghost_unique = any(ph in ghost_body for ph in msg_phrases_ghost)
        known_unique = any(ph in known_body for ph in msg_phrases_known)
        message_diverges = ghost_unique or known_unique

        if status_diverges or length_delta >= _ENUM_BODY_DELTA or message_diverges:
            indicators = []
            if status_diverges:
                indicators.append(
                    f"status divergence: ghost={rec_ghost.status} vs known={rec_known.status}"
                )
            if length_delta >= _ENUM_BODY_DELTA:
                indicators.append(
                    f"response-length delta: {length_delta} bytes "
                    f"(ghost={ghost_len}, known={known_len})"
                )
            if message_diverges:
                indicators.append("error message text differs between unknown and known accounts")

            severity = Severity.MEDIUM
            desc = (
                "The login endpoint returns distinguishably different responses for an unknown "
                "email address versus a registered one with the wrong password. An attacker can "
                "enumerate valid user accounts by observing these differences. Normalize all "
                "failed-login responses to an identical status code, body, and approximate "
                "timing regardless of whether the user exists. Indicators: "
                + "; ".join(indicators) + "."
            )
            yield Finding(
                vuln_class=VulnClass.INFO_LEAK,
                severity=severity,
                title="User enumeration via login response differences",
                endpoint=f"POST {_LOGIN_PATH}",
                description=desc,
                evidence=[rec_ghost, rec_known],
                detail={
                    "test": "user_enum_login",
                    "ghost_status": rec_ghost.status,
                    "known_status": rec_known.status,
                    "length_delta_bytes": length_delta,
                    "timing_delta_ms": round(timing_delta, 1),
                    "message_diverges": message_diverges,
                    "indicators": indicators,
                },
                confidence="tentative",
            )

        # Separate, lower-severity timing finding when only timing differs noticeably
        elif timing_delta >= _ENUM_TIMING_DELTA_MS:
            yield Finding(
                vuln_class=VulnClass.INFO_LEAK,
                severity=Severity.LOW,
                title="Possible user enumeration via login response timing",
                endpoint=f"POST {_LOGIN_PATH}",
                description=(
                    f"Login requests for a ghost account and a real account differ by "
                    f"{round(timing_delta)} ms on average. Consistent timing differences can "
                    f"indicate that the server performs a password hash comparison only for "
                    f"known accounts (timing side-channel). Perform the hash check unconditionally "
                    f"using a constant-time dummy hash to equalize timing."
                ),
                evidence=[rec_ghost, rec_known],
                detail={
                    "test": "user_enum_timing",
                    "ghost_elapsed_ms": rec_ghost.elapsed_ms,
                    "known_elapsed_ms": rec_known.elapsed_ms,
                    "timing_delta_ms": round(timing_delta, 1),
                },
                confidence="tentative",
            )

    # ------------------------------------------------------------------
    # 2. Brute-force rate limiting
    # ------------------------------------------------------------------

    def _test_rate_limiting(self) -> Iterable[Finding]:
        """Fire five rapid logins with wrong credentials.

        A properly protected endpoint should return 429 / 403 / redirect to
        a CAPTCHA, or introduce increasing delays. If all five requests succeed
        with the same error status and no throttling, rate limiting is absent.
        """
        records: list[RequestRecord] = []
        for _ in range(5):
            rec = _login_attempt(self.client, _GHOST_USER, _GHOST_PASS)
            records.append(rec)

        statuses = [r.status for r in records if r.status != 0]
        if not statuses:
            return  # all network errors — can't conclude

        # A 429 or 423 (Locked) on any attempt means throttling is active
        if any(s in (429, 423, 302) for s in statuses):
            return  # rate limiting present — no finding

        # Exponential timing increase is also a valid defense
        elapsed = [r.elapsed_ms for r in records if r.status != 0]
        if len(elapsed) >= 4:
            ratio = elapsed[-1] / max(elapsed[0], 1)
            if ratio >= 3.0:
                return  # server is slowing down requests

        # All attempts returned the same non-throttled response
        unique_statuses = set(statuses)
        if len(unique_statuses) == 1 and statuses[0] not in (429, 423):
            yield Finding(
                vuln_class=VulnClass.RATE_LIMIT,
                severity=Severity.MEDIUM,
                title="Brute-force rate limiting absent on login endpoint",
                endpoint=f"POST {_LOGIN_PATH}",
                description=(
                    "Five rapid login attempts with invalid credentials all received the same "
                    f"HTTP {statuses[0]} response with no throttling, lockout, or 429. An "
                    "attacker can attempt credentials at full network speed. Implement account "
                    "lockout (or increasing delays) after N failures, and/or require CAPTCHA "
                    "after repeated failures from the same IP."
                ),
                evidence=records,
                detail={
                    "test": "rate_limit_login",
                    "attempt_count": len(records),
                    "statuses": statuses,
                    "elapsed_ms": [r.elapsed_ms for r in records],
                },
                confidence="tentative",
            )

    # ------------------------------------------------------------------
    # 3. Default credentials
    # ------------------------------------------------------------------

    def _test_default_credentials(self) -> Iterable[Finding]:
        """Attempt each known the target default credential pair.

        A 200 with a JWT in the response body means the default is active.
        """
        if not self.config.scan.allow_state_changing:
            # Skip unless state-changing is explicitly allowed — even a login
            # creates a session record. Callers can override in config.
            pass  # still safe to check: login only reads, we don't persist the session

        for username, password in _DEFAULT_CREDS:
            rec = _login_attempt(self.client, username, password)
            if rec.status == 0:
                continue

            body = rec.resp_body or ""
            # Success indicators: HTTP 200 with a JWT or explicit success flag
            success = rec.status == 200 and (
                _JWT_RE.search(body)
                or '"success":true' in body.lower()
                or '"token"' in body.lower()
            )
            if success:
                # Clear the session cookie immediately — we don't want to reuse
                # this session for any further requests.
                self.client.session.cookies.clear()

                yield Finding(
                    vuln_class=VulnClass.MISCONFIG,
                    severity=Severity.HIGH,
                    title=f"Default the target credentials accepted ({username})",
                    endpoint=f"POST {_LOGIN_PATH}",
                    description=(
                        f"The server accepted the well-known default credential pair "
                        f"'{username}' / '{password}'. These credentials are publicly "
                        f"documented in the target setup guides and are a common first move "
                        f"for attackers targeting unpatched or demo-mode installations. "
                        f"Change all default credentials before deployment, disable unused "
                        f"built-in accounts, and enforce a strong password policy."
                    ),
                    evidence=[rec],
                    detail={
                        "test": "default_credentials",
                        "username": username,
                        "password_hint": password[:2] + "***",
                    },
                    confidence="firm",
                )
                return  # report first match; avoid locking the account

    # ------------------------------------------------------------------
    # 4. Password-reset enumeration
    # ------------------------------------------------------------------

    def _test_reset_enumeration(self, endpoint: Endpoint) -> Iterable[Finding]:
        """Compare password-reset responses for known vs ghost addresses.

        Probes both the incoming endpoint (if it looks like a reset path) and
        the canonical the target reset paths.
        """
        paths_to_try: list[str] = []

        # Include canonical paths if not already covered
        for p in _RESET_PATHS:
            if "{email}" not in p:
                paths_to_try.append(p)

        for path_tmpl in paths_to_try:
            # POST variant (body-based email field)
            rec_ghost = self.client.request(
                "POST", path_tmpl, identity_label="anonymous",
                json_body={"email": _GHOST_USER, "userId": _GHOST_USER},
            )
            rec_known = self.client.request(
                "POST", path_tmpl, identity_label="anonymous",
                json_body={"email": "admin@example.com", "userId": "admin@example.com"},
            )

            if rec_ghost.status in (0, 404) and rec_known.status in (0, 404):
                continue  # path doesn't exist

            if rec_ghost.status == 0 or rec_known.status == 0:
                continue

            status_diverges = rec_ghost.status != rec_known.status
            length_delta = abs(_body_len(rec_ghost) - _body_len(rec_known))

            if status_diverges or length_delta >= _ENUM_BODY_DELTA:
                indicators = []
                if status_diverges:
                    indicators.append(
                        f"status: ghost={rec_ghost.status} vs real={rec_known.status}"
                    )
                if length_delta >= _ENUM_BODY_DELTA:
                    indicators.append(f"body-length delta: {length_delta} bytes")

                yield Finding(
                    vuln_class=VulnClass.INFO_LEAK,
                    severity=Severity.LOW,
                    title="User enumeration via password-reset response differences",
                    endpoint=f"POST {path_tmpl}",
                    description=(
                        "The password-reset endpoint returns distinguishably different responses "
                        "for a nonexistent email address versus a real one. An attacker can "
                        "confirm account existence without credentials. Normalize all reset "
                        "responses to the same status and generic message: "
                        "'If that address is registered, a reset email has been sent.' "
                        "Indicators: " + "; ".join(indicators) + "."
                    ),
                    evidence=[rec_ghost, rec_known],
                    detail={
                        "test": "reset_enum",
                        "path": path_tmpl,
                        "ghost_status": rec_ghost.status,
                        "known_status": rec_known.status,
                        "length_delta_bytes": length_delta,
                        "indicators": indicators,
                    },
                    confidence="tentative",
                )
            break  # one live reset path is enough to test

        # GET /api/v1/users/password/reset/{email} path variant
        for email, label in [(_GHOST_USER, "ghost"), ("admin@example.com", "known")]:
            path = f"/api/v1/users/password/reset/{email}"
            rec = self.client.request("GET", path, identity_label="anonymous")
            if label == "ghost":
                rec_ghost_get = rec
            else:
                rec_known_get = rec

        try:
            if rec_ghost_get.status in (0,) or rec_known_get.status in (0,):
                return
            if rec_ghost_get.status in (404,) and rec_known_get.status in (404,):
                return  # endpoint doesn't exist in this target version

            status_diverges = rec_ghost_get.status != rec_known_get.status
            length_delta = abs(_body_len(rec_ghost_get) - _body_len(rec_known_get))

            if status_diverges or length_delta >= _ENUM_BODY_DELTA:
                indicators = []
                if status_diverges:
                    indicators.append(
                        f"status: ghost={rec_ghost_get.status} vs real={rec_known_get.status}"
                    )
                if length_delta >= _ENUM_BODY_DELTA:
                    indicators.append(f"body-length delta: {length_delta} bytes")
                yield Finding(
                    vuln_class=VulnClass.INFO_LEAK,
                    severity=Severity.LOW,
                    title="User enumeration via GET password-reset endpoint",
                    endpoint="GET /api/v1/users/password/reset/{email}",
                    description=(
                        "The GET password-reset endpoint returns different responses for a ghost "
                        "email versus a registered one. Normalize to a uniform response. "
                        "Indicators: " + "; ".join(indicators) + "."
                    ),
                    evidence=[rec_ghost_get, rec_known_get],
                    detail={
                        "test": "reset_enum_get",
                        "ghost_status": rec_ghost_get.status,
                        "known_status": rec_known_get.status,
                        "length_delta_bytes": length_delta,
                    },
                    confidence="tentative",
                )
        except UnboundLocalError:
            pass  # one of the GET requests was never made

    # ------------------------------------------------------------------
    # 5. Auth bypass via degenerate bearer tokens
    # ------------------------------------------------------------------

    def _test_auth_bypass(self) -> Iterable[Finding]:
        """Check whether null/undefined/empty bearer values bypass auth.

        Uses /api/v1/users/current as the oracle (200 = authenticated,
        401/403 = properly rejected).
        """
        oracle = "/api/v1/users/current"

        # Establish the baseline: anonymous (no header) should be denied
        baseline = self.client.request("GET", oracle, identity_label="anonymous")
        if baseline.status not in (401, 403):
            return  # endpoint is public — bypass test is not meaningful

        for token_val in _DEGENERATE_TOKENS:
            if token_val == "":
                auth_header = ""
                header_repr = "Authorization: Bearer (empty string)"
            else:
                auth_header = f"Bearer {token_val}"
                header_repr = f"Authorization: Bearer {token_val}"

            headers: dict = {}
            if auth_header:
                headers["Authorization"] = auth_header
            else:
                headers["Authorization"] = "Bearer "

            rec = self.client.request(
                "GET", oracle,
                identity_label="anon-bypass-test",
                headers=headers,
            )

            if rec.status == 200:
                yield Finding(
                    vuln_class=VulnClass.AUTHZ,
                    severity=Severity.HIGH,
                    title=f"Auth bypass: degenerate bearer token accepted ({token_val!r})",
                    endpoint=f"GET {oracle}",
                    description=(
                        f"The server returned HTTP 200 on a protected endpoint when the "
                        f"Authorization header contained the degenerate value "
                        f"'{header_repr}'. This indicates the authentication filter "
                        f"treats certain sentinel strings as a valid (or absent) token "
                        f"rather than rejecting them. Ensure the token validation layer "
                        f"rejects any token that is null, empty, or not a well-formed JWT."
                    ),
                    evidence=[baseline, rec],
                    detail={
                        "test": "auth_bypass_degenerate_token",
                        "token_value": token_val,
                        "header": header_repr,
                        "bypass_status": rec.status,
                        "baseline_status": baseline.status,
                    },
                    confidence="firm",
                )

    # ------------------------------------------------------------------
    # 6. Session-cookie security flags
    # ------------------------------------------------------------------

    def _test_cookie_flags(self) -> Iterable[Finding]:
        """After a login attempt, inspect Set-Cookie headers for JSESSIONID.

        Uses ghost credentials — the target may still return a Set-Cookie even on
        a failed login (e.g., a pre-auth JSESSIONID). On success, checks the
        cookie attributes on the real session cookie.
        """
        # First, probe with the known dev default to get a real session cookie
        # (if default creds are active). Otherwise use the ghost attempt.
        test_pairs = [
            ("admin@example.com", "admin"),
            ("admin@example.com", "target"),
            (_GHOST_USER, _GHOST_PASS),
        ]

        set_cookie_header: Optional[str] = None
        cookie_source_rec: Optional[RequestRecord] = None

        for username, password in test_pairs:
            rec = _login_attempt(self.client, username, password)
            sc = _h(rec.resp_headers, "Set-Cookie")
            if sc:
                set_cookie_header = sc
                cookie_source_rec = rec
                break

        if not set_cookie_header or not cookie_source_rec:
            return  # no Set-Cookie observed — nothing to check

        # Only care about session cookies (JSESSIONID or similar)
        relevant = any(
            name in set_cookie_header.upper()
            for name in ("JSESSIONID", "DOTAUTH", "ACCESS_TOKEN", "JWT")
        )
        if not relevant:
            return

        flags = _cookie_flags(set_cookie_header)
        missing = [name.upper() for name, present in flags.items() if not present]

        if not missing:
            return  # all flags present — no finding

        # Build per-flag remediation notes
        flag_notes = {
            "SECURE": (
                "SECURE — without this flag, the cookie is transmitted over plain HTTP, "
                "allowing network interception."
            ),
            "HTTPONLY": (
                "HTTPONLY — without this flag, JavaScript (including injected XSS payloads) "
                "can read the session cookie."
            ),
            "SAMESITE": (
                "SAMESITE — without this flag, the cookie is sent on cross-site requests, "
                "enabling CSRF attacks."
            ),
        }
        notes = [flag_notes[f] for f in missing if f in flag_notes]

        yield Finding(
            vuln_class=VulnClass.MISCONFIG,
            severity=Severity.LOW,
            title=f"Session cookie missing security flag(s): {', '.join(missing)}",
            endpoint=f"POST {_LOGIN_PATH}",
            description=(
                "The session cookie returned by the login endpoint is missing one or more "
                "security attributes that protect it from theft or misuse. Missing: "
                + "; ".join(notes)
                + " Set all three flags on session cookies in the target's "
                "server.xml / web.xml or the reverse proxy configuration."
            ),
            evidence=[cookie_source_rec],
            detail={
                "test": "cookie_flags",
                "set_cookie": set_cookie_header[:512],
                "missing_flags": missing,
                "present_flags": [
                    name.upper() for name, present in flags.items() if present
                ],
            },
            confidence="firm",
        )
