"""CSRF scanner for the target's REST endpoints (v1.0).

Tests four distinct CSRF attack surfaces:

1. Cross-Origin forged request (Origin header bypass)
   Send a POST/PUT/DELETE with a hostile Origin and no anti-CSRF token.
   If the server responds 2xx the endpoint accepts cross-site mutations.

2. Forged-Referer bypass
   Repeat the probe with a forged Referer pointing to an external site.
   Some frameworks reject mis-matched Referer; if this still returns 2xx the
   referrer check is absent.

3. form-urlencoded Content-Type bypass
   Re-send as ``application/x-www-form-urlencoded`` (the native CSRF payload
   type). A server that rejects JSON requests but accepts this reveals that
   its Content-Type check was not a real CSRF defence.

4. Auth-cookie security flags
   POST /api/v1/authentication and inspect every ``Set-Cookie`` header on the
   response. Flag cookies that are missing HttpOnly, Secure, or SameSite
   attributes, because weak cookie flags make CSRF and session hijacking more
   exploitable.

Scope guard:
  - Only state-changing methods (POST / PUT / PATCH / DELETE) are tested.
  - Only endpoints on paths that are plausibly browser-session paths (user,
    content, workflow, auth, asset, page, …) are in scope; pure API-token
    endpoints are skipped.
  - Tests 1-3 only run if ``allow_state_changing`` is set in the scan config.
  - Test 4 always runs as it is read-only (one extra login request).

False-positive guard:
  - If the request returns 401/403, the session was rejected and there is no
    CSRF exposure — the finding is suppressed.
  - If the identity authenticates with a Bearer token in an Authorization
    header (not a cookie) the request cannot be CSRF-replayed by a browser,
    so tests 1-3 are skipped.
"""
from __future__ import annotations

import json
import re
from typing import Iterable

from .base import Scanner
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

# ── constants ────────────────────────────────────────────────────────────────

_EVIL_ORIGIN = "https://evil.deluluscan-oob.example"
_EVIL_REFERER = "https://evil.deluluscan-oob.example/csrf-poc.html"

# Endpoint path fragments that indicate a browser-session-facing path.  Pure
# token/machine-API paths (integrations, webhooks, plugin) are excluded.
_BROWSER_PATH_PATTERNS = re.compile(
    r"/api/v[0-9]+/"
    r"(authentication|logout|users|user|content(?:let)?|workflow|"
    r"asset|page|category|site|folder|language|"
    r"tempfile|htmlpage|template|nav|push|bundle)",
    re.IGNORECASE,
)

# Anti-CSRF header names — strip these from the forged request to maximise
# how closely it mimics a real cross-site request.
_CSRF_HEADER_NAMES = frozenset({
    "x-csrf-token", "x-xsrf-token", "csrf-token",
    "x-requested-with", "x-target-csrf",
})

# Auth-cookie names used by the target.
_AUTH_COOKIE_NAMES = re.compile(
    r"(jsessionid|access_token|jwtaccesstoken|jwt|rme|csrftoken)",
    re.IGNORECASE,
)

_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


# ── helpers ──────────────────────────────────────────────────────────────────

def _header(headers: dict, name: str) -> str | None:
    """Case-insensitive header lookup."""
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _strip_csrf_headers(headers: dict) -> dict:
    """Return a copy of *headers* with known anti-CSRF fields removed."""
    return {k: v for k, v in headers.items() if k.lower() not in _CSRF_HEADER_NAMES}


def _parse_set_cookie(header_value: str) -> dict[str, str]:
    """Parse a single Set-Cookie header string into a lower-cased flag dict."""
    parts = [p.strip() for p in header_value.split(";")]
    flags: dict[str, str] = {}
    for part in parts[1:]:  # skip the name=value pair
        if "=" in part:
            k, v = part.split("=", 1)
            flags[k.strip().lower()] = v.strip().lower()
        else:
            flags[part.lower()] = "present"
    return flags


# ── scanner ──────────────────────────────────────────────────────────────────

class CsrfScanner(Scanner):
    """Dedicated CSRF protection scanner for the target's REST endpoints."""

    name = "csrf"
    vuln_classes = [VulnClass.MISCONFIG.value]

    # ── scope ────────────────────────────────────────────────────────────────

    def applies_to(self, endpoint: Endpoint) -> bool:
        if endpoint.method.upper() not in _STATE_CHANGING_METHODS:
            return False
        return bool(_BROWSER_PATH_PATTERNS.search(endpoint.path))

    # ── main entry point ─────────────────────────────────────────────────────

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        # Pick the most privileged cookie-session identity available.
        ident = (
            self.identities.get(IdentityRole.BACKEND.value)
            or self.identities.get(IdentityRole.ADMIN.value)
            or self.identities.get(IdentityRole.CONTENT_EDITOR.value)
        )
        if ident is None:
            return

        raw_headers = self.auth.headers_for(ident)

        # Tests 1-3: only for cookie-based auth (no Authorization header present)
        cookie_based = (
            any(k.lower() == "cookie" for k in raw_headers)
            and not any(k.lower() == "authorization" for k in raw_headers)
        )

        if cookie_based and self.config.scan.allow_state_changing:
            yield from self._test_cross_origin_request(endpoint, ident, raw_headers)
            yield from self._test_forged_referer(endpoint, ident, raw_headers)
            yield from self._test_form_urlencoded_bypass(endpoint, ident, raw_headers)

        # Test 4: auth-cookie flag audit — always run (read-only probe)
        yield from self._audit_auth_cookie_flags()

    # ── test 1: cross-origin request ─────────────────────────────────────────

    def _test_cross_origin_request(
        self, endpoint: Endpoint, ident, raw_headers: dict
    ) -> Iterable[Finding]:
        path = self.concrete_path(endpoint)
        headers = _strip_csrf_headers(dict(raw_headers))
        headers["Origin"] = _EVIL_ORIGIN

        rec = self.client.request(
            endpoint.method, path,
            identity_label=ident.label(),
            headers=headers,
            json_body={},
        )
        if rec is None or rec.status in (0, 401, 403, 405):
            return

        if _is_success(rec.status):
            yield Finding(
                vuln_class=VulnClass.MISCONFIG,
                severity=Severity.HIGH,
                title="CSRF: state-changing request accepted with cross-site Origin",
                endpoint=endpoint.key,
                description=(
                    f"A cookie-authenticated {endpoint.method.upper()} request to "
                    f"{endpoint.path} succeeded (HTTP {rec.status}) even when the "
                    f"Origin header was set to a hostile external site ({_EVIL_ORIGIN}) "
                    "and all known anti-CSRF headers were stripped from the request. "
                    "If the session cookie lacks SameSite=Strict/Lax, an attacker can "
                    "forge this request from any page and make the victim perform "
                    "unintended state-changing operations on their behalf."
                ),
                evidence=[rec],
                detail={
                    "test": "csrf_cross_origin",
                    "evil_origin": _EVIL_ORIGIN,
                    "response_status": rec.status,
                    "active": True,
                },
                confidence="firm",
            )

    # ── test 2: forged Referer bypass ─────────────────────────────────────────

    def _test_forged_referer(
        self, endpoint: Endpoint, ident, raw_headers: dict
    ) -> Iterable[Finding]:
        path = self.concrete_path(endpoint)
        headers = _strip_csrf_headers(dict(raw_headers))
        # Deliberately omit Origin so only the Referer check is exercised.
        headers.pop("origin", None)
        headers["Referer"] = _EVIL_REFERER

        rec = self.client.request(
            endpoint.method, path,
            identity_label=ident.label(),
            headers=headers,
            json_body={},
        )
        if rec is None or rec.status in (0, 401, 403, 405):
            return

        if _is_success(rec.status):
            yield Finding(
                vuln_class=VulnClass.MISCONFIG,
                severity=Severity.MEDIUM,
                title="CSRF: state-changing request accepted with external Referer",
                endpoint=endpoint.key,
                description=(
                    f"A cookie-authenticated {endpoint.method.upper()} request to "
                    f"{endpoint.path} succeeded (HTTP {rec.status}) with a Referer "
                    f"header pointing to an external attacker-controlled site "
                    f"({_EVIL_REFERER}). The absence of a Referer-origin check means "
                    "the server cannot distinguish legitimate same-site requests from "
                    "forged cross-site ones submitted via HTML forms or redirects."
                ),
                evidence=[rec],
                detail={
                    "test": "csrf_forged_referer",
                    "evil_referer": _EVIL_REFERER,
                    "response_status": rec.status,
                    "active": True,
                },
                confidence="tentative",
            )

    # ── test 3: form-urlencoded Content-Type bypass ───────────────────────────

    def _test_form_urlencoded_bypass(
        self, endpoint: Endpoint, ident, raw_headers: dict
    ) -> Iterable[Finding]:
        """Check whether the server accepts form-encoded bodies on a JSON endpoint.

        The canonical browser CSRF vector uses ``application/x-www-form-urlencoded``
        (no preflight required). If the server accepts this content type, any
        JSON Content-Type restriction is not a real CSRF defence.
        """
        path = self.concrete_path(endpoint)
        headers = _strip_csrf_headers(dict(raw_headers))
        headers["Origin"] = _EVIL_ORIGIN
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        # Remove JSON content type if present
        for k in list(headers):
            if k.lower() == "content-type" and k != "Content-Type":
                del headers[k]

        # Minimal form body — just enough to not be empty
        form_data = "dummy=1"

        rec = self.client.request(
            endpoint.method, path,
            identity_label=ident.label(),
            headers=headers,
            data=form_data,
        )
        if rec is None or rec.status in (0, 401, 403, 405, 415):
            # 415 Unsupported Media Type means the Content-Type check IS working.
            return

        if _is_success(rec.status):
            yield Finding(
                vuln_class=VulnClass.MISCONFIG,
                severity=Severity.HIGH,
                title="CSRF: endpoint accepts form-urlencoded — Content-Type is not a CSRF defence",
                endpoint=endpoint.key,
                description=(
                    f"A cookie-authenticated {endpoint.method.upper()} request to "
                    f"{endpoint.path} was accepted (HTTP {rec.status}) with "
                    "Content-Type: application/x-www-form-urlencoded and a hostile "
                    f"Origin ({_EVIL_ORIGIN}). Because browsers can submit this "
                    "content type cross-origin without a preflight, any Content-Type "
                    "restriction on this endpoint does NOT prevent CSRF. An attacker "
                    "can forge this request with a hidden HTML form."
                ),
                evidence=[rec],
                detail={
                    "test": "csrf_form_urlencoded",
                    "evil_origin": _EVIL_ORIGIN,
                    "content_type_sent": "application/x-www-form-urlencoded",
                    "response_status": rec.status,
                    "active": True,
                },
                confidence="firm",
            )

    # ── test 4: auth-cookie security flag audit ───────────────────────────────

    def _audit_auth_cookie_flags(self) -> Iterable[Finding]:
        """POST to the target authentication endpoint and inspect Set-Cookie flags.

        We log in without caching the result so we can see the raw Set-Cookie
        headers.  We immediately discard the cookie after inspection.
        """
        # Find any identity that has credentials so we can trigger a real login.
        login_ident = None
        for role in (
            IdentityRole.ADMIN.value,
            IdentityRole.BACKEND.value,
            IdentityRole.CONTENT_EDITOR.value,
        ):
            cand = self.identities.get(role)
            if cand and cand.username and cand.password:
                login_ident = cand
                break

        if login_ident is None:
            return

        rec = self.client.request(
            "POST", "/api/v1/authentication",
            identity_label="csrf_cookie_audit",
            json_body={
                "userId": login_ident.username,
                "password": login_ident.password,
                "rememberMe": False,
            },
        )

        if rec is None or rec.status != 200:
            return

        # Collect every Set-Cookie header (resp_headers may have a single merged
        # value if there are multiple — handle both styles).
        raw_cookies: list[str] = []
        for k, v in rec.resp_headers.items():
            if k.lower() == "set-cookie":
                # requests merges duplicate headers with ", " — split carefully
                # on "; " boundaries to avoid splitting on comma inside Expires.
                raw_cookies.append(v)

        if not raw_cookies:
            return

        for raw in raw_cookies:
            # Extract the cookie name from the first segment.
            name_val = raw.split(";")[0].strip()
            cookie_name = name_val.split("=")[0].strip()

            if not _AUTH_COOKIE_NAMES.search(cookie_name):
                continue  # not an auth cookie; skip

            flags = _parse_set_cookie(raw)
            issues: list[str] = []

            if "httponly" not in flags:
                issues.append("missing HttpOnly flag (JavaScript can read the cookie)")

            if "secure" not in flags:
                issues.append(
                    "missing Secure flag (cookie transmitted over plain HTTP)"
                )

            samesite = flags.get("samesite", "")
            if not samesite:
                issues.append(
                    "missing SameSite attribute (defaults to None in older browsers, "
                    "enabling cross-site requests with the cookie)"
                )
            elif samesite == "none":
                if "secure" not in flags:
                    issues.append(
                        "SameSite=None without Secure — browser will reject the cookie "
                        "(RFC 6265bis), and if accepted it is fully CSRF-exploitable"
                    )
                else:
                    issues.append(
                        "SameSite=None (with Secure) — cookie is sent on all cross-site "
                        "requests; CSRF is only mitigated by an anti-CSRF token"
                    )
            elif samesite == "lax":
                # SameSite=Lax is the modern browser default and provides partial
                # protection but is still exploitable via top-level navigations.
                pass  # acceptable — do not flag

            if not issues:
                continue

            severity = Severity.HIGH if "missing SameSite" in " ".join(issues) or "SameSite=None" in " ".join(issues) else Severity.MEDIUM

            yield Finding(
                vuln_class=VulnClass.MISCONFIG,
                severity=severity,
                title=f"Auth cookie '{cookie_name}' has weak security flags",
                endpoint="POST /api/v1/authentication",
                description=(
                    f"The authentication response sets the '{cookie_name}' cookie "
                    "with one or more missing security attributes:\n"
                    + "\n".join(f"  • {i}" for i in issues)
                    + "\n\nWeak cookie flags increase the risk of CSRF attacks and "
                    "session hijacking. Ensure all authentication cookies are set "
                    "with HttpOnly; Secure; SameSite=Lax (or Strict)."
                ),
                evidence=[rec],
                detail={
                    "test": "csrf_cookie_flags",
                    "cookie_name": cookie_name,
                    "raw_set_cookie": raw,
                    "flags_detected": flags,
                    "issues": issues,
                    "active": False,
                },
                confidence="firm",
            )
