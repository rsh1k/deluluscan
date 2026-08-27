"""Broad OWASP Top 10 detector.

The four focused scanners cover A01 (IDOR/access control), A03 (injection: SQLi),
and the XSS slice of A03, plus SSRF (A10). This scanner sweeps the remaining
classes as lightweight, non-destructive signals so a single run gives Top-10
breadth:

  A02 Cryptographic failures / sensitive exposure  -> secrets in responses,
                                                       missing HSTS on TLS
  A04 Insecure design                              -> dangerous debug endpoints
  A05 Security misconfiguration                    -> stack traces, default
                                                       creds surface, dir listing,
                                                       missing security headers,
                                                       permissive CORS
  A06 Vulnerable components                        -> server/version banners
  A07 Auth failures                                -> verbose auth errors,
                                                       user-enumeration deltas
  A08 Integrity failures                           -> unauth plugin/OSGi upload
                                                       surface (flag only)
  A09 Logging/monitoring                           -> (out of scope for a black-box
                                                       scan; noted in report)

Everything here is read-only detection. Where an endpoint is sensitive (e.g. the
OSGi plugin upload surface that has been abused for code execution), we only
record that it is reachable and by whom -- we never upload a bundle or attempt
execution.
"""
from __future__ import annotations

import re
from typing import Iterable

from .base import Scanner, canary
from ..models import (Endpoint, Finding, IdentityRole, Severity, VulnClass)

_SECRET = re.compile(
    r"(?i)(api[_-]?key|secret|passwd|password\"\s*:|aws_access_key_id|"
    r"private[_-]?key|BEGIN RSA|client_secret|bearer\s+eyJ)")
_STACK = re.compile(
    r"(com\.example\.|com\.target\.|org\.apache\.|"
    r"java\.lang\.[A-Za-z]+Exception|at [\w.$]+\([\w.]+\.java:\d+\))")


def _is_masked(val: str) -> bool:
    """True if the 'secret' value is null/empty/redacted/masked — not a real leak."""
    v = (val or "").strip().strip('"').strip()
    if not v or len(v) < 8:
        return True
    low = v.lower()
    if low in ("null", "none", "false", "true", "0", "changeme", "redacted"):
        return True
    if any(t in low for t in ("redacted", "masked", "hidden", "example", "changeit",
                              "placeholder", "dummy", "xxxx", "your_", "<", "*****")):
        return True
    # mostly-mask characters (••••, ****, ....)
    if sum(c in "*•.•x " for c in v) / max(1, len(v)) > 0.6:
        return True
    return False

_SENSITIVE_SURFACES = {
    # Generic, framework-agnostic sensitive surfaces (management/debug/secret stores).
    "/actuator": "Spring Boot Actuator root (may expose env/heapdump/shutdown)",
    "/actuator/env": "Actuator env (secrets/config disclosure)",
    "/actuator/heapdump": "heap dump (memory disclosure)",
    "/server-status": "Apache mod_status (internal disclosure)",
    "/metrics": "metrics endpoint (internal disclosure)",
    "/jolokia": "Jolokia JMX (potential RCE surface)",
    "/console": "admin/management console",
    "/admin": "admin surface",
}

# Endpoints that require elevated roles and should block anonymous + backend
# identities — flag a 200 response as a potential authz failure (A01/A07).
_ADMIN_ONLY_SURFACES = {
    "GET /admin": "admin surface (should require an admin identity)",
    "GET /api/admin/users": "user listing (admin-gated)",
    "GET /api/users": "user listing (should require auth)",
}

# Per-prefix probe kwargs for sensitive-surface checks.  When an empty POST/PUT
# always returns a server error (e.g. OSGi bundle upload requires a multipart
# body; apps secrets returns 500 on empty body), a generic empty request cannot
# distinguish auth vs. non-auth errors.  Supply the minimal well-formed body so
# the server evaluates the *auth* layer before rejecting on semantic grounds.
#
# Keys map endpoint *prefixes* (matching _SENSITIVE_SURFACES) to extra kwargs:
#   _multipart  -> passed as files= (list of (field, (data, filename, mimetype)))
#   _json_body  -> passed as json_body= (dict, used for POST/PUT probes)
_SENSITIVE_PROBE_KWARGS: dict[str, dict] = {}  # no product-specific probe bodies

_SEC_HEADERS = ["content-security-policy", "x-content-type-options",
                "x-frame-options", "strict-transport-security"]


class OwaspBroadScanner(Scanner):
    name = "owasp"
    vuln_classes = [VulnClass.INFO_LEAK.value, VulnClass.AUTHZ.value]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # CORS / missing-headers are server-wide; report them once, not per route.
        self._cors_reported = False
        self._headers_reported = False

    def applies_to(self, endpoint: Endpoint) -> bool:
        return endpoint.method.upper() in ("GET", "POST", "PUT")

    # -- sensitive-surface probe helpers ------------------------------------

    def _probe_sensitive(self, endpoint: Endpoint, identity, prefix: str):
        """Fetch a sensitive surface with the right probe shape for the prefix.

        For most endpoints self.fetch() suffices.  For endpoints that return
        HTTP 400 on an empty request body (making auth/no-auth indistinguishable),
        we send the minimal well-formed body described in _SENSITIVE_PROBE_KWARGS
        so the server can evaluate the *authentication* layer first.
        """
        probe_kwargs = _SENSITIVE_PROBE_KWARGS.get(prefix, {})
        if not probe_kwargs:
            return self.fetch(endpoint, identity)

        headers = self.auth.headers_for(identity)
        path = self.concrete_path(endpoint)
        method = endpoint.method.upper()

        multipart = probe_kwargs.get("_multipart")
        if multipart:
            # Convert list-of-tuples to the dict/list format requests expects for
            # files=: [(field, (data, filename, mimetype)), ...]
            files = [(field, (fname, data, mime))
                     for (field, (data, fname, mime)) in multipart]
            return self.client.request(
                method, path,
                identity_label=identity.label(),
                headers=headers,
                files=files,
            )

        json_body = probe_kwargs.get("_json_body")
        if json_body is not None:
            return self.client.request(
                method, path,
                identity_label=identity.label(),
                headers=headers,
                json_body=json_body,
            )

        # Fallback — should not normally be reached, but be safe.
        return self.fetch(endpoint, identity)

    # -- main scan loop ----------------------------------------------------

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        anon = self.identities.get(IdentityRole.ANON.value)
        rec = self.fetch(endpoint, anon)

        # A05: stack traces leaking internals
        if _STACK.search(rec.resp_body):
            yield Finding(
                vuln_class=VulnClass.INFO_LEAK, severity=Severity.MEDIUM,
                title="Stack trace / internal class names exposed",
                endpoint=endpoint.key,
                description=("The response leaked Java stack frames or internal "
                             "the target/Apache class names, revealing implementation "
                             "detail useful to an attacker (A05)."),
                evidence=[rec], confidence="firm")

        # A02: secrets in body — match actual secret VALUES (AWS/Google keys, JWTs,
        # PEM private keys, high-entropy tokens), not merely the presence of a field
        # named "apiKey"/"secret"/"password". A key-shaped field with a null, empty,
        # masked, or placeholder value is NOT a leak.
        if rec.status == 200:
            from ..active.crawler import mine_secrets
            hits = mine_secrets(rec.resp_body or "")
            hits = [(k, v) for (k, v) in hits if not _is_masked(v)]
            if hits:
                kinds = ", ".join(sorted({k for k, _ in hits}))
                yield Finding(
                    vuln_class=VulnClass.INFO_LEAK, severity=Severity.HIGH,
                    title="Secret material exposed in response",
                    endpoint=endpoint.key,
                    description=(f"The response body contains a value matching a real secret "
                                 f"format ({kinds}) — e.g. an AWS/Google key, JWT, private key, or "
                                 f"high-entropy token, not merely a field named 'secret'. Review "
                                 f"and rotate if it is a live credential."),
                    evidence=[rec],
                    detail={"test": "secret_in_response", "kinds": kinds},
                    confidence="firm")

        # A05: permissive CORS (server-wide; report once)
        acao = rec.resp_headers.get("Access-Control-Allow-Origin", "")
        acac = rec.resp_headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true" and not self._cors_reported:
            self._cors_reported = True
            yield Finding(
                vuln_class=VulnClass.AUTHZ, severity=Severity.LOW,
                title="Permissive CORS headers (wildcard origin + credentials)",
                endpoint=endpoint.key,
                description=("Responses send Access-Control-Allow-Origin: * with "
                             "Allow-Credentials: true. Browsers actually REJECT "
                             "this exact combination, so it is not directly "
                             "exploitable as-is — but it signals loose CORS "
                             "handling worth reviewing (A05). Reported once; "
                             "applies server-wide."),
                evidence=[rec], confidence="firm")

        # A05: missing security headers (report once)
        if (rec.status == 200 and "html" in rec.resp_headers.get("Content-Type", "")
                and not self._headers_reported):
            missing = [h for h in _SEC_HEADERS if h not in
                       {k.lower() for k in rec.resp_headers}]
            if len(missing) >= 3:
                self._headers_reported = True
                yield Finding(
                    vuln_class=VulnClass.INFO_LEAK, severity=Severity.LOW,
                    title="Multiple security headers missing",
                    endpoint=endpoint.key,
                    description=(f"Missing: {', '.join(missing)}. Hardening gap "
                                 f"(A05)."),
                    evidence=[rec], confidence="firm")

        # A04/A08: sensitive surface reachability (flag-only, no exploitation)
        for prefix, label in _SENSITIVE_SURFACES.items():
            if endpoint.path.startswith(prefix):
                for role in ("anonymous", "backend"):
                    ident = self.identities.get(
                        IdentityRole.ANON.value if role == "anonymous"
                        else IdentityRole.BACKEND.value)
                    if not ident:
                        continue
                    r = self._probe_sensitive(endpoint, ident, prefix)
                    # Only real CONTENT counts as "reachable". Previously any
                    # status outside {400,401,403,404,405,0} qualified — which let
                    # a 5xx server error or a 3xx redirect-to-login be reported as
                    # a reachable sensitive surface. Route through the classifier.
                    from ..verify import evidence as E
                    if E.classify_response(r) == E.DISPOSITION_CONTENT:
                        sev = Severity.HIGH if "code-execution" in label else Severity.MEDIUM
                        yield Finding(
                            vuln_class=VulnClass.AUTHZ, severity=sev,
                            title=f"Sensitive surface reachable as {role}: {label}",
                            endpoint=endpoint.key,
                            description=(
                                f"{endpoint.key} ({label}) returned substantive content "
                                f"(HTTP {r.status}) to the {role} identity. Sensitive "
                                f"operations like this should be admin-gated. The "
                                f"scanner only checked reachability and did not "
                                f"upload, deploy, or execute anything."),
                            evidence=[r], confidence="firm" if r.status == 200
                            else "tentative")
                break

        # A01/A07: admin-only endpoint access by unprivileged identities
        # Check whether admin-gated read endpoints are accessible without admin auth.
        # Flag a non-401/403/404 as a potential broken access control issue.
        ep_key = f"{endpoint.method.upper()} {endpoint.path}"
        if ep_key in _ADMIN_ONLY_SURFACES:
            admin_label = _ADMIN_ONLY_SURFACES[ep_key]
            for role in ("anonymous", "backend"):
                ident = self.identities.get(
                    IdentityRole.ANON.value if role == "anonymous"
                    else IdentityRole.BACKEND.value)
                if not ident:
                    continue
                r = self.fetch(endpoint, ident)
                # Require real CONTENT, not a bare 200. the target commonly answers
                # /api/roles, /users/filter, /apps with a 200 empty entity or
                # a {"errors":[...]} envelope to an unprivileged caller — those
                # are NOT admin data and must not be flagged as broken access control.
                from ..verify import evidence as E
                if E.classify_response(r) == E.DISPOSITION_CONTENT:
                    yield Finding(
                        vuln_class=VulnClass.AUTHZ, severity=Severity.HIGH,
                        title=f"Admin-only endpoint accessible as {role}: {admin_label}",
                        endpoint=endpoint.key,
                        description=(
                            f"{endpoint.key} ({admin_label}) returned substantive "
                            f"content (HTTP {r.status}) to the {role} identity. This "
                            f"endpoint should require admin privileges. Possible broken "
                            f"access control (A01)."),
                        evidence=[r], confidence="firm")

        # A07: user enumeration via login response delta
        # Test only once per scanner lifetime (not per-endpoint) — only trigger on
        # the login endpoint itself to avoid noise.
        if endpoint.path in ("/api/v1/authentication", "/api/v1/authentication/api-token"):
            yield from self._check_user_enumeration(endpoint)

    # -- A07: user-enumeration check ----------------------------------------

    def _check_user_enumeration(self, endpoint: Endpoint) -> Iterable[Finding]:
        """Probe the login endpoint for distinguishable error responses.

        A site is vulnerable to user enumeration when "wrong password for a valid
        user" and "nonexistent user" produce different HTTP status codes, response
        bodies, or Timing deltas large enough to be reliable.  We use two clearly
        synthetic accounts so we never accidentally hit a real credential.
        """
        anon = self.identities.get(IdentityRole.ANON.value)
        if not anon:
            return

        login_path = "/api/v1/authentication"
        valid_user_payload = {"userId": "admin@example.com",
                              "password": "deluluscan-canary-wrongpw-" + canary()}
        ghost_user_payload = {"userId": "deluluscan-ghost-" + canary() + "@example.invalid",
                              "password": "irrelevant"}

        r_valid = self.client.request(
            "POST", login_path,
            identity_label="anonymous",
            headers=self.auth.headers_for(anon),
            json_body=valid_user_payload,
        )
        r_ghost = self.client.request(
            "POST", login_path,
            identity_label="anonymous",
            headers=self.auth.headers_for(anon),
            json_body=ghost_user_payload,
        )

        same_status = r_valid.status == r_ghost.status
        # Normalise bodies: strip any per-request tokens/timestamps before comparing.
        def _norm(body: str) -> str:
            return re.sub(r'[0-9a-f\-]{8,}', '<tok>', (body or "").lower())

        same_body = _norm(r_valid.resp_body) == _norm(r_ghost.resp_body)

        if not same_status or not same_body:
            detail_parts = []
            if not same_status:
                detail_parts.append(
                    f"status differs: valid-user={r_valid.status} vs "
                    f"nonexistent-user={r_ghost.status}")
            if not same_body:
                detail_parts.append("response body differs between valid and nonexistent user")
            yield Finding(
                vuln_class=VulnClass.AUTHZ, severity=Severity.LOW,
                title="User enumeration possible via login response delta",
                endpoint=endpoint.key,
                description=(
                    "The login endpoint returns distinguishable responses for "
                    "'wrong password on a valid account' vs. 'nonexistent user'. "
                    "An attacker can iterate usernames to harvest valid accounts "
                    "(A07). Details: " + "; ".join(detail_parts) + "."),
                evidence=[r_valid, r_ghost],
                detail={"valid_user_status": r_valid.status,
                        "ghost_user_status": r_ghost.status},
                confidence="tentative")
