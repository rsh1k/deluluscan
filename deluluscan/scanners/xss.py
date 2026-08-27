"""XSS detector (reflection-based, non-executing).

This scanner never delivers a working XSS payload. It injects unique, inert
canaries and inspects whether the application returns them in a dangerous
HTML/JS context without escaping. Surfaces covered:

  1. Query-parameter reflection (GET/any method with query params).
  2. POST/PUT JSON body — string fields in the request body are probed to catch
     stored-and-immediately-reflected or echo-style XSS.
  3. Path-parameter reflection — non-UUID string path segments ({name}, {slug},
     {variable} etc.) are injected with canaries.
  4. Field-split filter-bypass on the authenticated user's own profile (the
     class of the target profile-field issues where a single-field check is tricked
     by splitting '<' and '=' across two adjacent fields).
  5. DOM XSS signal — checks whether user input lands inside a <script> block
     or an inline JS variable assignment without escaping.

Response analysis checks HTML *and* JSON bodies, as well as Location and other
response headers. Tries privileged identities (admin, backend) for endpoints
that require authentication.
"""
from __future__ import annotations

import json
import re
from typing import Iterable

from .base import Scanner, canary
from ..models import (Endpoint, Finding, IdentityRole, Severity, VulnClass)

# Inert markers. Note: NO "onerror", NO "script", NO javascript: -- these exist
# only to test whether HTML-special characters are escaped on output.
_REFLECT_MARKERS = [
    ("html_tag", lambda c: f"<{c}>"),          # tests < > escaping
    ("attr", lambda c: f'"{c}"'),              # tests quote escaping in attrs
    ("angle_eq", lambda c: f"<{c}={c}"),       # tests the <...= filter class
]

# Path-param names that are likely UUIDs or pure numeric IDs — skip these for
# string-injection probes because they won't be echoed as readable text.
_UUID_PARAM_RE = re.compile(
    r"(id|inode|identifier|uuid|hostid|siteid|folderid|userid|contentletid)",
    re.IGNORECASE,
)

# Match a UUID-shaped value so we can skip injecting into params that already
# carry a real UUID default value (they likely enforce UUID validation).
_UUID_VALUE_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# JS context: value echoed inside a <script> block or assigned to a JS variable.
_JS_ASSIGN_RE = re.compile(r"""(?:var|let|const)\s+\w+\s*=\s*["']([^"'<>]*)""")


def _is_uuid_param(name: str) -> bool:
    return bool(_UUID_PARAM_RE.search(name))


def _extract_json_string_fields(schema: dict, max_depth: int = 3) -> list[str]:
    """Walk a JSON Schema and return the names of leaf string properties."""
    if max_depth <= 0 or not isinstance(schema, dict):
        return []
    results: list[str] = []
    props = schema.get("properties", {})
    for prop_name, prop_schema in props.items():
        if not isinstance(prop_schema, dict):
            continue
        typ = prop_schema.get("type")
        if typ == "string":
            results.append(prop_name)
        elif typ == "object" or "properties" in prop_schema:
            # recurse into nested objects but prefix with parent key
            for nested in _extract_json_string_fields(prop_schema, max_depth - 1):
                results.append(f"{prop_name}.{nested}")
    return results


def _set_nested(obj: dict, dotted_key: str, value: str) -> None:
    """Set obj[a][b][c] = value given dotted_key='a.b.c'."""
    parts = dotted_key.split(".", 1)
    if len(parts) == 1:
        obj[dotted_key] = value
    else:
        parent, rest = parts
        if parent not in obj or not isinstance(obj[parent], dict):
            obj[parent] = {}
        _set_nested(obj[parent], rest, value)


def _check_reflection(marker: str, value: str, rec, *, allow_json: bool = True) -> str | None:
    """Return a short context label if *value* appears unescaped in the response.

    Returns one of: 'html', 'json', 'header', 'dom_js', or None.
    """
    body = rec.resp_body or ""
    ctype = rec.resp_headers.get("Content-Type", "")

    if value not in body:
        # also check headers (e.g. Location)
        for hval in rec.resp_headers.values():
            if value in hval:
                return "header"
        return None

    # Check the context in which the reflection occurs
    is_html = "html" in ctype or "<html" in body[:512].lower()
    is_json = "json" in ctype or (body.lstrip().startswith("{") or body.lstrip().startswith("["))

    # DOM XSS signal: value lands inside a <script> block
    script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", body, re.DOTALL | re.IGNORECASE)
    for blk in script_blocks:
        if marker in blk:
            return "dom_js"

    # Inline JS variable assignment
    for m in _JS_ASSIGN_RE.finditer(body):
        if marker in m.group(1):
            return "dom_js"

    if is_html:
        return "html"
    if allow_json and is_json:
        return "json"
    return None


class XssScanner(Scanner):
    name = "xss"
    vuln_classes = [VulnClass.XSS.value]

    def applies_to(self, endpoint: Endpoint) -> bool:
        method = endpoint.method.upper()
        return (
            bool(endpoint.query_params)
            or method in ("GET", "POST", "PUT", "PATCH")
            or bool(endpoint.path_params)
            or self._is_profile_or_write_endpoint(endpoint)
        )

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        # 1) Reflected XSS via query parameters (any method).
        for qp in endpoint.query_params[:6]:
            name = qp.get("name")
            if not name:
                continue
            schema = qp.get("schema", {}) or {}
            # Skip enum-only params — they can't accept a canary value
            if schema.get("enum"):
                continue
            yield from self._probe_query_param(endpoint, name)

        # 2) POST/PUT/PATCH JSON body injection.
        if (self.config.scan.allow_state_changing
                and endpoint.method.upper() in ("POST", "PUT", "PATCH")):
            yield from self._probe_body_fields(endpoint)

        # 3) Path-parameter string injection.
        yield from self._probe_path_params(endpoint)

        # 4) Field-split filter-bypass on the user's own profile.
        if (self.config.scan.allow_state_changing
                and self._is_profile_or_write_endpoint(endpoint)):
            yield from self._probe_profile_filter_bypass(endpoint)

    # ------------------------------------------------------------------
    # Endpoint classification helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_profile_endpoint(endpoint: Endpoint) -> bool:
        """Original narrow check kept for the filter-bypass probe."""
        return (endpoint.method.upper() == "PUT"
                and endpoint.path.rstrip("/").endswith("/users/current"))

    @staticmethod
    def _is_profile_or_write_endpoint(endpoint: Endpoint) -> bool:
        """Broader set of write endpoints that carry name/description fields."""
        method = endpoint.method.upper()
        path = endpoint.path.rstrip("/")

        if method == "PUT" and path.endswith("/users/current"):
            return True
        # POST to /api/v1/users — create user with XSS in name fields
        if method == "POST" and re.search(r"/api/v[0-9]+/users/?$", path):
            return True
        # Any PUT with "name" or "description" in the request body schema
        if method in ("PUT", "POST", "PATCH"):
            props = (endpoint.request_body_schema or {}).get("properties", {})
            for field_name in props:
                if field_name.lower() in ("name", "description", "title",
                                          "firstname", "lastname",
                                          "givenname", "surname"):
                    return True
        return False

    # ------------------------------------------------------------------
    # Probe helpers
    # ------------------------------------------------------------------
    def _ordered_identities(self):
        """Return identities to try, most-privileged first."""
        roles = [
            IdentityRole.ADMIN.value,
            IdentityRole.BACKEND.value,
            IdentityRole.CONTENT_EDITOR.value,
            IdentityRole.READONLY.value,
            IdentityRole.ANON.value,
        ]
        return [self.identities[r] for r in roles if r in self.identities]

    def _probe_query_param(self, endpoint: Endpoint, param: str) -> Iterable[Finding]:
        # Try anon first; fall back to authenticated identities.
        identities_to_try = [
            self.identities.get(IdentityRole.ANON.value),
            self.identities.get(IdentityRole.BACKEND.value),
            self.identities.get(IdentityRole.ADMIN.value),
        ]
        for identity in identities_to_try:
            if identity is None:
                continue
            for kind, build in _REFLECT_MARKERS:
                mark = canary()
                value = build(mark)
                rec = self.fetch(endpoint, identity, params={param: value})
                if rec.status == 0:
                    continue
                ctx = _check_reflection(mark, value, rec)
                # Only flag HTML and DOM-JS contexts. Pure JSON reflection is NOT
                # XSS by itself — JSON APIs normally echo params in error messages
                # and a browser won't render them as HTML without further client code.
                if ctx and ctx in ("html", "dom_js"):
                    sev = Severity.HIGH if ctx == "dom_js" else Severity.MEDIUM
                    yield Finding(
                        vuln_class=VulnClass.XSS,
                        severity=sev,
                        title=f"Unescaped reflection of query param '{param}' ({kind}) [{ctx}]",
                        endpoint=endpoint.key,
                        description=(
                            f"The value of query parameter '{param}' was reflected "
                            f"into an HTML/JS response (context: {ctx}) without "
                            f"escaping the marker '{value}'. This is a reflected-XSS "
                            f"candidate. Confirm manually in a browser; the scanner "
                            f"used an inert marker and did not attempt to execute script."),
                        evidence=[rec],
                        detail={"param": param, "marker_kind": kind,
                                "context": ctx,
                                "content_type": rec.resp_headers.get("Content-Type", ""),
                                "identity": identity.label()},
                        confidence="firm",
                    )
                    return  # one finding per param is enough

    def _probe_body_fields(self, endpoint: Endpoint) -> Iterable[Finding]:
        """Inject canary markers into string fields of the JSON request body."""
        schema = endpoint.request_body_schema or {}
        string_fields = _extract_json_string_fields(schema)
        if not string_fields:
            # Heuristic fallback: common fields likely present on any user/content API
            path_lower = endpoint.path.lower()
            if any(kw in path_lower for kw in ("/users", "/content", "/form", "/page")):
                string_fields = ["name", "firstName", "lastName", "description", "title"]

        if not string_fields:
            return

        # Prefer admin/backend identities for write endpoints
        identity = (
            self.identities.get(IdentityRole.ADMIN.value)
            or self.identities.get(IdentityRole.BACKEND.value)
            or self.identities.get(IdentityRole.ANON.value)
        )
        if identity is None:
            return

        for field_name in string_fields[:8]:  # cap to avoid explosion
            for kind, build in _REFLECT_MARKERS:
                mark = canary()
                value = build(mark)
                # Build a minimal body with just this one field injected.
                body: dict = {}
                _set_nested(body, field_name, value)
                rec = self.fetch(endpoint, identity, json_body=body)
                if rec.status == 0:
                    continue
                ctx = _check_reflection(mark, value, rec)
                # Body field XSS: require HTML or DOM-JS context.
                # JSON-only reflection is an echo (common in error bodies) not XSS.
                if ctx and ctx in ("html", "dom_js"):
                    sev = Severity.HIGH if ctx == "dom_js" else Severity.MEDIUM
                    yield Finding(
                        vuln_class=VulnClass.XSS,
                        severity=sev,
                        title=f"POST/PUT body field '{field_name}' reflected unescaped ({kind}) [{ctx}]",
                        endpoint=endpoint.key,
                        description=(
                            f"The value of request body field '{field_name}' was "
                            f"reflected into an HTML/JS response (context: {ctx}) "
                            f"without HTML-escaping the marker '{value}'. This "
                            f"indicates the application echoes user-supplied data "
                            f"into a renderable context. Confirm manually; the "
                            f"scanner used only an inert canary string."),
                        evidence=[rec],
                        detail={"field": field_name, "marker_kind": kind,
                                "context": ctx,
                                "content_type": rec.resp_headers.get("Content-Type", ""),
                                "identity": identity.label()},
                        confidence="firm",
                    )
                    break  # one finding per field is enough

    def _probe_path_params(self, endpoint: Endpoint) -> Iterable[Finding]:
        """Inject a canary into non-UUID string path parameters and check reflection."""
        string_path_params = [
            p for p in endpoint.path_params
            if not _is_uuid_param(p)
        ]
        if not string_path_params:
            return

        # Try anon first, then authenticated, since some path lookups are public
        identities_to_try = [
            self.identities.get(IdentityRole.ANON.value),
            self.identities.get(IdentityRole.BACKEND.value),
            self.identities.get(IdentityRole.ADMIN.value),
        ]

        for param in string_path_params:
            for identity in identities_to_try:
                if identity is None:
                    continue
                for kind, build in _REFLECT_MARKERS:
                    mark = canary()
                    value = build(mark)
                    rec = self.fetch(endpoint, identity,
                                     path_overrides={param: value})
                    if rec.status == 0:
                        continue
                    ctx = _check_reflection(mark, value, rec)
                    # Only flag HTML/DOM-JS contexts. JSON reflection is not XSS.
                    if ctx and ctx in ("html", "dom_js"):
                        sev = Severity.HIGH if ctx == "dom_js" else Severity.MEDIUM
                        yield Finding(
                            vuln_class=VulnClass.XSS,
                            severity=sev,
                            title=f"Path param '{{{param}}}' reflected unescaped ({kind}) [{ctx}]",
                            endpoint=endpoint.key,
                            description=(
                                f"The path parameter '{param}' value was reflected "
                                f"into an HTML/JS response (context: {ctx}) without "
                                f"escaping the marker '{value}'. Confirm "
                                f"manually in a browser; the scanner used only an "
                                f"inert canary."),
                            evidence=[rec],
                            detail={"path_param": param, "marker_kind": kind,
                                    "context": ctx,
                                    "content_type": rec.resp_headers.get("Content-Type", ""),
                                    "identity": identity.label()},
                            confidence="firm",
                        )
                        break  # one finding per path param
                else:
                    continue
                break  # found a hit with this identity; no need to escalate

    def _probe_profile_filter_bypass(self, endpoint: Endpoint) -> Iterable[Finding]:
        """Detect the two-field-split escaping gap, using inert canaries on the
        authenticated identity's OWN profile (no other user is touched)."""
        identity = (self.identities.get(IdentityRole.BACKEND.value)
                    or self.identities.get(IdentityRole.ADMIN.value))
        if not identity:
            return
        whoami = self.client.request(
            "GET", "/api/v1/users/current",
            identity_label=identity.label(),
            headers=self.auth.headers_for(identity))
        if whoami.status != 200:
            return
        try:
            doc = json.loads(whoami.resp_body)
            entity = doc.get("entity", doc) if isinstance(doc, dict) else {}
            uid = (doc.get("userId") or entity.get("userId")
                   or doc.get("id") or entity.get("id"))
        except Exception:
            return
        if not uid:
            return

        c1, c2 = canary("zfirst"), canary("zlast")
        # field A holds "<" only; field B holds "=" only -> each passes a naive
        # single-field filter, but together they form "<marker= ...". Inert.
        first = f"<{c1}"
        last = f"{c2}=x"
        # the target requires the current password to update the profile — the
        # researcher's PoC sends it, and without it the PUT is rejected (so an
        # earlier version of this probe silently bailed and missed the bug).
        body = {"userId": uid, "givenName": first, "surname": last}
        if getattr(identity, "password", None):
            body["currentPassword"] = identity.password
        put = self.client.request(
            "PUT", "/api/v1/users/current",
            identity_label=identity.label(),
            headers=self.auth.headers_for(identity),
            json_body=body)
        if put.status != 200:
            # retry once without password in case this build doesn't require it
            if "currentPassword" in body:
                body.pop("currentPassword")
                put = self.client.request(
                    "PUT", "/api/v1/users/current", identity_label=identity.label(),
                    headers=self.auth.headers_for(identity), json_body=body)
            if put.status != 200:
                return
        # read back via a context that renders the name
        back = self.client.request(
            "GET", "/api/v1/users/current",
            identity_label=identity.label(),
            headers=self.auth.headers_for(identity))
        if first in back.resp_body and last in back.resp_body:
            yield Finding(
                vuln_class=VulnClass.XSS,
                severity=Severity.HIGH,
                title="Profile name fields store unescaped HTML metacharacters",
                endpoint="PUT /api/v1/users/current",
                description=(
                    "Inert canaries split as '<marker' (givenName) and "
                    "'marker=x' (surname) were both accepted and stored without "
                    "rejection or escaping. A per-field filter that only blocks "
                    "fields containing BOTH '<' and '=' can be bypassed by "
                    "splitting markup across the two name fields. Stored output "
                    "must be HTML-escaped at render time, especially in the admin "
                    "Users panel. The scanner stored only inert markers and did "
                    "not inject any script or event handler."),
                evidence=[put, back],
                detail={"givenName": first, "surname": last, "userId": uid},
                confidence="firm",
            )
