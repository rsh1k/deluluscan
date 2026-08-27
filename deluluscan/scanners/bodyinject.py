"""Body injection scanner.

Tests SQL injection, XSS, SSTI, and path traversal via POST/PUT/PATCH request
bodies rather than query parameters. The existing sqli.py and xss.py scanners
only probe query parameters; this scanner complements them by fuzzing every
injectable string field in a JSON body.

Detection strategy per field:
  1. Error-based SQLi   – inject SQL metacharacters and look for DB error text.
  2. Boolean SQLi       – compare true/false condition response sizes.
  3. XSS reflection     – inject <MARKER> and check it survives unescaped.
  4. SSTI               – inject {{7*7}} / #{7*7} / ${7*7}; look for "49".
  5. Path traversal     – for path-looking field names, inject ../etc/passwd.

The scanner is conservative: it only yields a Finding when there is clear
positive evidence. "Different response" alone is not enough.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

from .base import Scanner, canary
from .sqli import _DB_ERRORS
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

# ---------------------------------------------------------------------------
# SSTI detection
# ---------------------------------------------------------------------------
# Rare arithmetic (1337*1331 = 1779547) instead of 7*7=49: a bare "49" collides
# constantly with real data (counts, sizes, prices, hex), the classic SSTI false
# positive. 1779547 effectively never appears unless the server evaluated it.
_SSTI_A, _SSTI_B = 1337, 1331
_SSTI_PRODUCT = str(_SSTI_A * _SSTI_B)          # "1779547"
_SSTI_PAYLOADS = [
    "{{1337*1331}}",
    "#{1337*1331}",
    "${1337*1331}",
    "<%=1337*1331%>",
]

# ---------------------------------------------------------------------------
# Path traversal detection
# ---------------------------------------------------------------------------
_TRAVERSAL_PAYLOAD = "../../../etc/passwd"
_TRAVERSAL_HIT = re.compile(r"root:.*:0:0:", re.DOTALL)
_PATH_FIELD_NAMES = re.compile(
    r"(path|uri|url|file|dir|folder|location|resource|asset|template|include)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Endpoints to skip outright
# ---------------------------------------------------------------------------
_SKIP_PATHS = re.compile(
    r"/(login|logout|logoutUser|authenticate|auth|token|refresh"
    r"|password/reset|forgot.?password)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Seed body templates for well-known endpoints
# ---------------------------------------------------------------------------
_TARGET_SEEDS: list[tuple[re.Pattern[str], dict[str, Any]]] = [
    (re.compile(r"/api/v1/users", re.IGNORECASE),
     {"userId": "test@test.com", "email": "test@test.com",
      "firstName": "test", "lastName": "test"}),
    (re.compile(r"/api/v1/workflow", re.IGNORECASE),
     {"name": "test", "description": "test"}),
    (re.compile(r"/api/content", re.IGNORECASE),
     {"stName": "webPageContent", "title": "test"}),
]


def _seed_from_schema(schema: dict[str, Any]) -> dict[str, Any] | None:
    """Generate a minimal valid body from a JSON Schema object definition."""
    if not schema:
        return None
    # Unwrap $ref-resolved schema: look for 'properties' at top level or under
    # a single allOf/anyOf/oneOf item.
    props = schema.get("properties")
    if not props:
        for key in ("allOf", "anyOf", "oneOf"):
            candidates = schema.get(key, [])
            for c in candidates:
                props = c.get("properties")
                if props:
                    break
        if not props:
            return None

    body: dict[str, Any] = {}
    for field_name, field_schema in props.items():
        ftype = field_schema.get("type", "string")
        if isinstance(ftype, list):
            ftype = ftype[0]
        if ftype == "string":
            # Use a format-aware default
            fmt = field_schema.get("format", "")
            if fmt in ("email",):
                body[field_name] = "test@test.com"
            elif fmt in ("uuid",):
                body[field_name] = "00000000-0000-0000-0000-000000000000"
            elif fmt in ("date", "date-time"):
                body[field_name] = "2024-01-01"
            else:
                body[field_name] = "test"
        elif ftype in ("integer", "number"):
            body[field_name] = 1
        elif ftype == "boolean":
            body[field_name] = True
        elif ftype == "array":
            body[field_name] = []
        elif ftype == "object":
            body[field_name] = {}
        # skip null/unknown types
    return body if body else None


def _seed_body_for_endpoint(endpoint: Endpoint) -> dict[str, Any] | None:
    """Return a minimal seed body for the endpoint or None if we should skip."""
    # 1. Try the schema if present
    if endpoint.request_body_schema:
        seed = _seed_from_schema(endpoint.request_body_schema)
        if seed:
            return seed

    # 2. Try target-specific heuristics
    for pattern, template in _TARGET_SEEDS:
        if pattern.search(endpoint.path):
            return dict(template)  # copy so mutations don't bleed

    # 3. No seed available — skip
    return None


def _string_fields(body: dict[str, Any]) -> list[str]:
    """Return the keys whose values are plain strings (injectable candidates)."""
    return [k for k, v in body.items() if isinstance(v, str)]


def _is_only_bool_int(body: dict[str, Any]) -> bool:
    """True if the body has NO string fields at all."""
    return all(isinstance(v, (bool, int, float, list, dict)) for v in body.values())


def _looks_uuid(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                             value, re.IGNORECASE))


def _ssti_evaluated(text: str, payload: str) -> bool:
    """True only if the rare product appears AND the payload literal does NOT —
    i.e. the server actually evaluated the expression rather than reflecting it
    verbatim. Requiring 1779547 (not 49) removes the collision-with-real-data FP;
    requiring payload-absence removes the reflected-but-unevaluated FP."""
    body = text or ""
    return _SSTI_PRODUCT in body and payload not in body


class BodyInjectScanner(Scanner):
    """Injection scanner for POST/PUT/PATCH request bodies."""

    name = "bodyinject"
    vuln_classes = [
        VulnClass.SQLI.value,
        VulnClass.XSS.value,
        VulnClass.SSTI.value if hasattr(VulnClass, "SSTI") else "ssti",
        "path_traversal",
    ]

    # Deduplicate: (endpoint_key, vuln_class) → already reported
    _seen: set[tuple[str, str]]

    def applies_to(self, endpoint: Endpoint) -> bool:
        if endpoint.method.upper() not in ("POST", "PUT", "PATCH"):
            return False
        if _SKIP_PATHS.search(endpoint.path):
            return False
        return True

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        self._seen = set()

        seed = _seed_body_for_endpoint(endpoint)
        if seed is None:
            return
        if _is_only_bool_int(seed):
            return

        string_fields = _string_fields(seed)
        if not string_fields:
            return

        # Pick the admin identity as primary prober; fall back to backend.
        admin = (self.identities.get(IdentityRole.ADMIN.value)
                 or self.identities.get(IdentityRole.BACKEND.value))
        anon = self.identities.get(IdentityRole.ANON.value)

        if not admin:
            return

        # Baseline: does the endpoint even respond to a valid body?
        baseline = self.fetch(endpoint, admin, json_body=seed)
        if baseline.status == 0:
            return  # network error, can't test

        # We proceed even if baseline is 4xx — some endpoints return 400 for
        # our dummy data but still reflect error bodies we can analyse.

        for field_name in string_fields[:8]:   # cap at 8 fields per endpoint
            yield from self._probe_field(endpoint, admin, anon, seed, field_name, baseline)

    # ------------------------------------------------------------------
    # Per-field probing
    # ------------------------------------------------------------------

    def _probe_field(self, endpoint: Endpoint, admin, anon,
                     seed: dict[str, Any], field_name: str,
                     baseline) -> Iterable[Finding]:
        # --- 1. Error-based SQLi ---
        finding = self._sqli_error(endpoint, admin, seed, field_name, baseline)
        if finding:
            yield finding
            self._mark(endpoint, "sqli")

        # --- 2. Boolean-differential SQLi (only if not already flagged) ---
        if not self._already_seen(endpoint, "sqli"):
            finding = self._sqli_boolean(endpoint, admin, seed, field_name, baseline)
            if finding:
                yield finding
                self._mark(endpoint, "sqli")

        # --- 3. XSS reflection ---
        if not self._already_seen(endpoint, "xss"):
            finding = self._xss_reflect(endpoint, admin, seed, field_name, baseline)
            if finding:
                yield finding
                self._mark(endpoint, "xss")

        # --- 4. SSTI ---
        if not self._already_seen(endpoint, "ssti"):
            finding = self._ssti(endpoint, admin, seed, field_name, baseline)
            if finding:
                yield finding
                self._mark(endpoint, "ssti")

        # --- 5. Path traversal (only for path-like field names) ---
        if (not self._already_seen(endpoint, "path_traversal")
                and _PATH_FIELD_NAMES.search(field_name)):
            finding = self._path_traversal(endpoint, admin, seed, field_name, baseline)
            if finding:
                yield finding
                self._mark(endpoint, "path_traversal")

    # ------------------------------------------------------------------
    # Injection probes
    # ------------------------------------------------------------------

    def _sqli_error(self, endpoint, admin, seed, field_name, baseline):
        for payload in ("'", '"', "')", "';--"):
            body = dict(seed)
            body[field_name] = seed[field_name] + payload
            rec = self.fetch(endpoint, admin, json_body=body)
            m = _DB_ERRORS.search(rec.resp_body)
            if m:
                return Finding(
                    vuln_class=VulnClass.SQLI,
                    severity=Severity.CRITICAL,
                    title=f"SQL error via body field '{field_name}' on {endpoint.key}",
                    endpoint=endpoint.key,
                    description=(
                        f"Injecting {payload!r} into JSON body field '{field_name}' "
                        f"triggered a database error signature: "
                        f"{m.group(0)[:80]}. This strongly indicates SQL injection "
                        f"via the request body. Confirm with sqlmap against your "
                        f"localhost target."),
                    evidence=[baseline, rec],
                    detail={"field": field_name, "payload": payload,
                            "signature": m.group(0)[:120]},
                    confidence="firm",
                )
        return None

    def _sqli_boolean(self, endpoint, admin, seed, field_name, baseline):
        body_true = dict(seed)
        body_true[field_name] = seed[field_name] + "' OR '1'='1"
        body_false = dict(seed)
        body_false[field_name] = seed[field_name] + "' AND '1'='2"

        rec_true = self.fetch(endpoint, admin, json_body=body_true)
        rec_false = self.fetch(endpoint, admin, json_body=body_false)

        if (rec_true.status == 200 and rec_false.status == 200
                and abs(rec_true.resp_len - rec_false.resp_len)
                > max(64, int(0.2 * (baseline.resp_len + 1)))):
            return Finding(
                vuln_class=VulnClass.SQLI,
                severity=Severity.HIGH,
                title=f"Boolean-differential SQLi in body field '{field_name}' on {endpoint.key}",
                endpoint=endpoint.key,
                description=(
                    f"True-condition and false-condition payloads in JSON body "
                    f"field '{field_name}' produced materially different response "
                    f"sizes ({rec_true.resp_len} vs {rec_false.resp_len} bytes). "
                    f"This is a boolean-based SQLi indicator via the request body. "
                    f"Verify with sqlmap."),
                evidence=[rec_true, rec_false],
                detail={"field": field_name,
                        "true_len": rec_true.resp_len,
                        "false_len": rec_false.resp_len},
                confidence="tentative",
            )
        return None

    def _xss_reflect(self, endpoint, admin, seed, field_name, baseline):
        mark = canary("xbi")
        # Use a tag-like shape so we test angle-bracket escaping.
        payload = f"<{mark}>"
        body = dict(seed)
        body[field_name] = payload
        rec = self.fetch(endpoint, admin, json_body=body)

        if rec.status == 0:
            return None
        # The canary must appear in the response literally (unescaped).
        if payload not in rec.resp_body:
            return None
        ctype = rec.resp_headers.get("Content-Type", "")
        html_ctx = "html" in ctype or "<html" in rec.resp_body[:512].lower()
        if not html_ctx:
            return None

        return Finding(
            vuln_class=VulnClass.XSS,
            severity=Severity.MEDIUM,
            title=f"Unescaped XSS reflection via body field '{field_name}' on {endpoint.key}",
            endpoint=endpoint.key,
            description=(
                f"HTML marker {payload!r} injected into JSON body field "
                f"'{field_name}' was reflected unescaped into an HTML response. "
                f"This is a reflected-XSS candidate. Confirm manually in a "
                f"browser; the scanner used an inert canary with no event handler."),
            evidence=[baseline, rec],
            detail={"field": field_name, "marker": payload, "content_type": ctype},
            confidence="firm",
        )

    def _ssti(self, endpoint, admin, seed, field_name, baseline):
        for payload in _SSTI_PAYLOADS:
            body = dict(seed)
            body[field_name] = payload
            rec = self.fetch(endpoint, admin, json_body=body)

            if rec.status == 0:
                continue
            if _ssti_evaluated(rec.resp_body, payload):
                return Finding(
                    vuln_class=VulnClass.SSTI if hasattr(VulnClass, "SSTI") else VulnClass.MISCONFIG,
                    severity=Severity.HIGH,
                    title=f"SSTI candidate via body field '{field_name}' on {endpoint.key}",
                    endpoint=endpoint.key,
                    description=(
                        f"Template expression {payload!r} injected into JSON body "
                        f"field '{field_name}' produced the evaluated result "
                        f"'{_SSTI_PRODUCT}' (=1337*1331) in the response, while the "
                        f"payload literal did not survive — server-side template "
                        f"injection. Confirm with a read-only template probe before escalating."),
                    evidence=[baseline, rec],
                    detail={"field": field_name, "payload": payload},
                    confidence="tentative",
                )
        return None

    def _path_traversal(self, endpoint, admin, seed, field_name, baseline):
        body = dict(seed)
        body[field_name] = _TRAVERSAL_PAYLOAD
        rec = self.fetch(endpoint, admin, json_body=body)

        if rec.status == 0:
            return None
        if _TRAVERSAL_HIT.search(rec.resp_body):
            return Finding(
                vuln_class=VulnClass.MISCONFIG,
                severity=Severity.CRITICAL,
                title=f"Path traversal via body field '{field_name}' on {endpoint.key}",
                endpoint=endpoint.key,
                description=(
                    f"Injecting '{_TRAVERSAL_PAYLOAD}' into JSON body field "
                    f"'{field_name}' returned content matching /etc/passwd. "
                    f"This is a path traversal vulnerability allowing arbitrary "
                    f"file read. Confirm with a non-sensitive path before reporting."),
                evidence=[baseline, rec],
                detail={"field": field_name, "payload": _TRAVERSAL_PAYLOAD},
                confidence="firm",
            )
        return None

    # ------------------------------------------------------------------
    # Deduplication helpers
    # ------------------------------------------------------------------

    def _mark(self, endpoint: Endpoint, vuln: str) -> None:
        self._seen.add((endpoint.key, vuln))

    def _already_seen(self, endpoint: Endpoint, vuln: str) -> bool:
        return (endpoint.key, vuln) in self._seen
