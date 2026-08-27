"""Schema-aware request-body fuzzing.

The query-param scanners (sqli/xss) miss the largest part of a modern API:
JSON request bodies. This scanner reads each endpoint's OpenAPI requestBody
schema, builds a minimally-valid body, and then sends variants where one string
field at a time carries a benign detection marker:

  * a SQL metacharacter  -> watch for DB-error signatures in the response;
  * an inert reflection canary -> watch for unescaped reflection (XSS surface).

It never sends a working payload (no scripts, no stacked queries, no data
extraction) — only single markers that reveal whether the field reaches a SQL
string or is echoed unescaped.

Safety: sending a body is a write. To avoid mutating state, this scanner by
default only fuzzes endpoints whose path looks read-only (search/query/validate/
preview/check/filter/resolve). Set allow_state_changing to also fuzz genuine
write endpoints. Either way it operates as the configured identity.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from .base import Scanner, canary
from .sqli import _DB_ERRORS
from ..models import (Endpoint, Finding, IdentityRole, Severity, VulnClass)

_READ_ONLY_HINT = re.compile(
    r"(_search|/search|_query|/query|/find|/validate|/preview|/check|"
    r"/filter|/resolve|/lookup|_eval|/render)", re.IGNORECASE)

_SQL_MARK = "1'\""
_MAX_FIELDS = 8


class BodyFuzzScanner(Scanner):
    name = "bodyfuzz"
    vuln_classes = [VulnClass.SQLI.value, VulnClass.XSS.value]

    def applies_to(self, endpoint: Endpoint) -> bool:
        if endpoint.method.upper() not in ("POST", "PUT", "PATCH"):
            return False
        if not endpoint.request_body_schema:
            return False
        if self.config.scan.allow_state_changing:
            return True
        # otherwise only the read-only-looking ones
        return _READ_ONLY_HINT.search(endpoint.path) is not None

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        identity = (self.identities.get(IdentityRole.BACKEND.value)
                    or self.identities.get(IdentityRole.ANON.value))
        string_fields = _string_fields(endpoint.request_body_schema)
        if not string_fields:
            return
        base_body = _skeleton(endpoint.request_body_schema)

        for field in string_fields[:_MAX_FIELDS]:
            # 1) SQLi marker
            body = _set_field(dict(base_body), field, f"{base_body_get(base_body, field)}{_SQL_MARK}")
            rec = self._send(endpoint, identity, body)
            if rec and _DB_ERRORS.search(rec.resp_body):
                yield Finding(
                    vuln_class=VulnClass.SQLI, severity=Severity.HIGH,
                    title=f"DB error from body field '{field}'",
                    endpoint=endpoint.key,
                    description=(
                        f"Injecting a SQL metacharacter into JSON body field "
                        f"'{field}' produced a database error signature. This is a "
                        f"SQLi candidate in a request body the query-param scanners "
                        f"don't reach. Confirm with the sqlmap integration "
                        f"(it supports JSON bodies via -p / --data)."),
                    evidence=[rec], detail={"field": field, "marker": _SQL_MARK},
                    confidence="firm")
                continue
            # 2) XSS reflection marker
            mark = canary()
            body = _set_field(dict(base_body), field, f"<{mark}>")
            rec = self._send(endpoint, identity, body)
            if rec and f"<{mark}>" in rec.resp_body and \
                    "html" in rec.resp_headers.get("Content-Type", "").lower():
                yield Finding(
                    vuln_class=VulnClass.XSS, severity=Severity.MEDIUM,
                    title=f"Unescaped reflection of body field '{field}'",
                    endpoint=endpoint.key,
                    description=(
                        f"Body field '{field}' was reflected unescaped into an "
                        f"HTML response. Stored/reflected XSS candidate; confirm "
                        f"the render context manually. Inert marker only."),
                    evidence=[rec], detail={"field": field},
                    confidence="firm")

    def _send(self, endpoint, identity, body):
        try:
            return self.client.request(
                endpoint.method, self.concrete_path(endpoint),
                identity_label=identity.label(),
                headers=self.auth.headers_for(identity), json_body=body)
        except Exception:
            return None


# ---- tiny OpenAPI schema helpers -----------------------------------------
def _resolve(schema: dict) -> dict:
    # we don't chase $ref across the doc here; treat unknown as object
    return schema if isinstance(schema, dict) else {}


def _string_fields(schema: dict, prefix: str = "", depth: int = 0) -> list[str]:
    out: list[str] = []
    if depth > 4 or not isinstance(schema, dict):
        return out
    props = schema.get("properties", {})
    for name, sub in props.items():
        t = sub.get("type")
        path = f"{prefix}{name}"
        if t == "string":
            out.append(path)
        elif t == "object":
            out.extend(_string_fields(sub, path + ".", depth + 1))
    return out


def _skeleton(schema: dict, depth: int = 0) -> dict:
    body: dict[str, Any] = {}
    if depth > 4 or not isinstance(schema, dict):
        return body
    for name, sub in (schema.get("properties", {}) or {}).items():
        t = sub.get("type")
        if t == "string":
            body[name] = "test"
        elif t in ("integer", "number"):
            body[name] = 1
        elif t == "boolean":
            body[name] = False
        elif t == "array":
            body[name] = []
        elif t == "object":
            body[name] = _skeleton(sub, depth + 1)
    return body


def base_body_get(body: dict, dotted: str):
    cur: Any = body
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part, "")
        else:
            return ""
    return cur if isinstance(cur, str) else ""


def _set_field(body: dict, dotted: str, value: str) -> dict:
    parts = dotted.split(".")
    cur = body
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value
    return body
