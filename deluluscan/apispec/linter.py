"""Security linter for an OpenAPI 3.x / Swagger 2.0 specification.

Static analysis of the API *contract*: operations missing authentication (esp.
state-changing ones), secrets in query/path parameters, API keys carried in the
URL, plaintext-HTTP servers, mass-assignment-prone request schemas, and
deprecated operations still advertised. Detection only, offline — pass a parsed
spec dict. Complements discovery (which parses the same spec for endpoints).
"""
from __future__ import annotations

import re
from typing import Optional

from ..models import Finding, Severity, VulnClass

_SEV = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
        "critical": Severity.CRITICAL}
_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_STATE_CHANGING = ("post", "put", "patch", "delete")
_SENSITIVE = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
                        r"ssn|credit|card|cvv|auth|session|otp)", re.I)


def _f(cls, sev, title, endpoint, desc, detail=None) -> Finding:
    return Finding(vuln_class=cls, severity=_SEV[sev], title=title, endpoint=endpoint,
                   description=desc, detail=detail or {}, confidence="firm",
                   verdict="likely_true_positive", exploitability="conditional")


def _op_secured(op: dict, global_security) -> bool:
    """True if the operation requires auth. Operation `security` overrides global;
    an explicit empty list means deliberately public."""
    if "security" in op:
        return bool(op.get("security"))
    return bool(global_security)


def lint_spec(spec: dict) -> list:
    if not isinstance(spec, dict):
        return []
    findings: list[Finding] = []
    is_swagger2 = "swagger" in spec
    global_security = spec.get("security")

    # security schemes location (v3: components.securitySchemes ; v2: securityDefinitions)
    schemes = (spec.get("components", {}) or {}).get("securitySchemes", {}) if not is_swagger2 \
        else spec.get("securityDefinitions", {}) or {}
    for name, sc in (schemes or {}).items():
        if not isinstance(sc, dict):
            continue
        if sc.get("type") == "apiKey" and sc.get("in") == "query":
            findings.append(_f(VulnClass.INFO_LEAK, "medium",
                f"API key passed in the URL query ({name})", f"securityScheme:{name}",
                "An apiKey security scheme with in:query puts the key in URLs — logged by proxies, "
                "servers, and browser history.", {"scheme": name, "rule": "spec-apikey-query"}))

    # servers over plaintext HTTP (v3 servers / v2 schemes)
    servers = [s.get("url", "") for s in (spec.get("servers") or []) if isinstance(s, dict)]
    if is_swagger2:
        if "http" in (spec.get("schemes") or []) and "https" not in (spec.get("schemes") or []):
            servers = ["http://" + str(spec.get("host", "?"))]
    for url in servers:
        if str(url).startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            findings.append(_f(VulnClass.CRYPTO, "medium", "API served over plaintext HTTP",
                f"server:{url}", f"Server URL {url} uses http:// — traffic (incl. tokens) is unencrypted.",
                {"server": url, "rule": "spec-http-server"}))

    has_any_scheme = bool(schemes)
    unauth_state_changing = 0

    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in _METHODS or not isinstance(op, dict):
                continue
            m = method.lower()
            ep = f"{m.upper()} {path}"
            secured = _op_secured(op, global_security)

            if not secured:
                if m in _STATE_CHANGING:
                    unauth_state_changing += 1
                    findings.append(_f(VulnClass.AUTHZ, "high",
                        "State-changing operation without authentication", ep,
                        f"{ep} is a {m.upper()} with no security requirement — anyone can invoke it.",
                        {"rule": "spec-unauth-write"}))
                else:
                    findings.append(_f(VulnClass.AUTHZ, "low",
                        "Operation without authentication", ep,
                        f"{ep} declares no security requirement (public read — confirm intended).",
                        {"rule": "spec-unauth-read"}))

            # sensitive data in query/path params
            for prm in (op.get("parameters") or []) + (item.get("parameters") or []):
                if not isinstance(prm, dict):
                    continue
                if prm.get("in") in ("query", "path") and _SENSITIVE.search(str(prm.get("name", ""))):
                    findings.append(_f(VulnClass.INFO_LEAK, "medium",
                        f"Sensitive parameter in {prm.get('in')}: {prm.get('name')}", ep,
                        f"Parameter '{prm.get('name')}' is passed in the {prm.get('in')} — sensitive "
                        "values there get logged/cached. Move to a header or request body.",
                        {"param": prm.get("name"), "in": prm.get("in"), "rule": "spec-sensitive-param"}))

            # mass-assignment-prone request schema
            rb = op.get("requestBody") or {}
            for _ct, media in ((rb.get("content") or {}).items() if isinstance(rb, dict) else []):
                schema = (media or {}).get("schema") or {}
                if schema.get("additionalProperties") is True:
                    findings.append(_f(VulnClass.BOPLA, "low",
                        "Request schema allows arbitrary properties (mass assignment)", ep,
                        f"{ep} accepts additionalProperties:true — clients can set unexpected fields "
                        "(mass assignment / BOPLA). Define an explicit allowlist schema.",
                        {"rule": "spec-mass-assignment"}))

            if op.get("deprecated") is True:
                findings.append(_f(VulnClass.INVENTORY, "low", "Deprecated operation still advertised", ep,
                    f"{ep} is deprecated but still in the spec — shadow/zombie API surface.",
                    {"rule": "spec-deprecated"}))

    if not has_any_scheme and unauth_state_changing:
        findings.insert(0, _f(VulnClass.AUTHZ, "high", "API defines no authentication scheme",
            "spec", "The specification declares no security schemes at all, yet exposes "
            f"{unauth_state_changing} state-changing operation(s) — the whole API is unauthenticated.",
            {"rule": "spec-no-auth-scheme"}))
    return findings
