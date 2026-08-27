"""GraphQL attack-surface mapping via introspection.

Runs the standard introspection query, and if the server answers, maps the
surface: root queries/mutations, dangerous mutations (delete/admin/password/…),
and sensitive-looking fields (password/token/secret/ssn/…). Emits findings:
introspection-enabled in production is a misconfiguration; the enumerated
mutations/fields become a prioritized surface for authz/BOLA testing. Detection
only — it reads the schema, it does not run the mutations.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass

INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
    "types { name kind fields { name args { name } type { name kind ofType { name kind } } } } } }")

_DANGEROUS_MUT = re.compile(
    r"(delete|remove|drop|destroy|reset|revoke|grant|disable|enable|shutdown|"
    r"admin|password|passwd|impersonate|sudo|escalat|createuser|deleteuser|purge|wipe)", re.I)
_SENSITIVE_FIELD = re.compile(
    r"(password|passwd|secret|token|apikey|api_key|ssn|credit|card|cvv|private[_-]?key|"
    r"session|auth|credential)", re.I)


@dataclass
class GraphQLSurface:
    url: str
    introspection_enabled: bool = False
    queries: list = field(default_factory=list)
    mutations: list = field(default_factory=list)          # list[{name, dangerous}]
    sensitive_fields: list = field(default_factory=list)   # list[{type, field}]
    type_count: int = 0

    def to_dict(self) -> dict:
        return {"url": self.url, "introspection_enabled": self.introspection_enabled,
                "queries": self.queries, "mutations": self.mutations,
                "sensitive_fields": self.sensitive_fields, "type_count": self.type_count}


def parse_schema(introspection: dict, url: str = "") -> GraphQLSurface:
    surf = GraphQLSurface(url=url)
    schema = (((introspection or {}).get("data") or {}).get("__schema")
              or (introspection or {}).get("__schema"))
    if not schema:
        return surf
    surf.introspection_enabled = True
    q_name = (schema.get("queryType") or {}).get("name")
    m_name = (schema.get("mutationType") or {}).get("name")
    types = schema.get("types") or []
    surf.type_count = len([t for t in types if not str(t.get("name", "")).startswith("__")])
    for t in types:
        tname = t.get("name", "")
        fields = t.get("fields") or []
        if tname == q_name:
            surf.queries = [f.get("name") for f in fields]
        if tname == m_name:
            for f in fields:
                fn = f.get("name", "")
                surf.mutations.append({"name": fn, "dangerous": bool(_DANGEROUS_MUT.search(fn))})
        if not tname.startswith("__"):
            for f in fields:
                if _SENSITIVE_FIELD.search(f.get("name", "")):
                    surf.sensitive_fields.append({"type": tname, "field": f.get("name")})
    return surf


def surface_to_findings(surf: GraphQLSurface) -> list:
    out: list[Finding] = []
    if surf.introspection_enabled:
        out.append(Finding(
            vuln_class=VulnClass.GRAPHQL, severity=Severity.MEDIUM,
            title="GraphQL introspection enabled", endpoint=surf.url,
            description=(f"Introspection is enabled — the full schema ({surf.type_count} types, "
                         f"{len(surf.queries)} queries, {len(surf.mutations)} mutations) is "
                         "disclosed to any client. Disable introspection in production."),
            detail={"queries": surf.queries[:50], "mutations": [m["name"] for m in surf.mutations][:50],
                    "rule": "graphql-introspection"},
            confidence="confirmed", verdict="true_positive", exploitability="conditional"))
    dangerous = [m["name"] for m in surf.mutations if m["dangerous"]]
    if dangerous:
        out.append(Finding(
            vuln_class=VulnClass.INVENTORY, severity=Severity.LOW,
            title=f"High-impact GraphQL mutations exposed ({len(dangerous)})", endpoint=surf.url,
            description=("State-changing/admin mutations are reachable on the schema — a prioritized "
                         "surface for BFLA/BOLA/authorization testing: " + ", ".join(dangerous[:15]) + "."),
            detail={"mutations": dangerous, "rule": "graphql-dangerous-mutations"},
            confidence="firm", verdict="likely_true_positive", exploitability="conditional"))
    if surf.sensitive_fields:
        out.append(Finding(
            vuln_class=VulnClass.INFO_LEAK, severity=Severity.LOW,
            title=f"Sensitive fields in GraphQL schema ({len(surf.sensitive_fields)})", endpoint=surf.url,
            description=("Fields with credential/PII-like names are queryable — verify authorization "
                         "on: " + ", ".join(f"{s['type']}.{s['field']}" for s in surf.sensitive_fields[:12]) + "."),
            detail={"fields": surf.sensitive_fields, "rule": "graphql-sensitive-fields"},
            confidence="firm", verdict="likely_true_positive", exploitability="conditional"))
    return out


def analyze_graphql(fetch: Callable, url: str) -> tuple:
    """fetch(url, json_body) -> (status:int, json:dict). Returns (surface, findings)."""
    try:
        status, body = fetch(url, {"query": INTROSPECTION_QUERY})
    except Exception:
        return GraphQLSurface(url=url), []
    surf = parse_schema(body if isinstance(body, dict) else {}, url)
    return surf, surface_to_findings(surf)
