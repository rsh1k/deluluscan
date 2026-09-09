"""Analyze a set of MCP tool definitions for poisoning / injection signals."""
from __future__ import annotations

import re
from typing import Optional

from ..models import Finding, RequestRecord, Severity, VulnClass
from . import patterns as P

_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL}
_compiled = {r.id: re.compile(r.pattern, re.I) for r in P.RULES}
_LONG_DESC = 1500          # a tool whose "help text" is enormous hides room for payloads


def _rec(tool_name: str, snippet: str) -> RequestRecord:
    return RequestRecord(method="MCP", url=f"tool:{tool_name}", identity="anon", status=0,
                         elapsed_ms=0.0, resp_body=(snippet or "")[:600])


def _schema_props(tool: dict):
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    return list(props.keys()) if isinstance(props, dict) else []


def analyze_tools(tools: list, *, source: str = "mcp") -> list:
    """tools: list of {name, description, inputSchema}. Returns Findings."""
    out: list = []
    tool_names = {(t.get("name") or "").lower() for t in tools if isinstance(t, dict)}

    def add(vc, sev, title, tool_name, desc_text, detail, snippet=""):
        out.append(Finding(
            vuln_class=VulnClass(vc), severity=_SEV[sev], title=title,
            endpoint=f"mcp:{tool_name}", description=desc_text,
            evidence=[_rec(tool_name, snippet)], confidence="firm",
            detail={**detail, "tool": tool_name, "source": source,
                    "remediation": ("Treat MCP tool metadata as untrusted input: pin tool "
                                    "definitions and alert on change (rug-pulls), sanitize/deny "
                                    "instruction-like descriptions, require human approval for "
                                    "execution/file/network tools, and isolate untrusted servers.")}))

    for t in tools:
        if not isinstance(t, dict):
            continue
        name = t.get("name") or "<unnamed>"
        desc = t.get("description") or ""

        # 1) pattern-based tool poisoning in the description
        for rule in P.RULES:
            text = desc if rule.where in ("description", "any") else name
            m = _compiled[rule.id].search(text or "")
            if m:
                add(rule.vuln_class, rule.severity,
                    rule.title, name,
                    f"{rule.note} (tool '{name}'). Matched: “{m.group(0)[:120]}”.",
                    {"rule": rule.id, "cwe": rule.cwe, "field": rule.where},
                    snippet=m.group(0))

        # 2) hidden / invisible characters in the description (concealment)
        if P.HIDDEN_CHARS.search(desc):
            add("ai_llm", "high", "MCP tool description contains hidden/invisible characters", name,
                f"Tool '{name}' hides content with zero-width/bidi unicode — instructions a human "
                "reviewer can't see but the model reads (concealed tool poisoning).",
                {"rule": "hidden-unicode", "cwe": "CWE-451"})
        if P.HTML_COMMENT.search(desc):
            add("ai_llm", "medium", "MCP tool description hides content in HTML comments", name,
                f"Tool '{name}' embeds HTML comments — a place to conceal instructions from a "
                "human reviewer.", {"rule": "html-comment"})

        # 3) suspiciously long description (payload room in a 'help' field)
        if len(desc) > _LONG_DESC:
            add("ai_llm", "low", "MCP tool description is abnormally long", name,
                f"Tool '{name}' has a {len(desc)}-char description — unusually large for help text; "
                "review it for embedded instructions.", {"rule": "long-desc", "length": len(desc)})

        # 4) dangerous capability (execution / filesystem / network) — human review
        cap = P.DANGEROUS_CAPABILITY.search(f"{name} {desc}")
        if cap:
            add("misconfig", "medium", "MCP tool exposes a high-impact capability", name,
                f"Tool '{name}' appears to offer a high-impact capability (“{cap.group(0)}”: "
                "execution / filesystem / network). Such tools should require explicit human "
                "approval and never auto-execute from untrusted servers.",
                {"rule": "dangerous-capability", "capability": cap.group(0), "cwe": "CWE-749"})

        # 5) sensitive input parameters a benign tool shouldn't collect
        for prop in _schema_props(t):
            if P.SENSITIVE_PARAM.match(prop):
                add("ai_llm", "medium", "MCP tool collects a sensitive parameter", name,
                    f"Tool '{name}' declares an input parameter '{prop}' — a benign tool rarely needs "
                    "to be handed credentials/secrets; this can trick the agent into surrendering them.",
                    {"rule": "sensitive-param", "param": prop, "cwe": "CWE-200"})
    return out
