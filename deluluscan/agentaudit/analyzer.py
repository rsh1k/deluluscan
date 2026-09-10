"""Static audit of an AI-agent configuration against the OWASP Top 10 for Agentic
Applications (2026).

An agent's blast radius is every tool, credential, and data source it can reach,
compounded across an autonomous multi-step plan. This inspects an agent's *config*
— its tools, autonomy/approval settings, memory/RAG sources, identity scopes,
system prompt, and guardrails — and flags the agentic risk categories: excessive
agency, insufficient human oversight, tool misuse, memory/goal-hijacking surface,
identity & privilege abuse, sensitive-data exposure, and missing traceability.

Config formats vary (LangChain/AutoGPT/CrewAI/custom), so extraction is tolerant:
it looks for common field names anywhere in the structure. High precision — a
well-governed agent (human-in-the-loop, bounded, sanitized memory, scoped
identity, guardrails) yields zero findings. Static, offline, detection only.
"""
from __future__ import annotations

import json
import re

from ..models import Finding, RequestRecord, Severity, VulnClass

_FRAMEWORK = "OWASP Agentic Top 10 (2026)"
_DANGEROUS = re.compile(
    r"(?i)\b(exec|execute|shell|bash|command|eval|run[_\s-]?code|spawn|subprocess|"
    r"write[_\s-]?file|delete|remove|drop[_\s-]?table|send[_\s-]?email|sendmail|payment|"
    r"transfer|purchase|http[_\s-]?request|fetch[_\s-]?url|browse|sql|database[_\s-]?write|"
    r"deploy|terminate|shutdown)\b")
_UNTRUSTED_SOURCE = re.compile(r"(?i)\b(web|internet|url|email|inbox|user[_\s-]?upload|"
                               r"user[_\s-]?input|rag|document|attachment|external|scrape)\b")
_BROAD_SCOPE = re.compile(r"(?i)(^\*$|admin|superuser|root|owner|\*:\*|full[_\s-]?access|all)")
_SENSITIVE = re.compile(r"(?i)(password|secret|api[_-]?key|token|ssn|credit|private[_-]?key|credential)")


def _walk(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def _find_bool(cfg, *names):
    """Return the first boolean whose key matches any name (case-insensitive), else None."""
    want = {n.lower() for n in names}
    for k, v in _walk(cfg):
        if isinstance(k, str) and k.lower() in want and isinstance(v, bool):
            return v
    return None


def _find_any(cfg, *names):
    want = {n.lower() for n in names}
    for k, v in _walk(cfg):
        if isinstance(k, str) and k.lower() in want:
            return v
    return None


def _tools(cfg) -> list:
    for key in ("tools", "functions", "capabilities", "plugins", "actions"):
        v = cfg.get(key) if isinstance(cfg, dict) else None
        if isinstance(v, list):
            return v
    return []


def _tool_text(t) -> str:
    if isinstance(t, str):
        return t
    if isinstance(t, dict):
        return " ".join(str(t.get(k, "")) for k in ("name", "description", "func", "type"))
    return str(t)


def analyze_agent(cfg: dict, *, source: str = "agent") -> list:
    if not isinstance(cfg, dict):
        return []
    out: list = []
    rec = RequestRecord(method="AGENT", url=source, identity="anon", status=0, elapsed_ms=0.0)

    def add(vc, sev, title, desc, category, rule, extra=None):
        out.append(Finding(vuln_class=vc, severity=sev, title=title, endpoint=source,
                           description=desc, evidence=[rec], confidence="firm",
                           detail={"framework": _FRAMEWORK, "category": category, "rule": rule,
                                   "source": "agentaudit", **(extra or {})}))

    tools = _tools(cfg)
    dangerous = [t for t in tools if _DANGEROUS.search(_tool_text(t))]

    # governance signals (approval / oversight / bounds)
    auto_approve = _find_bool(cfg, "auto_approve", "autoApprove", "auto_execute", "autonomous", "yolo")
    hitl = _find_bool(cfg, "human_in_the_loop", "humanInTheLoop", "require_approval",
                      "requireApproval", "confirm", "approval_required")
    max_steps = _find_any(cfg, "max_steps", "maxSteps", "max_iterations", "maxIterations",
                          "step_limit", "budget", "recursion_limit")

    # --- Excessive Agency / Insufficient Human Oversight ---
    ungoverned = (auto_approve is True) or (hitl is False) or (hitl is None and auto_approve is None)
    if dangerous and ungoverned:
        sev = Severity.HIGH if (auto_approve is True or hitl is False) else Severity.MEDIUM
        add(VulnClass.AI_LLM, sev, "Excessive agency: high-impact tools without human approval",
            f"The agent can call high-impact tool(s) {[_tool_text(t)[:30] for t in dangerous][:5]} "
            "(execution/file-write/network/payment) with no human-in-the-loop / approval gate — a "
            "poisoned input can drive real-world actions autonomously.",
            "Excessive Agency / Human Oversight", "asi-excessive-agency",
            {"dangerous_tools": [_tool_text(t)[:60] for t in dangerous][:10], "cwe": "CWE-250"})

    # --- Unbounded autonomy ---
    if (auto_approve is True or _find_bool(cfg, "autonomous") is True) and not max_steps:
        add(VulnClass.AI_LLM, Severity.MEDIUM, "Unbounded agent autonomy (no step/budget limit)",
            "The agent runs autonomously with no max-steps / iteration / budget limit — a hijacked "
            "goal can loop or escalate without bound.", "Excessive Agency", "asi-unbounded-autonomy",
            {"cwe": "CWE-400"})

    # --- Memory / context poisoning surface ---
    mem = _find_any(cfg, "memory", "rag", "knowledge", "retrieval", "context_sources", "data_sources")
    if mem is not None:
        mem_text = json.dumps(mem, default=str)
        sanitized = _find_bool(cfg, "sanitize", "sanitize_input", "validate_input", "content_filter",
                               "input_validation", "trusted_only")
        if _UNTRUSTED_SOURCE.search(mem_text) and sanitized is not True:
            add(VulnClass.AI_LLM, Severity.HIGH, "Memory/RAG ingests untrusted sources without sanitization",
                "The agent pulls context from untrusted sources (web/email/user uploads/RAG) with no "
                "sanitization or trust boundary — a single poisoned document can hijack the agent's "
                "goal or exfiltrate data (memory poisoning / goal hijacking).",
                "Memory Poisoning / Goal Hijacking", "asi-memory-poisoning", {"cwe": "CWE-20"})

    # --- Identity & privilege abuse ---
    ident = _find_any(cfg, "identity", "credentials", "scopes", "permissions", "role", "iam", "auth")
    if ident is not None and _BROAD_SCOPE.search(json.dumps(ident, default=str)):
        add(VulnClass.AUTHZ, Severity.HIGH, "Over-privileged agent identity",
            "The agent runs with broad/admin/wildcard privileges — a compromised or hijacked agent "
            "inherits that blast radius across every tool and service it can reach. Scope it to "
            "least privilege per task.", "Identity & Privilege Abuse", "asi-privilege-abuse",
            {"cwe": "CWE-269"})

    # --- Poisoned tool descriptions (reuse the MCP analyzer) ---
    tool_dicts = [t for t in tools if isinstance(t, dict) and t.get("description")]
    if tool_dicts:
        try:
            from ..mcp.analyzer import analyze_tools
            for f in analyze_tools(tool_dicts, source="agentaudit"):
                f.detail["framework"] = _FRAMEWORK
                f.detail["category"] = "Tool Poisoning / Insecure Plugin"
                out.append(f)
        except Exception:
            pass

    # --- Sensitive data in agent config/memory ---
    for k, v in _walk(cfg):
        if isinstance(k, str) and _SENSITIVE.search(k) and isinstance(v, str) and len(v) >= 6 \
                and not v.startswith(("{", "$", "!")):
            add(VulnClass.INFO_LEAK, Severity.HIGH, "Hardcoded secret in agent configuration",
                f"The agent config embeds a secret in '{k}' — it lands in the agent's context/logs "
                "and version control. Use a secret store / runtime injection.",
                "Sensitive Information Disclosure", "asi-config-secret", {"cwe": "CWE-798"})
            break

    # --- Missing traceability ---
    logging_on = _find_bool(cfg, "logging", "audit", "trace", "observability", "telemetry")
    if dangerous and logging_on is False:
        add(VulnClass.LOGGING_FAILURE, Severity.LOW, "No audit trail for agent actions",
            "The agent invokes high-impact tools but logging/audit is disabled — its actions can't be "
            "traced or investigated after an incident.", "Insufficient Traceability", "asi-no-audit",
            {"cwe": "CWE-778"})
    return out
