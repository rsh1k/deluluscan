"""Detection patterns for MCP (Model Context Protocol) tool poisoning.

An MCP server advertises tools as {name, description, inputSchema}. The AI agent
reads those descriptions and *acts on them* — so the description field is an
unsanitised prompt-injection surface. A malicious or compromised server embeds
instructions in what looks like help text ("tool poisoning"), hides them with
invisible unicode, tells the model to exfiltrate files/secrets, or shadows other
tools. These rules flag those signals in a tool manifest. Grounded in the public
MCP threat-modeling literature (tool poisoning, hidden instructions, rug-pulls,
tool shadowing, cross-server / confused-deputy).
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class McpRule:
    id: str
    where: str            # description | name | any
    pattern: str
    vuln_class: str
    severity: str
    title: str
    note: str
    cwe: str = ""


# Imperative instructions aimed at the MODEL embedded in tool metadata.
RULES: list[McpRule] = [
    McpRule("prompt-override", "description",
            r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+(instruction|prompt|message|rule)"
            r"|disregard\s+(all\s+|the\s+|any\s+)?(previous|prior|above|instruction|rule)",
            "ai_llm", "high", "MCP tool description overrides prior instructions",
            "The tool description instructs the model to ignore/override its prior instructions — "
            "a prompt-injection (tool-poisoning) payload.", "CWE-77"),
    McpRule("hidden-from-user", "description",
            r"do\s+not\s+(tell|inform|mention|reveal|notify|show|disclose)\s+(the\s+)?(user|human|operator)"
            r"|without\s+(telling|informing|notifying|asking)\s+(the\s+)?(user|human)"
            r"|(secretly|silently|covertly)\b",
            "ai_llm", "high", "MCP tool description tells the model to hide actions from the user",
            "The description directs the model to act without informing the user — deception / "
            "confused-deputy behaviour typical of tool poisoning.", "CWE-77"),
    McpRule("exfil-secrets", "description",
            r"(read|cat|open|load|send|upload|exfiltrate|leak|include|attach)\b[^.]{0,40}"
            r"(\.ssh|id_rsa|\.env\b|/etc/passwd|~/\.|password|secret|credential|api[_\s-]?key|token|private\s*key)",
            "ai_llm", "critical", "MCP tool description references reading/exfiltrating secrets",
            "The description tells the model to read or transmit credentials/keys/sensitive files — "
            "a data-exfiltration tool-poisoning payload.", "CWE-200"),
    McpRule("exfil-external", "description",
            r"(send|post|upload|forward|exfiltrate|report)\b[^.]{0,40}(https?://|to\s+the\s+(server|endpoint|url|attacker))",
            "ai_llm", "high", "MCP tool description sends data to an external destination",
            "The description instructs the model to transmit data to an external URL/endpoint.", "CWE-200"),
    McpRule("mandatory-preamble", "description",
            r"(before|prior to)\s+(using|calling|invoking)\s+(any|this|the|each|every)\s+(other\s+)?tool"
            r"|(always|you\s+must|the\s+model\s+must|it\s+is\s+(required|mandatory))\b[^.]{0,60}(call|use|invoke|run)",
            "ai_llm", "high", "MCP tool description mandates behaviour before other tools run",
            "The description imposes mandatory pre-actions on the agent (a hallmark of tool poisoning "
            "that hijacks the agent's workflow).", "CWE-77"),
    McpRule("tool-shadowing", "description",
            r"(instead\s+of|rather\s+than|override|replace|intercept)\b[^.]{0,30}\btool"
            r"|when\s+the\s+(user|agent|model)\s+(calls|uses|invokes)\b",
            "ai_llm", "high", "MCP tool description shadows or reroutes other tools",
            "The description references intercepting/replacing another tool's behaviour "
            "(tool shadowing / cross-tool manipulation).", "CWE-77"),
    McpRule("fake-system", "description",
            r"<\s*(system|important|instructions?)\s*>|\[\s*system\s*\]|^\s*###?\s*(system|instruction)",
            "ai_llm", "medium", "MCP tool description spoofs a system/instruction block",
            "The description embeds a fake system/instruction block to smuggle authority.", "CWE-77"),
]

# Invisible / bidi / zero-width characters used to HIDE instructions from a human
# reviewer while the model still reads them.
HIDDEN_CHARS = re.compile(r"[​-‏‪-‮⁠⁡⁢⁣﻿­]")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)

# Tool capabilities worth a human's eyes (execution / filesystem / network).
DANGEROUS_CAPABILITY = re.compile(
    r"\b(exec|execute|shell|bash|/bin/|command|eval|run[_\s-]?code|spawn|subprocess|"
    r"read[_\s-]?file|write[_\s-]?file|delete[_\s-]?file|filesystem|arbitrary|fetch[_\s-]?url|"
    r"http[_\s-]?request|proxy|download|upload)\b")

# Input-schema property names a benign tool should not be collecting.
SENSITIVE_PARAM = re.compile(
    r"^(password|passwd|secret|api[_-]?key|apikey|token|access[_-]?token|private[_-]?key|"
    r"ssh[_-]?key|credential|session|system[_-]?prompt|file[_-]?content|env|environment)$")
