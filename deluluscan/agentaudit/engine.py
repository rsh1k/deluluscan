"""AgentAudit — load an agent configuration and audit it (OWASP Agentic Top 10)."""
from __future__ import annotations

import json

from .analyzer import analyze_agent


def _agents_from(data) -> list:
    """Accept a single agent dict, a list of agents, or {agents:[...]}/{agent:{...}}."""
    if isinstance(data, list):
        return [a for a in data if isinstance(a, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("agents"), list):
            return [a for a in data["agents"] if isinstance(a, dict)]
        if isinstance(data.get("agent"), dict):
            return [data["agent"]]
        return [data]
    return []


class AgentAudit:
    def scan_config(self, data) -> list:
        out = []
        for a in _agents_from(data):
            out.extend(analyze_agent(a, source=a.get("name", "agent")))
        return out

    def scan_file(self, path: str) -> list:
        text = open(path, encoding="utf-8", errors="replace").read()
        try:
            data = json.loads(text)
        except Exception:
            try:
                import yaml
                data = yaml.safe_load(text)
            except Exception:
                return []
        return self.scan_config(data)
