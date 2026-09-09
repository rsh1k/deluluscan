"""McpScan — load an MCP tool manifest and analyze it for poisoning.

Offline by default: point it at a captured `tools/list` result (JSON). A live
fetch is injectable for callers that speak MCP, but the analysis itself is pure
static inspection of the tool definitions — detection only, nothing is executed.
"""
from __future__ import annotations

import json
from typing import Callable, Optional

from .analyzer import analyze_tools


def _tools_from(data) -> list:
    """Accept a raw tools list, a {tools:[...]} object, or a full JSON-RPC
    `tools/list` response {result:{tools:[...]}}."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("tools"), list):
            return data["tools"]
        res = data.get("result")
        if isinstance(res, dict) and isinstance(res.get("tools"), list):
            return res["tools"]
    return []


class McpScan:
    def scan_tools(self, tools: list) -> list:
        return analyze_tools(tools)

    def scan_manifest(self, data) -> list:
        return analyze_tools(_tools_from(data))

    def scan_file(self, path: str) -> list:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return self.scan_manifest(json.load(fh))

    def scan_live(self, fetch: Callable) -> list:
        """fetch() -> the `tools/list` result (list or dict). Injected transport."""
        return self.scan_manifest(fetch())
