"""CLI: analyze an MCP tool manifest for tool poisoning / prompt injection.

    python3 -m deluluscan.mcp --manifest tools.json [--json]

Give it a captured MCP `tools/list` result (a JSON list, {tools:[...]}, or a full
JSON-RPC response). Static analysis only — nothing is executed."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import McpScan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.mcp",
                                 description="MCP tool-poisoning / prompt-injection analyzer")
    ap.add_argument("--manifest", required=True, help="JSON file: a tools/list result")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        finds = McpScan().scan_file(a.manifest)
    except Exception as e:
        raise SystemExit(f"[mcp] could not read manifest: {e}")
    if a.json:
        print(json.dumps([f.to_dict() for f in finds], indent=2, default=str))
        return 0
    print(f"[mcp] {a.manifest}: {len(finds)} finding(s)")
    for f in sorted(finds, key=lambda x: x.severity.rank, reverse=True):
        print(f"  [{f.severity.value.upper():8}] {f.detail['tool']:20} {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
