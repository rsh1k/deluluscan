"""CLI: audit an AI-agent configuration against the OWASP Agentic Top 10 (2026).

    python3 -m deluluscan.agentaudit --config agent.json [--json]

Accepts a single agent, a list, or {agents:[...]} (JSON or YAML). Static analysis
of the config — nothing is run."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import AgentAudit


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.agentaudit",
                                 description="OWASP Agentic Top 10 config audit")
    ap.add_argument("--config", required=True, help="agent config file (JSON/YAML)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        finds = AgentAudit().scan_file(a.config)
    except Exception as e:
        raise SystemExit(f"[agentaudit] could not read config: {e}")
    if a.json:
        print(json.dumps([f.to_dict() for f in finds], indent=2, default=str))
        return 0
    print(f"[agentaudit] {a.config}: {len(finds)} finding(s)")
    for f in sorted(finds, key=lambda x: x.severity.rank, reverse=True):
        print(f"  [{f.severity.value.upper():8}] {f.detail.get('category',''):32} {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
