"""SARIF 2.1.0 output.

SARIF is the standard format consumed by CI security dashboards and code-scanning
tools (GitHub Advanced Security, Azure DevOps, etc.). Emitting it lets deluluscan
findings flow into an existing pipeline alongside SAST results.
"""
from __future__ import annotations

import json
import os
import re

_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}
# a SAST endpoint is "<path>:<line>"; a web endpoint is a URL — only split the former
_FILE_LINE = re.compile(r"^(?P<path>(?!\w+://).+?):(?P<line>\d+)$")


def _physical_location(endpoint: str) -> dict:
    """Turn a finding endpoint into a SARIF physicalLocation. For a source
    finding ("path/to/file.py:42") the line goes in region.startLine and the URI
    is the bare file path, so GitHub code-scanning (and any SARIF viewer) can
    anchor it. For a web URL the endpoint is kept as the artifact URI."""
    m = _FILE_LINE.match(endpoint or "")
    if m:
        return {"artifactLocation": {"uri": m.group("path")},
                "region": {"startLine": int(m.group("line"))}}
    return {"artifactLocation": {"uri": endpoint or "unknown"}}


def write_sarif(result: dict, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    findings = result.get("findings", [])
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rule_id = f"deluluscan/{f['vuln_class']}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f["vuln_class"],
            "shortDescription": {"text": f"deluluscan {f['vuln_class']} detector"},
            "defaultConfiguration": {"level": _LEVEL.get(f["severity"], "note")},
        })
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL.get(f["severity"], "note"),
            "message": {"text": f"{f['title']} — {f['description'][:300]}"},
            "properties": {"severity": f["severity"],
                           "confidence": f.get("confidence"),
                           "verdict": f.get("verdict"),
                           "exploitability": f.get("exploitability"),
                           "endpoint": f["endpoint"]},
            "locations": [{"physicalLocation": _physical_location(f["endpoint"])}],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "deluluscan",
                "informationUri": "https://example.local/deluluscan",
                "version": "0.2.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    path = os.path.join(out_dir, "results.sarif")
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2)
    return path
