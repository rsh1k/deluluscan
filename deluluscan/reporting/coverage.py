"""Coverage reporting.

Answers the honest question "what did the scan actually test, and what did it
skip?" — instead of leaving you to guess from a finding count. For every
(endpoint, scanner) pair we record whether the scanner ran or was skipped (and
why), then emit:

  * coverage.json  — the full matrix, machine-readable;
  * coverage.html  — a readable grid;
  * a console summary: per-scanner coverage %, and the endpoints that NO
    active scanner touched (the real blind spots).

This makes the tool's limits auditable: a scanner that "applies_to == False"
for an endpoint is a deliberate skip (e.g. SQLi only probes query params), and
the report shows exactly where that leaves gaps so you know what still needs
manual testing.
"""
from __future__ import annotations

import html
import json
import os
from collections import defaultdict


class CoverageTracker:
    """Collect (endpoint_key, scanner_name) -> status during a scan."""

    def __init__(self):
        # endpoint_key -> {scanner_name: "tested" | "skipped:<reason>"}
        self.matrix: dict[str, dict[str, str]] = defaultdict(dict)
        self.scanners: set[str] = set()

    def record(self, endpoint_key: str, scanner_name: str,
               tested: bool, reason: str = "") -> None:
        self.scanners.add(scanner_name)
        self.matrix[endpoint_key][scanner_name] = (
            "tested" if tested else f"skipped:{reason or 'not applicable'}")

    def as_dict(self) -> dict:
        return {"scanners": sorted(self.scanners), "matrix": dict(self.matrix)}


def _summarize(cov: dict) -> dict:
    scanners = cov["scanners"]
    matrix = cov["matrix"]
    per_scanner = {s: {"tested": 0, "skipped": 0} for s in scanners}
    untouched = []
    for ep, row in matrix.items():
        if not any(v == "tested" for v in row.values()):
            untouched.append(ep)
        for s in scanners:
            status = row.get(s, "skipped:absent")
            key = "tested" if status == "tested" else "skipped"
            per_scanner[s][key] += 1
    total = len(matrix) or 1
    pct = {s: round(100 * per_scanner[s]["tested"] / total, 1) for s in scanners}
    return {"endpoints": len(matrix), "per_scanner_pct": pct,
            "untouched_endpoints": untouched}


def write_coverage(cov: dict, out_dir: str) -> tuple[str, str, dict]:
    os.makedirs(out_dir, exist_ok=True)
    summary = _summarize(cov)

    jpath = os.path.join(out_dir, "coverage.json")
    with open(jpath, "w") as fh:
        json.dump({"summary": summary, **cov}, fh, indent=2)

    scanners = cov["scanners"]
    rows = []
    for ep, row in sorted(cov["matrix"].items()):
        cells = []
        for s in scanners:
            st = row.get(s, "skipped:absent")
            if st == "tested":
                cells.append("<td class='t'>&#10003;</td>")
            else:
                cells.append(f"<td class='s' title='{html.escape(st)}'>&middot;</td>")
        rows.append(f"<tr><td class='ep'>{html.escape(ep)}</td>{''.join(cells)}</tr>")
    head = "".join(f"<th>{html.escape(s)}</th>" for s in scanners)
    pct = "".join(
        f"<th>{summary['per_scanner_pct'][s]}%</th>" for s in scanners)
    hpath = os.path.join(out_dir, "coverage.html")
    with open(hpath, "w") as fh:
        fh.write(f"""<!doctype html><meta charset=utf-8>
<style>body{{font:13px system-ui;margin:1.5rem}}table{{border-collapse:collapse}}
td,th{{border:1px solid #ddd;padding:2px 6px;text-align:center}}
.ep{{text-align:left;font-family:monospace;font-size:11px}}
.t{{background:#d4edda;color:#155724}}.s{{background:#f8f9fa;color:#bbb}}
caption{{text-align:left;font-weight:600;margin-bottom:.5rem}}</style>
<table><caption>deluluscan coverage — {summary['endpoints']} endpoints ·
{len(summary['untouched_endpoints'])} untouched by any scanner</caption>
<tr><th>endpoint</th>{head}</tr>
<tr><th>coverage</th>{pct}</tr>
{''.join(rows)}</table>""")
    return jpath, hpath, summary
