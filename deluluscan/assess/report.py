"""Multi-format LOCAL report writer for a merged assessment.

Writes findings to files you can export/share — JSON, Markdown, a self-contained
offline HTML file, plus CSV/XLSX/JUnit (via reporting.exporters) and SARIF (via
reporting.sarif). Everything is written to local disk; nothing is uploaded or
published. (The publish/Pages path in deluluscan.dashboard is separate and not used
here.)
"""
from __future__ import annotations

import html as _html
import json
import os
import time
from typing import Iterable

from ..reporting import exporters as _exporters
from ..reporting import sarif as _sarif

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOR = {"critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309",
              "low": "#1d4ed8", "info": "#334155"}


def _sorted(findings: list) -> list:
    return sorted(findings, key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 9))


def _counts(findings: list) -> dict:
    c = {k: 0 for k in _SEV_ORDER}
    for f in findings:
        c[f.get("severity", "info")] = c.get(f.get("severity", "info"), 0) + 1
    return c


# --------------------------------------------------------------------------
def to_markdown(payload: dict) -> str:
    findings = _sorted(payload.get("findings", []))
    meta = payload.get("meta", {})
    counts = _counts(findings)
    L = [f"# Security Assessment — {meta.get('target', 'target')}",
         "",
         f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(meta.get('generated_at', time.time())))}_",
         "",
         "## Summary",
         "",
         "| Severity | Count |", "|---|---|"]
    for sev in _SEV_ORDER:
        if counts.get(sev):
            L.append(f"| {sev.title()} | {counts[sev]} |")
    L.append(f"| **Total** | **{len(findings)}** |")
    L += ["", "## Findings", ""]
    for i, f in enumerate(findings, 1):
        L.append(f"### {i}. [{f.get('severity','').upper()}] {f.get('title','')}")
        L.append("")
        L.append(f"- **Class:** {f.get('vuln_class','')}  ·  **Verdict:** {f.get('verdict','')}"
                 f"  ·  **Confidence:** {f.get('confidence','')}  ·  **Exploitability:** {f.get('exploitability','')}")
        L.append(f"- **Endpoint:** `{f.get('endpoint','')}`")
        if f.get("description"):
            L.append(f"- {f['description']}")
        det = f.get("detail") or {}
        rem = det.get("remediation")
        if rem:
            L.append(f"- **Remediation:** {rem}")
        src = det.get("source")
        if src:
            L.append(f"- _source: {src}_")
        L.append("")
    if not findings:
        L.append("_No findings._")
    return "\n".join(L) + "\n"


def to_html(payload: dict) -> str:
    findings = _sorted(payload.get("findings", []))
    meta = payload.get("meta", {})
    counts = _counts(findings)
    def esc(x): return _html.escape(str(x or ""))
    rows = []
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        det = f.get("detail") or {}
        rem = esc(det.get("remediation", ""))
        rows.append(
            f'<tr><td>{i}</td>'
            f'<td><span class="badge" style="background:{_SEV_COLOR.get(sev,"#334155")}">{esc(sev).upper()}</span></td>'
            f'<td><strong>{esc(f.get("title"))}</strong><div class="desc">{esc(f.get("description"))}</div>'
            + (f'<div class="rem"><b>Remediation:</b> {rem}</div>' if rem else "")
            + f'</td>'
            f'<td>{esc(f.get("vuln_class"))}</td>'
            f'<td><code>{esc(f.get("endpoint"))}</code></td>'
            f'<td>{esc(f.get("verdict"))}<br><small>{esc(f.get("exploitability"))}</small></td></tr>')
    summary = "".join(
        f'<span class="pill" style="background:{_SEV_COLOR[s]}">{s.title()}: {counts[s]}</span>'
        for s in _SEV_ORDER if counts.get(s))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assessment — {esc(meta.get('target','target'))}</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background:#0b0f19; color:#e5e7eb; }}
.wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
h1 {{ font-size: 1.5rem; }} .meta {{ color:#9ca3af; font-size:.9rem; }}
.pills {{ margin: 16px 0; display:flex; gap:8px; flex-wrap:wrap; }}
.pill, .badge {{ color:#fff; padding:3px 10px; border-radius:999px; font-size:.8rem; font-weight:600; }}
table {{ width:100%; border-collapse: collapse; margin-top:16px; font-size:.92rem; }}
th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #1f2937; vertical-align:top; }}
th {{ color:#9ca3af; font-weight:600; position:sticky; top:0; background:#0b0f19; }}
td code {{ color:#93c5fd; word-break:break-all; }}
.desc {{ color:#cbd5e1; margin-top:4px; }} .rem {{ color:#86efac; margin-top:4px; font-size:.88rem; }}
tr:hover td {{ background:#0f1524; }}
@media (prefers-color-scheme: light) {{ body {{ background:#f8fafc; color:#0f172a; }} th {{ background:#f8fafc; color:#475569; }} th,td{{border-color:#e2e8f0;}} tr:hover td{{background:#f1f5f9;}} .desc{{color:#334155;}} td code{{color:#1d4ed8;}} }}
</style></head><body><div class="wrap">
<h1>Security Assessment — {esc(meta.get('target','target'))}</h1>
<div class="meta">Generated {esc(time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(meta.get('generated_at', time.time()))))} · {len(findings)} finding(s) · Deluluscan</div>
<div class="pills">{summary or '<span class="pill" style="background:#334155">No findings</span>'}</div>
<table><thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Class</th><th>Endpoint</th><th>Verdict</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=6>No findings.</td></tr>'}</tbody></table>
</div></body></html>"""


# --------------------------------------------------------------------------
def write_reports(payload: dict, out_dir: str, formats: Iterable[str]) -> dict:
    """Write each requested format to out_dir. Returns {fmt: path}. Local only."""
    os.makedirs(out_dir, exist_ok=True)
    written = {}
    for fmt in [f.lower().strip() for f in formats]:
        if fmt == "json":
            p = os.path.join(out_dir, "report.json")
            with open(p, "w") as fh:
                json.dump(payload, fh, indent=2, default=str)
            written["json"] = p
        elif fmt in ("md", "markdown"):
            p = os.path.join(out_dir, "report.md")
            with open(p, "w") as fh:
                fh.write(to_markdown(payload))
            written["md"] = p
        elif fmt == "html":
            p = os.path.join(out_dir, "report.html")
            with open(p, "w") as fh:
                fh.write(to_html(payload))
            written["html"] = p
        elif fmt == "sarif":
            written["sarif"] = _sarif.write_sarif(payload, out_dir)
        elif fmt in _exporters.FORMATS:
            ext = {"junit": "xml"}.get(fmt, fmt)
            p = os.path.join(out_dir, f"report.{ext}")
            written[fmt] = _exporters.export(payload, fmt, p)
        else:
            raise ValueError(f"unknown format {fmt!r}; known: json, md, html, sarif, "
                             + ", ".join(sorted(_exporters.FORMATS)))
    return written
