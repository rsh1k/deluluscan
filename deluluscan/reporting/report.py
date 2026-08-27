"""Reporting.

Writes two artifacts: a machine-readable results.json and a self-contained
results.html (no external assets) suitable for attaching to a bug report.
Evidence request/response excerpts are included but Authorization headers are
already redacted upstream.
"""
from __future__ import annotations

import html
import json
import os
import time

_SEV_COLOR = {"critical": "#b00020", "high": "#d9480f", "medium": "#b8860b",
              "low": "#2b6cb0", "info": "#555"}


def write_json(result: dict, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "results.json")
    with open(path, "w") as fh:
        json.dump(result, fh, indent=2, default=str)
    return path


def _evidence_block(ev: dict) -> str:
    body = html.escape((ev.get("resp_body") or "")[:1200])
    return (f"<div class='ev'><code>{html.escape(ev.get('method',''))} "
            f"{html.escape(ev.get('url',''))}</code> "
            f"&rarr; <b>{ev.get('status')}</b> "
            f"({ev.get('resp_len')} bytes, {ev.get('elapsed_ms')}ms, "
            f"as <i>{html.escape(ev.get('identity',''))}</i>)"
            f"<pre>{body}</pre></div>")


def _verify_block(v: dict) -> str:
    if not v:
        return ""
    _VC = {"true_positive": "#1b7a3d", "likely_true_positive": "#2f855a",
           "inconclusive": "#8a6d00", "likely_false_positive": "#8a4b00",
           "false_positive": "#777"}
    _XC = {"exploitable": "#b00020", "conditional": "#d9480f",
           "mitigated": "#2b6cb0", "not_exploitable": "#1b7a3d", "unknown": "#777"}
    verdict = v.get("verdict", "inconclusive")
    expl = v.get("exploitability", "unknown")
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in v.get("reasons", []))
    corr = "".join(f"<li>{html.escape(r)}</li>" for r in v.get("corroborations", []))
    conf = "".join(f"<li>{html.escape(r)}</li>" for r in v.get("confounders", []))
    ctrls = "".join(
        f"<li><b>{html.escape(c.get('name',''))}</b>: "
        f"{'present' if c.get('present') else 'absent'} "
        f"({html.escape(c.get('strength','n/a'))}) — {html.escape(c.get('detail',''))}</li>"
        for c in v.get("controls", []))
    repro = html.escape(v.get("repro", "") or "")
    ai = html.escape(v.get("ai_analysis", "") or "")
    return f"""
      <div class='verify'>
        <span class='vb' style='background:{_VC.get(verdict,'#777')}'>{verdict.replace('_',' ')}</span>
        <span class='vb' style='background:{_XC.get(expl,'#777')}'>exploitability: {expl.replace('_',' ')}</span>
        <span class='vprob'>score {v.get('confidence_score',0):.2f} · {v.get('probes',0)} probe(s)</span>
        {f"<div class='vsec'><b>Why:</b><ul>{reasons}</ul></div>" if reasons else ""}
        {f"<div class='vsec'><b>Corroborating signals:</b><ul>{corr}</ul></div>" if corr else ""}
        {f"<div class='vsec'><b>False-positive checks:</b><ul>{conf}</ul></div>" if conf else ""}
        {f"<div class='vsec'><b>Compensating controls:</b><ul>{ctrls}</ul></div>" if ctrls else ""}
        {f"<div class='vsec'><b>AI root-cause analysis:</b> {ai}</div>" if ai else ""}
        {f"<div class='vsec repro'><b>Safe manual reproduction:</b> {repro}</div>" if repro else ""}
      </div>"""


_REMEDIATION = {
    "sqli": "Use parameterized queries / prepared statements; never concatenate user input "
            "into SQL. Validate and allow-list sortable columns (do not pass raw sort params "
            "into ORDER BY). Apply least-privilege DB accounts.",
    "xss": "Context-encode all user-controlled output (HTML/attribute/JS/URL). Prefer a "
           "templating engine that auto-escapes. Add a strict Content-Security-Policy and "
           "set HttpOnly/SameSite on session cookies.",
    "authz": "Enforce function- and object-level authorization on every state-changing "
             "endpoint server-side; never rely on the client hiding an action. Check the "
             "caller's role/ownership before performing privileged operations (BFLA/BOLA).",
    "idor": "Verify the authenticated principal owns or may access the referenced object on "
            "every request; use unguessable identifiers and server-side access checks rather "
            "than trusting IDs supplied by the client.",
    "ssrf": "Deny requests to internal/link-local ranges by default; allow-list outbound hosts; "
            "resolve and validate destinations; block redirects to private ranges.",
    "info_leak": "Remove secrets/backups/VCS metadata from web-served paths; deny access to "
                 "dotfiles and archives; scrub stack traces and verbose errors from responses.",
    "bopla": "Return only the properties each role is permitted to see; validate and allow-list "
             "writable properties (mass-assignment) server-side.",
    "misconfig": "Harden defaults: disable directory listing and management endpoints, set "
                 "security headers, restrict CORS to trusted origins, and firewall management/"
                 "data services off the public network.",
    "supply_chain": "Confirm the exact running version/patch level, then upgrade to a fixed "
                    "release; subscribe to the component's security advisories; remove unused "
                    "components.",
    "graphql": "Disable introspection in production, enforce query depth/complexity limits and "
               "cost analysis, and apply per-field authorization.",
    "crypto": "Use vetted algorithms and libraries; enforce TLS; rotate and protect keys; avoid "
              "custom crypto.",
    "rate_limit": "Apply per-account and per-IP rate limits and lockout/backoff on "
                  "authentication and other sensitive flows.",
    "inventory": "Review the exposed surface; decommission forgotten hosts/endpoints; ensure "
                 "every reachable service is intended and access-controlled.",
    "business_logic": "Enforce server-side invariants and workflow/state checks; do not trust "
                      "client-supplied prices, quantities, or step ordering.",
    "error_handling": "Return generic error messages to clients; log details server-side only.",
}

_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONFIRMED = {"true_positive", "confirmed", "likely_true_positive"}


def _remediation_for(f: dict) -> str:
    return _REMEDIATION.get(f.get("vuln_class", ""),
                            "Review the finding, confirm impact, and apply the appropriate "
                            "server-side control and configuration hardening.")


def _risk_posture(findings: list) -> tuple:
    def confirmed(f):
        return (f.get("verdict") in _CONFIRMED) or (f.get("exploitability") == "exploitable")
    crit = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    if any(confirmed(f) for f in crit):
        return ("CRITICAL", "At least one confirmed critical issue provides a direct path to "
                "compromise. Immediate remediation is recommended before further exposure.")
    if crit or any(confirmed(f) for f in high):
        return ("HIGH", "Serious issues were identified that a motivated attacker could exploit. "
                "Prioritize remediation of the items below.")
    if high or any(f.get("severity") == "medium" for f in findings):
        return ("ELEVATED", "Meaningful weaknesses were found. None are confirmed critical, but "
                "several warrant timely remediation.")
    return ("LOW", "No high-impact issues were confirmed in this assessment. Address the items "
            "noted and maintain current controls.")


def _exec_summary(findings: list, all_findings: list, counts: dict, meta: dict) -> str:
    posture, narrative = _risk_posture(findings)
    pcolor = {"CRITICAL": "#8b0000", "HIGH": "#d1242f", "ELEVATED": "#bf8700",
              "LOW": "#1a7f37"}[posture]
    top = sorted(findings, key=lambda f: (
        f.get("verdict") in _CONFIRMED, _RANK.get(f.get("severity"), 0)), reverse=True)[:5]
    items = "".join(
        f"<li><b>{html.escape(f['severity'].upper())}</b> — {html.escape(f['title'])}"
        + (" <span style='color:#1a7f37'>(confirmed)</span>"
           if f.get('verdict') in _CONFIRMED else " <span style='color:#9a6700'>(candidate)</span>")
        + "</li>" for f in top)
    seen = set(); recs = []
    for f in top:
        r = _remediation_for(f)
        if r not in seen:
            seen.add(r); recs.append(r)
    rec_html = "".join(f"<li>{html.escape(r)}</li>" for r in recs[:5])
    fp = meta.get("fingerprint", {}) or {}
    techs = ", ".join(f"{d['tech']}{(' ' + d['version']) if d.get('version') else ''}"
                      for d in fp.get("detections", [])[:6]) or "not conclusively identified"
    sev_line = " ".join(f"{s}: {counts.get(s,0)}" for s in
                        ("critical", "high", "medium", "low", "info"))
    return f"""
<section class='exec'>
  <h2>Executive summary</h2>
  <p>This assessment evaluated <b>{html.escape(meta.get('target',''))}</b>
     ({meta.get('endpoints_scanned','?')} endpoints). Identified technology: {html.escape(techs)}.</p>
  <p><span class='posture' style='background:{pcolor}'>OVERALL RISK: {posture}</span></p>
  <p>{html.escape(narrative)}</p>
  <p><b>Findings by severity:</b> {sev_line}</p>
  <p><b>Most important findings:</b></p>
  <ul>{items or '<li>No medium+ findings.</li>'}</ul>
  <p><b>Recommended priorities:</b></p>
  <ol>{rec_html or '<li>Maintain current controls.</li>'}</ol>
  <p class='meta'>Severity reflects exploitability and confirmation state, not raw CVSS alone.
     "Confirmed" items were verified with a differential check; "candidate" items require
     manual validation. This automated assessment complements, but does not replace, manual testing.</p>
</section>"""


def _priority_matrix(findings: list) -> str:
    cols = [("Confirmed", _CONFIRMED),
            ("Likely / conditional", {"conditional", "likely_false_positive"}),
            ("Candidate", {"unverified", "inconclusive", ""})]
    head = "".join(f"<th>{c}</th>" for c, _ in cols)
    body = ""
    for s in ("critical", "high", "medium"):
        cells = ""
        for _, verds in cols:
            n = sum(1 for f in findings if f.get("severity") == s
                    and (f.get("verdict") or "") in verds)
            shade = "#fde8e8" if (s in ("critical", "high") and n) else ("#fff8e1" if n else "#fff")
            cells += f"<td style='background:{shade};text-align:center'>{n or ''}</td>"
        body += f"<tr><th style='text-align:left'>{s.upper()}</th>{cells}</tr>"
    return (f"<section class='matrix'><h2>Prioritization matrix</h2>"
            f"<table class='pm'><tr><th>Severity \\ Confidence</th>{head}</tr>{body}</table>"
            f"<p class='meta'>Fix top-left first: confirmed criticals/highs carry both impact "
            f"and proof. Candidates need manual validation before remediation effort.</p></section>")


def write_html(result: dict, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    meta = result.get("meta", {})
    all_findings = result.get("findings", [])
    # HTML shows actionable severities only (medium/high/critical); info & low are
    # kept in results.json / SARIF for audit but omitted from the report.
    _SHOW = {"medium", "high", "critical"}
    findings = [f for f in all_findings if f.get("severity") in _SHOW]
    hidden = len(all_findings) - len(findings)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    rows = []
    for f in findings:
        color = _SEV_COLOR.get(f["severity"], "#555")
        ev_html = "".join(_evidence_block(e) for e in f.get("evidence", [])[:3])
        ai = html.escape(f.get("ai_notes", "") or "")
        vblock = _verify_block(f.get("detail", {}).get("verification", {}))
        verdict = f.get("verdict", "unverified")
        val = f.get("detail", {}).get("validation", {}) or {}
        vstate = val.get("state", ""); vconf = val.get("confidence")
        _stc = {"reviewed": "#1a7f37", "dismissed": "#8a8a8a", "validating": "#9a6700", "new": "#555"}
        vbadge = (f"<span class='conf' style='background:{_stc.get(vstate,'#555')};"
                  f"color:#fff;padding:1px 6px;border-radius:4px'>{vstate}"
                  f"{f' {vconf:.2f}' if isinstance(vconf,(int,float)) else ''}</span>"
                  if vstate else "")
        rows.append(f"""
        <details class='finding'>
          <summary>
            <span class='badge' style='background:{color}'>{f['severity'].upper()}</span>
            <span class='cls'>{html.escape(f['vuln_class'])}</span>
            <span class='title'>{html.escape(f['title'])}</span>
            <span class='conf'>{html.escape(verdict.replace('_',' '))} · {html.escape(f.get('confidence',''))}</span>
            {vbadge}
          </summary>
          <p class='ep'><code>{html.escape(f['endpoint'])}</code>{f" &nbsp;<b>+{f.get('detail',{}).get('affected_count',1)-1} more endpoint(s)</b>" if f.get('detail',{}).get('affected_count',1) > 1 else ""}</p>
          <p>{html.escape(f['description'])}</p>
          <p class='remediation'><b>Remediation:</b> {html.escape(_remediation_for(f))}</p>
          {vblock}
          {f"<p class='ai'><b>AI triage:</b> {ai}</p>" if ai else ""}
          <div class='detail'><b>detail:</b> <pre>{html.escape(json.dumps({k: v for k, v in f.get('detail', {}).items() if k != 'verification'}, indent=2))}</pre></div>
          <div class='evidence'>{ev_html}</div>
        </details>""")

    summary = " ".join(
        f"<span class='badge' style='background:{_SEV_COLOR[s]}'>{s}: {counts.get(s,0)}</span>"
        for s in ("critical", "high", "medium", "low", "info"))

    doc = f"""<!doctype html><html><head><meta charset='utf-8'>
<title>deluluscan report — {html.escape(meta.get('target',''))}</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}}
 h1{{font-size:1.4rem}} .meta{{color:#555;font-size:.85rem}}
 .badge{{color:#fff;padding:.1rem .5rem;border-radius:.4rem;font-size:.75rem;margin-right:.4rem}}
 .finding{{background:#fff;border:1px solid #e2e2e2;border-radius:.5rem;margin:.6rem 0;padding:.6rem .9rem}}
 summary{{cursor:pointer}} .cls{{font-variant:small-caps;color:#666;margin-right:.4rem}}
 .title{{font-weight:600}} .conf{{float:right;color:#888;font-size:.75rem}}
 .ep code{{background:#f1f1f1;padding:.1rem .3rem;border-radius:.3rem}}
 pre{{background:#0d1117;color:#c9d1d9;padding:.6rem;border-radius:.4rem;overflow:auto;font-size:.75rem;max-height:18rem}}
 .ev{{margin:.4rem 0}} .ai{{background:#fff8e1;padding:.4rem .6rem;border-radius:.4rem}}
 .verify{{background:#f4f8fb;border:1px solid #dce6ee;border-radius:.4rem;padding:.5rem .7rem;margin:.5rem 0}}
 .vb{{color:#fff;padding:.1rem .5rem;border-radius:.4rem;font-size:.72rem;margin-right:.4rem}}
 .vprob{{color:#888;font-size:.72rem}} .vsec{{margin-top:.4rem;font-size:.85rem}}
 .vsec ul{{margin:.2rem 0 .2rem 1.1rem;padding:0}} .repro{{background:#eef7f0;padding:.4rem .6rem;border-radius:.4rem}}
 .exec{{background:#fff;border:1px solid #e2e2e2;border-left:4px solid #0d1117;border-radius:.5rem;padding:.8rem 1.1rem;margin:1rem 0}}
 .posture{{color:#fff;padding:.2rem .7rem;border-radius:.4rem;font-weight:600}}
 .remediation{{background:#eef7f0;padding:.4rem .6rem;border-radius:.4rem;margin:.4rem 0}}
 .matrix table.pm{{border-collapse:collapse;margin:.5rem 0}} .pm th,.pm td{{border:1px solid #ddd;padding:.35rem .7rem}}
</style></head><body>
<h1>Deluluscan — security assessment report</h1>
<p class='meta'>Target: <b>{html.escape(meta.get('target',''))}</b> ·
 endpoints scanned: {meta.get('endpoints_scanned')} ·
 source: {html.escape(str(meta.get('source','')))} ·
 AI: {html.escape(str(meta.get('ai_provider','')))} ·
 duration: {meta.get('duration_s')}s ·
 generated {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
{_exec_summary(findings, all_findings, counts, meta)}
{_priority_matrix(findings)}
<h2>Technical findings</h2>
<p>{summary}</p>
<p class='meta'>This report was produced by an authorized detection scan. Findings
are candidates requiring manual confirmation; no exploitation, payload delivery,
or code execution was performed.</p>
<hr>
{''.join(rows) if rows else '<p>No medium, high, or critical findings.</p>'}
{f"<p class='meta'>{hidden} info/low finding(s) omitted from this report; see results.json for the full list.</p>" if hidden else ""}
</body></html>"""

    path = os.path.join(out_dir, "results.html")
    with open(path, "w") as fh:
        fh.write(doc)
    return path
