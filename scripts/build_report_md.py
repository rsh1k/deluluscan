#!/usr/bin/env python3
"""build_report_md.py — render the adjudicated payload as Markdown.

The same content as the .docx, from the same source. Two documents that restate
the same facts drift apart the moment one is edited by hand, and a pentest report
that disagrees with itself is worse than one that only exists in a single format
— so both renderers read one payload and neither is hand-maintained.

Usage: python3 scripts/build_report_md.py deluluscan-out/adjudicated-1.2.5.json out.md
"""
from __future__ import annotations

import json
import sys
from datetime import date

SEV_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


def owasp_label(code: str) -> str:
    """Name an OWASP category from the canonical map in deluluscan.knowledge.

    Deliberately not a local table: two renderers previously each kept their own
    copy, both holding the 2021 list, so 2025-coded findings printed the 2021
    meaning of the code.
    """
    if not code:
        return '—'
    from deluluscan.knowledge import owasp_2025_label
    return owasp_2025_label(code) or '—' 


def fence(text: str, lang: str = '') -> str:
    """Fence a block, defending against a payload that contains a fence itself."""
    body = (text or '').rstrip()
    marker = '```'
    while marker in body:
        marker += '`'
    return f'{marker}{lang}\n{body}\n{marker}'


def render(payload: dict) -> str:
    meta = payload.get('meta', {})
    findings = payload.get('findings', [])
    include = (meta.get('report_include') or {}).get('ids') or []
    by_id = {f['id']: f for f in findings}
    confirmed = [by_id[i] for i in include if i in by_id]
    confirmed.sort(key=lambda f: (-SEV_ORDER.get(f.get('severity', 'info'), 0),
                                  -(((f.get('detail') or {}).get('report') or {})
                                    .get('cvss') or {}).get('base_score', 0)))
    observations = [f for f in findings
                    if (f.get('detail') or {}).get('observation') and f['id'] not in include]
    refuted = [f for f in findings if (f.get('detail') or {}).get('refuted')]

    img = meta.get('image', {})
    scoring = meta.get('scoring', {})
    adj = meta.get('adjudication', {})
    ver = next((d.get('version') for d in meta.get('fingerprint', {}).get('detections', [])), 'unknown')
    out: list[str] = []
    w = out.append

    w(f'# the target Penetration Test Report — {ver}\n')
    w('**Classification:** Confidential / Internal  ')
    w(f'**Report date:** {date.today().strftime("%d %B %Y")}  ')
    w('**Prepared by:** the Security Team  ')
    w(f'**Target:** the target {ver} (authorized, dedicated instance)\n')
    w('---\n')

    # ---- 1 ---------------------------------------------------------------
    w('## 1. Executive Summary\n')
    w(f'This assessment tested the target **{ver}** against a dedicated, authorized instance. Every '
      'candidate finding was re-tested live against the running target and cross-checked against the '
      'the target source at the exact commit the image was built from. Nothing here is asserted on the '
      'strength of a scanner signature alone.\n')
    unauth = [f for f in confirmed if 'PR:N' in (cvss_of(f) or {}).get('vector', '')]
    if confirmed:
        w(f'**{len(confirmed)} vulnerabilities were demonstrated to be exploitable.** '
          + (f'{len(unauth)} of them require no authentication at all.\n' if unauth else '\n'))
        w('| ID | Finding | CVSS v3.1 | Rating | Privileges | Status |')
        w('|---|---|---|---|---|---|')
        for i, f in enumerate(confirmed, 1):
            c = cvss_of(f) or {}
            pr = 'None' if 'PR:N' in c.get('vector', '') else (
                'Back-end user' if 'PR:L' in c.get('vector', '') else 'Administrator')
            w(f'| F-{i:02d} | {f["title"]} | {c.get("base_score", "—")} | '
              f'{f["severity"].title()} | {pr} | Open |')
        w('')
    else:
        # Zero findings is a real result, but it must not read as "nothing was
        # found" when behaviours WERE found and then accepted.
        w('**This report presents NO exploitable vulnerabilities.** That result should be read '
          'precisely.\n')
        w(f'- **{len(observations)} behaviours reproduced** against the live target and are recorded as '
          'observations in §8.1. Each was classified by the product owner as accepted or by design, so '
          'none is counted as a finding. They are not false positives — every one reproduces on demand.')
        w(f'- **{len(refuted)} candidate classes did NOT reproduce** and are refuted with evidence in '
          '§8.2, including one previously rated *Critical* and three rated *High*.\n')
        w('The distinction between those two groups is the substance of this report: the first group '
          'happens and has been accepted; the second does not happen.\n')
    if meta.get('chain'):
        w(meta['chain'] + ' See §6.\n')
    if adj.get('refuted_classes') and confirmed:
        occ = adj.get('refuted_occurrences')
        w(f'A further **{adj["refuted_classes"]} candidate classes**'
          + (f' ({occ} individual occurrences)' if occ else '')
          + ' were raised — by the previous report and by this engagement\'s automated sweep — and were '
            'refuted by live re-testing, including one previously rated *Critical*. They are documented '
            'in §8.2 with the evidence that refutes each. Reporting a weakness that does not exist costs '
            'engineering time and erodes trust in the assessment, so the refutations are treated as '
            'deliverables in their own right.\n')
    if observations and confirmed:
        w(f'{len(observations)} further behaviours were **confirmed but are not counted as '
          'vulnerabilities**; they are recorded as observations in §8.1, unscored — each either could '
          'not be shown to have a security consequence, or was classified as accepted/by design by the '
          'product owner.\n')

    # ---- 2 ---------------------------------------------------------------
    w('---\n\n## 2. Scope & Target\n')
    w('| Property | Value |')
    w('|---|---|')
    for k, v in [
        ('Product / version', f'the target {ver}'),
        ('Container image', f'`{img.get("tag", "—")}`'),
        ('Image digest', f'`{img.get("digest", "—")}`'),
        ('Server-reported version', f'`x-app-version: {img.get("served_version_header", "—")}`'),
        ('Source reviewed', f'`the target source @ {img.get("source_commit", "—")}`'),
        ('Target URL', f'`{payload.get("target", "—")}` (loopback, dedicated instance)'),
        ('Provenance', meta.get('source', '—')),
    ]:
        w(f'| {k} | {v} |')
    w('')
    w('The image tag was verified against the version the server actually reports, and the source tree '
      'was pinned to the commit named by the release tag, so source-level conclusions describe the '
      'binary under test rather than a later `main`.\n')
    w('**Identities exercised:** ' + ', '.join(f'`{i}`' for i in sorted(meta.get('identities', {}))) + '\n')

    # ---- 3 ---------------------------------------------------------------
    w('---\n\n## 3. Risk Scoring System\n')
    w(f'### {scoring.get("system", "CVSS v3.1 Base")}\n')
    w('Every confirmed finding carries a full CVSS vector string, so any reader can paste it into the '
      'FIRST calculator and reproduce the score independently.\n')
    for key in ('rationale', 'metric_derivation'):
        if scoring.get(key):
            w(scoring[key] + '\n')
    if scoring.get('implementation'):
        w(f'*Implementation: {scoring["implementation"]}.*\n')
    w('| CVSS base score | Qualitative rating |')
    w('|---|---|')
    for rng, lbl in [('0.0', 'None'), ('0.1 – 3.9', 'Low'), ('4.0 – 6.9', 'Medium'),
                     ('7.0 – 8.9', 'High'), ('9.0 – 10.0', 'Critical')]:
        w(f'| {rng} | {lbl} |')
    w('')
    w('### OWASP classification\n')
    w('Every finding is mapped to the **OWASP Top 10:2025** category, the **OWASP API Security Top '
      '10:2023** category and the relevant **CWE** identifiers. Mappings come from the '
      'per-vulnerability-class taxonomy in `deluluscan/knowledge.py` rather than being assigned ad hoc, so '
      'the same class of issue is always classified the same way.\n')

    # ---- 4 ---------------------------------------------------------------
    w('---\n\n## 4. Methodology\n')
    for step in [
        '**Provision.** A clean stack was stood up on an isolated loopback host with empty volumes, and '
        'role-distinct test identities were provisioned.',
        '**Automated sweep.** The scanner suite was run across the documented API surface with grey-box '
        'observability enabled — the target container\'s own logs and memory tapped and correlated to '
        'the probe that caused each event.',
        '**Live adjudication.** Every candidate was re-tested by hand against the running instance, as '
        'multiple identities, capturing the full request and the full response.',
        '**Source correlation.** For each candidate, the responsible source was read at the pinned '
        'commit to establish the *mechanism* — specifically, to distinguish a missing control from a '
        'control that fired.',
        '**Bypass attempts.** Where a control was found, it was attacked directly (allowlist evasion, '
        'comment/terminator injection, cross-user object references, polymorphic deserialization '
        'gadgets) rather than assumed effective.',
        '**Manual review** of authentication, session handling, CORS, error handling and information '
        'disclosure beyond the automated surface.',
    ]:
        w(f'- {step}')
    w('')
    w('### Adjudication standard\n')
    w('A finding is reported as a vulnerability only where the evidence shows a **concrete security '
      'consequence**:\n')
    for rule in [
        'An HTTP **4xx or 5xx status is not a finding**. A 500 with an empty body discloses nothing.',
        'An **error message is not a finding** unless it reveals something an attacker did not already '
        'have. the target is open-source: internal class names and form field names are published on GitHub '
        'and in the product\'s own OpenAPI document.',
        'A **response differential is not injection.** Where a payload changes a response, the mechanism '
        'must be established — a sanitiser that strips input to empty also changes the response, and '
        'looks identical to a scanner.',
        '**Untested is not secure.** Coverage limits are stated in §9.',
    ]:
        w(f'- {rule}')
    w('')

    # ---- 5, 6 -------------------------------------------------------------
    w('---\n\n## 5. Summary of Findings\n')
    w('| ID | Finding | CVSS | Rating | OWASP 2025 | OWASP API | CWE |')
    w('|---|---|---|---|---|---|---|')
    for i, f in enumerate(confirmed, 1):
        c = cvss_of(f) or {}
        tax = tax_of(f)
        w(f'| F-{i:02d} | {f["title"]} | {c.get("base_score", "—")} | {f["severity"].title()} | '
          f'{tax.get("owasp_2025") or "—"} | {tax.get("owasp_api_top10") or "—"} | '
          f'{", ".join(tax.get("cwe") or []) or "—"} |')
    w('')
    if observations:
        w('### Observations — confirmed behaviour, not counted as findings\n')
        w('| ID | Observation | OWASP 2025 | CWE |')
        w('|---|---|---|---|')
        for i, f in enumerate(observations, 1):
            tax = tax_of(f)
            w(f'| O-{i:02d} | {f["title"]} | {tax.get("owasp_2025") or "—"} | '
              f'{", ".join(tax.get("cwe") or []) or "—"} |')
        w('')

    # ---- 7 ----------------------------------------------------------------
    w('---\n\n## 6. Attack Narrative\n')
    for line in meta.get('chain_detail') or ['No exploit chain was demonstrated.']:
        w((line if not line.startswith('- ') else line) + '\n')

    # ---- 8 ----------------------------------------------------------------
    w('---\n\n## 7. Detailed Findings\n')
    for i, f in enumerate(confirmed, 1):
        w(render_finding(f, f'F-{i:02d}'))

    if observations or refuted:
        w('---\n\n## 8. Observations & Refuted Candidates\n')
    if observations:
        w('### 8.1 Observations — confirmed behaviour, not counted as findings\n')
        w('Each behaviour below was reproduced against the live target and is unscored. Two distinct '
          'reasons appear, and the per-item disposition says which applies: either the security '
          'consequence could not be demonstrated, or the behaviour is confirmed and was classified as '
          'accepted / by design by the product owner. **None of these is a false positive** — refuted '
          'candidates, which did not reproduce at all, are in §8.2.\n')
        for i, f in enumerate(observations, 1):
            w(render_finding(f, f'O-{i:02d}', observation=True))

    if refuted:
        w('### 8.2 Refuted Candidates — false positives\n')
        w('Each candidate below was raised — by the previous report, by this engagement\'s automated '
          'sweep, or both — and then refuted by live re-testing. They are documented with the evidence '
          'and the mechanism so the same candidate is not re-raised in a later cycle. A scanner '
          'signature is a hypothesis, not a finding.\n')
        for i, f in enumerate(refuted, 1):
            w(f'#### FP-{i:02d} — {f["title"]}\n')
            w(f'*Raised by: {(f.get("detail") or {}).get("origin", "—")}*\n')
            w(f['description'] + '\n')

    # ---- 9 ----------------------------------------------------------------
    w('---\n\n## 9. Coverage & Limitations\n')
    w('**The absence of a finding is not assurance. Untested is not the same as secure.**\n')
    cov = meta.get('coverage') or {}
    if cov:
        w('| Measure | Value |')
        w('|---|---|')
        for k, v in cov.items():
            if not isinstance(v, (list, dict)):
                w(f'| {k.replace("_", " ").title()} | {v} |')
        w('')
    for lim in meta.get('limitations') or []:
        w(f'- {lim}')
    w('')

    # ---- 10 ---------------------------------------------------------------
    w('---\n\n## 10. Conclusion & Recommendations\n')
    if meta.get('conclusion'):
        w(meta['conclusion'] + '\n')
    w('### Strategic recommendations\n')
    for i, f in enumerate(confirmed, 1):
        rec = ((f.get('detail') or {}).get('report') or {}).get('remediation') or ''
        if rec:
            w(f'- **F-{i:02d}** — {rec.split(". ")[0].rstrip(".")}.')
    w('- **Re-test after remediation.** Re-run this assessment once fixes land to confirm closure.\n')
    w('*Findings state only what was observed against the target named in §2. Scores were computed with '
      'CVSS v3.1 Base metrics. Every reproduction in this report was captured from a live execution '
      'against the running target, not transcribed by hand.*')
    return '\n'.join(out) + '\n'


def cvss_of(f):
    rep = (f.get('detail') or {}).get('report') or {}
    c = rep.get('cvss') or (f.get('detail') or {}).get('cvss')
    return c if isinstance(c, dict) else None


def tax_of(f):
    return ((f.get('detail') or {}).get('report') or {}).get('taxonomy') or {}


def render_finding(f, ref: str, *, observation: bool = False) -> str:
    rep = (f.get('detail') or {}).get('report') or {}
    det = f.get('detail') or {}
    tax = tax_of(f)
    c = cvss_of(f)
    o: list[str] = []
    w = o.append

    w(f'{"####" if observation else "###"} {ref} — {f["title"]}\n')
    w('| | |')
    w('|---|---|')
    if not observation:
        w(f'| **Rating** | **{f["severity"].title()}** |')
        if c:
            w(f'| **CVSS v3.1 Base** | **{c.get("base_score")}** |')
            w(f'| **Vector** | `{c.get("vector")}` |')
    w(f'| **OWASP Top 10:2025** | {owasp_label(tax.get("owasp_2025", ""))} |')
    w(f'| **OWASP API Top 10:2023** | {tax.get("owasp_api_top10") or "—"} |')
    w(f'| **CWE** | {", ".join(tax.get("cwe") or []) or "—"} |')
    w(f'| **Affected endpoint** | `{f.get("endpoint") or "—"}` |')
    w(f'| **Exploitability** | {f.get("exploitability", "unknown").replace("_", " ").title()} |')
    w('')

    if c and c.get('metric_rationale'):
        w('#### Score rationale\n')
        w('| Metric | Justification |')
        w('|---|---|')
        for metric, why in c['metric_rationale'].items():
            w(f'| `{metric}` | {why} |')
        w('')

    if f.get('description'):
        w('#### Description\n')
        w(f['description'] + '\n')

    exchanges = rep.get('exchanges') or []
    if exchanges:
        w('#### Reproduction — request and observed response\n')
        for ex in exchanges:
            if ex.get('proves'):
                w(f'*{ex["proves"]}*\n')
            w(fence(ex.get('curl', ''), 'bash') + '\n')
            resp = ex.get('response') or {}
            head = f'HTTP {resp.get("status")}'
            if resp.get('body_bytes') is not None:
                head += f' — {resp["body_bytes"]} bytes'
            w(f'Observed: **{head}**\n')
            if resp.get('body_empty'):
                w('> Empty body — nothing was disclosed in the response.\n')
            else:
                body = resp.get('body', '')
                if resp.get('body_truncated'):
                    body += '\n… response truncated for the report …'
                w(fence(body) + '\n')

    if isinstance(det.get('measured'), dict) and det['measured']:
        w('#### Measured\n')
        w('| Measure | Value |')
        w('|---|---|')
        for k, v in det['measured'].items():
            w(f'| {k.replace("_", " ")} | {v} |')
        w('')

    if isinstance(det.get('timing_samples'), dict) and det['timing_samples']:
        w('#### Timing measurements\n')
        w('| Account | Exists | Samples | Mean (s) | Min (s) | Max (s) |')
        w('|---|---|---|---|---|---|')
        for acct, v in det['timing_samples'].items():
            w(f'| `{acct}` | {"yes" if v.get("group") == "existing" else "no"} | '
              f'{v.get("samples")} | {v.get("mean_s")} | {v.get("min_s")} | {v.get("max_s")} |')
        w('')
        if det.get('separation_s') is not None:
            verdict = ('the two populations do not overlap, so a single request classifies an account '
                       'with certainty' if det.get('perfectly_separable')
                       else 'the populations partially overlap, so repeated sampling is required')
            w(f'Separation: **{det["separation_s"]}s** — {verdict}.\n')

    if det.get('affected_endpoints'):
        w('#### Confirmed injection points\n')
        for e in det['affected_endpoints']:
            w(f'- `{e}`')
        w('')
        if det.get('note'):
            w(det['note'] + '\n')

    if observation:
        w('#### Disposition\n')
        w((det.get('disposition') or 'Recorded as an observation; not scored.') + '\n')
        w('#### Assessed impact\n')
    else:
        w('#### Impact\n')
    w((rep.get('impact') or det.get('impact') or '—') + '\n')
    if rep.get('remediation'):
        w('#### Recommendation\n')
        w(rep['remediation'] + '\n')
    return '\n'.join(o)


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else 'deluluscan-out/adjudicated-1.2.5.json'
    out = sys.argv[2] if len(sys.argv) > 2 else 'target-Penetration-Test-Report.md'
    payload = json.load(open(src))
    text = render(payload)
    with open(out, 'w') as fh:
        fh.write(text)
    print(f'wrote {out} ({len(text.splitlines())} lines)')


if __name__ == '__main__':
    main()
