"""deluluscan.reporting — derive a pentest-report block from captured evidence.

Design rule: **prose is a view over evidence, never a source of truth.**

Every field produced here is computed from the RequestRecords a scanner
actually captured while probing the target. Nothing is hand-authored per
finding, so the report cannot drift from what was really tested, and it
regenerates identically on the next scan.

The emitted block is what the dashboard renders:

    objective     - what this test set out to determine
    location      - endpoint + source code references
    method        - how it was tested (derived from vuln class + identities used)
    steps         - ordered, human-readable test procedure
    reproduction  - runnable curl commands rebuilt from the real requests
    outcome       - what was observed, stated in terms of the evidence
    impact        - consequence if exploited
    remediation   - the fix
    references    - CWE / OWASP / advisory ids
"""
from __future__ import annotations

import json
import shlex
from typing import Any, Iterable, Optional

from ..models import Finding, RequestRecord

# Headers we never reproduce verbatim in a shareable command: they either carry
# a secret or are set automatically by curl / the HTTP stack.
_SKIP_HEADERS = {
    "authorization", "cookie", "set-cookie", "x-csrf-token", "content-length",
    "host", "connection", "accept-encoding", "user-agent",
}

# How each identity authenticates in a reproduction command. Credentials are
# NEVER inlined — they are referenced from the config so the command is safe to
# paste into a ticket.
_IDENTITY_HINT = {
    "anonymous": "# (no credentials — anonymous request)",
    "admin": '-u "$DELULUSCAN_ADMIN"        # admin identity from config.yaml',
}


def _auth_flag(identity: str) -> str:
    if identity in _IDENTITY_HINT:
        return _IDENTITY_HINT[identity]
    return f'-u "$DELULUSCAN_{identity.upper()}"   # {identity} identity from config.yaml'


def curl_for(rec: RequestRecord, *, base_url: str | None = None,
             role: str = "") -> str:
    """Rebuild a runnable curl command from a real captured exchange.

    Secrets are referenced, not embedded. The command reproduces the request
    that produced the evidence, so a reviewer can re-run it verbatim.

    `role` labels what the exchange PROVES ("THE VIOLATION" vs "baseline"). A
    reader who copies an unlabelled baseline request sees the expected 401 and
    reasonably concludes the finding is bogus — so every command states both the
    identity and the status that was observed.
    """
    parts: list[str] = ["curl -s -i"]
    if rec.method and rec.method.upper() != "GET":
        parts.append(f"-X {rec.method.upper()}")

    auth = _auth_flag(rec.identity or "anonymous")
    inline_auth = "" if auth.startswith("#") else auth.split("#")[0].strip()
    if inline_auth:
        parts.append(inline_auth)

    for k, v in (rec.req_headers or {}).items():
        if k.lower() in _SKIP_HEADERS:
            continue
        parts.append(f"-H {shlex.quote(f'{k}: {v}')}")

    if rec.req_body:
        body = rec.req_body
        try:                                  # compact JSON for a tidy one-liner
            body = json.dumps(json.loads(body), separators=(",", ":"))
        except (ValueError, TypeError):
            pass
        parts.append(f"-d {shlex.quote(body)}")

    url = rec.url or ""
    if base_url and url.startswith(base_url):
        url = url  # keep absolute; explicit is better in a report
    parts.append(shlex.quote(url))

    cmd = " ".join(parts)
    comment = auth if auth.startswith("#") else ""
    lead = f"# as {rec.identity or 'anonymous'}"
    if role:
        lead += f"  <<< {role}"
    if comment:
        lead += f"  {comment.lstrip('# ')}"
    if rec.status:
        lead += f"\n# observed: HTTP {rec.status}"
    return f"{lead}\n{cmd}"


# Headers worth showing in a report response: enough to judge the finding
# (what was served, how much, whether it was cacheable) without a wall of noise.
_SHOW_RESP_HEADERS = {
    "content-type", "content-length", "location", "www-authenticate",
    "set-cookie", "cache-control", "x-frame-options",
    "content-security-policy", "access-control-allow-origin",
}
_MAX_BODY_CHARS = 1200


def response_for(rec: RequestRecord) -> dict[str, Any]:
    """The observed response for one exchange, shaped for a report.

    A curl command on its own asserts nothing — the reader has to see what came
    back to judge whether a 500 leaked anything or was an empty failure. The
    body is truncated (with the elision made explicit, never silently) because
    an untruncated 900KB spec would bury the finding it is evidence for.
    """
    body = rec.resp_body if isinstance(rec.resp_body, str) else (
        "" if rec.resp_body is None else str(rec.resp_body))
    full_len = rec.resp_len if rec.resp_len is not None else len(body)
    truncated = len(body) > _MAX_BODY_CHARS
    shown = body[:_MAX_BODY_CHARS]

    headers = {k: v for k, v in (rec.resp_headers or {}).items()
               if k.lower() in _SHOW_RESP_HEADERS}

    return {
        "status": rec.status,
        "identity": rec.identity or "anonymous",
        "headers": headers,
        "body": shown,
        "body_bytes": full_len,
        "body_truncated": truncated,
        "body_empty": full_len == 0,
        "elapsed_ms": rec.elapsed_ms,
        "error": rec.error or "",
    }


def exchange_for(rec: RequestRecord, *, base_url: str | None = None,
                 role: str = "") -> dict[str, Any]:
    """One captured exchange as {request curl, observed response, what it proves}."""
    return {
        "curl": curl_for(rec, base_url=base_url, role=role),
        "response": response_for(rec),
        "proves": role,
    }


def _role_for(rec: RequestRecord, violator: str | None) -> str:
    """What this captured exchange proves, for the reader."""
    st = rec.status or 0
    if violator and rec.identity == violator:
        return "THE VIOLATION: this identity should NOT be served"
    if st in (401, 403):
        return "expected baseline: correctly denied (proves auth IS enforced)"
    if rec.identity == "admin":
        return "entitled baseline: admin is allowed here"
    if 200 <= st < 300:
        return "served"
    return "baseline"


def _prereq_block(by_id: dict[str, int]) -> str:
    """Shell prerequisites so the reproduction commands run as-is.

    The commands reference credentials via $DELULUSCAN_<IDENTITY> rather than inlining
    them (so the report is safe to share). Without this block a reader hits an
    interactive password prompt and cannot reproduce anything.
    """
    if not by_id:
        return ""
    names = sorted({i for i in by_id if i and i != "anonymous"})
    if not names:
        return ""
    lines = ["# Prerequisites — export the test credentials from your config.",
             "# Credentials are referenced, never embedded in this report.",
             "# Generate every export from the scan config:",
             "#   eval \"$(python3 -c \"import yaml;c=yaml.safe_load(open('config.dev.yaml'));"
             "[print(f'export DELULUSCAN_{l.upper()}=\\\"{v[\\\"username\\\"]}:{v[\\\"password\\\"]}\\\"') "
             "for l,v in c['identities'].items() if v and v.get('username')]\")\"",
             "# Identities used by this finding:"]
    lines += [f"#   DELULUSCAN_{n.upper()}" for n in names]
    return "\n".join(lines)


def _status_by_identity(evidence: Iterable[RequestRecord]) -> dict[str, int]:
    """Last observed status per identity (ordered by first appearance)."""
    out: dict[str, int] = {}
    for e in evidence:
        if e.identity:
            out[e.identity] = e.status
    return out


def _describe_differential(by_id: dict[str, int]) -> str:
    """State the access-control observation in plain terms."""
    if not by_id:
        return ""
    if len(by_id) == 1:
        (ident, st), = by_id.items()
        return f"Tested as {ident} only (HTTP {st})."
    pairs = ", ".join(f"{i} -> HTTP {s}" for i, s in by_id.items())
    if len(set(by_id.values())) == 1:
        return (f"All identities received the same response ({pairs}) — access "
                f"control is consistent across privilege levels for this operation.")
    allowed = [i for i, s in by_id.items() if 200 <= s < 300]
    denied = [i for i, s in by_id.items() if s in (401, 403)]
    msg = f"Responses differ by identity: {pairs}."
    if allowed and denied:
        msg += (f" {', '.join(denied)} {'is' if len(denied) == 1 else 'are'} denied while "
                f"{', '.join(allowed)} {'is' if len(allowed) == 1 else 'are'} served — "
                f"the operation is gated, but not at the privilege level it should be.")
    return msg


# What each vuln class is actually testing for, and how.
_OBJECTIVE = {
    "authz": "Determine whether {ep} enforces authorization at the correct privilege "
             "level, or merely authenticates the caller.",
    "idor":  "Determine whether {ep} performs per-object authorization, or returns an "
             "object to any authenticated caller who names its identifier.",
    "bopla": "Determine whether {ep} exposes or accepts object properties beyond those "
             "the caller is entitled to read or write.",
    "sqli":  "Determine whether input to {ep} is concatenated into a SQL statement "
             "rather than parameterised.",
    "ssti":  "Determine whether {ep} evaluates template expressions supplied in the request.",
    "xss":   "Determine whether input to {ep} is reflected into a response without "
             "contextual output encoding.",
    "ssrf":  "Determine whether {ep} can be induced to issue server-side requests to an "
             "attacker-chosen destination.",
    "crypto": "Determine whether {ep} relies on weak, predictable, or hard-coded "
              "cryptographic material.",
    "rate_limit": "Determine whether {ep} restricts the rate or volume of requests.",
    "info_leak": "Determine whether {ep} discloses server internals or data beyond what "
                 "the caller is entitled to see.",
    "misconfig": "Determine whether {ep} is deployed with an insecure configuration.",
    "business_logic": "Determine whether the business flow behind {ep} can be abused or "
                      "bypassed out of its intended sequence.",
}

_METHOD = {
    "authz": "Differential authorization testing — the same request is replayed as each "
             "configured identity ({ids}) and the responses compared. A low-privilege "
             "identity that is served where only a higher tier should be indicates "
             "broken function-level authorization.",
    "idor":  "Object-level authorization testing — an object belonging to another "
             "principal is requested using a lower-privileged identity ({ids}); a "
             "successful read or write indicates missing per-object authorization.",
    "sqli":  "Differential injection testing — a benign value and a payload that is "
             "inert unless concatenated into SQL are each submitted, and the responses "
             "and database error behaviour compared.",
    "ssti":  "Template-expression probing — an arithmetic expression is submitted and the "
             "response inspected for server-side evaluation.",
    "xss":   "Reflection testing — a unique canary is submitted and the response "
             "inspected for unencoded reflection in an executable context.",
    "ssrf":  "Server-side request probing — a callback/loopback destination is supplied "
             "and outbound behaviour observed.",
}

_DEFAULT_METHOD = ("Differential probing across the configured identities ({ids}); "
                   "requests and responses were captured as evidence.")


def _steps(finding: Finding, by_id: dict[str, int]) -> list[str]:
    """The ordered procedure actually carried out, reconstructed from evidence."""
    ep = finding.endpoint or "the endpoint"
    steps: list[str] = []
    if by_id:
        for ident, st in by_id.items():
            steps.append(f"Issue {ep} as the {ident} identity — observed HTTP {st}.")
    else:
        steps.append(f"Issue {ep} and record the response.")
    steps.append("Compare the responses across identities and against the expected "
                 "privilege level for this operation.")
    det = finding.detail or {}
    if det.get("param"):
        steps.insert(0, f"Target the '{det['param']}' parameter, which reaches the "
                        f"vulnerable sink.")
    if det.get("payload"):
        steps.insert(1, f"Submit the probe value: {det['payload']!r}.")
    return steps


def _outcome(finding: Finding, by_id: dict[str, int]) -> str:
    """What was observed — phrased from evidence, qualified by verdict."""
    diff = _describe_differential(by_id)
    verdict = (finding.verdict or "unverified").replace("_", " ")
    lead = {
        "true_positive": "CONFIRMED.",
        "likely_true_positive": "LIKELY CONFIRMED.",
        "false_positive": "NOT REPRODUCED.",
        "likely_false_positive": "LIKELY NOT REPRODUCED.",
        "inconclusive": "INCONCLUSIVE.",
        "not_tested": "NOT TESTED.",
    }.get(finding.verdict, f"Verdict: {verdict}.")
    body = diff or finding.description or ""
    vdet = (finding.detail or {}).get("verification", {}) or {}
    reasons = vdet.get("reasons") or []
    if reasons:
        body = f"{body} {reasons[0]}".strip()
    return f"{lead} {body}".strip()


def build_report(finding: Finding, *, code_paths: Optional[list[str]] = None,
                 impact: str = "", remediation: str = "",
                 references: Optional[list[str]] = None,
                 base_url: str | None = None) -> dict[str, Any]:
    """Derive the full structured report block for one finding, from its evidence."""
    vc = getattr(finding.vuln_class, "value", finding.vuln_class) or ""
    ep = finding.endpoint or ""
    ev = list(finding.evidence or [])
    by_id = _status_by_identity(ev)
    ids = ", ".join(by_id) or "the configured identities"

    objective = _OBJECTIVE.get(vc, "Assess {ep} for " + (vc or "security") +
                               " weaknesses.").format(ep=ep or "this endpoint")
    method = _METHOD.get(vc, _DEFAULT_METHOD).format(ids=ids)

    # Standing methodology for this class (deluluscan/knowledge.py): fills the
    # verification steps, class-level remediation, and taxonomy references so
    # every finding carries consistent, current guidance instead of a blank.
    from .. import knowledge as _kb
    km = _kb.methodology_for(vc)
    kb_refs = []
    if km:
        kb_refs = ([f"OWASP {km.owasp_2025}"] if km.owasp_2025 else []) \
            + ([f"OWASP-API {km.api_top10}"] if km.api_top10 else []) \
            + list(km.cwe) + list(km.references)

    # Reproduction: rebuilt from the real exchanges, each labelled with what it
    # proves. The violating request is called out explicitly so a reader cannot
    # mistake a baseline 401 for a refutation of the finding.
    violator = (finding.detail or {}).get("violating_identity")
    # Explicit per-exchange labels, when the analyst supplied them. Labelling by
    # identity alone is wrong whenever one identity sends BOTH the violating
    # request and its control — the control then renders as a second violation,
    # which overstates the finding. An explicit list wins over the heuristic.
    labels = (finding.detail or {}).get("evidence_labels") or []

    def label_for(idx: int, rec: RequestRecord) -> str:
        if idx < len(labels) and labels[idx]:
            return str(labels[idx])
        return _role_for(rec, violator)

    prereq = _prereq_block(by_id)
    repro = ([prereq] if prereq else []) + [
        curl_for(r, base_url=base_url, role=label_for(i, r))
        for i, r in enumerate(ev[:4])
    ]
    # The same exchanges, but each curl paired with the response it actually
    # produced. A reproduction step without its response cannot be adjudicated:
    # "HTTP 500" and "HTTP 500 with an empty body" are different findings.
    exchanges = [
        exchange_for(r, base_url=base_url, role=label_for(i, r))
        for i, r in enumerate(ev[:4])
    ]

    # Explicit taxonomy, so the report states the category rather than burying
    # it in a references list.
    taxonomy = {
        "owasp_2025": (km.owasp_2025 if km else ""),
        "owasp_api_top10": (km.api_top10 if km else ""),
        "cwe": (list(km.cwe) if km else []),
    }

    # Audit-framework controls implicated by this class. Advisory: whether a
    # control is actually failed depends on scope and compensating controls,
    # which a scan does not observe — so each entry carries its basis and the
    # mapping is per class, never invented per finding.
    from .. import compliance as _cm
    compliance_block = _cm.mapping_for_report(vc)

    # CVSS is only asserted when an adjudicator supplied the impact judgement
    # (see deluluscan.cvss.derive). An auto-invented score would be exactly the kind
    # of unearned assertion this report format exists to prevent.
    cvss = (finding.detail or {}).get("cvss") or None

    return {
        "objective": objective,
        "location": {"endpoint": ep, "code_paths": code_paths or []},
        "method": method,
        "steps": _steps(finding, by_id),
        "reproduction": repro,
        "exchanges": exchanges,
        "taxonomy": taxonomy,
        "compliance": compliance_block,
        "cvss": cvss,
        "outcome": _outcome(finding, by_id),
        "impact": impact or (finding.detail or {}).get("impact", ""),
        "remediation": (remediation or (finding.detail or {}).get("remediation", "")
                        or (km.remediation if km else "")),
        # How to independently VERIFY this class — the deep-verification discipline
        # (a reflection is a lead, not proof), pulled from the knowledge base.
        "verify_steps": (finding.detail or {}).get("verify_steps")
                        or (list(km.verify) if km else []),
        "references": (references or []) + [r for r in kb_refs if r not in (references or [])],
        "observed": {"status_by_identity": by_id,
                     "requests_captured": len(ev)},
        "generated": "derived-from-evidence",
    }


def attach_reports(findings: Iterable[Finding], *, base_url: str | None = None) -> None:
    """Attach a derived report block to each finding's detail, in place."""
    for f in findings:
        det = f.detail if isinstance(f.detail, dict) else {}
        det["report"] = build_report(
            f,
            code_paths=det.get("code_paths") or [],
            impact=det.get("impact", ""),
            remediation=det.get("remediation", ""),
            references=[r for r in [det.get("cwe"), det.get("owasp")] if r],
            base_url=base_url,
        )
        f.detail = det
