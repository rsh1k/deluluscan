"""Evidence anchoring — make the AI cite the traffic, or say it didn't.

An LLM asked to explain a finding will sometimes state a fact the scan never
observed: a status code it did not receive, an endpoint it did not hit, a value
it did not see. In a security report that is worse than useless — a confident,
specific, wrong sentence a reader will act on. The public AI-fuzzing write-ups
that found real bugs at scale all share one guard against this: every AI claim is
tied back to a captured request/response (an "operation id"), so a human can
replay it and a hallucinated claim has nothing to point at.

This module is that guard, generalised. Given a piece of AI text and the finding
it describes, it extracts the *concrete, checkable* claims (HTTP status codes,
paths, identity roles, quoted literal values) and verifies each one actually
appears in the finding's observed evidence — the request/response records, the
endpoint, the detail. Claims that are not backed are reported as UNANCHORED, and
`annotate()` appends an honest "unverified" note rather than letting them stand.

Pure text-vs-evidence: no AI provider, no network. It enforces the house rule —
*the report may only state what the scan observed* — against the one component
that can invent things.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# Identity roles the scanner reasons about; only these are treated as identity
# claims, so ordinary prose ("an administrator would…") is not over-flagged.
_IDENTITY_WORDS = ("anonymous", "backend", "admin", "readonly", "content_editor",
                   "publisher", "api_user", "reader", "author", "frontend_user")

_STATUS = re.compile(r"\b([1-5]\d\d)\b")
_PATH = re.compile(r"(?<![\w])(/[A-Za-z0-9_\-./{}]{2,})")
_QUOTED = re.compile(r"[`\"']([^`\"']{3,60})[`\"']")
# A quoted literal only counts as a checkable claim if it looks like a concrete
# value (has a digit, a separator, or is an ALL-CAPS token) rather than an
# ordinary English word or phrase the model chose to quote for emphasis.
_CONCRETE = re.compile(r"[\d/@_.:=-]")


@dataclass
class AnchorResult:
    anchored: bool                       # every checkable claim is backed by evidence
    coverage: float                      # fraction of claims that are anchored
    claims: list = field(default_factory=list)       # [(kind, value, ok)]
    unanchored: list = field(default_factory=list)   # [(kind, value)]


def evidence_corpus(finding) -> tuple[str, set]:
    """All observed text for a finding, plus the set of identities it touched."""
    parts = [str(getattr(finding, "endpoint", "") or ""),
             str(getattr(finding, "description", "") or ""),
             json.dumps(getattr(finding, "detail", {}) or {}, default=str)]
    idents: set = set()
    for ev in (getattr(finding, "evidence", None) or []):
        idents.add(str(getattr(ev, "identity", "") or "").lower())
        parts.append(str(getattr(ev, "status", "") or ""))
        parts.append(str(getattr(ev, "url", "") or ""))
        parts.append(str(getattr(ev, "method", "") or ""))
        parts.append(json.dumps(getattr(ev, "resp_headers", {}) or {}, default=str))
        parts.append(json.dumps(getattr(ev, "req_headers", {}) or {}, default=str))
        parts.append(str(getattr(ev, "resp_body", "") or "")[:4000])
        parts.append(str(getattr(ev, "req_body", "") or "")[:2000])
    return "\n".join(parts), {i for i in idents if i}


def extract_claims(text: str) -> list[tuple[str, str]]:
    """The concrete, checkable claims in a piece of AI text."""
    text = text or ""
    claims: list[tuple[str, str]] = []
    seen: set = set()

    def add(kind: str, value: str):
        key = (kind, value.lower())
        if value and key not in seen:
            seen.add(key)
            claims.append((kind, value))

    for m in _STATUS.finditer(text):
        # skip durations/percentages that happen to be 3 digits ("200ms", "100%")
        tail = text[m.end():m.end() + 2].lower()
        if tail.startswith("ms") or tail.startswith("%"):
            continue
        add("status", m.group(1))
    for m in _PATH.finditer(text):
        add("path", m.group(1).rstrip(".,);:"))
    low = text.lower()
    for w in _IDENTITY_WORDS:
        if re.search(rf"\b{w}\b", low):
            add("identity", w)
    for m in _QUOTED.finditer(text):
        v = m.group(1).strip()
        if _CONCRETE.search(v) and not v.endswith((".", "!", "?")) and " " not in v.strip("/"):
            add("quoted", v)
    return claims


def _backed(kind: str, value: str, corpus: str, corpus_low: str, idents: set) -> bool:
    if kind == "status":
        return value in corpus                     # exact 3-digit token
    if kind == "identity":
        return value in idents or value in corpus_low
    # path / quoted: substring match, case-insensitive
    return value.lower() in corpus_low


def check_claims(text: str, finding=None, *, corpus: str = "", idents: set = None) -> AnchorResult:
    """Verify every checkable claim in `text` against the finding's evidence."""
    if finding is not None:
        corpus, idents = evidence_corpus(finding)
    idents = idents or set()
    corpus_low = (corpus or "").lower()

    claims = extract_claims(text)
    checked, unanchored = [], []
    for kind, value in claims:
        ok = _backed(kind, value, corpus, corpus_low, idents)
        checked.append((kind, value, ok))
        if not ok:
            unanchored.append((kind, value))
    total = len(checked)
    coverage = 1.0 if total == 0 else (total - len(unanchored)) / total
    return AnchorResult(anchored=not unanchored, coverage=coverage,
                        claims=checked, unanchored=unanchored)


def annotate(text: str, finding=None, *, corpus: str = "", idents: set = None) -> str:
    """Return `text` unchanged when every claim is anchored; otherwise append an
    honest note listing the claims the captured evidence does not back."""
    text = (text or "").strip()
    if not text:
        return text
    res = check_claims(text, finding, corpus=corpus, idents=idents)
    if res.anchored:
        return text
    listed = ", ".join(f"{k}:{v}" for k, v in res.unanchored[:8])
    return (f"{text}\n⚠ unverified: {len(res.unanchored)} claim(s) not backed by "
            f"captured evidence ({listed}). Advisory only — re-check against the "
            f"request/response records.")


def _strip_marker(note: str) -> str:
    """Audit the AI's own statement, not the '⚠ unverified' note annotate() added."""
    return (note or "").split("\n⚠ unverified:", 1)[0]


def anchor_findings(findings) -> list:
    """Batch report-integrity pass: return the findings whose ai_notes make a
    claim the finding's own evidence does not support. Used to audit a finished
    result set (and by the tests)."""
    flagged = []
    for f in findings:
        note = _strip_marker(getattr(f, "ai_notes", "") or "")
        if not note:
            continue
        res = check_claims(note, f)
        if not res.anchored:
            flagged.append((f, res.unanchored))
    return flagged


def audit_ai_integrity(findings) -> dict:
    """Report-level summary of AI-note anchoring across a whole result set — how
    many findings carry an AI note, how many of those notes make a claim the scan
    did not observe, and which. Goes in `meta["ai_integrity"]` so a report reader
    can see the AI's reliability at a glance and never mistakes an unbacked AI
    sentence for a measured fact."""
    audited = 0
    flagged: list = []
    for f in findings:
        note = _strip_marker(getattr(f, "ai_notes", "") or "").strip()
        if not note:
            continue
        audited += 1
        res = check_claims(note, f)
        if not res.anchored:
            flagged.append({
                "title": getattr(f, "title", ""),
                "endpoint": getattr(f, "endpoint", ""),
                "coverage": round(res.coverage, 2),
                "unanchored": [f"{k}:{v}" for k, v in res.unanchored[:8]],
            })
    return {"ai_notes_audited": audited,
            "anchored": audited - len(flagged),
            "unverified": len(flagged),
            "flagged": flagged[:50]}
