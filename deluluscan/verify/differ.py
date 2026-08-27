"""Baseline-vs-PoC response differ — Burp Comparer parity + the core of
adversarial validation.

The key question a validator must answer is not "did my payload appear in the
response?" (payload presence proves nothing — it may be escaped, in a WAF block
page, or in a non-rendered JSON field) but "does the PoC response differ from an
innocuous baseline in an *exploitable* way?" This module captures a structured
diff between two responses so per-class validators can reason about it.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ResponseDiff:
    status_changed: bool
    baseline_status: int
    poc_status: int
    length_delta: int
    length_ratio: float                 # poc_len / baseline_len
    marker_reflected: bool              # did our unique PoC marker appear?
    marker_context: str                 # "html" | "attribute" | "script" | "json" | "text" | "none"
    new_error_signature: bool           # PoC introduced a DB/stack error not in baseline
    timing_delta_ms: float
    added_snippet: str = ""             # short sample of what changed
    notes: list[str] = field(default_factory=list)

    def exploitable_signal(self) -> bool:
        """Does the diff show a *behavioral* change (not mere reflection)?"""
        return (self.status_changed or self.new_error_signature
                or abs(self.length_delta) > 64
                or self.timing_delta_ms > 1000
                or (self.marker_reflected and self.marker_context in
                    ("html", "attribute", "script")))


_DB_ERROR_RE = re.compile(
    r"sql syntax|sqlexception|ora-\d{5}|psql:|mysql_fetch|syntax error at or near|"
    r"unclosed quotation|odbc|jdbc|sqlite3\.|pg::|near \"", re.I)
_STACK_RE = re.compile(r"traceback \(most recent call|\.java:\d+\)|at [\w.$]+\(|"
                       r"nullpointerexception|stacktrace", re.I)


def _body(rec) -> str:
    return getattr(rec, "resp_body", "") or ""


def marker_context(body: str, marker: str) -> str:
    """Where does the marker land? Determines XSS exploitability far better than
    mere presence (OWASP/PortSwigger context analysis)."""
    if not marker or marker not in body:
        return "none"
    idx = body.find(marker)
    window = body[max(0, idx - 80): idx + len(marker) + 20]
    low = window.lower()
    # inside a <script> block
    if "<script" in body[max(0, idx - 400):idx].lower() and "</script" not in body[max(0, idx-400):idx].lower():
        return "script"
    # inside an HTML tag attribute (quote before marker, within a tag)
    if re.search(r"<[^>]*=$|=\"[^\"]*$|='[^']*$", body[max(0, idx - 120):idx]):
        return "attribute"
    # between tags as HTML text
    if "<" in window and ">" in window:
        return "html"
    if window.strip().startswith(("{", "[")) or '":' in window or '"}' in window:
        return "json"
    return "text"


def diff_responses(baseline, poc, marker: str = "") -> ResponseDiff:
    b_body, p_body = _body(baseline), _body(poc)
    b_status = getattr(baseline, "status", 0)
    p_status = getattr(poc, "status", 0)
    b_len = getattr(baseline, "resp_len", len(b_body))
    p_len = getattr(poc, "resp_len", len(p_body))
    b_ms = getattr(baseline, "elapsed_ms", 0.0) or 0.0
    p_ms = getattr(poc, "elapsed_ms", 0.0) or 0.0

    reflected = bool(marker) and marker in p_body
    ctx = marker_context(p_body, marker) if reflected else "none"
    new_error = bool((_DB_ERROR_RE.search(p_body) or _STACK_RE.search(p_body))
                     and not (_DB_ERROR_RE.search(b_body) or _STACK_RE.search(b_body)))

    added = ""
    if b_body != p_body:
        sm = difflib.SequenceMatcher(None, b_body[:4000], p_body[:4000])
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ("insert", "replace"):
                added = p_body[j1:j2][:160]
                if added.strip():
                    break

    d = ResponseDiff(
        status_changed=(b_status != p_status),
        baseline_status=b_status, poc_status=p_status,
        length_delta=(p_len - b_len),
        length_ratio=(p_len / b_len if b_len else 0.0),
        marker_reflected=reflected, marker_context=ctx,
        new_error_signature=new_error,
        timing_delta_ms=(p_ms - b_ms), added_snippet=added)
    if new_error:
        d.notes.append("PoC introduced a DB/stack error absent from baseline")
    if reflected and ctx in ("html", "attribute", "script"):
        d.notes.append(f"marker reflected in {ctx} context (executable)")
    elif reflected:
        d.notes.append(f"marker reflected but in {ctx} context (not directly executable)")
    return d
