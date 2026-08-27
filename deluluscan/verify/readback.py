"""Stored-injection read-back verification.

Why this exists — the sink the surface scan couldn't see
--------------------------------------------------------
A surface stored-XSS check writes a value and looks for it on the ONE response it
gets back. The confirmed the target bug rendered the malicious name safely in the
modern Angular grid (escaped) but executed it in a *different* surface — a legacy
Dojo detail iframe that did ``elem.innerHTML = user.name``. Checking only the
write response, or only the obvious list view, declares "escaped / safe" and
misses the exploitable sink entirely.

So the right primitive is: write once, then read the stored value back through
**every** surface that echoes it — REST JSON, the admin grid, the legacy portlet
frame, exports, search — and classify how it appears in EACH. One raw render in
an authenticated surface is enough to be exploitable; a hundred escaped ones do
not make it safe.

`classify_reflection` distinguishes the outcomes that actually matter — served
raw (live markup) vs HTML-escaped (inert) vs stripped vs absent — and
`detect_concat_reassembly` catches the field-split case where two individually-
harmless fields recombine into live markup at the sink.

Detection-only: this reads values back and inspects text. It never fires a
weaponized payload.
"""
from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

# how a stored value can appear when read back
RAW = "raw"                 # verbatim -> live markup in an HTML sink (dangerous)
HTML_ESCAPED = "html_escaped"   # &lt;.. -> inert
JS_ESCAPED = "js_escaped"       # <.. -> inert in a JS-string context
STRIPPED = "stripped"           # present but the dangerous chars removed
ABSENT = "absent"               # not found at all


def _has_live_markup(text: str, needle: str) -> bool:
    """`needle` appears with its `<`/`>` intact (i.e. as parseable markup), not
    entity-encoded."""
    if needle not in text:
        return False
    # if EVERY occurrence is immediately preceded by an entity-decode of '<',
    # it's escaped; require at least one truly-raw occurrence.
    return ("&lt;" not in text.replace(needle, "", 0)) or needle in text


def classify_reflection(stored_value: str, response_text: str) -> str:
    """How does `stored_value` come back in `response_text`? Worst-case wins."""
    if not response_text:
        return ABSENT
    if stored_value and stored_value in response_text:
        return RAW
    # A server may escape all of &<>"' (quote=True) or just &<> (quote=False,
    # the common "escape the angle brackets" case). Either neutralises the markup.
    for q in (True, False):
        esc_html = html.escape(stored_value, quote=q)
        if esc_html != stored_value and esc_html in response_text:
            return HTML_ESCAPED
    # JS/unicode-escaped form of the angle brackets
    js_esc = stored_value.replace("<", "\\u003c").replace(">", "\\u003e")
    if js_esc != stored_value and js_esc in response_text:
        return JS_ESCAPED
    # a distinctive alnum marker inside the payload survived but the markup didn't
    marker = re.sub(r"[^A-Za-z0-9]", "", stored_value)[:12]
    if marker and marker in re.sub(r"[^A-Za-z0-9]", "", response_text):
        return STRIPPED
    return ABSENT


@dataclass
class SinkResult:
    sink: str                    # human label / URL of the read surface
    status: int
    classification: str
    dangerous: bool              # RAW in a surface that renders HTML
    excerpt: str = ""


@dataclass
class ReadbackReport:
    stored_value: str
    results: list[SinkResult] = field(default_factory=list)

    @property
    def raw_sinks(self) -> list[SinkResult]:
        return [r for r in self.results if r.classification == RAW]

    @property
    def raw_html_sinks(self) -> list[SinkResult]:
        """RAW in a surface a browser renders as HTML — the only place a stored
        value actually EXECUTES. (A JSON API returning raw markup is a precondition,
        not execution: JSON is not an HTML context.)"""
        return [r for r in self.results if r.classification == RAW and r.dangerous]

    @property
    def raw_api_sinks(self) -> list[SinkResult]:
        return [r for r in self.results if r.classification == RAW and not r.dangerous]

    @property
    def worst(self) -> str:
        order = [RAW, STRIPPED, JS_ESCAPED, HTML_ESCAPED, ABSENT]
        seen = {r.classification for r in self.results}
        for c in order:
            if c in seen:
                return c
        return ABSENT

    def verdict(self) -> tuple[str, str]:
        """(stored_render_state, reason). Distinguishes EXECUTION (raw in an HTML
        sink) from the mere PRECONDITION (raw in a JSON API) — conflating the two
        is precisely the "JSON rawness == XSS" error this layer exists to avoid."""
        if self.raw_html_sinks:
            return ("served_raw_html",
                    "stored value rendered as live markup in HTML surface(s): "
                    + ", ".join(r.sink for r in self.raw_html_sinks[:5])
                    + " — executes in a browser")
        if self.raw_api_sinks:
            return ("served_raw_api",
                    "stored value returned RAW by non-HTML (JSON) surface(s): "
                    + ", ".join(r.sink for r in self.raw_api_sinks[:5])
                    + " — a precondition for stored XSS, but NOT execution; an HTML "
                    "render sink must be confirmed (e.g. in a browser)")
        if self.worst == ABSENT:
            return ("not_reflected",
                    "stored value was not echoed by any read-back surface tested")
        return ("neutralised",
                f"stored value is echoed but escaped/stripped everywhere tested "
                f"(worst: {self.worst})")


def readback_across_sinks(stored_value: str,
                          sinks: list[tuple[str, str]],
                          fetch: Callable[[str], tuple[int, str]],
                          html_sinks: Optional[set[str]] = None) -> ReadbackReport:
    """Read `stored_value` back from every sink and classify it.

    `sinks` is [(label, path), ...]; `fetch(path) -> (status, body)` is injected
    so this is transport-agnostic and unit-testable. `html_sinks` names the labels
    whose body is rendered as HTML by a browser (so RAW there = executable); for
    a pure-JSON API, RAW is a precondition but not itself execution.
    """
    html_sinks = html_sinks if html_sinks is not None else {s[0] for s in sinks}
    report = ReadbackReport(stored_value=stored_value)
    for label, path in sinks:
        try:
            status, body = fetch(path)
        except Exception as exc:
            report.results.append(SinkResult(label, 0, ABSENT, False, f"error: {exc}"[:120]))
            continue
        cls = classify_reflection(stored_value, body or "")
        dangerous = (cls == RAW) and (label in html_sinks)
        excerpt = ""
        if stored_value and (body or ""):
            i = body.find(stored_value[:20])
            if i >= 0:
                excerpt = body[max(0, i - 20):i + len(stored_value[:20]) + 20]
        report.results.append(SinkResult(label, status, cls, dangerous, excerpt[:160]))
    return report


def detect_concat_reassembly(fragments: list[str], separator: str,
                             response_text: str) -> bool:
    """Field-split case: individually-harmless fragments recombine into live markup.
    True if the reassembled `separator.join(fragments)` appears RAW in the sink,
    even though no single fragment would look dangerous on its own."""
    reassembled = separator.join(fragments)
    return classify_reflection(reassembled, response_text or "") == RAW
