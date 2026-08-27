"""Session-handling engine — Burp session-handling-rules / Stepper parity.

Two building blocks that make multi-step and authenticated testing automatic:

* ``MatchReplaceRule`` — regex match-and-replace applied to any part of an
  outgoing request (path, a header, or the body). Burp's "match and replace".
* ``Macro`` — an ordered sequence of requests with *extraction rules* that pull
  values out of responses (JSON key or regex) into a shared context, so a later
  request can reuse them (e.g. log in, extract the token/CSRF, inject it into
  every subsequent request). This is how the tool auto-refreshes a session.

``SessionEngine`` ties them together: ``substitute`` expands ``{{var}}`` tokens
from the context and applies match/replace rules; ``run_macro`` executes a macro
to (re)populate the context. Everything operates on ``RequestSpec`` and sends
through the safety-gated ``Repeater``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .http_tools import RequestSpec, Repeater

_VAR = re.compile(r"\{\{(\w+)\}\}")


@dataclass
class MatchReplaceRule:
    location: str        # "path" | "header:<Name>" | "body" | "any"
    pattern: str
    replacement: str
    name: str = ""

    def apply(self, spec: RequestSpec, context: Optional[dict] = None) -> RequestSpec:
        repl = _expand(self.replacement, context or {})
        c = spec.clone()
        if self.location == "path":
            c.path = re.sub(self.pattern, repl, c.path)
        elif self.location == "body":
            if c.data is not None:
                c.data = re.sub(self.pattern, repl, c.data)
            elif c.json_body is not None:
                c.json_body = json.loads(re.sub(self.pattern, repl,
                                                json.dumps(c.json_body)))
        elif self.location.startswith("header:"):
            hname = self.location.split(":", 1)[1]
            for k in list(c.headers):
                if k.lower() == hname.lower():
                    c.headers[k] = re.sub(self.pattern, repl, c.headers[k])
        elif self.location == "any":
            c.path = re.sub(self.pattern, repl, c.path)
            if c.data is not None:
                c.data = re.sub(self.pattern, repl, c.data)
        return c


@dataclass
class Extraction:
    name: str
    source: str          # "body_json" | "body_regex" | "header"
    selector: str        # json key (dotted) | regex with 1 group | header name


def _dig(obj: Any, dotted: str) -> Optional[str]:
    node = obj
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return None if isinstance(node, (dict, list)) else str(node)


def _extract(rec, ex: Extraction) -> Optional[str]:
    if ex.source == "body_json":
        try:
            return _dig(json.loads(rec.resp_body), ex.selector)
        except Exception:
            return None
    if ex.source == "body_regex":
        m = re.search(ex.selector, rec.resp_body or "")
        return m.group(1) if m else None
    if ex.source == "header":
        for k, v in (rec.resp_headers or {}).items():
            if k.lower() == ex.selector.lower():
                return v
    return None


@dataclass
class Macro:
    name: str
    steps: list[RequestSpec] = field(default_factory=list)
    extractions: list[Extraction] = field(default_factory=list)

    def run(self, repeater: Repeater, context: Optional[dict] = None,
            identity_label: str = "anonymous") -> dict:
        context = dict(context or {})
        for spec in self.steps:
            prepared = _substitute_spec(spec, context)
            rec = repeater.send(prepared, identity_label=identity_label)
            for ex in self.extractions:
                val = _extract(rec, ex)
                if val is not None:
                    context[ex.name] = val
        return context


def _expand(text: Optional[str], context: dict) -> Optional[str]:
    if not text:
        return text
    return _VAR.sub(lambda m: str(context.get(m.group(1), m.group(0))), text)


def _substitute_spec(spec: RequestSpec, context: dict) -> RequestSpec:
    c = spec.clone()
    c.path = _expand(c.path, context)
    c.headers = {k: _expand(v, context) for k, v in c.headers.items()}
    if c.data is not None:
        c.data = _expand(c.data, context)
    if isinstance(c.json_body, (dict, list)):
        c.json_body = json.loads(_expand(json.dumps(c.json_body), context))
    return c


class SessionEngine:
    def __init__(self, rules: Optional[list[MatchReplaceRule]] = None,
                 macros: Optional[dict[str, Macro]] = None):
        self.rules = rules or []
        self.macros = macros or {}
        self.context: dict[str, Any] = {}

    def substitute(self, spec: RequestSpec) -> RequestSpec:
        out = _substitute_spec(spec, self.context)
        for rule in self.rules:
            out = rule.apply(out, self.context)
        return out

    def run_macro(self, name: str, repeater: Repeater,
                  identity_label: str = "anonymous") -> dict:
        macro = self.macros.get(name)
        if not macro:
            return self.context
        self.context = macro.run(repeater, self.context, identity_label)
        return self.context
