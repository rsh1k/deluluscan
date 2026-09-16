"""Parse a Rules-of-Engagement document into an RoEPolicy.

Primary format is structured YAML/JSON (explicit, unambiguous). A tolerant
text/markdown fallback recognises the common headings a written RoE uses
("In scope:", "Out of scope:", "Do not test:", "Testing window:", "Rate limit:")
so an analyst can point at their existing doc. Best-effort — the structured form
is authoritative.
"""
from __future__ import annotations

import json
import re

from .policy import RoEPolicy

_HEADINGS = {
    "in_scope": r"(in[\s_-]?scope|targets?|authoriz(?:ed|ation)|scope)",
    "out_of_scope": r"(out[\s_-]?of[\s_-]?scope|exclud(?:ed|e)|do[\s_-]?not[\s_-]?(?:test|scan|touch)|off[\s_-]?limits)",
    "excluded_tests": r"(prohibited[\s_-]?tests?|excluded[\s_-]?tests?|do[\s_-]?not[\s_-]?run|forbidden)",
}
_HOSTISH = re.compile(r"^[\w.*-]+(?:/\d{1,3})?$")
_WINDOW = re.compile(r"(\d{1,2}:\d{2})\s*(?:-|to|–|—)\s*(\d{1,2}:\d{2})")
_RATE = re.compile(r"(\d+(?:\.\d+)?)\s*(?:req(?:uest)?s?\s*/?\s*(?:per\s*)?s(?:ec(?:ond)?)?|rps)", re.I)


def _from_structured(data: dict) -> RoEPolicy:
    def _list(k, *alts):
        for key in (k, *alts):
            v = data.get(key)
            if isinstance(v, list):
                return [str(x).strip() for x in v if str(x).strip()]
            if isinstance(v, str) and v.strip():
                return [s.strip() for s in re.split(r"[,\n]", v) if s.strip()]
        return []
    win = data.get("window") or data.get("testing_window") or {}
    if isinstance(win, list) and len(win) == 2:
        ws, we = win
    elif isinstance(win, dict):
        ws, we = win.get("start"), win.get("end")
    else:
        ws = we = None
    return RoEPolicy(
        in_scope=_list("in_scope", "scope", "targets", "in-scope"),
        out_of_scope=_list("out_of_scope", "exclude", "exclusions", "out-of-scope"),
        excluded_tests={s.lower() for s in _list("excluded_tests", "prohibited_tests", "excluded-tests")},
        window_start=ws, window_end=we,
        max_requests=data.get("max_requests"),
        rate_limit_rps=data.get("rate_limit_rps") or data.get("rate_limit"),
        allow_destructive=bool(data.get("allow_destructive", False)),
        allow_remote=bool(data.get("allow_remote", False)),
        notes=str(data.get("notes", "")))


def _from_text(text: str) -> RoEPolicy:
    p = RoEPolicy()
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower().rstrip(":").strip()
        matched = None
        for key, pat in _HEADINGS.items():
            if re.fullmatch(rf"#*\s*{pat}", low) or re.match(rf"#*\s*{pat}\s*:", line.lower()):
                matched = key
                break
        if matched:
            section = matched
            # allow "In scope: a, b" on one line
            after = line.split(":", 1)[1].strip() if ":" in line else ""
            if after:
                _absorb(p, section, after)
            continue
        m = _WINDOW.search(line)
        if m and ("window" in low or "time" in low):
            p.window_start, p.window_end = m.group(1), m.group(2)
            continue                                   # directive line — do not absorb
        r = _RATE.search(line)
        if r and ("rate" in low or "limit" in low or "throttle" in low):
            p.rate_limit_rps = float(r.group(1))
            continue
        if section:
            # strip only a leading list marker ("- ", "* ", "1. ", "1) ") — NOT
            # leading digits/dots, which are part of an IP/CIDR (10.0.0.0/24).
            item = re.sub(r"^\s*(?:[-*•]\s+|\d+[.)]\s+)", "", line).strip()
            _absorb(p, section, item)
    return p


def _hostlike(tok: str) -> bool:
    """A scope entry must be a domain/CIDR/IP/wildcard — not a bare word."""
    return bool(_HOSTISH.match(tok)) and ("." in tok or "/" in tok or tok.startswith("*."))


def _absorb(p: RoEPolicy, section: str, text: str):
    for tok in re.split(r"[,\s]+", text):
        tok = tok.strip().strip(".,;:")
        if not tok:
            continue
        if _hostlike(tok):
            (p.in_scope if section == "in_scope" else p.out_of_scope).append(tok)
        elif section in ("excluded_tests", "out_of_scope"):
            # a bare word under an exclusion section is a prohibited TEST type
            # ("Do not test: sqli"), not a host.
            p.excluded_tests.add(tok.lower())


def parse_roe(text_or_data, fmt: str = "auto") -> RoEPolicy:
    if isinstance(text_or_data, dict):
        return _from_structured(text_or_data)
    text = text_or_data or ""
    if fmt in ("json", "auto"):
        try:
            return _from_structured(json.loads(text))
        except Exception:
            pass
    if fmt in ("yaml", "auto"):
        try:
            import yaml
            data = yaml.safe_load(text)
            if isinstance(data, dict) and any(k in data for k in
                    ("in_scope", "scope", "targets", "out_of_scope", "exclude")):
                return _from_structured(data)
        except Exception:
            pass
    return _from_text(text)


def load_roe(path: str) -> RoEPolicy:
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    fmt = "yaml" if path.lower().endswith((".yaml", ".yml")) else \
          "json" if path.lower().endswith(".json") else "auto"
    return parse_roe(text, fmt)
