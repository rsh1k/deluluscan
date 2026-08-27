"""Request self-repair — the "go the extra step" layer.

When a probe gets an HTTP 4xx, the request itself was rejected (missing param,
empty/invalid body, bad enum, wrong id) and never reached the resource logic. A
naive scanner concludes "same response for everyone => bug"; a real tester (and
stateful fuzzers like RESTler / RestTestGen) instead *reads the error, fixes the
request, and fires again* before drawing any conclusion.

This module inspects a 4xx response + the endpoint's OpenAPI schema and produces
repaired ``RequestSpec`` variants: filling required query/path params, a minimal
valid JSON body, a plausible enum value parsed straight out of the error message,
and real ids harvested from a prior listing. All repairs go back through the
safety-gated Repeater. Nothing here shells out or leaves the authorized target.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .http_tools import RequestSpec, Repeater
from ..verify import evidence as E

# pull hints out of common client-error messages
_ENUM_RE = re.compile(r"no enum constant\s+([\w.$]+)", re.I)
_NEEDS_JSON_RE = re.compile(r"(jsonobject|jsonarray) text must begin|cannot deserialize|"
                            r"must begin with '\{'|invalid json|failed to parse", re.I)
_MISSING_PHRASE_RE = re.compile(r"(missing|required|expected|must (?:provide|supply|include))"
                                r"([^.,;:]*)", re.I)
# words that are never the actual parameter name
_STOPWORDS = {"missing", "required", "expected", "param", "parameter", "parameters",
              "field", "fields", "property", "is", "are", "the", "a", "an", "valid",
              "must", "not", "null", "provide", "supply", "include", "value", "for",
              "one", "of", "and", "or", "please", "you", "your", "this", "request",
              "body", "at", "least", "either", "both"}
_NAME_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,40}")

# reasonable filler values by name/type
_FILLERS = {
    "identifier": "SYSTEM_HOST", "inode": "SYSTEM_HOST", "id": "1",
    "limit": "10", "offset": "0", "page": "1", "languageId": "1",
    "language": "1", "live": "false", "working": "true",
}
_SAMPLE_UUID = "00000000-0000-0000-0000-000000000000"


@dataclass
class RepairResult:
    repaired: bool
    spec: Optional[RequestSpec]
    what: str            # human description of the repair attempted
    reached_resource: bool = False   # did the repaired request stop returning 4xx?
    disposition: str = ""


def _spec_required_params(endpoint) -> list[dict]:
    out = []
    for p in getattr(endpoint, "query_params", []) or []:
        if p.get("required") or p.get("in") == "query":
            out.append(p)
    return out


def suggest_repairs(rec, spec: RequestSpec, endpoint=None) -> list[RepairResult]:
    """Produce candidate repaired specs for a 4xx response (best-effort, ordered)."""
    body = E._body(rec)
    low = body.lower()
    out: list[RepairResult] = []

    # 1) missing required parameter(s) named in the error. Tokenize the phrase
    #    after "missing/required" and drop filler words, so "Missing required
    #    inode/identifier param" yields ['inode', 'identifier'].
    candidates: list[str] = []
    for mm in _MISSING_PHRASE_RE.finditer(body):
        for tok in _NAME_TOKEN_RE.findall(mm.group(2) or ""):
            if tok.lower() not in _STOPWORDS and tok not in candidates:
                candidates.append(tok)
    for name in candidates[:4]:
        val = _FILLERS.get(name, _FILLERS.get(name.lower(), "1"))
        out.append(RepairResult(True, spec.with_param(name, val),
                                f"supplied missing param {name}={val}"))
        if name.lower() in ("inode", "identifier", "id"):
            out.append(RepairResult(True, spec.with_param(name, _SAMPLE_UUID),
                                    f"supplied {name}={_SAMPLE_UUID}"))

    # 2) endpoint declares required query params the request didn't send
    if endpoint is not None:
        for p in _spec_required_params(endpoint):
            nm = p.get("name")
            if nm and nm not in (spec.params or {}):
                val = _FILLERS.get(nm, _FILLERS.get(nm.lower(), "1"))
                out.append(RepairResult(True, spec.with_param(nm, val),
                                        f"supplied spec-required param {nm}={val}"))

    # 3) needs a JSON body
    if _NEEDS_JSON_RE.search(low) or (spec.method.upper() in ("POST", "PUT", "PATCH")
                                      and not spec.json_body and not spec.data):
        c = spec.clone(); c.json_body = {"stInode": _SAMPLE_UUID, "name": "deluluscan"}
        out.append(RepairResult(True, c, "supplied a minimal valid JSON body"))

    # 4) invalid enum — swap the bad path token for the enum's first constant
    em = _ENUM_RE.search(body)
    if em:
        enum_cls = em.group(1)
        # the message is "...SystemAction.1" — the trailing token was the bad value
        bad = enum_cls.rsplit(".", 1)[-1]
        for good in ("NEW", "PUBLISH", "SAVE", "UNPUBLISH", "ARCHIVE"):
            c = spec.clone()
            if bad and bad in c.path:
                c.path = c.path.replace(f"/{bad}", f"/{good}")
                out.append(RepairResult(True, c, f"replaced invalid enum '{bad}' with '{good}'"))
                break
    return out


class RequestRepairer:
    """Fires repaired variants and reports whether any reached the resource."""

    def __init__(self, client, max_attempts: int = 4):
        self.repeater = Repeater(client)
        self.max_attempts = max_attempts

    def repair_and_retry(self, rec, spec: RequestSpec, identity_label: str,
                         endpoint=None) -> RepairResult:
        """Return the first repaired request that stopped returning a 4xx (i.e.
        actually reached the resource), or a not-repaired result."""
        disp = E.classify_response(rec)
        if disp not in (E.DISPOSITION_BAD_REQUEST,):
            return RepairResult(False, None, "no repair needed", False, disp)
        for attempt in suggest_repairs(rec, spec, endpoint)[: self.max_attempts]:
            if not attempt.spec:
                continue
            retry = self.repeater.send(attempt.spec, identity_label=identity_label)
            rdisp = E.classify_response(retry)
            attempt.disposition = rdisp
            attempt.reached_resource = rdisp not in (E.DISPOSITION_BAD_REQUEST,)
            if attempt.reached_resource:
                attempt.what += f" -> reached resource ({rdisp}, HTTP {retry.status})"
                return attempt
        return RepairResult(False, None,
                            "could not repair the request to reach the resource",
                            False, disp)
