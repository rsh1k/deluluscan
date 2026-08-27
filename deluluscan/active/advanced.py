"""Advanced analyzers (v0.6): HTTP verb/method tampering, bounded race-condition
testing, and deeper GraphQL abuse (batching, alias amplification, depth limits).

All authorized-target only. The race prober is intentionally bounded (a small
number of parallel requests to reveal a TOCTOU window) and is gated behind
allow_state_changing because it may cause an action to execute more than once on
your own test instance — it confirms the flaw by exercising it, nothing more.
"""
from __future__ import annotations

import concurrent.futures
import json
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..verify import evidence as E


# ===========================================================================
# HTTP verb / method tampering — function-level authz bypass (API5 / A01)
# ===========================================================================
_ALT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]
_OVERRIDE_HEADERS = ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"]


@dataclass
class VerbFinding:
    technique: str      # "alt_method" | "method_override"
    method: str
    detail: str
    status: int


class VerbTamper:
    """Given a canonical method that is DENIED, try alternate methods and
    method-override headers; flag any that are granted (auth enforced on the
    verb, not the resource)."""

    def __init__(self, send: Callable):
        # send(method, extra_headers) -> record
        self.send = send

    @staticmethod
    def _granted(rec) -> bool:
        # real content returned (not empty/denied/permission-message)
        return E.classify_response(rec) == E.DISPOSITION_CONTENT

    def test(self, canonical_method: str) -> list[VerbFinding]:
        out: list[VerbFinding] = []
        base = self.send(canonical_method, None)
        if self._granted(base):
            return out  # canonical already works; nothing to bypass
        for m in _ALT_METHODS:
            if m == canonical_method.upper():
                continue
            rec = self.send(m, None)
            if self._granted(rec):
                out.append(VerbFinding("alt_method", m,
                    f"'{m}' reached the resource that '{canonical_method}' denied "
                    f"— access control is enforced on the verb, not the object", rec.status))
                break
        for h in _OVERRIDE_HEADERS:
            rec = self.send("POST", {h: canonical_method})
            if self._granted(rec):
                out.append(VerbFinding("method_override", canonical_method,
                    f"method-override header '{h}: {canonical_method}' bypassed the "
                    f"method restriction", rec.status))
                break
        return out


# ===========================================================================
# Race conditions — business-logic TOCTOU (API6). Bounded & gated.
# ===========================================================================
@dataclass
class RaceFinding:
    parallel: int
    successes: int
    detail: str


class RaceProbe:
    HARD_CAP = 20

    def test(self, send_once: Callable, *, parallel: int = 8,
             expected_successes: int = 1, success_pred: Optional[Callable] = None
             ) -> Optional[RaceFinding]:
        parallel = min(parallel, self.HARD_CAP)
        pred = success_pred or (lambda r: r is not None and getattr(r, "status", 0) in (200, 201))
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as ex:
            recs = list(ex.map(lambda _: send_once(), range(parallel)))
        successes = sum(1 for r in recs if pred(r))
        if successes > expected_successes:
            return RaceFinding(parallel, successes,
                f"{successes}/{parallel} parallel requests succeeded where only "
                f"{expected_successes} should — a race/TOCTOU window lets the action "
                f"be performed multiple times (e.g. limit/coupon/balance overrun)")
        return None


# ===========================================================================
# GraphQL deep abuse — batching, alias amplification, missing depth limit
# ===========================================================================
@dataclass
class GraphQLAdvFinding:
    kind: str          # "batching" | "alias_amplification" | "no_depth_limit"
    detail: str
    status: int


def _nested_query(depth: int) -> str:
    # a bounded self-referential introspection-ish nesting to test depth limits
    inner = "name"
    for _ in range(depth):
        inner = f"fields{{type{{{inner}}}}}"
    return json.dumps({"query": "query{__type(name:\"Query\"){" + inner + "}}"})


def _batch_query(n: int) -> str:
    return json.dumps([{"query": f"query a{i}{{__typename}}"} for i in range(n)])


def _alias_query(n: int) -> str:
    aliases = " ".join(f"a{i}:__typename" for i in range(n))
    return json.dumps({"query": "query{" + aliases + "}"})


class GraphQLAdvanced:
    DEPTH_CAP = 8
    BATCH_N = 10
    ALIAS_N = 25

    def test(self, send_body: Callable) -> list[GraphQLAdvFinding]:
        # send_body(raw_json_string) -> record
        out: list[GraphQLAdvFinding] = []

        # batching: an array batch that all resolve => rate-limit bypass surface
        rec = send_body(_batch_query(self.BATCH_N))
        if rec is not None and rec.status == 200 and (rec.resp_body or "").count("__typename") \
                + (rec.resp_body or "").count("Query") >= 2 and (rec.resp_body or "").strip().startswith("["):
            out.append(GraphQLAdvFinding("batching",
                f"the endpoint executed a batch of {self.BATCH_N} queries in one "
                f"request — batching can bypass per-request rate limits (credential "
                f"stuffing, enumeration)", rec.status))

        # alias amplification: many aliases resolved in one query
        rec = send_body(_alias_query(self.ALIAS_N))
        if rec is not None and rec.status == 200 and (rec.resp_body or "").count("a0") >= 1 \
                and (rec.resp_body or "").count(":") >= self.ALIAS_N // 2:
            out.append(GraphQLAdvFinding("alias_amplification",
                f"{self.ALIAS_N} aliased fields resolved in a single query — alias "
                f"amplification enables resource abuse and rate-limit bypass", rec.status))

        # depth limit: a deeply nested (bounded) query that is accepted
        rec = send_body(_nested_query(self.DEPTH_CAP))
        if rec is not None and rec.status == 200 and "error" not in (rec.resp_body or "").lower():
            out.append(GraphQLAdvFinding("no_depth_limit",
                f"a query nested to depth {self.DEPTH_CAP} was accepted without a "
                f"complexity/depth error — nested-query DoS risk; enforce a depth "
                f"and cost limit", rec.status))
        return out
