"""Fuzzing & anomaly detection — candidate unknown-bug lead generation.

IMPORTANT — what this is and is NOT:
  This module does NOT "scan for zero-days". A zero-day is, by definition, a flaw
  for which no signature or rule exists yet, so no scanner can detect one directly.
  What actually leads researchers to novel bugs is *fuzzing* (feeding malformed /
  mutated input and watching for anomalous behaviour) and *differential/anomaly
  analysis* (noticing when a target behaves inconsistently in a way a signature
  wouldn't catch). This module automates that first step and surfaces CANDIDATE
  LEADS for a human to investigate. It never labels anything a confirmed zero-day.

Grounding (research):
  - PHUZZ (arXiv 2406.06261): coverage-guided web fuzzing found real 0-days in WP
    plugins by mutating API inputs and observing anomalies.
  - ANVIL (arXiv 2408.16028): anomaly-based identification found bugs a signature
    scanner (CodeQL) missed — deviation from normal behaviour is the signal.
  - Schneier/EMSI (2026): the responsible bar is "reproducible PoC + false-positive
    metrics; treat mass 'zero-day' claims as unproven." Hence: leads, not verdicts.

Method (black-box HTTP, safety-gated like the rest of the tool):
  1. Baseline each endpoint with a few benign inputs -> learn normal (status set,
     length band, latency band, whether input reflects, error fingerprints).
  2. Mutate inputs with a library of boundary / malformed / type-confusion /
     oversized / encoding payloads (generic, not vuln-class signatures).
  3. Flag responses that DEVIATE from the learned baseline: a server error only the
     mutation triggers, a crash/timeout, a large response-shape shift, a raw
     stack/exception surfaced, or unstable/non-deterministic behaviour.
  4. Emit each anomaly as a low/medium candidate lead with the exact repro input,
     rated `tentative` / verdict `unverified` — for a human to investigate.
"""
from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .models import Endpoint, Finding, Severity, VulnClass


# Generic malformed / boundary payloads. These are NOT vuln signatures — they are
# inputs likely to push code down un-tested paths (the essence of fuzzing).
_MUTATIONS = [
    # boundary numbers
    "-1", "0", "2147483648", "9999999999999999999999", "-2147483649", "1e309", "NaN",
    # type confusion (array/object where scalar expected, and vice versa)
    "[]", "{}", "true", "null", '{"$gt":""}', "[1,2,3]",
    # oversized / repetition
    "A" * 5000, "%s" * 200, "../" * 60,
    # encoding / unicode / null / control
    "%00", "%0a%0d", "\u0000", "\uffff\ufffe", "%c0%ae", "％2e", "\r\n\r\n",
    # format / template / expression markers (behavioural, not payloads to exploit).
    # Use rare arithmetic (1337*1331 = 1779547) instead of 7*7=49: a bare "49"
    # collides constantly with real data (counts, sizes, prices, UUID hex), which
    # was a persistent SSTI false positive. 1779547 effectively never appears
    # unless the server actually evaluated the expression.
    "{{1337*1331}}", "${1337*1331}", "#{1337*1331}", "%25%2e", "\\x00\\x01",
    # deeply nested / recursive shapes
    '{"a":' * 40 + '1' + '}' * 40,
    # empty & whitespace
    "", " ", "\t\n",
]

_EXCEPTION_RE = re.compile(
    r"(?i)traceback \(most recent call last\)|exception in thread|"
    r"\bat [\w.$]+\([\w.]+\.java:\d+\)|nullpointerexception|"
    r"panic:|runtime error:|segmentation fault|stack trace|"
    r"undefined index|fatal error:|unhandled exception|"
    r"[\w.]+Error: .+ at line \d+")


@dataclass
class FuzzConfig:
    enabled: bool = False
    max_endpoints: int = 40
    mutations_per_param: int = 0        # 0 = use full built-in set
    baseline_samples: int = 2
    per_request_timeout_s: float = 8.0


@dataclass
class _Baseline:
    statuses: set = field(default_factory=set)
    min_len: int = 0
    max_len: int = 0
    max_latency: float = 0.0
    reflects: bool = False
    has_error: bool = False


class Fuzzer:
    """Black-box behavioural fuzzer. `client.request(method, path, ...)` returns a
    record with .status, .resp_body, .resp_len, .elapsed_ms."""

    def __init__(self, client, auth, cfg, identities, fuzz_cfg: Optional[FuzzConfig] = None):
        self.client = client
        self.auth = auth
        self.cfg = cfg
        self.identities = identities
        self.fz = fuzz_cfg or FuzzConfig(enabled=True)
        self._rng = random.Random(1337)   # deterministic for reproducibility

    def _identity_label(self) -> str:
        # fuzz as the least-privileged identity that exists (surface reachable to all)
        for key in ("anonymous", "backend", "admin"):
            if key in self.identities:
                return key
        return "anonymous"

    def _fuzzable_params(self, ep: Endpoint) -> list[str]:
        names = [p.get("name") for p in (ep.query_params or []) if p.get("name")]
        props = (ep.request_body_schema or {}).get("properties") or {}
        names += list(props.keys())
        # also fuzz templated path segments
        names += [p for p in (ep.path_params or [])]
        return names

    def _send(self, ep: Endpoint, param: Optional[str], value: Optional[str], label: str):
        headers = {}
        ident = self.identities.get(label)
        if ident is not None and self.auth is not None:
            try:
                headers = dict(self.auth.headers_for(ident))
            except Exception:
                headers = {}
        path = ep.path
        query = None
        body = None
        if param is not None:
            if param in (ep.path_params or []):
                path = path.replace("{" + param + "}", value if value is not None else "")
            elif any(p.get("name") == param for p in (ep.query_params or [])):
                query = {param: value}
            else:
                body = {param: value}
        try:
            kwargs = {"identity_label": label, "headers": headers}
            if query is not None:
                kwargs["params"] = query
            if body is not None:
                kwargs["json_body"] = body
            return self.client.request(ep.method or "GET", path, **kwargs)
        except Exception:
            return None

    def _baseline(self, ep: Endpoint, param: str, label: str) -> _Baseline:
        b = _Baseline(min_len=10 ** 9)
        benign = ["1", "test", "abc123"][: max(1, self.fz.baseline_samples)]
        for val in benign:
            rec = self._send(ep, param, val, label)
            if rec is None:
                continue
            b.statuses.add(rec.status)
            ln = getattr(rec, "resp_len", 0) or 0
            b.min_len = min(b.min_len, ln); b.max_len = max(b.max_len, ln)
            b.max_latency = max(b.max_latency, getattr(rec, "elapsed_ms", 0.0) or 0.0)
            body = getattr(rec, "resp_body", "") or ""
            if val in body:
                b.reflects = True
            if _EXCEPTION_RE.search(body):
                b.has_error = True
        if b.min_len == 10 ** 9:
            b.min_len = 0
        return b

    def _classify_anomaly(self, ep: Endpoint, param: str, value: str, rec, base: _Baseline):
        """Return (severity, kind, note) if the response deviates from baseline in a
        way worth a human's look, else None."""
        if rec is None:
            # request itself failed only for the mutation -> possible crash/hang
            return (Severity.MEDIUM, "connection_dropped",
                    "The server dropped/failed the connection for a malformed input a "
                    "benign value handled — possible crash or unhandled condition.")
        body = getattr(rec, "resp_body", "") or ""
        status = rec.status
        latency = getattr(rec, "elapsed_ms", 0.0) or 0.0
        ln = getattr(rec, "resp_len", 0) or 0

        # 1) a server error (5xx) the benign baseline never produced
        if status >= 500 and not any(s >= 500 for s in base.statuses):
            return (Severity.MEDIUM, "new_server_error",
                    f"Malformed input to '{param}' triggered HTTP {status} while benign "
                    f"input did not — an unhandled server-side condition worth investigating.")
        # 2) a raw exception / stack trace the baseline didn't surface
        if _EXCEPTION_RE.search(body) and not base.has_error:
            return (Severity.MEDIUM, "exception_surfaced",
                    f"Malformed input to '{param}' surfaced a raw exception/stack trace not "
                    f"present for benign input — points at an unhandled code path.")
        # 3) latency outlier (possible ReDoS / algorithmic blowup)
        if base.max_latency > 0 and latency > max(3000.0, base.max_latency * 8):
            return (Severity.MEDIUM, "latency_outlier",
                    f"Input to '{param}' caused a large latency spike ({latency:.0f}ms vs "
                    f"baseline ~{base.max_latency:.0f}ms) — possible algorithmic/ReDoS blowup.")
        # 4) template/expression evaluation marker reflected as computed value.
        # Require the rare product 1779547 AND the payload literal to be ABSENT
        # (a reflected-but-unevaluated "{{1337*1331}}" is not SSTI).
        if (value in ("{{1337*1331}}", "${1337*1331}", "#{1337*1331}")
                and "1779547" in body and "1337*1331" not in body):
            return (Severity.HIGH, "expression_evaluation",
                    f"An expression payload in '{param}' appears to have been EVALUATED "
                    f"(server returned 1779547 = 1337*1331) — a strong template-injection/SSTI lead.")
        # 5) large response-shape shift on an otherwise-normal status
        if status in base.statuses and base.max_len > 0 and ln > max(base.max_len * 20, 50000):
            return (Severity.LOW, "response_shape_shift",
                    f"Input to '{param}' produced a response ~{ln} bytes vs baseline "
                    f"~{base.max_len} — an unexpected behavioural shift worth a look.")
        return None

    def run(self, endpoints: Iterable[Endpoint]) -> list[Finding]:
        if not self.fz.enabled:
            return []
        label = self._identity_label()
        findings: list[Finding] = []
        muts = list(_MUTATIONS)
        if self.fz.mutations_per_param and self.fz.mutations_per_param < len(muts):
            muts = self._rng.sample(muts, self.fz.mutations_per_param)
        seen_keys = set()
        count = 0
        for ep in endpoints:
            if count >= self.fz.max_endpoints:
                break
            params = self._fuzzable_params(ep)
            if not params:
                continue
            count += 1
            for param in params:
                base = self._baseline(ep, param, label)
                for value in muts:
                    rec = self._send(ep, param, value, label)
                    anomaly = self._classify_anomaly(ep, param, value, rec, base)
                    if not anomaly:
                        continue
                    sev, kind, note = anomaly
                    key = (ep.key, param, kind)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    findings.append(self._finding(ep, param, value, sev, kind, note, rec))
        return findings

    def _finding(self, ep, param, value, sev, kind, note, rec) -> Finding:
        vc = VulnClass.ERROR_HANDLING
        if kind == "expression_evaluation":
            vc = VulnClass.SQLI  # injection-family; SSTI has no dedicated class
        elif kind == "latency_outlier":
            vc = VulnClass.BUSINESS_LOGIC
        status = getattr(rec, "status", "n/a") if rec else "no-response"
        shown = value if len(value) <= 60 else value[:57] + "..."
        return Finding(
            vuln_class=vc, severity=sev,
            title=f"Fuzzing anomaly ({kind}) on {param} — candidate lead",
            endpoint=f"{ep.method} {ep.path}",
            description=(
                f"{note} This is a FUZZING LEAD, not a confirmed vulnerability: the tool "
                f"observed behaviour deviating from the endpoint's baseline when '{param}' "
                f"received a malformed value. A human should reproduce and investigate — it "
                f"may be a benign edge case or the seed of an unknown bug. Repro input for "
                f"'{param}': {shown!r} (HTTP {status})."),
            evidence=[rec] if rec else [],
            detail={"test": "fuzz_anomaly", "kind": kind, "param": param,
                    "mutation": value[:200], "status": status, "lead": True},
            confidence="tentative", verdict="unverified", exploitability="unknown")
