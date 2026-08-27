"""Resource-consumption / amplification detector (Phase 3, telemetry-aware).

Sends BOUNDED amplification payloads — a tiny request that is expensive to
process — and MEASURES the target's memory delta via the grey-box stats stream
(`--observe`) to decide whether the app bounds request-driven consumption
(OWASP API4 / CWE-770). The white-hat stance is deliberate: it measures the
amplification factor, it does NOT try to take the box down. Payloads are capped
(a large-but-bounded page size, a moderately nested body, a sub-256KB string), so
a confirmed finding is "a small request caused a large, measured memory jump",
graded `conditional` — full DoS is not demonstrated (that needs the destructive
resource pass with restart-between-probes, out of scope for a measured probe).

Gated hard: runs only with `--observe` (needs measurement) AND
`--allow-state-changing` (heavy traffic is opt-in), on a bounded number of
endpoints. Without the recorder it is a no-op.
"""
from __future__ import annotations

import time
from typing import Iterable, Optional

from ..models import Endpoint, Finding, RequestRecord, Severity, VulnClass
from .base import Scanner

_PAGING_KEYS = ("limit", "per_page", "perPage", "size", "count", "pageSize", "max", "rows")


def _nested(depth: int):
    d: dict = {"v": 1}
    for _ in range(depth):
        d = {"v": d}
    return d


class ResourceConsumptionScanner(Scanner):
    name = "resource_consumption"
    vuln_classes = [VulnClass.RATE_LIMIT.value]

    def __init__(self, client, auth, config, identities, recorder=None):
        super().__init__(client, auth, config, identities)
        self.recorder = recorder
        self._budget = 4                     # heavy: only a few endpoints per scan
        self._interval = float(getattr(getattr(config, "observe", None),
                                       "stats_interval_s", 2.0) or 2.0)

    def applies_to(self, endpoint: Endpoint) -> bool:
        if self.recorder is None or self._budget <= 0:
            return False
        if not getattr(self.config.scan, "allow_state_changing", False):
            return False
        m = (endpoint.method or "").upper()
        return bool(endpoint.query_params) or m in ("POST", "PUT", "PATCH")

    def _actor(self):
        for label in ("admin", "backend", "publisher", "content_editor", "anonymous"):
            ident = self.identities.get(label)
            if ident:
                return ident
        return next(iter(self.identities.values()), None)

    def _mem_at(self, *, before: float = None, after: float = None) -> Optional[float]:
        """Latest mem sample before `before`, or the PEAK sample after `after`."""
        samples = [(e.wall, e.data.get("mem_bytes")) for e in self.recorder.events()
                   if e.source == "stats" and isinstance(e.data.get("mem_bytes"), (int, float))]
        samples = [(w, m) for (w, m) in samples if m]
        if not samples:
            return None
        if before is not None:
            prev = [m for (w, m) in samples if w <= before]
            return prev[-1] if prev else None
        if after is not None:
            post = [m for (w, m) in samples if w >= after]
            return max(post) if post else None
        return None

    def _probes(self, endpoint: Endpoint, ident):
        m = (endpoint.method or "GET").upper()
        path = self.concrete_path(endpoint)
        hdrs = dict(self.auth.headers_for(ident)) if ident else {}
        label = ident.label() if ident else "anonymous"
        # (a) oversized pagination on query params
        if endpoint.query_params:
            params = {}
            for qp in endpoint.query_params[:6]:
                n = qp.get("name") if isinstance(qp, dict) else str(qp)
                if n:
                    params[n] = 100000 if n.lower() in [k.lower() for k in _PAGING_KEYS] else "1"
            for k in _PAGING_KEYS:
                params.setdefault(k, 100000)
            yield ("oversized-pagination",
                   lambda: self.client.request(m, path, identity_label=label,
                                               headers=dict(hdrs), params=params))
        # (b) bounded nested + long-string body on write verbs
        if m in ("POST", "PUT", "PATCH"):
            body = {"nested": _nested(40), "blob": "A" * 200_000}
            yield ("nested+blob-body",
                   lambda: self.client.request(m, path, identity_label=label,
                                               headers=dict(hdrs), json_body=body))

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if not self.applies_to(endpoint):
            return
        self._budget -= 1
        ident = self._actor()
        for label, sender in self._probes(endpoint, ident):
            t_before = time.time()
            before = self._mem_at(before=t_before)
            try:
                rec = sender()
            except TypeError:
                continue
            if rec is None:
                continue
            time.sleep(max(self._interval * 2.0, 3.0))   # let stats capture the peak
            after = self._mem_at(after=t_before)
            if before is None or after is None or before <= 0:
                continue
            ratio = after / before
            delta = after - before
            if ratio >= 1.25 and delta >= 40_000_000:
                ev = RequestRecord(method="STATS", url="(docker stats)", identity="server",
                                   status=0, elapsed_ms=rec.elapsed_ms,
                                   resp_body=(f"mem before≈{int(before)}B after≈{int(after)}B "
                                              f"(x{ratio:.2f}, +{int(delta)}B) for a "
                                              f"{label} request"))
                yield Finding(
                    vuln_class=VulnClass.RATE_LIMIT, severity=Severity.MEDIUM,
                    title=f"Request-driven memory amplification via {label} on {endpoint.method} {endpoint.path}",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    description=(f"A single bounded '{label}' request drove observed heap from "
                                 f"~{int(before)}B to ~{int(after)}B (x{ratio:.2f}). The app does "
                                 f"not appear to bound request-driven allocation for this input, "
                                 f"which an attacker can amplify toward denial of service. "
                                 f"MEASURED amplification only — full DoS was not attempted; "
                                 f"confirm via the destructive resource pass (repeat, restart "
                                 f"between probes)."),
                    evidence=[ev, rec],
                    detail={"test": "resource_consumption", "vector": label,
                            "mem_before": int(before), "mem_after": int(after),
                            "ratio": round(ratio, 2), "source": "telemetry"},
                    verdict="likely_true_positive", exploitability="conditional",
                    confidence="firm")
                return
