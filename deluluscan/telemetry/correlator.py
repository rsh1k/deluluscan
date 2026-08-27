"""Correlate live probes with the target's own telemetry -> findings.

Given (a) the observability timeline (Recorder) and (b) the per-request windows
HttpClient captured during the sweep, the Correlator produces grey-box findings
that a black-box HTTP view cannot:

  * analyze_trace_leaks   — a probe whose time window overlaps a server stack
    trace is attributed that trace's vulnerability class (SQLi/SSTI/… CONFIRMED
    by the server's own error, not just a suggestive response).
  * analyze_secrets_in_logs — credentials/PII observed in the log stream (CWE-532).
  * analyze_detection_gap — a successful state-changing operation that produced
    NO correlated log line (OWASP A09 logging & monitoring failure).
  * analyze_memory        — sustained heap growth / OOM correlated with the sweep
    (unrestricted resource consumption LEAD; confirmed only by the resource pass).

Discipline (matches deluluscan/verify): a server error is strong corroboration, so
trace-leak findings are graded `firm` / `likely_true_positive` — but a live
re-test still owns the final verdict, and passive memory growth is a `tentative`
LEAD, never a hard verdict. Baseline noise (anything observed before the sweep
began) is subtracted so target startup chatter is not reported as an exploit.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from ..models import Finding, RequestRecord, Severity, VulnClass
from . import signatures


@dataclass
class ProbeWindow:
    method: str
    url: str
    status: int
    identity: str
    t0: float                 # wall epoch at request start
    t1: float                 # wall epoch at response/close
    probe_id: str = ""

    @property
    def path(self) -> str:
        try:
            return urlparse(self.url).path or self.url
        except Exception:
            return self.url

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


def probe_windows_from(raw) -> list[ProbeWindow]:
    """Build ProbeWindows from the lightweight dicts HttpClient captures."""
    out: list[ProbeWindow] = []
    for r in (raw or []):
        try:
            out.append(ProbeWindow(
                method=r.get("method", "GET"), url=r.get("url", ""),
                status=int(r.get("status", 0)), identity=r.get("identity", "anonymous"),
                t0=float(r["t0"]), t1=float(r["t1"]), probe_id=r.get("probe_id", "")))
        except (KeyError, TypeError, ValueError):
            continue
    return out


_SEV = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
        "critical": Severity.CRITICAL, "info": Severity.INFO}


class Correlator:
    def __init__(self, recorder, baseline_end: float = 0.0):
        # baseline_end: wall time the main sweep STARTED. Events before it are the
        # target's own startup/idle noise and must not be attributed to a probe.
        self.rec = recorder
        self.baseline_end = baseline_end or 0.0

    # -- helpers ------------------------------------------------------------
    def _baseline_trace_labels(self) -> set[str]:
        return {e.data.get("trace_label", "") for e in self.rec.events()
                if e.kind == "exception" and e.wall < self.baseline_end}

    # the target's WebResource.init() gate runs before any business logic — a
    # request that came back 401/403 never reached the code that could raise a
    # SQLi/SSTI/deserialization trace, so it can never be the TRUE cause of one.
    # Under concurrent load several probes' windows legitimately overlap the
    # same log line; picking "latest start" alone (with no regard for whether
    # the candidate could plausibly have caused it) misattributes a real trace
    # from one endpoint onto an unrelated, auth-rejected request to another.
    _PRE_AUTH_REJECTED = {401, 403}

    def _attribute(self, ev, windows: list[ProbeWindow],
                   pad_before: float = 0.5, pad_after: float = 2.5) -> Optional[ProbeWindow]:
        """The probe most likely responsible for a telemetry event: the latest
        plausible request whose [t0-pad, t1+pad] contains the event's wall time.
        Auth-rejected candidates (401/403) are only used if nothing else overlaps —
        they cannot have caused a downstream server error, so attributing to one
        over an available non-rejected candidate would misattribute a real trace."""
        best = None
        best_rejected = None
        for w in windows:
            if (w.t0 - pad_before) <= ev.wall <= (w.t1 + pad_after):
                if w.status in self._PRE_AUTH_REJECTED:
                    if best_rejected is None or w.t0 > best_rejected.t0:
                        best_rejected = w
                    continue
                if best is None or w.t0 > best.t0:
                    best = w
        return best if best is not None else best_rejected

    @staticmethod
    def _rec_from_window(w: ProbeWindow, note: str = "") -> RequestRecord:
        return RequestRecord(method=w.method.upper(), url=w.url, identity=w.identity,
                             status=w.status, elapsed_ms=round((w.t1 - w.t0) * 1000, 1),
                             resp_body=note)

    # -- 1. trace-leak correlation -----------------------------------------
    def analyze_trace_leaks(self, windows: list[ProbeWindow]) -> list[Finding]:
        baseline = self._baseline_trace_labels()
        by_key: dict = {}      # (vuln_class, path, label) -> {finding, count}
        for ev in self.rec.events():
            if ev.kind != "exception" or ev.wall < self.baseline_end:
                continue
            label = ev.data.get("trace_label", "")
            if label in baseline:
                continue       # pre-existing startup noise, not probe-induced
            w = self._attribute(ev, windows)
            if w is None:
                continue       # cannot pin it to a request — don't guess
            vc = ev.data.get("trace_class", "error_handling")
            sig_sev = ev.data.get("trace_severity", "low")
            gkey = (vc, w.path, label)
            if gkey in by_key:
                by_key[gkey]["count"] += 1
                continue
            probe_rec = self._rec_from_window(w, f"[server log] {ev.text[:400]}")
            f = Finding(
                vuln_class=VulnClass(vc),
                severity=_SEV.get(sig_sev, Severity.LOW),
                title=f"{label} triggered on {w.key} (server-log confirmed)",
                endpoint=w.key,
                description=(f"A probe to {w.key} as '{w.identity}' provoked a server-side "
                             f"{label} in the target's log stream within the request window. "
                             f"The server's own error confirms request-controlled input reached "
                             f"the underlying engine — a black-box view saw only the HTTP status "
                             f"({w.status})."),
                evidence=[probe_rec],
                detail={"test": "telemetry_trace", "trace_label": label,
                        "trace_class": vc, "log_line": ev.text[:600],
                        "probe_id": w.probe_id, "correlation": "log-window overlap"},
                confidence="firm")
            # Strong corroboration, but a live re-test still owns the verdict.
            f.verdict = "likely_true_positive"
            f.exploitability = "conditional"
            by_key[gkey] = {"finding": f, "count": 1}
        out = []
        for v in by_key.values():
            f = v["finding"]
            if v["count"] > 1:
                f.detail["occurrences"] = v["count"]
            out.append(f)
        return out

    # -- 2. secrets in logs -------------------------------------------------
    def analyze_secrets_in_logs(self) -> list[Finding]:
        by_kind: dict = {}     # kind -> {count, sample}
        for ev in self.rec.events():
            for kind in ev.data.get("secret_kinds", []) or []:
                slot = by_kind.setdefault(kind, {"count": 0, "sample": ev.text[:400]})
                slot["count"] += 1
        out = []
        for kind, slot in by_kind.items():
            sev = signatures.secret_severity([kind])
            rec = RequestRecord(method="LOG", url="(target log stream)",
                                identity="server", status=0, elapsed_ms=0.0,
                                resp_body=slot["sample"])   # already redacted at ingest
            f = Finding(
                vuln_class=VulnClass.INFO_LEAK,
                severity=_SEV.get(sev, Severity.MEDIUM),
                title=f"Sensitive value written to logs ({kind})",
                endpoint="(server logs)",
                description=(f"A value of type '{kind}' was observed in the target's log "
                             f"stream ({slot['count']} occurrence(s)). Anyone with log access "
                             f"— or any downstream log-forwarding/SIEM — can harvest it. The "
                             f"value is redacted here; the finding records only its presence."),
                evidence=[rec],
                detail={"test": "secret_in_logs", "kind": kind,
                        "occurrences": slot["count"]},
                confidence="firm")
            f.verdict = "true_positive"      # directly observed in the log stream
            f.exploitability = "conditional"
            out.append(f)
        return out

    # -- 3. detection gap (logging & monitoring failure) --------------------
    def analyze_detection_gap(self, windows: list[ProbeWindow],
                              min_ops: int = 3, unlogged_frac: float = 0.8) -> list[Finding]:
        """`windows` are security-relevant successful operations that SHOULD be
        logged. If a log source produced nothing at all, we cannot tell 'not
        logged' from 'not observed', so we abstain."""
        log_events = [e for e in self.rec.events()
                      if e.source in ("log", "pg") and e.wall >= self.baseline_end]
        if not log_events:
            return []          # no log visibility -> cannot assert a gap honestly
        by_ep: dict = {}       # ep key -> {total, unlogged, sample_window}
        for w in windows:
            got = any((w.t0 - 0.5) <= e.wall <= (w.t1 + 2.5) for e in log_events)
            slot = by_ep.setdefault(w.key, {"total": 0, "unlogged": 0, "w": w})
            slot["total"] += 1
            if not got:
                slot["unlogged"] += 1
        out = []
        for ep, slot in by_ep.items():
            if slot["total"] < min_ops:
                continue
            frac = slot["unlogged"] / slot["total"]
            if frac < unlogged_frac:
                continue
            w = slot["w"]
            rec = self._rec_from_window(
                w, "[no correlated log line in the observation window]")
            f = Finding(
                vuln_class=VulnClass.LOGGING_FAILURE,
                severity=Severity.MEDIUM,
                title=f"State-changing operation not logged: {ep}",
                endpoint=ep,
                description=(f"{slot['unlogged']}/{slot['total']} successful "
                             f"state-changing requests to {ep} produced no correlated entry "
                             f"in the observed log stream. Such an operation should leave an "
                             f"audit trail; without one, an attacker exercising it is invisible "
                             f"to defenders. Caveat: a separate audit sink not tapped here could "
                             f"still record it — confirm against the intended sink."),
                evidence=[rec],
                detail={"test": "detection_gap", "unlogged": slot["unlogged"],
                        "total": slot["total"], "unlogged_fraction": round(frac, 2)},
                confidence="firm")
            f.verdict = "likely_true_positive"
            f.exploitability = "conditional"
            out.append(f)
        return out

    # -- 4. memory / resource behaviour ------------------------------------
    def analyze_memory(self, growth_ratio: float = 1.5) -> list[Finding]:
        out: list[Finding] = []
        # (a) OOM in the log stream during the sweep — strong signal.
        for ev in self.rec.events():
            if ev.kind == "exception" and ev.wall >= self.baseline_end \
                    and ev.data.get("trace_label") in ("Out of memory",):
                rec = RequestRecord(method="LOG", url="(target log stream)",
                                    identity="server", status=0, elapsed_ms=0.0,
                                    resp_body=ev.text[:400])
                f = Finding(
                    vuln_class=VulnClass.RATE_LIMIT, severity=Severity.HIGH,
                    title="Target ran out of memory during the scan",
                    endpoint="(runtime)",
                    description=("An OutOfMemoryError / heap-exhaustion signal appeared in the "
                                 "target's log stream during the sweep — request-driven memory "
                                 "pressure the app did not bound. Confirm the specific input via "
                                 "the destructive resource pass (restarting between probes)."),
                    evidence=[rec],
                    detail={"test": "telemetry_oom", "log_line": ev.text[:400]},
                    confidence="firm")
                f.verdict = "likely_true_positive"
                f.exploitability = "conditional"
                out.append(f)
                break
        # (b) sustained heap growth from docker stats (passive LEAD).
        samples = [(e.wall, e.data.get("mem_bytes")) for e in self.rec.events()
                   if e.source == "stats" and isinstance(e.data.get("mem_bytes"), (int, float))]
        samples = [(w, m) for (w, m) in samples if m]
        if len(samples) >= 6:
            base = [m for (w, m) in samples if w < self.baseline_end] or \
                   [m for (_, m) in samples[:max(2, len(samples) // 5)]]
            base_med = sorted(base)[len(base) // 2]
            tail = [m for (_, m) in samples[-3:]]
            peak = max(m for (_, m) in samples)
            sustained = base_med > 0 and min(tail) >= base_med * (1 + (growth_ratio - 1) * 0.6)
            if base_med > 0 and peak >= base_med * growth_ratio and sustained:
                rec = RequestRecord(method="STATS", url="(docker stats)", identity="server",
                                    status=0, elapsed_ms=0.0,
                                    resp_body=(f"baseline≈{int(base_med)}B peak≈{int(peak)}B "
                                               f"end≈{int(tail[-1])}B"))
                f = Finding(
                    vuln_class=VulnClass.RATE_LIMIT, severity=Severity.LOW,
                    title="Heap grew during the scan and did not recover (possible leak)",
                    endpoint="(runtime)",
                    description=(f"Observed heap climbed from a baseline of ~{int(base_med)} bytes "
                                 f"to ~{int(peak)} bytes during the sweep and stayed elevated. This "
                                 f"is a LEAD, not proof — it can be normal warm-up/caching. Confirm "
                                 f"a genuine leak/unbounded consumption with the destructive "
                                 f"resource pass (repeat one request K times; watch it not recover "
                                 f"after GC)."),
                    evidence=[rec],
                    detail={"test": "telemetry_mem_growth", "baseline_bytes": int(base_med),
                            "peak_bytes": int(peak), "end_bytes": int(tail[-1])},
                    confidence="tentative")
                f.verdict = "unverified"
                f.exploitability = "unknown"
                out.append(f)
        return out

    # -- summary for meta ---------------------------------------------------
    def summary(self) -> dict:
        events = self.rec.events()
        by_source: dict = {}
        exceptions = secrets = 0
        for e in events:
            by_source[e.source] = by_source.get(e.source, 0) + 1
            if e.kind == "exception":
                exceptions += 1
            if e.data.get("secret_kinds"):
                secrets += 1
        return {"events": len(events), "by_source": by_source,
                "exception_lines": exceptions, "secret_lines": secrets,
                "dropped": getattr(self.rec, "dropped", 0)}
