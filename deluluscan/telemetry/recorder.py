"""The observability timeline.

A `Recorder` is the single, thread-safe sink every telemetry source writes into.
Two invariants make it safe to keep and even publish:

  * Redaction at INGEST. `add_log()` runs the raw line through
    signatures.redact_secrets() BEFORE storing it, so the target's secrets never
    land in Deluluscan's own telemetry store (which is written to
    deluluscan-out/telemetry.jsonl and could otherwise become a second-order leak).
  * Wall-clock correlation. Every event carries `wall` (epoch seconds). Because
    the target container shares the host kernel clock, a probe's wall-clock window
    and a log line's timestamp are directly comparable — that is what lets the
    correlator attribute a stack trace to the request that caused it.

Bounded by a deque so a chatty target cannot exhaust memory during a long scan.
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from . import signatures


@dataclass
class TelemetryEvent:
    wall: float                       # epoch seconds — the correlation key
    source: str                       # "log" | "stats" | "pg" | ...
    kind: str                         # "line" | "exception" | "sample"
    text: str = ""                    # redacted log text (log sources)
    data: dict = field(default_factory=dict)   # structured payload (stats) / trace meta

    def to_dict(self) -> dict:
        return {"wall": round(self.wall, 3), "source": self.source,
                "kind": self.kind, "text": self.text, "data": self.data}


class Recorder:
    def __init__(self, max_events: int = 200_000):
        self._events: deque[TelemetryEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self.dropped = 0                # events lost to the maxlen bound

    # -- ingest -------------------------------------------------------------
    def add(self, ev: TelemetryEvent) -> None:
        with self._lock:
            if len(self._events) == self._events.maxlen:
                self.dropped += 1
            self._events.append(ev)

    def add_log(self, raw: str, *, source: str = "log", wall: Optional[float] = None) -> TelemetryEvent:
        """Record one log line: redact secrets, classify any exception trace."""
        wall = time.time() if wall is None else wall
        text, secret_kinds = signatures.redact_secrets((raw or "").rstrip("\n"))
        data: dict = {}
        if secret_kinds:
            data["secret_kinds"] = secret_kinds
        sig = signatures.classify_trace(text)
        kind = "line"
        if sig is not None:
            kind = "exception"
            data["trace_class"] = sig.vuln_class
            data["trace_label"] = sig.label
            data["trace_severity"] = sig.severity
        ev = TelemetryEvent(wall=wall, source=source, kind=kind, text=text, data=data)
        self.add(ev)
        return ev

    def add_stats(self, data: dict, *, source: str = "stats", wall: Optional[float] = None) -> TelemetryEvent:
        wall = time.time() if wall is None else wall
        ev = TelemetryEvent(wall=wall, source=source, kind="sample", data=dict(data))
        self.add(ev)
        return ev

    # -- query --------------------------------------------------------------
    def events(self) -> list[TelemetryEvent]:
        with self._lock:
            return list(self._events)

    def window(self, t0: float, t1: float, *, pad_before: float = 0.5,
               pad_after: float = 2.0) -> list[TelemetryEvent]:
        """Events whose wall time falls in [t0-pad_before, t1+pad_after].

        The asymmetric pad reflects reality: application logging is usually
        emitted slightly AFTER the request completes (async appenders, buffered
        stdout), so the tail pad is larger than the lead pad."""
        lo, hi = t0 - pad_before, t1 + pad_after
        return [e for e in self.events() if lo <= e.wall <= hi]

    def log_texts(self) -> list[str]:
        return [e.text for e in self.events() if e.source in ("log", "pg") and e.text]

    def persist(self, path: str) -> None:
        try:
            with open(path, "w") as fh:
                for e in self.events():
                    fh.write(json.dumps(e.to_dict()) + "\n")
        except Exception:
            pass          # telemetry persistence must never break a scan
