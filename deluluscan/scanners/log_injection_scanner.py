"""Log-injection / log-forging detector (Phase 2, telemetry-aware).

Unsanitized input containing CR/LF that reaches a log writer lets an attacker
forge log lines — fabricate audit entries, hide their tracks, or poison a SIEM
(CWE-117). This can only be CONFIRMED by reading the logs back, so this scanner
requires the grey-box telemetry recorder (`--observe`); without it, it is a no-op
(a black-box scanner cannot prove the newline split a real log line).

Discipline: only a BENIGN canary is injected — a value carrying an embedded
newline and a unique forged-line marker (a fake INFO line). The finding fires
only when that marker is observed at the START of its own log line
(signatures.forged_line_present) — i.e. the injection actually split the log, not
merely appeared inline within an escaped field.
"""
from __future__ import annotations

import time
from typing import Iterable, Optional

from ..models import Endpoint, Finding, RequestRecord, Severity, VulnClass
from .base import Scanner, canary


class LogInjectionScanner(Scanner):
    name = "log_injection"
    vuln_classes = [VulnClass.LOG_INJECTION.value]

    def __init__(self, client, auth, config, identities, recorder=None):
        super().__init__(client, auth, config, identities)
        self.recorder = recorder      # deluluscan.telemetry.Recorder or None
        self._budget = 20             # bounded: probe at most N endpoints per scan

    def applies_to(self, endpoint: Endpoint) -> bool:
        if self.recorder is None or self._budget <= 0:
            return False
        m = (endpoint.method or "").upper()
        return bool(endpoint.query_params) or m in ("POST", "PUT", "PATCH")

    def _actor(self):
        for label in ("admin", "backend", "publisher", "content_editor", "anonymous"):
            ident = self.identities.get(label)
            if ident:
                return ident
        return next(iter(self.identities.values()), None)

    def _slots(self, endpoint: Endpoint, ident, value: str):
        """Yield (label, sender) senders that place `value` in one injection point."""
        m = (endpoint.method or "GET").upper()
        path = self.concrete_path(endpoint)
        hdrs = dict(self.auth.headers_for(ident)) if ident else {}
        label = ident.label() if ident else "anonymous"
        for qp in (endpoint.query_params or [])[:2]:
            name = qp.get("name") if isinstance(qp, dict) else str(qp)
            if not name:
                continue
            yield (f"param:{name}",
                   lambda _n=name: self.client.request(m, path, identity_label=label,
                                                       headers=dict(hdrs), params={_n: value}))
        if m in ("POST", "PUT", "PATCH"):
            yield ("json-field",
                   lambda: self.client.request(m, path, identity_label=label,
                                               headers=dict(hdrs),
                                               json_body={"name": value, "value": value}))

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if self.recorder is None or self._budget <= 0:
            return
        from ..telemetry import signatures
        self._budget -= 1
        ident = self._actor()
        for label, sender in self._slots(endpoint, ident, "PLACEHOLDER"):
            token = canary("")
            forged = f"DELULUSCAN-FORGED-{token}"
            # value = <marker>CRLF<forged INFO line>. If logged verbatim, the CRLF
            # splits the record and `forged` begins its own line.
            value = f"deluluscan{token}\r\n{forged} INFO injected-audit-entry"
            # rebuild the sender bound to this concrete value
            real_sender = dict(self._slots(endpoint, ident, value))[label]
            try:
                rec = real_sender()
            except TypeError:
                continue
            if rec is None:
                continue
            time.sleep(1.5)      # let the app flush its log appender
            if signatures.forged_line_present(self.recorder.log_texts(), forged):
                log_ev = RequestRecord(method="LOG", url="(target log stream)",
                                       identity="server", status=0, elapsed_ms=0.0,
                                       resp_body=f"[forged line observed] {forged} INFO injected-audit-entry")
                yield Finding(
                    vuln_class=VulnClass.LOG_INJECTION, severity=Severity.MEDIUM,
                    title=f"Log injection via {label} on {endpoint.method} {endpoint.path}",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    description=(f"A value with an embedded CRLF sent via '{label}' produced a "
                                 f"FORGED log line in the target's log stream — the injected "
                                 f"marker began its own record. An attacker can fabricate audit "
                                 f"entries, break log parsers, or poison a SIEM. Only a benign "
                                 f"canary was used."),
                    evidence=[r for r in (rec, log_ev) if r is not None],
                    detail={"test": "log_injection", "slot": label,
                            "marker": forged, "source": "telemetry"},
                    verdict="true_positive", exploitability="exploitable",
                    confidence="firm")
                return       # one confirmed injection point per endpoint is enough
