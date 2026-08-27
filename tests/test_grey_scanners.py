"""Phase 2/3 grey-box scanners: memory-disclosure, log-injection, resource-consumption.

Offline against fake clients + a fake telemetry recorder — no Docker, no live
target. Locks down the false-positive discipline (a bare 200 / SPA index is not a
memory leak; log-injection needs a FORGED line, not an inline echo; resource
findings need a MEASURED sustained memory jump) and the hard gating (log-injection
and resource-consumption no-op without the recorder / without state-changing).

Run: python3 -m tests.test_grey_scanners
"""
from __future__ import annotations

import sys

from deluluscan.models import Endpoint, RequestRecord, Severity, VulnClass
from deluluscan.scanners.memory_disclosure_scanner import MemoryDisclosureScanner
from deluluscan.scanners.log_injection_scanner import LogInjectionScanner
from deluluscan.scanners.resource_consumption_scanner import ResourceConsumptionScanner

_checks = 0
_failures: list[str] = []


def check(cond, label):
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


class _Auth:
    def headers_for(self, ident):
        return {}


class _Cfg:
    class _Scan:
        allow_state_changing = True
    class _Obs:
        stats_interval_s = 0.01
    scan = _Scan()
    observe = _Obs()


def _idents():
    class I:
        def __init__(self, l): self._l = l; self.username = l; self.bearer_token = None
        def label(self): return self._l
    return {"anonymous": I("anonymous"), "admin": I("admin")}


# ---- memory disclosure ----------------------------------------------------
class _DiscClient:
    """Serves configured (status, ct, body) for specific paths; SPA-200 otherwise."""
    def __init__(self, routes):
        self.routes = routes
    def status_probe(self, method, path, *, identity_label="anonymous", headers=None,
                     read_timeout=5.0, max_bytes=4096, params=None):
        if path in self.routes:
            st, ct, body = self.routes[path]
        else:
            st, ct, body = 200, "text/html", "<!doctype html><div id=root></div>"  # SPA catch-all
        return RequestRecord(method="GET", url="http://h" + path, identity=identity_label,
                             status=st, elapsed_ms=1.0,
                             resp_headers={"Content-Type": ct}, resp_body=body)


def test_memory_disclosure_open_heapdump():
    routes = {"/actuator/heapdump": (200, "application/octet-stream", "JAVA PROFILE 1.0.2\x00")}
    sc = MemoryDisclosureScanner(_DiscClient(routes), _Auth(), _Cfg(), _idents())
    fs = list(sc.run(Endpoint(method="GET", path="/")))
    hd = [f for f in fs if f.detail.get("family") == "heapdump" and f.detail.get("state") == "open"]
    check(len(hd) == 1 and hd[0].severity == Severity.HIGH and hd[0].exploitability == "exploitable",
          "open anonymous heap dump -> HIGH exploitable MEMORY_DISCLOSURE")


def test_memory_disclosure_spa_200_is_not_a_finding():
    # actuator path returns the SPA index (200 text/html) -> must NOT be flagged
    routes = {"/actuator": (200, "text/html", "<!doctype html><div id=root></div>")}
    sc = MemoryDisclosureScanner(_DiscClient(routes), _Auth(), _Cfg(), _idents())
    fs = list(sc.run(Endpoint(method="GET", path="/")))
    check(all(f.detail.get("state") != "open" for f in fs),
          "a 200 SPA-index response is not mistaken for an exposed diagnostics surface")


def test_memory_disclosure_gated_is_low():
    routes = {"/actuator/env": (401, "application/json", "unauthorized")}
    sc = MemoryDisclosureScanner(_DiscClient(routes), _Auth(), _Cfg(), _idents())
    fs = list(sc.run(Endpoint(method="GET", path="/")))
    gated = [f for f in fs if f.detail.get("state") == "gated"]
    check(len(gated) == 1 and gated[0].severity == Severity.LOW,
          "a 401 diagnostics surface is recorded as present-but-gated (LOW)")


def test_memory_disclosure_runs_once():
    sc = MemoryDisclosureScanner(_DiscClient({}), _Auth(), _Cfg(), _idents())
    ep = Endpoint(method="GET", path="/x")
    check(sc.applies_to(ep) is True, "applies before first run")
    list(sc.run(ep))
    check(sc.applies_to(ep) is False, "does not re-run per endpoint (fixed-path scanner)")


# ---- log injection --------------------------------------------------------
class _FakeRecorder:
    def __init__(self, lines): self._lines = list(lines)
    def log_texts(self): return list(self._lines)


class _EchoLogClient:
    """Records sent values; the paired recorder decides what 'appears' in logs."""
    def __init__(self): self.sent = []
    def request(self, method, path, *, identity_label="anonymous", headers=None,
                params=None, json_body=None, data=None, **kw):
        self.sent.append({"params": params, "json": json_body})
        return RequestRecord(method=method, url="http://h" + path, identity=identity_label,
                             status=200, elapsed_ms=1.0)


def test_log_injection_noop_without_recorder():
    sc = LogInjectionScanner(_EchoLogClient(), _Auth(), _Cfg(), _idents(), recorder=None)
    ep = Endpoint(method="POST", path="/api/v1/x")
    check(sc.applies_to(ep) is False, "log-injection no-ops without the telemetry recorder")
    check(list(sc.run(ep)) == [], "log-injection yields nothing without a recorder")


def test_log_injection_confirmed_on_forged_line(monkeypatch=None):
    import deluluscan.scanners.log_injection_scanner as mod
    mod.time.sleep = lambda *_a, **_k: None      # don't actually wait in the test
    client = _EchoLogClient()
    ep = Endpoint(method="POST", path="/api/v1/comments")
    # recorder that will report a forged line for whatever marker the scanner used:
    captured = {}

    class _Rec:
        def log_texts(self):
            # the scanner sends value containing "DELULUSCAN-FORGED-<token>"; echo it as
            # its own forged line so forged_line_present() fires
            v = client.sent[-1]["json"]["value"] if client.sent else ""
            for tok in v.split():
                if tok.startswith("DELULUSCAN-FORGED-"):
                    captured["marker"] = tok
                    return [f"{tok} INFO injected-audit-entry"]
            return ["INFO nothing forged here"]

    sc = LogInjectionScanner(client, _Auth(), _Cfg(), _idents(), recorder=_Rec())
    fs = list(sc.run(ep))
    check(len(fs) == 1 and fs[0].vuln_class == VulnClass.LOG_INJECTION,
          "a forged log line -> a LOG_INJECTION finding")
    check(fs and fs[0].verdict == "true_positive" and fs[0].exploitability == "exploitable",
          "confirmed log injection is true_positive/exploitable")


def test_log_injection_inline_echo_is_not_confirmed():
    import deluluscan.scanners.log_injection_scanner as mod
    mod.time.sleep = lambda *_a, **_k: None
    client = _EchoLogClient()
    ep = Endpoint(method="POST", path="/api/v1/comments")

    class _Rec:
        def log_texts(self):
            # marker appears INLINE within a legit line, not starting its own line
            return ["INFO user submitted value DELULUSCAN-FORGED-inline within field"]

    sc = LogInjectionScanner(client, _Auth(), _Cfg(), _idents(), recorder=_Rec())
    check(list(sc.run(ep)) == [],
          "an inline echo (no split line) is a precondition, not a confirmed injection")


# ---- resource consumption -------------------------------------------------
class _HeavyClient:
    def request(self, method, path, *, identity_label="anonymous", headers=None,
                params=None, json_body=None, data=None, **kw):
        return RequestRecord(method=method, url="http://h" + path, identity=identity_label,
                             status=200, elapsed_ms=50.0)


class _StatsRecorder:
    """Feeds a mem baseline, then a spike after the probe, via a monotonic clock
    the scanner reads through recorder.events()."""
    def __init__(self, baseline, spike):
        import types
        self.baseline = baseline; self.spike = spike; self._phase = {"sent": False}
        self._events = []

    def events(self):
        # before send: one baseline sample in the past; after send: a spike sample now
        import time as _t
        now = _t.time()
        evs = [type("E", (), {"source": "stats", "wall": now - 100,
                              "data": {"mem_bytes": self.baseline}})()]
        if self._phase["sent"]:
            evs.append(type("E", (), {"source": "stats", "wall": now + 100,
                                      "data": {"mem_bytes": self.spike}})())
        return evs


def test_resource_consumption_gated():
    # no recorder -> no-op
    sc = ResourceConsumptionScanner(_HeavyClient(), _Auth(), _Cfg(), _idents(), recorder=None)
    check(sc.applies_to(Endpoint(method="POST", path="/x")) is False,
          "resource scanner no-ops without a recorder")
    # recorder present but state-changing off -> no-op
    class _CfgNoState(_Cfg):
        class _Scan: allow_state_changing = False
        scan = _Scan()
    sc2 = ResourceConsumptionScanner(_HeavyClient(), _Auth(), _CfgNoState(), _idents(),
                                     recorder=_StatsRecorder(1, 2))
    check(sc2.applies_to(Endpoint(method="POST", path="/x")) is False,
          "resource scanner no-ops without --allow-state-changing")


def test_resource_consumption_flags_measured_amplification():
    import deluluscan.scanners.resource_consumption_scanner as mod
    mod.time.sleep = lambda *_a, **_k: None
    rec = _StatsRecorder(baseline=100_000_000, spike=300_000_000)
    # flip to 'sent' as soon as a request goes out
    client = _HeavyClient()
    orig = client.request
    def _req(*a, **k):
        rec._phase["sent"] = True
        return orig(*a, **k)
    client.request = _req
    sc = ResourceConsumptionScanner(client, _Auth(), _Cfg(), _idents(), recorder=rec)
    fs = list(sc.run(Endpoint(method="POST", path="/api/v1/import")))
    check(len(fs) == 1 and fs[0].vuln_class == VulnClass.RATE_LIMIT,
          "a measured 3x memory jump -> a RATE_LIMIT amplification finding")
    check(fs and fs[0].exploitability == "conditional",
          "amplification is graded conditional (measured, full DoS not attempted)")


def test_resource_consumption_no_flag_on_flat_memory():
    import deluluscan.scanners.resource_consumption_scanner as mod
    mod.time.sleep = lambda *_a, **_k: None
    rec = _StatsRecorder(baseline=100_000_000, spike=105_000_000)   # ~flat
    client = _HeavyClient()
    orig = client.request
    def _req(*a, **k):
        rec._phase["sent"] = True
        return orig(*a, **k)
    client.request = _req
    sc = ResourceConsumptionScanner(client, _Auth(), _Cfg(), _idents(), recorder=rec)
    check(list(sc.run(Endpoint(method="POST", path="/x"))) == [],
          "flat memory under a heavy request -> no finding")


def main():
    print("== deluluscan grey-box scanners (phase 2/3) ==")
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks}:")
        for f in _failures:
            print("  -", f)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
