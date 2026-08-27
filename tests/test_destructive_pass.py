"""The deferred destructive pass: probe the dangerous endpoints, keep the scan.

The incident this encodes: `DELETE /admin/maintenance/_shutdown` sent mid-sweep
shut the target down and cost the rest of the run. The answer is ordering, not
exclusion — sweep everything else first, then probe the destructive operations
with the target restartable between them.

What must hold:
  * destructive endpoints are held out of the main loop and probed afterwards,
  * a probe that kills the target triggers a restart and the pass CONTINUES,
  * with no restart_command, the pass stops and says which endpoints went
    unprobed — never silently, because "unprobed" must not read as "clean",
  * the target is brought back after the pass, since verification / the pivot /
    the integrity check all still need it,
  * when destructive probing is off, the endpoints are reported as deferred and
    unprobed rather than omitted.

Run: python3 -m tests.test_destructive_pass
"""
from __future__ import annotations

import sys
import types

from deluluscan.models import Endpoint, Finding, Severity, VulnClass
from deluluscan.orchestrator import Orchestrator
from deluluscan.safety import DestructivePolicy

_checks = 0
_failures: list[str] = []


def check(cond: bool, label: str) -> None:
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


SHUTDOWN = Endpoint(method="DELETE", path="/admin/maintenance/_shutdown")
REINDEX = Endpoint(method="DELETE", path="/api/v1/esindex/reindex")
DUMPDB = Endpoint(method="GET", path="/admin/maintenance/_downloadDb")


class _FakeScanner:
    """Yields one finding per endpoint, and records what it was asked to probe."""
    name = "fake"

    def __init__(self):
        self.seen: list[str] = []

    def applies_to(self, ep):
        return True

    def run(self, ep):
        self.seen.append(ep.key)
        yield Finding(vuln_class=VulnClass.AUTHZ, severity=Severity.CRITICAL,
                      title=f"anonymous reached {ep.key}", endpoint=ep.key,
                      description="test finding", detail={"test": "fake"})


def _orch(*, restart_command="", enabled=True, dies_after=None):
    """An Orchestrator with its network and coverage stubbed out.

    `dies_after` — number of destructive endpoints probed before the target stops
    answering (simulating the shutdown endpoint actually working).
    """
    o = Orchestrator.__new__(Orchestrator)
    o.progress = lambda ev, data: o.events.append((ev, data))
    o.events = []
    o.findings = []
    o.meta = {}
    o.destructive_policy = DestructivePolicy(enabled=enabled)
    o._dest_why_not = "" if enabled else "destructive probing disabled for this test"
    o.cfg = types.SimpleNamespace(
        identities={"anonymous": object(), "admin": object()},
        scan=types.SimpleNamespace(destructive=types.SimpleNamespace(
            restart_command=restart_command, health_path="/health",
            wait_timeout_s=1, allow_remote=False)))
    o.auth = types.SimpleNamespace(refresh=lambda i: {})
    o.coverage = types.SimpleNamespace(record=lambda *a, **k: None)

    state = {"probed": 0, "alive": True, "restarts": 0}
    o._state = state

    def target_alive():
        return state["alive"]

    def restart_target():
        if not restart_command:
            return False, ("target is down and no scan.destructive.restart_command "
                           "is configured")
        state["alive"] = True
        state["restarts"] += 1
        return True, ""

    o._target_alive = target_alive
    o._restart_target = restart_target

    if dies_after is not None:
        orig_alive = target_alive

        def counting_alive():
            return state["alive"]

        o._target_alive = counting_alive
    return o, state


def _instrument_death(o, state, scanner, dies_after):
    """Make the target die on the `dies_after`-th probe — ONCE, not on every probe
    from then on. A destructive endpoint takes the target down when it is probed;
    it does not re-kill an instance that has since been restarted."""
    real_run = scanner.run

    def run(ep):
        state["probed"] += 1
        if state["probed"] == dies_after:
            state["alive"] = False
        yield from real_run(ep)

    scanner.run = run


def test_destructive_endpoints_are_probed_after_the_sweep():
    o, state = _orch(restart_command="true")
    sc = _FakeScanner()
    report = o._destructive_pass([SHUTDOWN, REINDEX, DUMPDB], [sc])
    check(len(report["probed"]) == 3,
          f"all 3 destructive endpoints were probed ({report['probed']})")
    check(sc.seen == [SHUTDOWN.key, REINDEX.key, DUMPDB.key],
          "the scanner really was invoked on each of them")
    check(report["findings"] == 3, "findings from the destructive pass are collected")
    check(len(o.findings) == 3, "and appended to the run's findings")


def test_findings_are_marked_as_destructive_pass():
    o, _ = _orch(restart_command="true")
    o._destructive_pass([SHUTDOWN], [_FakeScanner()])
    d = o.findings[0].detail
    check(d.get("destructive_pass") is True,
          "a finding from this pass is marked destructive_pass=True")
    check("deferred" in (d.get("destructive_reason") or ""),
          "and carries the reason it was deferred, for the report")


def test_policy_is_open_during_the_pass_and_closed_after():
    o, _ = _orch(restart_command="true")
    seen_phase = {}

    class _PhaseScanner(_FakeScanner):
        def run(self, ep):
            seen_phase["in_pass"] = o.destructive_policy.in_destructive_phase
            return iter(())

    o._destructive_pass([SHUTDOWN], [_PhaseScanner()])
    check(seen_phase.get("in_pass") is True,
          "the destructive phase is open while the pass runs")
    check(o.destructive_policy.in_destructive_phase is False,
          "and is closed again afterwards, so nothing later can send one")


def test_a_probe_that_kills_the_target_triggers_restart_and_continues():
    o, state = _orch(restart_command="docker compose restart target")
    sc = _FakeScanner()
    _instrument_death(o, state, sc, dies_after=1)   # first probe takes it down
    report = o._destructive_pass([SHUTDOWN, REINDEX, DUMPDB], [sc])
    check(len(report["probed"]) == 3,
          f"the pass continued past the kill and probed all 3 ({report['probed']})")
    check(report["restarts"] >= 1,
          f"the target was restarted to get there ({report['restarts']} restart(s))")
    check(report["aborted_reason"] == "", "and the pass was not aborted")


def test_without_a_restart_command_the_pass_stops_loudly():
    o, state = _orch(restart_command="")
    sc = _FakeScanner()
    _instrument_death(o, state, sc, dies_after=1)
    report = o._destructive_pass([SHUTDOWN, REINDEX, DUMPDB], [sc])
    check(len(report["probed"]) == 1, "only the endpoint before the kill was probed")
    check(len(report["skipped"]) == 2,
          f"the unprobed endpoints are listed explicitly ({report['skipped']})")
    check("restart_command" in report["aborted_reason"],
          "the abort reason names the missing restart_command")
    check(any(ev == "destructive_aborted" for ev, _ in o.events),
          "the operator is told — unprobed must never read as clean")


def test_target_is_restored_after_the_pass():
    o, state = _orch(restart_command="true")
    sc = _FakeScanner()
    _instrument_death(o, state, sc, dies_after=3)   # dies on the LAST probe
    report = o._destructive_pass([SHUTDOWN, REINDEX, DUMPDB], [sc])
    check(len(report["probed"]) == 3, "all three were probed")
    check(state["alive"] is True,
          "the target is back up after the pass — verification still needs it")


def test_unrestorable_target_is_flagged_not_hidden():
    o, state = _orch(restart_command="")
    sc = _FakeScanner()
    _instrument_death(o, state, sc, dies_after=3)   # dies on the LAST probe
    report = o._destructive_pass([SHUTDOWN, REINDEX, DUMPDB], [sc])
    check(bool(report.get("post_pass_warning")),
          "a target left down after the pass is recorded as a warning")
    check(any(ev == "destructive_target_down" for ev, _ in o.events),
          "and surfaced to the operator")


def test_disabled_reports_deferred_endpoints_rather_than_omitting_them():
    o, _ = _orch(enabled=False)
    sc = _FakeScanner()
    report = o._destructive_pass([SHUTDOWN, REINDEX], [sc])
    check(sc.seen == [], "nothing is probed when destructive testing is off")
    check(len(report["skipped"]) == 2,
          "but both endpoints are reported as deferred-and-unprobed")
    check("disabled" in report["aborted_reason"],
          "with the reason they were not probed")
    check(report["endpoints"] == [SHUTDOWN.key, REINDEX.key],
          "the report still names the full destructive endpoint set")


def test_lifecycle_ops_get_a_longer_settle_window():
    """Observed live: the target answered for >6s after DELETE /maintenance/_shutdown
    and only died during the NEXT probe, so a short liveness check blamed the
    outage on the wrong endpoint. Lifecycle ops must be given longer to die."""
    from deluluscan.safety import is_lifecycle
    check(is_lifecycle("DELETE", "/admin/maintenance/_shutdown"),
          "shutdown is a lifecycle op (delayed death)")
    check(is_lifecycle("POST", "/api/plugins/_restart"), "restart is a lifecycle op")
    check(is_lifecycle("PUT", "/api/plugins/jar/x.jar/_stop"), "bundle stop is a lifecycle op")
    check(not is_lifecycle("DELETE", "/api/v1/esindex/reindex"),
          "a reindex is destructive but not a lifecycle op")
    check(not is_lifecycle("GET", "/admin/maintenance/_downloadDb"),
          "a DB dump is destructive but not a lifecycle op")

    o, state = _orch(restart_command="true")
    windows = []
    o._target_settled = lambda checks=3, gap_s=2.0: (windows.append(checks), True)[1]
    o._destructive_pass([SHUTDOWN, REINDEX], [_FakeScanner()])
    check(windows and windows[0] > windows[1],
          f"shutdown gets a longer settle window than reindex (got {windows})")


def test_outage_is_attributed_to_the_endpoint_that_caused_it():
    o, state = _orch(restart_command="true")
    sc = _FakeScanner()
    _instrument_death(o, state, sc, dies_after=1)   # the FIRST endpoint kills it
    report = o._destructive_pass([SHUTDOWN, REINDEX, DUMPDB], [sc])
    check(report["caused_outage"] == [SHUTDOWN.key],
          f"the outage is recorded against the endpoint that caused it "
          f"(got {report['caused_outage']})")
    check(any(ev == "destructive_outage" for ev, _ in o.events),
          "and surfaced as evidence that the operation is reachable and worked")


def test_settled_requires_consecutive_answers():
    """A single probe is not enough: a graceful shutdown answers while winding down."""
    o, state = _orch()
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        return calls["n"] == 1      # alive once, then gone

    o._target_alive = flaky
    check(o._target_settled(checks=3, gap_s=0) is False,
          "alive-then-dead does NOT count as settled")
    calls["n"] = 99
    o._target_alive = lambda: True
    check(o._target_settled(checks=3, gap_s=0) is True,
          "consistently alive does count as settled")


def test_empty_destructive_set_is_a_no_op():
    o, _ = _orch()
    report = o._destructive_pass([], [_FakeScanner()])
    check(report["probed"] == [] and report["findings"] == 0,
          "no destructive endpoints -> a clean no-op report")
    check(not any(ev == "destructive_start" for ev, _ in o.events),
          "and no destructive-pass noise in the progress feed")


def main() -> int:
    print("== deferred destructive pass ==")
    test_destructive_endpoints_are_probed_after_the_sweep()
    test_findings_are_marked_as_destructive_pass()
    test_policy_is_open_during_the_pass_and_closed_after()
    test_a_probe_that_kills_the_target_triggers_restart_and_continues()
    test_without_a_restart_command_the_pass_stops_loudly()
    test_target_is_restored_after_the_pass()
    test_unrestorable_target_is_flagged_not_hidden()
    test_disabled_reports_deferred_endpoints_rather_than_omitting_them()
    test_lifecycle_ops_get_a_longer_settle_window()
    test_outage_is_attributed_to_the_endpoint_that_caused_it()
    test_settled_requires_consecutive_answers()
    test_empty_destructive_set_is_a_no_op()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks} checks:")
        for f in _failures:
            print("  -", f)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
