"""Offline tests for the timing-differential request-smuggling detector.

An injected sender fakes elapsed times so no socket is opened. Locks down: the
non-destructive detection logic, the confirm-before-report discipline, and the
tentative grading (timing is a lead, not proof)."""
from __future__ import annotations

from deluluscan.active.smuggling import SmugglingProbe, DesyncResult
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def _sender(clte=0.05, tecl=0.05, baseline=0.05):
    """Return elapsed based on which payload is sent."""
    def send(host, port, tls, raw, timeout):
        if b"Transfer-Encoding" in raw:
            return clte if raw.rstrip().endswith(b"1\r\nA\r\nX") else tecl
        return baseline
    return send


def test_clean_server_no_findings():
    probe = SmugglingProbe(send=_sender(), timeout=8, min_gap_s=4)
    res, finds = probe.run("t", 80, "/")
    check("no desync on fast server", not any(r.suspected for r in res))
    check("no findings", finds == [])


def test_clte_desync_detected():
    probe = SmugglingProbe(send=_sender(clte=8.0), timeout=8, min_gap_s=4)  # CL.TE hangs
    res, finds = probe.run("t", 80, "/")
    clte = next(r for r in res if r.variant == "CL.TE")
    check("CL.TE suspected", clte.suspected, clte)
    check("finding emitted", any("CL.TE" in f.title for f in finds), [f.title for f in finds])
    f = finds[0]
    check("smuggling is HIGH", f.severity == Severity.HIGH)
    check("graded tentative/inconclusive (timing is a lead)",
          f.confidence == "tentative" and f.verdict == "inconclusive")
    check("exploitability unknown", f.exploitability == "unknown")
    check("basis is timing_differential", f.detail.get("basis") == "timing_differential")


def test_tecl_desync_detected():
    probe = SmugglingProbe(send=_sender(tecl=8.0), timeout=8, min_gap_s=4)
    res, finds = probe.run("t", 80, "/")
    check("TE.CL suspected", any(r.variant == "TE.CL" and r.suspected for r in res))
    check("TE.CL finding", any("TE.CL" in f.title for f in finds))


def test_small_delay_not_flagged():
    # a 2x-but-under-min_gap slowdown must NOT trip (avoids noise-driven FPs)
    probe = SmugglingProbe(send=_sender(clte=0.15, baseline=0.05), timeout=8,
                           delay_factor=3.0, min_gap_s=4.0)
    res, finds = probe.run("t", 80, "/")
    check("minor jitter not flagged", finds == [], [f.title for f in finds])


def test_unreachable_host_safe():
    def boom(host, port, tls, raw, timeout): raise OSError("refused")
    probe = SmugglingProbe(send=boom)
    res, finds = probe.run("t", 80, "/")
    check("unreachable -> no crash, no findings", res == [] and finds == [])


def test_confirm_before_report():
    # first CL.TE probe hangs, but the confirmation probe is fast -> NOT reported
    calls = {"n": 0}
    def send(host, port, tls, raw, timeout):
        if b"Transfer-Encoding" in raw and raw.rstrip().endswith(b"1\r\nA\r\nX"):
            calls["n"] += 1
            return 8.0 if calls["n"] == 1 else 0.05   # transient blip, then fast
        return 0.05
    probe = SmugglingProbe(send=send, timeout=8, min_gap_s=4)
    res, finds = probe.run("t", 80, "/")
    check("transient blip is re-probed and dropped", finds == [], [f.title for f in finds])


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
