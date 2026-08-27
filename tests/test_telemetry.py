"""Grey-box observability plane — signatures, recorder, and the correlator that
turns a telemetry timeline + probe windows into findings.

Everything here is exercised OFFLINE against synthetic events and probe windows —
no Docker, no live target — because the live sources are fail-soft plumbing and
the security signal lives in the pure functions here.

Run: python3 -m tests.test_telemetry
"""
from __future__ import annotations

import sys
import time

from deluluscan.models import Severity, VulnClass
from deluluscan.telemetry import Recorder, Correlator, ProbeWindow, probe_windows_from
from deluluscan.telemetry import signatures as sig

_checks = 0
_failures: list[str] = []


def check(cond, label):
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


# ---- signatures -----------------------------------------------------------
def test_trace_classification():
    s = sig.classify_trace("org.postgresql.util.PSQLException: ERROR: syntax error at or near \"'\"")
    check(s is not None and s.vuln_class == "sqli", "PSQLException -> sqli")
    s = sig.classify_trace("freemarker.core.InvalidReferenceException: expression is undefined")
    check(s is not None and s.vuln_class == "ssti", "freemarker -> ssti")
    s = sig.classify_trace("java.io.InvalidClassException: local class incompatible")
    check(s is not None and s.vuln_class == "supply_chain", "InvalidClassException -> deser/supply_chain")
    s = sig.classify_trace("java.lang.OutOfMemoryError: Java heap space")
    check(s is not None and s.vuln_class == "rate_limit" and s.label == "Out of memory",
          "OutOfMemoryError -> rate_limit")
    check(sig.classify_trace("GET /api/v1/health 200 12ms") is None,
          "an ordinary access-log line is not an exception")


def test_secret_redaction():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.abcdEFGH1234"
    line = f"INFO logged in token={jwt} for user"
    red, kinds = sig.redact_secrets(line)
    check("jwt" in kinds, "jwt detected in log line")
    check(jwt not in red and "<redacted:jwt>" in red, "jwt value is redacted, not retained")

    line2 = "DEBUG connecting password=SuperSecret123! to db"
    red2, kinds2 = sig.redact_secrets(line2)
    check("password" in kinds2 and "SuperSecret123!" not in red2,
          "password value redacted")

    red3, kinds3 = sig.redact_secrets("plain informational line, nothing secret")
    check(not kinds3 and red3 == "plain informational line, nothing secret",
          "benign line untouched")


def test_forged_line_detection():
    lines = ["INFO real log line", "FORGED-abc123 injected entry", "INFO another"]
    check(sig.forged_line_present(lines, "FORGED-abc123"), "forged line at start detected")
    inline = ["INFO user said FORGED-abc123 inline within a field"]
    check(not sig.forged_line_present(inline, "FORGED-abc123"),
          "marker inline within a legit line is NOT a forged line")


# ---- recorder -------------------------------------------------------------
def test_recorder_redacts_at_ingest_and_classifies():
    rec = Recorder()
    ev = rec.add_log("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.SIG12345 here", wall=100.0)
    check("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.SIG12345" not in ev.text,
          "recorder redacts secrets at ingest (never stored raw)")
    check(ev.data.get("secret_kinds") == ["jwt"], "recorder tags secret kind")
    ev2 = rec.add_log("org.postgresql.util.PSQLException: ERROR: bad", wall=101.0)
    check(ev2.kind == "exception" and ev2.data.get("trace_class") == "sqli",
          "recorder classifies an exception line")
    win = rec.window(100.5, 101.5, pad_before=0.6, pad_after=0.6)
    check(len(win) == 2, "window returns events within [t0-pad, t1+pad]")


# ---- correlator: trace-leak ----------------------------------------------
def _win(method, path, status, t0, dur=0.1, ident="anonymous"):
    return ProbeWindow(method=method, url=f"http://localhost:8080{path}",
                       status=status, identity=ident, t0=t0, t1=t0 + dur)


def test_trace_leak_attributed_to_probe():
    rec = Recorder()
    base = 1000.0
    # a SQL error appears right after a probe to /api/categories
    rec.add_log("org.postgresql.util.PSQLException: ERROR: unterminated quoted string",
                wall=base + 5.1)
    windows = [_win("GET", "/api/v1/content", 200, base + 1.0),
               _win("GET", "/api/categories", 500, base + 5.0)]
    corr = Correlator(rec, baseline_end=base)
    findings = corr.analyze_trace_leaks(windows)
    check(len(findings) == 1, "one trace-leak finding produced")
    f = findings[0]
    check(f.vuln_class == VulnClass.SQLI, "trace-leak finding is SQLi")
    check("/api/categories" in f.endpoint, "attributed to the correct (latest overlapping) probe")
    check(f.confidence == "firm" and f.verdict == "likely_true_positive",
          "server-log-confirmed => firm/likely_true_positive (live re-test still owns final verdict)")


def test_baseline_exception_is_not_reported():
    rec = Recorder()
    base = 2000.0
    # a PSQLException BEFORE the sweep began (startup noise)
    rec.add_log("org.postgresql.util.PSQLException: ERROR: pre-existing", wall=base - 10)
    windows = [_win("GET", "/api/categories", 500, base + 1.0)]
    corr = Correlator(rec, baseline_end=base)
    # same label appears during sweep too -> still suppressed as baseline noise
    rec.add_log("org.postgresql.util.PSQLException: ERROR: during", wall=base + 1.05)
    findings = corr.analyze_trace_leaks(windows)
    check(findings == [], "an exception label seen in the baseline is not attributed to a probe")


def test_trace_leak_skips_auth_rejected_probe_when_a_real_candidate_overlaps():
    # Regression: the target build 1.2.4 live scan. An orderby SQLi trace from
    # GET /api/categories (real, confirmed separately) landed inside the
    # correlation window of a concurrent, unrelated POST /api/v1/workflow/1/comments
    # request that WebResource rejected with 401 before touching any query —
    # the old "latest overlapping window wins" rule attributed the trace to the
    # 401'd comments endpoint just because it started later, producing a
    # server-log-confirmed SQLi finding on an endpoint the request never reached.
    rec = Recorder()
    base = 4000.0
    rec.add_log("org.postgresql.util.PSQLException: ERROR: syntax error at or near \"ASC\"",
                wall=base + 0.5)
    windows = [_win("GET", "/api/categories", 500, base + 0.4, dur=0.05),
               _win("POST", "/api/v1/workflow/1/comments", 401, base + 0.9, dur=0.01,
                    ident="anonymous")]
    corr = Correlator(rec, baseline_end=base)
    findings = corr.analyze_trace_leaks(windows)
    check(len(findings) == 1, "one trace-leak finding produced")
    check("/api/categories" in findings[0].endpoint,
          "attributed to the real (non-rejected) candidate, not the later 401'd one")


def test_trace_leak_falls_back_to_rejected_probe_if_nothing_else_overlaps():
    # An auth-rejected window is still better than no attribution at all when
    # it's the ONLY candidate — this keeps existing single-candidate behaviour.
    rec = Recorder()
    base = 4500.0
    rec.add_log("org.postgresql.util.PSQLException: ERROR: boom", wall=base + 0.5)
    windows = [_win("GET", "/api/roles", 401, base + 0.4, dur=0.05)]
    corr = Correlator(rec, baseline_end=base)
    findings = corr.analyze_trace_leaks(windows)
    check(len(findings) == 1 and "/api/roles" in findings[0].endpoint,
          "falls back to the only overlapping (rejected) window rather than dropping the event")


def test_unattributable_trace_skipped():
    rec = Recorder()
    base = 3000.0
    rec.add_log("freemarker.core.ParseException: boom", wall=base + 50)  # no probe near t=+50
    windows = [_win("GET", "/x", 200, base + 1.0)]
    corr = Correlator(rec, baseline_end=base)
    check(corr.analyze_trace_leaks(windows) == [],
          "a trace with no overlapping probe window is not guessed at")


# ---- correlator: secrets in logs -----------------------------------------
def test_secrets_in_logs_finding():
    rec = Recorder()
    rec.add_log("password=hunter2 while starting", wall=10.0)
    rec.add_log("password=hunter2 again", wall=11.0)
    corr = Correlator(rec, baseline_end=0.0)
    findings = corr.analyze_secrets_in_logs()
    check(len(findings) == 1 and findings[0].vuln_class == VulnClass.INFO_LEAK,
          "secret-in-logs -> one INFO_LEAK finding")
    check(findings[0].detail.get("occurrences") == 2, "occurrences counted")
    check("hunter2" not in findings[0].evidence[0].resp_body,
          "the raw secret is never carried into the finding evidence")


# ---- correlator: detection gap -------------------------------------------
def test_detection_gap_flags_unlogged_writes():
    rec = Recorder()
    base = 5000.0
    # some UNRELATED log activity exists (so we DO have log visibility), but not
    # in the windows of the write operations
    rec.add_log("INFO periodic housekeeping", wall=base + 0.2)
    corr = Correlator(rec, baseline_end=base)
    windows = [_win("POST", "/api/v1/users", 201, base + 10 + i) for i in range(4)]
    findings = corr.analyze_detection_gap(windows)
    check(len(findings) == 1 and findings[0].vuln_class == VulnClass.LOGGING_FAILURE,
          "4 unlogged writes -> one LOGGING_FAILURE finding")
    check(findings[0].detail.get("unlogged") == 4, "counts the unlogged operations")


def test_detection_gap_silent_when_logged():
    rec = Recorder()
    base = 6000.0
    corr = Correlator(rec, baseline_end=base)
    windows = []
    for i in range(4):
        t = base + 10 + i
        windows.append(_win("POST", "/api/v1/users", 201, t))
        rec.add_log(f"AUDIT user created req#{i}", wall=t + 0.05)  # each IS logged
    check(corr.analyze_detection_gap(windows) == [],
          "operations that ARE logged produce no detection-gap finding")


def test_detection_gap_abstains_without_log_visibility():
    rec = Recorder()          # no log events at all
    base = 7000.0
    corr = Correlator(rec, baseline_end=base)
    windows = [_win("POST", "/api/v1/users", 201, base + 10 + i) for i in range(4)]
    check(corr.analyze_detection_gap(windows) == [],
          "with no log source observed, we abstain (cannot tell 'unlogged' from 'unobserved')")


# ---- correlator: memory ---------------------------------------------------
def test_memory_growth_lead():
    rec = Recorder()
    base = 8000.0
    for i in range(3):        # baseline ~100MB
        rec.add_stats({"mem_bytes": 100_000_000, "cpu_pct": 5.0, "pids": 40}, wall=base - 5 + i)
    for i in range(6):        # climbs to ~300MB and stays
        rec.add_stats({"mem_bytes": 100_000_000 + (i + 1) * 40_000_000}, wall=base + 1 + i)
    corr = Correlator(rec, baseline_end=base)
    findings = corr.analyze_memory()
    mem = [f for f in findings if f.detail.get("test") == "telemetry_mem_growth"]
    check(len(mem) == 1 and mem[0].vuln_class == VulnClass.RATE_LIMIT,
          "sustained heap growth -> a RATE_LIMIT lead")
    check(mem[0].confidence == "tentative" and mem[0].verdict == "unverified",
          "memory growth is a LEAD (tentative/unverified), never a hard verdict")


def test_memory_stable_no_finding():
    rec = Recorder()
    base = 9000.0
    for i in range(9):        # flat
        rec.add_stats({"mem_bytes": 120_000_000}, wall=base - 3 + i)
    corr = Correlator(rec, baseline_end=base)
    check([f for f in corr.analyze_memory() if f.detail.get("test") == "telemetry_mem_growth"] == [],
          "flat memory produces no growth lead")


def test_oom_in_log_is_firm():
    rec = Recorder()
    base = 9500.0
    rec.add_log("java.lang.OutOfMemoryError: Java heap space", wall=base + 3)
    corr = Correlator(rec, baseline_end=base)
    oom = [f for f in corr.analyze_memory() if f.detail.get("test") == "telemetry_oom"]
    check(len(oom) == 1 and oom[0].severity == Severity.HIGH and oom[0].confidence == "firm",
          "an OOM in the log stream is a firm high-severity finding")


# ---- knowledge coverage for new classes ----------------------------------
def test_new_classes_have_methodology():
    from deluluscan import knowledge as kb
    for vc in (VulnClass.LOGGING_FAILURE, VulnClass.LOG_INJECTION, VulnClass.MEMORY_DISCLOSURE):
        k = kb.methodology_for(vc)
        check(k is not None and k.summary and k.verify and k.remediation and k.owasp_2025,
              f"knowledge base covers {vc.value}")


# ---- probe-window plumbing ------------------------------------------------
def test_probe_windows_from_dicts():
    raw = [{"method": "GET", "url": "http://h/x", "status": 200,
            "identity": "anon", "t0": 1.0, "t1": 1.2},
           {"bad": "row"}]           # malformed rows are skipped, not fatal
    ws = probe_windows_from(raw)
    check(len(ws) == 1 and ws[0].path == "/x", "probe_windows_from parses good rows, skips bad")


def test_http_client_probe_log_capture():
    # the choke-point capture is opt-in and records a window per SENT request
    from deluluscan.http_client import HttpClient
    c = HttpClient("http://localhost:9")   # nothing listening -> transport error path
    check(c.probe_log is None, "probe_log is off by default (zero overhead)")
    c.enable_probe_log()
    c.request("GET", "/nope", identity_label="anonymous")   # errors, but still a window
    check(len(c.probe_log) == 1 and c.probe_log[0]["method"] == "GET",
          "enabling probe_log records a window even on the transport-error path")


def main():
    print("== deluluscan telemetry / observability ==")
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
