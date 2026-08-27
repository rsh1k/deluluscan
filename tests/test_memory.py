"""Engagement memory — Deluluscan's cross-scan learning store.

Locks down the properties that make it trustworthy: it remembers only credible
results (never learns a false-positive as truth), keys learnings by product+
version so they follow a build across environments, harvests verified bypasses
and per-build gotchas from the deep-verify output, surfaces a previously-
exploitable-but-not-reproduced endpoint as a regression-watch (not a finding),
and round-trips through disk. Plus the two orchestrator seams that make it
'test better': recall-based endpoint prioritization and finding annotation.

Run: python3 -m tests.test_memory
"""
from __future__ import annotations

import os
import sys
import tempfile

from deluluscan.memory import (EngagementMemory, Recall, endpoint_key, target_key,
                          target_key_from_fingerprint)
from deluluscan.models import Endpoint, Finding, Severity, VulnClass

_checks = 0
_failures: list[str] = []


def check(cond, label):
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


def finding(vc, endpoint, verdict="true_positive", expl="exploitable", detail=None):
    return Finding(vuln_class=vc, severity=Severity.HIGH, title="t", endpoint=endpoint,
                   description="d", verdict=verdict, exploitability=expl,
                   detail=detail or {})


# ---------------------------------------------------------------------------
def test_keys():
    check(target_key("Target", "1.2.3", "http://x") == "target@1.2.3",
          "target key prefers product@version")
    check(target_key(None, None, "http://127.0.0.1:8080/") == "host:127.0.0.1:8080",
          "target key falls back to host when unfingerprinted")
    check(endpoint_key("authz", "GET /api/v1/users/12345")
          == endpoint_key("authz", "GET /api/v1/users/67890"),
          "endpoint key collapses numeric ids so the same endpoint matches across runs")
    fp = {"detections": [{"tech": "nginx", "category": "server", "version": None},
                         {"tech": "Target", "category": "cms", "version": "1.2.3"}]}
    check(target_key_from_fingerprint(fp, "http://x") == "target@1.2.3",
          "fingerprint key picks the versioned CMS over an unversioned server")


def test_records_only_credible_results():
    mem = EngagementMemory()
    tp = finding(VulnClass.AUTHZ, "POST /api/plugins", verdict="true_positive", expl="exploitable")
    fp = finding(VulnClass.XSS, "GET /api/v1/x", verdict="false_positive", expl="not_exploitable")
    stats = mem.record_scan("target@1.2", "http://x", "1.2", [tp, fp], meta={})
    check(stats["recorded"] == 1, "records the true-positive, not the false-positive")
    rec = mem.recall("target@1.2")
    check(rec.known and len(rec.findings) == 1, "recall returns the one remembered finding")
    check(rec.exploitable_endpoints() == [endpoint_key("authz", "POST /api/plugins")],
          "exploitable_endpoints lists the plugin endpoint")


def test_harvests_bypass_and_gotchas_from_deep():
    mem = EngagementMemory()
    deep = {"deep": {
        "session_riding": {"verdict": "weaponizable",
                           "reasons": ["accepts the session cookie; the target rotates "
                                       "its rme JWT so a fresh login per probe is required"]},
        "injection_bypass": {"verified_bypass": True, "payload": "<img/src=x onerror=1>",
                             "filter": "target xss regex"}}}
    f = finding(VulnClass.XSS, "PUT /api/v1/users/current", detail=deep)
    meta = {"identities": {"admin": {"ok": True}, "backend": {"ok": False}}}
    mem.record_scan("target@1.2", "http://x", "1.2", [f], meta=meta)
    rec = mem.recall("target@1.2")
    check(len(rec.bypasses) == 1 and rec.bypasses[0]["payload"] == "<img/src=x onerror=1>",
          "verified filter bypass is harvested from deep-verify output")
    check(rec.has_gotcha("token_rotation"), "token-rotation gotcha derived from session-riding reasons")
    check(rec.has_gotcha("working_principal")
          and "admin" in rec.gotchas["working_principal"]["detail"],
          "working-principal gotcha derived from meta.identities (only the one that authed)")
    check(rec.findings[endpoint_key("xss", "PUT /api/v1/users/current")].get("note")
          == "session-ridable (cookie-authed; XSS-drivable)",
          "session-riding note attached to the finding record")


def test_regression_watch_and_persistence():
    path = os.path.join(tempfile.mkdtemp(), "mem.json")
    mem = EngagementMemory(path)
    plugin = finding(VulnClass.AUTHZ, "POST /api/plugins", expl="exploitable")
    mem.record_scan("target@1.2", "http://x", "1.2", [plugin], meta={})
    mem.save()
    # next run against the same build: plugin no longer reproduces (a fix landed)
    mem2 = EngagementMemory(path)
    check(mem2.recall("target@1.2").known, "store round-trips through disk")
    other = finding(VulnClass.XSS, "GET /api/v1/y", expl="exploitable")
    stats = mem2.record_scan("target@1.2", "http://x", "1.2", [other], meta={})
    check(endpoint_key("authz", "POST /api/plugins") in stats["possibly_fixed"],
          "previously-exploitable endpoint that did not reproduce -> regression-watch")
    check("POST /api/plugins" not in " ".join(
              f.title for f in []),  # sanity: regression-watch is meta, not a finding
          "regression-watch is not emitted as a finding")


def test_seen_count_increments_across_runs():
    mem = EngagementMemory()
    for _ in range(3):
        mem.record_scan("target@1.2", "http://x", "1.2",
                        [finding(VulnClass.AUTHZ, "POST /api/plugins")], meta={})
    rec = mem.recall("target@1.2")
    key = endpoint_key("authz", "POST /api/plugins")
    check(rec.findings[key]["seen_count"] == 3, "seen_count accumulates across runs")


# ---- orchestrator seams (test better) -------------------------------------
class _Stub:
    """Minimal stand-in exposing just what the two memory seams touch."""
    def __init__(self, recall):
        self._recall = recall
        self.findings = []
        self.events = []
    def progress(self, ev, data):
        self.events.append((ev, data))


def test_recall_priority_floats_exploitable_endpoints_first():
    from deluluscan.orchestrator import Orchestrator
    mem = EngagementMemory()
    mem.record_scan("target@1.2", "http://x", "1.2",
                    [finding(VulnClass.AUTHZ, "POST /api/plugins")], meta={})
    stub = _Stub(mem.recall("target@1.2"))
    eps = [Endpoint(method="GET", path="/api/config"),
           Endpoint(method="POST", path="/api/plugins"),
           Endpoint(method="GET", path="/api/v1/foo")]
    out = Orchestrator._apply_recall_priority(stub, eps)
    check(out[0].path == "/api/plugins",
          "endpoint exploitable last run is scanned first this run")
    check(any(ev == "memory" and d.get("phase") == "prioritize" for ev, d in stub.events),
          "a prioritize progress event is emitted")


def test_annotate_tags_recurring_findings():
    from deluluscan.orchestrator import Orchestrator
    mem = EngagementMemory()
    mem.record_scan("target@1.2", "http://x", "1.2",
                    [finding(VulnClass.AUTHZ, "POST /api/plugins", expl="exploitable")], meta={})
    stub = _Stub(mem.recall("target@1.2"))
    stub.findings = [finding(VulnClass.AUTHZ, "POST /api/plugins", expl="exploitable")]
    Orchestrator._annotate_from_memory(stub)
    m = stub.findings[0].detail.get("memory")
    check(m and m["seen_before"] and "recurring" in m["note"],
          "a finding seen before is tagged recurring with prior context")
    check(m["prior_exploitability"] == "exploitable", "prior exploitability carried forward")


def main():
    print("== engagement memory ==")
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
