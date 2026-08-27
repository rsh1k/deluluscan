"""Verdict discipline — a verdict must be EARNED by real probes.

The cardinal sin for a security tool is rendering a null result as a confident
refutation: it manufactures false negatives that look like diligence. This
suite locks in the invariant:

    no probes sent  ->  verdict MUST be "not_tested" (never "false_positive")
    probes sent, nothing reproduced -> "false_positive" is legitimate

Regression context: deluluscan.recheck used to default verdict="false_positive"
with confidence="firm", and silently `continue`d past any scanner whose
applies_to() returned False — or, worse, any scanner name that did not exist
at all (the vuln_class->scanner map pointed "authz" at a nonexistent scanner).
The result was confident refutations for endpoints that were never contacted.

Run: python3 -m tests.test_verdict_discipline
"""
from __future__ import annotations

import sys
import types

from deluluscan.recheck import recheck, scanners_for_class, _class_index, _build_endpoint
from deluluscan.scanners import SCANNER_REGISTRY

_checks = 0
_failures: list[str] = []


def check(cond: bool, label: str) -> None:
    global _checks
    _checks += 1
    status = "PASS" if cond else "FAIL"
    print(f"{status}  {label}")
    if not cond:
        _failures.append(label)


class _FakeConfig:
    """Minimal Config stand-in: no network, no auth, loopback-allowed."""
    def __init__(self):
        self.base_url = "http://127.0.0.1:9"     # discard port; nothing listens
        self.verify_tls = False
        self.identities = {}
        # timeout_s belongs on .scan, matching the real ScanConfig. It used to sit
        # at the top level here because recheck() read it off cfg — so the stub
        # mirrored the bug and nothing caught that the configured timeout was
        # being ignored in favour of the 15.0s default.
        self.scan = types.SimpleNamespace(rate_limit_rps=1000.0, timeout_s=0.2)

    def assert_target_allowed(self):
        return True


def test_unknown_scanner_is_not_tested():
    """A scanner name that isn't registered must NOT yield false_positive."""
    ep = _build_endpoint("GET", "/api/plugins", None, None)
    out = recheck(_FakeConfig(), ep, ["authz"])   # 'authz' is a CLASS, not a scanner
    check(out["verdict"] == "not_tested",
          f"unknown scanner -> not_tested (got {out['verdict']!r})")
    check(out["confidence"] == "none",
          f"unknown scanner -> confidence none (got {out['confidence']!r})")
    check(out["retested"] is False, "unknown scanner -> retested False")
    check(out["probe_stats"]["requests"] == 0, "unknown scanner -> zero requests recorded")
    check("authz" in out["scanners_skipped"], "unknown scanner is reported in scanners_skipped")
    check("is not registered" in out["scanners_skipped"]["authz"],
          "skip reason explains the scanner is not registered")
    check("vuln CLASS" in out["scanners_skipped"]["authz"],
          "skip reason hints that 'authz' is a class and suggests --vuln-class")
    check(any("NOT TESTED" in r for r in out["reasons"]),
          "reasons state NOT TESTED explicitly")
    # It is fine (good, even) to say "this is NOT a false positive"; what must
    # never happen is ASSERTING the candidate is one.
    check(not any("appears to be a FALSE POSITIVE" in r for r in out["reasons"]),
          "reasons must NOT assert false positive when nothing was tested")
    check(out["verdict"] != "false_positive",
          "verdict must not be false_positive when nothing was tested")


def test_non_applicable_scanner_is_not_tested():
    """applies_to()==False must be surfaced as not_tested, not a refutation."""
    class _NeverApplies:
        name = "never"
        vuln_classes = ["sqli"]

        def __init__(self, *a, **kw):
            pass

        def applies_to(self, endpoint):
            return False

        def run(self, endpoint):
            raise AssertionError("run() must not be called when applies_to() is False")

    SCANNER_REGISTRY["_test_never"] = _NeverApplies
    try:
        ep = _build_endpoint("GET", "/api/v1/thing", None, None)
        out = recheck(_FakeConfig(), ep, ["_test_never"])
        check(out["verdict"] == "not_tested",
              f"applies_to False -> not_tested (got {out['verdict']!r})")
        check("_test_never" in out["scanners_skipped"],
              "non-applicable scanner reported in scanners_skipped")
        check("applies_to" in out["scanners_skipped"]["_test_never"],
              "skip reason names applies_to()")
    finally:
        SCANNER_REGISTRY.pop("_test_never", None)


def test_scanner_that_sends_nothing_is_not_tested():
    """A scanner that runs but sends zero HTTP requests proves nothing."""
    class _SilentScanner:
        name = "silent"
        vuln_classes = ["sqli"]

        def __init__(self, *a, **kw):
            pass

        def applies_to(self, endpoint):
            return True

        def run(self, endpoint):
            return []          # no findings AND no traffic

    SCANNER_REGISTRY["_test_silent"] = _SilentScanner
    try:
        ep = _build_endpoint("GET", "/api/v1/thing", None, None)
        out = recheck(_FakeConfig(), ep, ["_test_silent"])
        check(out["verdict"] == "not_tested",
              f"zero-traffic scanner -> not_tested (got {out['verdict']!r})")
        check("zero HTTP requests" in out["scanners_skipped"].get("_test_silent", ""),
              "skip reason names the zero-request condition")
    finally:
        SCANNER_REGISTRY.pop("_test_silent", None)


def test_real_probe_with_no_finding_is_a_legitimate_refutation():
    """A scanner that genuinely sends traffic and finds nothing MAY refute."""
    class _ProbingScanner:
        name = "probing"
        vuln_classes = ["sqli"]

        def __init__(self, client, auth, config, identities):
            self.client = client

        def applies_to(self, endpoint):
            return True

        def run(self, endpoint):
            # real request attempt; target is a dead port so it errors, but the
            # attempt is genuine and is recorded by the telemetry counters.
            self.client.request("GET", "/probe", identity_label="anonymous")
            return []

    SCANNER_REGISTRY["_test_probing"] = _ProbingScanner
    try:
        ep = _build_endpoint("GET", "/api/v1/thing", None, None)
        out = recheck(_FakeConfig(), ep, ["_test_probing"])
        check(out["probe_stats"]["requests"] >= 1,
              "probing scanner records at least one request attempt")
        # transport failed (dead port) => no responses => still not_tested,
        # because an unreachable target cannot refute anything either.
        check(out["verdict"] == "not_tested",
              f"probe attempted but no response -> not_tested (got {out['verdict']!r})")
    finally:
        SCANNER_REGISTRY.pop("_test_probing", None)


def test_class_index_is_derived_from_registry():
    """vuln_class -> scanner mapping must come from the registry, not a literal."""
    idx = _class_index()
    check("authz" in idx and len(idx["authz"]) > 1,
          "authz class maps to multiple real scanners")
    for vc, names in idx.items():
        for n in names:
            check_ok = n in SCANNER_REGISTRY
            if not check_ok:
                check(False, f"class index references unknown scanner {n!r} for {vc!r}")
                return
    check(True, "every scanner named in the class index actually exists")
    # the historical bug: "authz" resolving to a scanner literally named "authz"
    check("authz" not in SCANNER_REGISTRY,
          "no scanner is literally named 'authz' (it is a class) — mapping must expand it")
    check(all(n in SCANNER_REGISTRY for n in scanners_for_class("authz")),
          "scanners_for_class('authz') returns only real, registered scanners")


def main() -> int:
    print("== verdict discipline ==")
    test_unknown_scanner_is_not_tested()
    test_non_applicable_scanner_is_not_tested()
    test_scanner_that_sends_nothing_is_not_tested()
    test_real_probe_with_no_finding_is_a_legitimate_refutation()
    test_class_index_is_derived_from_registry()
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
