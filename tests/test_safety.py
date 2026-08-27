"""Tests for the generic destructive-operation safety policy (deluluscan/safety.py).

Destructive ops (shutdown / bulk delete / reindex / DB dump) are classified and
DEFERRED to a dedicated pass after the main sweep, never sent mid-sweep. This
covers the generic classifier + split + policy phases (no product-specific rules).
Run: python3 -m tests.test_safety
"""
import os, sys, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from deluluscan.models import Endpoint  # noqa: E402
from deluluscan.safety import (is_destructive, is_lifecycle, destructive_reason,  # noqa: E402
                               split_destructive, DestructivePolicy, UnrestrictedPolicy)
_PASS = 0; _FAIL = 0
def check(n, c, d=""):
    global _PASS, _FAIL
    if c: _PASS += 1; print(f"PASS  {n}")
    else: _FAIL += 1; print(f"FAIL  {n}  [{d}]")

def test_classifier_flags_destructive():
    for m, p in [("POST", "/api/v1/system/_shutdown"), ("DELETE", "/admin/maintenance"),
                 ("POST", "/admin/maintenance/reindex"), ("POST", "/api/db/dump")]:
        check(f"{m} {p} classified destructive", is_destructive(m, p), destructive_reason(m, p))

def test_classifier_leaves_safe_ops_alone():
    for m, p in [("GET", "/api/v1/users/1"), ("POST", "/api/v1/login"),
                 ("GET", "/api/v1/content"), ("PUT", "/api/v1/profile")]:
        check(f"{m} {p} not destructive", not is_destructive(m, p), f"{m} {p}")

def test_split_defers_destructive():
    eps = [Endpoint("GET", "/api/v1/users"), Endpoint("POST", "/api/v1/system/_shutdown"),
           Endpoint("DELETE", "/api/v1/content/_delete"), Endpoint("GET", "/api/v1/health")]
    safe, destructive = split_destructive(eps)
    check("safe endpoints kept in the main sweep", len(safe) == 2)
    check("destructive endpoints split out", len(destructive) == 2
          and all(is_destructive(e.method, e.path) for e in destructive))

def test_policy_gates_until_destructive_phase():
    pol = DestructivePolicy(enabled=True)
    check("destructive op blocked before the destructive phase",
          not pol.allows("POST", "/api/v1/system/_shutdown")[0])
    pol.begin_destructive_phase()
    check("destructive op allowed during the destructive phase",
          pol.allows("POST", "/api/v1/system/_shutdown")[0])
    pol.end_destructive_phase()
    check("safe op always allowed", pol.allows("GET", "/api/v1/users")[0])

def test_disabled_policy_never_sends_destructive():
    pol = DestructivePolicy(enabled=False)
    pol.begin_destructive_phase()
    check("disabled policy still blocks destructive ops",
          not pol.allows("POST", "/api/v1/system/_shutdown")[0])

if __name__ == "__main__":
    for fn in [v for v in list(globals().values()) if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try: fn()
        except Exception as e:
            import traceback; _FAIL += 1; print(f"FAIL  {fn.__name__}  [exc: {e}]"); traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed"); sys.exit(1 if _FAIL else 0)
