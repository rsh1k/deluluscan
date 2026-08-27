"""Generalised deep verification runs researcher-grade depth on EVERY class, not
just stored XSS: multi-identity re-testing, session-riding auth analysis, and
filter-bypass computation — refining exploitability only on concrete evidence and
never flipping a live verdict.

Run: python3 -m tests.test_deep_generalized
"""
from __future__ import annotations

import sys

from deluluscan.models import Finding, Severity, VulnClass
from deluluscan.verify.deep import (DeepContext, DeepVerifier, IdentityMatrixStrategy,
                               InjectionBypassStrategy, SessionRidingStrategy,
                               is_privileged_endpoint, split_endpoint)

_checks = 0
_failures: list[str] = []


def check(cond, label):
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


def finding(vc, endpoint, verdict="true_positive", expl="unknown", sev=Severity.HIGH):
    return Finding(vuln_class=vc, severity=sev, title="t", endpoint=endpoint,
                   description="d", verdict=verdict, exploitability=expl)


class FakeCtx(DeepContext):
    """DeepContext with the four live seams stubbed."""
    def __init__(self, identities, statuses=None, vectors=None, cookies=None):
        super().__init__(identities={l: object() for l in identities})
        self._statuses = statuses or {}
        self._vectors = vectors or {}
        self._cookies = cookies or []
        # every identity must look usable to victim_label(); patch membership
        self._usable = set(identities)
    def victim_label(self):
        for l in ("admin", "backend"):
            if l in self._usable:
                return l
        return None
    def probe_as(self, label, method, path):
        return self._statuses.get(label, 401)
    def auth_vectors(self, method, path, victim_label):
        return dict(self._vectors)
    def cookie_facts(self, victim_label):
        return list(self._cookies)


# ---------------------------------------------------------------------------
def test_helpers():
    check(split_endpoint("PUT /api/v1/x") == ("PUT", "/api/v1/x"), "endpoint split")
    check(is_privileged_endpoint("/api/v1/plugins"), "plugin is privileged")
    check(not is_privileged_endpoint("/api/v1/appconfiguration"), "appconfig is not privileged")


def test_identity_matrix_finds_who_gets_in():
    ctx = FakeCtx(["anonymous", "backend", "admin"],
                  statuses={"anonymous": 401, "backend": 200, "admin": 200})
    f = finding(VulnClass.AUTHZ, "GET /api/v1/roles/layouts")
    s = IdentityMatrixStrategy()
    check(s.applies(f), "applies to a GET authz finding")
    res = s.analyze(f, ctx)
    check(res.analysis["sub_tier_reachable"] == ["backend"],
          f"identifies the sub-tier identity that got in (got {res.analysis['sub_tier_reachable']})")
    check(any("broken access control confirmed across identities" in r for r in res.reasons),
          "reasons state the differential result")


def test_session_riding_weaponizable_when_cookie_authed():
    ctx = FakeCtx(["admin", "backend"],
                  vectors={"anonymous": 401, "session_cookie": 200, "bearer_jwt": 200, "basic": 200})
    f = finding(VulnClass.AUTHZ, "POST /api/v1/plugins", expl="conditional")
    s = SessionRidingStrategy()
    check(s.applies(f), "applies to a privileged endpoint")
    res = s.analyze(f, ctx)
    check(res.analysis["verdict"] == "weaponizable", "cookie-authed -> weaponizable")
    check(res.exploitability == "exploitable",
          "refines conditional -> exploitable on session-riding evidence")


def test_session_riding_contained_downgrades_overclaim():
    from deluluscan.verify.exploitability import analyze_set_cookie
    ctx = FakeCtx(["admin"],
                  vectors={"anonymous": 401, "session_cookie": 401, "bearer_jwt": 200, "basic": 200},
                  cookies=analyze_set_cookie(["rme=eyJa.eyJbxxxxxx.sig; HttpOnly", "JSESSIONID=x; HttpOnly"]))
    f = finding(VulnClass.AUTHZ, "POST /api/v1/plugins", expl="exploitable")
    res = SessionRidingStrategy().analyze(f, ctx)
    check(res.analysis["verdict"] == "contained", "header-only + all-HttpOnly -> contained")
    check(res.exploitability == "conditional",
          "downgrades an over-claimed 'exploitable' to 'conditional' with evidence")


def test_injection_bypass_computes_verified_bypass():
    f = finding(VulnClass.XSS, "PUT /api/v1/users/current")
    res = InjectionBypassStrategy().analyze(f, finding and FakeCtx([]))
    check(res.analysis["verified_bypass"] is True, "computes a verified filter bypass for XSS")
    check(any("beats the input filter" in r for r in res.reasons), "reasons name the bypass")


def test_deep_verifier_enriches_and_respects_discipline():
    ctx = FakeCtx(["anonymous", "backend", "admin"],
                  statuses={"anonymous": 200, "backend": 200, "admin": 200},
                  vectors={"anonymous": 401, "session_cookie": 200, "bearer_jwt": 200, "basic": 200})
    tp = finding(VulnClass.AUTHZ, "GET /api/v1/roles/layouts", verdict="true_positive", expl="conditional")
    fp = finding(VulnClass.AUTHZ, "GET /api/v1/roles/layouts", verdict="false_positive", expl="not_exploitable")
    stats = DeepVerifier(ctx).run([tp, fp])
    check("deep" in tp.detail, "credible finding gets a deep analysis block")
    check(tp.detail["deep"].get("identity_matrix"), "identity matrix ran")
    check(tp.detail["deep"].get("session_riding"), "session riding ran")
    check(tp.exploitability == "exploitable", "exploitability refined on evidence")
    check("deep" not in fp.detail, "a false-positive is NOT re-tested (no wasted probes, no flip)")
    check(fp.verdict == "false_positive", "deep layer never changes the verdict")
    check(stats["exploitability_refined"] >= 1, "stats count the refinement")
    check(any("[deep:" in r for r in tp.detail.get("verification", {}).get("reasons", [])),
          "deep reasons are threaded into the verification block for the report")


def main():
    print("== generalised deep verification ==")
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
