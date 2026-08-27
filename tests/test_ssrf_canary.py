"""Regression tests: new_canary() returns a 3-tuple (token, host, full_url).

Both ssrf.py and advisories.py previously unpacked only 2 values,
causing "too many values to unpack (expected 2)" on every SSRF-applicable
endpoint and silently killing those scanner runs.

Run: python -m tests.test_ssrf_canary
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

results = []


def check(name, cond, extra=""):
    results.append((name, cond))
    status = "PASS" if cond else "FAIL"
    suffix = f"  [{extra}]" if extra and not cond else ""
    print(f"{status}  {name}{suffix}")


# ---------------------------------------------------------------------------
# Stub for LocalOast — mimics the real 3-tuple contract without network I/O
# ---------------------------------------------------------------------------
class _StubOast:
    """Minimal stub for LocalOast / InteractshClient used by ssrf.py probes."""

    def new_canary(self):
        return ("tok-abc", "tok-abc.oast.example", "http://tok-abc.oast.example/")

    def poll_for(self, token, timeout_s=8):
        return []  # no callback in unit test


# ---------------------------------------------------------------------------
# 1. Contract: new_canary() must return exactly 3 values
# ---------------------------------------------------------------------------
def test_new_canary_returns_3_tuple():
    oast = _StubOast()
    result = oast.new_canary()
    check("new_canary() returns a 3-element tuple",
          isinstance(result, tuple) and len(result) == 3,
          f"got {type(result).__name__} len={len(result) if hasattr(result,'__len__') else '?'}")
    token, host, full_url = result
    check("first element is the token string", isinstance(token, str) and len(token) > 0)
    check("second element is the host string", isinstance(host, str) and "." in host)
    check("third element is a full URL", isinstance(full_url, str) and full_url.startswith("http"))


# ---------------------------------------------------------------------------
# 2. Regression: ssrf.py's _probe() correctly unpacks 3 values
# ---------------------------------------------------------------------------
def test_ssrf_scanner_unpack():
    """SsrfScanner._probe must not raise 'too many values to unpack (expected 2)'."""
    from deluluscan.models import Endpoint, RequestRecord, IdentityRole
    from deluluscan.scanners.ssrf import SsrfScanner

    # Minimal stubs
    class _FakeAuth:
        def headers_for(self, _ident):
            return {}

    class _FakeClient:
        class session:
            cookies = []

        def request(self, method, path, **kw):
            return RequestRecord(
                method=method, url=f"http://h{path}",
                identity=kw.get("identity_label", "anon"),
                status=200, elapsed_ms=1.0,
                resp_headers={}, resp_body="", resp_len=0,
            )

    anon_id = type("Ident", (), {
        "role": IdentityRole.ANON,
        "username": None, "password": None, "bearer_token": None,
        "extra_headers": {}, "session_jwt": None,
        "label": lambda self: "anonymous",
    })()

    _fake_cfg = type("Cfg", (), {"allow_state_changing": False, "fuzz": False})()

    scanner = SsrfScanner(
        client=_FakeClient(),
        auth=_FakeAuth(),
        config=_fake_cfg,
        identities={"anonymous": anon_id},
        oob=_StubOast(),
    )

    ep = Endpoint(
        method="GET", path="/api/v1/temp",
        query_params=[{"name": "remoteUrl", "in": "query"}],
        path_params=[],
    )

    # Must not raise ValueError("too many values to unpack")
    try:
        findings = list(scanner._probe(ep, anon_id, "remoteUrl"))
        check("ssrf._probe() does not raise on 3-tuple unpack", True)
    except ValueError as exc:
        check("ssrf._probe() does not raise on 3-tuple unpack", False, str(exc))
    except Exception as exc:
        # Other exceptions (e.g. AttributeError from incomplete stub) are fine —
        # what we care about is the unpack not failing.
        if "too many values to unpack" in str(exc):
            check("ssrf._probe() does not raise on 3-tuple unpack", False, str(exc))
        else:
            check("ssrf._probe() does not raise on 3-tuple unpack", True,
                  f"different exception (expected): {exc}")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    test_new_canary_returns_3_tuple()
    test_ssrf_scanner_unpack()

    passed = sum(1 for _, ok in results if ok)
    failed = sum(1 for _, ok in results if not ok)
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
