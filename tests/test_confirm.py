"""Tests for v0.9 confirmation features: cloud-metadata SSRF, active CORS/CSRF,
and headless-browser degradation.
Run: python -m tests.test_confirm
"""
from __future__ import annotations
import sys, os, types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import RequestRecord, Endpoint, Identity, IdentityRole
from deluluscan.active import injection as I
from deluluscan.scanners.misc_scanner import CorsScanner, CsrfScanner, _EVIL_ORIGIN
from deluluscan.verify import browser as B

results = []
def check(name, cond, extra=""):
    results.append((name, cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))

def rec(status=200, body="", headers=None):
    return RequestRecord(method="GET", url="http://h/x", identity="a", status=status,
                         elapsed_ms=10.0, resp_headers=headers or {}, resp_body=body, resp_len=len(body))


# ---- metadata SSRF ---------------------------------------------------------
def test_metadata_ssrf_hit():
    r = rec(200, '{"AccessKeyId":"ASIA...","Token":"...","instance-id":"i-0"}')
    check("metadata SSRF confirmed on credential/metadata signature",
          I.classify_metadata_ssrf(r, "url", I.METADATA_URLS[0]) is not None)

def test_metadata_ssrf_no_fp():
    check("metadata SSRF: no FP on ordinary body",
          I.classify_metadata_ssrf(rec(200, '{"ok":true}'), "url", "x") is None)


# ---- test doubles for scanners --------------------------------------------
class FakeAuth:
    def __init__(self, headers): self._h = headers
    def headers_for(self, ident): return dict(self._h)

class FakeClient:
    def __init__(self, responder): self.responder = responder
    def request(self, method, path, *, identity_label=None, headers=None, **k):
        return self.responder(method, path, headers or {}, k)

class FakeScan:
    allow_state_changing = True
class FakeConfig:
    scan = FakeScan()
    base_url = "http://localhost:8080"

def _ep(method="GET", path="/api/x"):
    return Endpoint(method=method, path=path)

def _ident():
    return Identity(role=IdentityRole.BACKEND, username="e", password="p")


# ---- active CORS -----------------------------------------------------------
def test_cors_reflect_with_credentials():
    def responder(method, path, headers, k):
        origin = headers.get("Origin", "")
        return rec(200, "{}", headers={"Access-Control-Allow-Origin": origin,
                                        "Access-Control-Allow-Credentials": "true"})
    sc = CorsScanner(FakeClient(responder), FakeAuth({}), FakeConfig(),
                     {"backend": _ident()})
    out = list(sc.run(_ep()))
    check("CORS: reflected Origin + credentials -> HIGH finding",
          any("credentials" in f.title.lower() for f in out), str([f.title for f in out]))

def test_cors_no_fp_when_fixed_origin():
    def responder(method, path, headers, k):
        return rec(200, "{}", headers={"Access-Control-Allow-Origin": "https://trusted.example",
                                        "Access-Control-Allow-Credentials": "true"})
    sc = CorsScanner(FakeClient(responder), FakeAuth({}), FakeConfig(), {"backend": _ident()})
    out = list(sc.run(_ep()))
    check("CORS: no FP when origin is not reflected", out == [], str([f.title for f in out]))


# ---- CSRF skip on bearer auth ----------------------------------------------
def test_csrf_skipped_for_bearer_auth():
    def responder(method, path, headers, k):
        return rec(200, '{"done":true}')
    sc = CsrfScanner(FakeClient(responder),
                     FakeAuth({"Authorization": "Bearer x"}), FakeConfig(), {"backend": _ident()})
    out = list(sc.run(_ep("POST", "/api/v1/thing")))
    check("CSRF: skipped when auth is a bearer token (not CSRF-able)", out == [],
          str([f.title for f in out]))

def test_csrf_flags_cookie_session():
    def responder(method, path, headers, k):
        return rec(200, '{"updated":true,"id":"abc123"}')
    sc = CsrfScanner(FakeClient(responder),
                     FakeAuth({"Cookie": "JSESSIONID=abc"}), FakeConfig(), {"backend": _ident()})
    out = list(sc.run(_ep("POST", "/api/v1/thing")))
    check("CSRF: flags cookie-session state change accepted cross-site",
          any("csrf" in f.title.lower() for f in out), str([f.title for f in out]))


# ---- browser degradation ---------------------------------------------------
def test_browser_static_fallback_or_result():
    # exec payload reflected in HTML; with no working browser we get a graceful
    # result object (executed None) — never a crash, never a false "confirmed".
    html = '<div>' + B.exec_payload("tok123") + '</div>'
    res = B.confirm_in_browser(html, "tok123")
    ok = res is not None and res.executed in (True, False, None)
    check("browser check returns a graceful result (no crash)", ok, str(res))

def test_exec_payload_is_inert_marker():
    p = B.exec_payload("tokZ")
    check("exec payload only sets a sentinel (no exfiltration)",
          "window.__deluluscan_xss" in p and "document.cookie" not in p and "fetch(" not in p)


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    total = len(results); passed = sum(1 for _, c in results if c)
    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)
