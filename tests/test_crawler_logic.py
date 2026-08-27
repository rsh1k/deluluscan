"""Tests for v1.2: SPA/JS crawler + secret mining, business-logic parameter
tampering, and auth-flow (reset poisoning / token leak / email-change) scanner.
Run: python -m tests.test_crawler_logic
"""
from __future__ import annotations
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import RequestRecord, Endpoint, Identity, IdentityRole
from deluluscan.active.crawler import SpaCrawler, mine_secrets
from deluluscan.scanners.logic_scanner import LogicScanner
from deluluscan.scanners.auth_flow_scanner import AuthFlowScanner

results = []
def check(name, cond, extra=""):
    results.append((name, cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))

def rec(status=200, body="", headers=None):
    return RequestRecord(method="POST", url="http://h/x", identity="a", status=status,
                         elapsed_ms=8.0, resp_headers=headers or {}, resp_body=body, resp_len=len(body))

class FakeAuth:
    def __init__(self, h=None): self._h = h or {"Authorization": "Bearer x"}
    def headers_for(self, ident): return dict(self._h)
class FakeClient:
    def __init__(self, responder): self.responder = responder
    def request(self, method, path, *, identity_label=None, headers=None, **k):
        return self.responder(method, path, identity_label, headers or {}, k)
class FakeScan:
    allow_state_changing = True
class FakeConfig:
    scan = FakeScan(); base_url = "http://localhost:8080"
def _id(role): return Identity(role=role, username="u", password="p")
def _ep(method="GET", path="/api/x", qp=None):
    e = Endpoint(method=method, path=path)
    if qp: e.query_params = [{"name": n} for n in qp]
    return e


# ---- secret mining ---------------------------------------------------------
def test_mine_real_secrets():
    js = 'var k="AKIA1234567890ABCDEF";const g="AIza' + "B"*35 + '";'
    hits = mine_secrets(js)
    kinds = {k for k, _ in hits}
    check("mine_secrets finds AWS + Google keys", "aws_access_key" in kinds and "google_api_key" in kinds, str(hits))

def test_mine_ignores_placeholders():
    js = 'apiKey: "YOUR_API_KEY_HERE", token="example_token_placeholder"'
    check("mine_secrets ignores obvious placeholders", mine_secrets(js) == [], str(mine_secrets(js)))


# ---- SPA crawler static mode ----------------------------------------------
def test_crawler_finds_endpoints_and_scripts():
    pages = {
        "/": '<html><script src="/static/main.js"></script></html>',
        "/static/main.js": 'fetch("/api/v1/hidden/admin");axios.get("/api/internal/keys")',
    }
    def fetch(p): return pages.get(p, "")
    res = SpaCrawler(fetch).static_crawl(roots=("/",))
    check("crawler follows script src and mines API paths",
          "/api/v1/hidden/admin" in res.paths and "/api/internal/keys" in res.paths
          and res.scripts_scanned == 1, str(res.paths))

def test_crawler_flags_secret_in_js():
    pages = {"/": '<script src="/a.js"></script>', "/a.js": 'const AWS="AKIA1234567890ABCDEF"'}
    res = SpaCrawler(lambda p: pages.get(p, "")).static_crawl(roots=("/",))
    check("crawler surfaces secrets found in JS", any(k == "aws_access_key" for k, _ in res.secrets),
          str(res.secrets))


# ---- business-logic parameter tampering -----------------------------------
def test_logic_flags_negative_quantity():
    def responder(method, path, label, headers, k):
        return rec(200, '{"order":{"total":-50,"items":1}}')   # accepts anything
    sc = LogicScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                      {"backend": _id(IdentityRole.BACKEND)})
    # state-changing cart add with a value param -> negative accepted is meaningful
    out = list(sc.run(_ep("POST", "/api/v1/cart", qp=["quantity"])))
    check("logic: negative quantity accepted on POST -> parameter-tampering finding",
          any("negative" in f.title.lower() for f in out), str([f.title for f in out]))

def test_logic_no_fp_when_rejected():
    def responder(method, path, label, headers, k):
        val = (k.get("params") or {}).get("quantity", "1")
        try: bad = float(val) <= 0 or float(val) > 1000000
        except: bad = True
        return rec(400, '{"message":"invalid quantity"}') if bad else rec(200, '{"ok":1}')
    sc = LogicScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                      {"backend": _id(IdentityRole.BACKEND)})
    out = list(sc.run(_ep("POST", "/api/v1/cart", qp=["quantity"])))
    check("logic: no FP when server rejects absurd values", out == [], str([f.title for f in out]))

def test_logic_ignores_pagination_limit():
    # THE reported false positive: limit=-1 on a read-only list is 'unbounded',
    # a standard idiom — must NOT be flagged as parameter tampering.
    def responder(method, path, label, headers, k):
        return rec(200, '{"entity":[{"a":1},{"a":2}]}')   # accepts limit=-1 happily
    sc = LogicScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                      {"backend": _id(IdentityRole.BACKEND)})
    out = list(sc.run(_ep("GET", "/api/v1/announcements", qp=["limit"])))
    check("logic: pagination 'limit' on a GET list is NOT flagged (no FP)",
          out == [], str([f.title for f in out]))

def test_logic_monetary_param_on_get_still_tested():
    def responder(method, path, label, headers, k):
        return rec(200, '{"transfer":{"amount":-1000,"ok":true}}')  # accepts negative amount
    sc = LogicScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                      {"backend": _id(IdentityRole.BACKEND)})
    out = list(sc.run(_ep("GET", "/api/v1/wallet/transfer", qp=["amount"])))
    check("logic: monetary 'amount' on GET IS tested (negative accepted -> finding)",
          any("negative" in f.title.lower() for f in out), str([f.title for f in out]))


# ---- auth flow: reset poisoning / token leak / email change ---------------
def test_reset_host_poisoning():
    def responder(method, path, label, headers, k):
        host = headers.get("X-Forwarded-Host") or headers.get("Host") or "server"
        return rec(200, f'{{"message":"reset link sent to https://{host}/reset?t=abc"}}')
    sc = AuthFlowScanner(FakeClient(responder), FakeAuth({}), FakeConfig(),
                         {"anonymous": _id(IdentityRole.ANON)})
    out = list(sc.run(_ep("POST", "/api/v1/forgotpassword")))
    check("authflow: host-header reset poisoning detected",
          any("host-header" in f.title.lower() for f in out), str([f.title for f in out]))

def test_reset_token_leak():
    def responder(method, path, label, headers, k):
        return rec(200, '{"resetToken":"a1b2c3d4e5f6g7h8i9j0k1l2"}')
    sc = AuthFlowScanner(FakeClient(responder), FakeAuth({}), FakeConfig(),
                         {"anonymous": _id(IdentityRole.ANON)})
    out = list(sc.run(_ep("POST", "/api/v1/forgotpassword")))
    check("authflow: reset token leaked in response detected",
          any("token disclosed" in f.title.lower() for f in out), str([f.title for f in out]))

def test_email_change_no_reauth():
    def responder(method, path, label, headers, k):
        if path.endswith("/users/current") and method == "GET":
            return rec(200, '{"userId":"u1","email":"me@x.com"}')
        if method == "PUT":
            return rec(200, '{"userId":"u1","email":"deluluscan-changed@example.com"}')
        return rec(404, "")
    sc = AuthFlowScanner(FakeClient(responder), FakeAuth({"Authorization": "Bearer x"}),
                         FakeConfig(), {"backend": _id(IdentityRole.BACKEND),
                                        "anonymous": _id(IdentityRole.ANON)})
    out = list(sc.run(_ep("POST", "/api/v1/forgotpassword")))
    check("authflow: email change without password re-auth detected",
          any("email change" in f.title.lower() for f in out), str([f.title for f in out]))


def test_ratelimit_skipped_when_limiter_header_present():
    from deluluscan.scanners.owasp_suite_scanner import FlowScanner
    # auth flow, but server returns a rate-limit budget header -> limiter EXISTS -> no finding
    def responder(method, path, label, headers, k):
        return rec(200, '{"entity":{}}', {"x-dotratelimit-toks-max": "10000/10000"})
    sc = FlowScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                     {"anonymous": _id(IdentityRole.ANON)})
    out = list(sc.run(_ep("POST", "/api/v1/authentication")))
    check("rate-limit: no finding when a rate-limit header is present (limiter exists)",
          not any("rate limit" in f.title.lower() for f in out), str([f.title for f in out]))

def test_ratelimit_ignored_on_non_auth_endpoint():
    from deluluscan.scanners.owasp_suite_scanner import FlowScanner
    def responder(method, path, label, headers, k):
        return rec(200, '{"entity":[]}')   # no limiter header, but NOT an auth flow
    sc = FlowScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                     {"anonymous": _id(IdentityRole.ANON)})
    out = list(sc.run(_ep("GET", "/api/v1/announcements")))
    check("rate-limit: not flagged on ordinary (non-auth) endpoints",
          not any("rate limit" in f.title.lower() for f in out), str([f.title for f in out]))


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    total = len(results); passed = sum(1 for _, c in results if c)
    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)
