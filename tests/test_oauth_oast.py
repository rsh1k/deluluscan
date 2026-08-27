"""Tests for v1.3: localhost OAST listener, OAuth redirect/token-theft scanner,
and iterable-identifier IDOR.
Run: python -m tests.test_oauth_oast
"""
from __future__ import annotations
import sys, os, urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import RequestRecord, Endpoint, Identity, IdentityRole
from deluluscan.integrations.local_oast import LocalOastListener
from deluluscan.scanners.oauth_scanner import OAuthScanner
from deluluscan.scanners.idor_iter_scanner import IterableIdorScanner

results = []
def check(name, cond, extra=""):
    results.append((name, cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))

def rec(status=200, body="", headers=None):
    return RequestRecord(method="GET", url="http://h/x", identity="a", status=status,
                         elapsed_ms=8.0, resp_headers=headers or {}, resp_body=body, resp_len=len(body))
class FakeAuth:
    def __init__(self, h=None): self._h = h or {}
    def headers_for(self, ident): return dict(self._h)
class FakeClient:
    def __init__(self, responder): self.responder = responder
    def request(self, method, path, *, identity_label=None, headers=None, allow_redirects=True, **k):
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


# ---- localhost OAST listener ----------------------------------------------
def test_oast_binds_loopback_and_correlates():
    lo = LocalOastListener()
    started = lo.start()
    check("OAST listener starts and binds 127.0.0.1", started and lo.base_domain.startswith("127.0.0.1:"))
    token, host, full = lo.new_canary()
    check("OAST canary embeds token in loopback URL path",
          host.startswith("127.0.0.1:") and token in host and full == "http://" + host)
    # simulate the target calling back (loopback HTTP GET carrying the token)
    try:
        urllib.request.urlopen(full, timeout=2).read()
    except Exception as e:
        pass
    hits = lo.poll_for(token, timeout_s=3.0)
    check("OAST correlates a loopback callback carrying the token", len(hits) >= 1, str(hits))
    lo.stop()

def test_oast_no_false_hit_for_other_token():
    lo = LocalOastListener(); lo.start()
    t1, h1, u1 = lo.new_canary()
    try: urllib.request.urlopen(u1, timeout=2).read()
    except Exception: pass
    lo.poll_for(t1, timeout_s=2.0)
    hits_other = lo.poll_for("dfz-nonexistent-token", timeout_s=1.0)
    check("OAST does not correlate an unrelated token", hits_other == [], str(hits_other))
    lo.stop()


# ---- OAuth redirect / token theft -----------------------------------------
def test_oauth_open_redirect_uri():
    def responder(method, path, label, headers, k):
        if "evil.deluluscan-oob.example" in path:
            return rec(302, "", {"Location": "https://evil.deluluscan-oob.example/cb?code=abc123"})
        return rec(200, "login")
    sc = OAuthScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                      {"anonymous": _id(IdentityRole.ANON)})
    out = list(sc.run(_ep("GET", "/api/v1/dotsaml/login/idp1", qp=["redirect_uri"])))
    check("OAuth open redirect_uri -> ATO finding",
          any("redirect_uri" in f.title.lower() or "auth code" in f.title.lower() for f in out),
          str([f.title for f in out]))

def test_oauth_no_fp_when_redirect_rejected():
    def responder(method, path, label, headers, k):
        # server ignores attacker redirect, always goes to its own domain
        return rec(302, "", {"Location": "https://trusted.local/cb?code=abc"})
    sc = OAuthScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                      {"anonymous": _id(IdentityRole.ANON)})
    out = list(sc.run(_ep("GET", "/api/v1/oauth/authorize", qp=["redirect_uri", "state"])))
    check("OAuth: no redirect FP when attacker host not honored",
          not any("redirect" in f.title.lower() and "theft" in f.title.lower() for f in out),
          str([f.title for f in out]))


# ---- iterable IDOR ---------------------------------------------------------
def test_iterable_idor_detected():
    def responder(method, path, label, headers, k):
        # /users/100 -> own; neighbours return DISTINCT real users
        if path.endswith("/100"):
            return rec(200, '{"id":100,"email":"me@x.com","ssn":"111"}')
        if path.endswith("/99"):
            return rec(200, '{"id":99,"email":"alice@x.com","ssn":"222"}')
        if path.endswith("/101"):
            return rec(200, '{"id":101,"email":"bob@x.com","ssn":"333"}')
        return rec(200, '{"id":107,"email":"carol@x.com","ssn":"444"}')
    sc = IterableIdorScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                             {"backend": _id(IdentityRole.BACKEND)})
    out = list(sc.run(_ep("GET", "/api/v1/users/100")))
    check("iterable IDOR flagged when neighbour ids return distinct objects",
          any("iterable" in f.title.lower() for f in out), str([f.title for f in out]))

def test_iterable_idor_no_fp_same_record():
    def responder(method, path, label, headers, k):
        # self-scoped endpoint: every id returns the caller's own record
        return rec(200, '{"id":100,"email":"me@x.com","ssn":"111"}')
    sc = IterableIdorScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                             {"backend": _id(IdentityRole.BACKEND)})
    out = list(sc.run(_ep("GET", "/api/v1/users/100")))
    check("iterable IDOR: no FP when same record echoed for all ids", out == [],
          str([f.title for f in out]))

def test_iterable_idor_no_fp_when_denied():
    def responder(method, path, label, headers, k):
        if path.endswith("/100"):
            return rec(200, '{"id":100,"email":"me@x.com"}')
        return rec(403, "Access denied")   # neighbours properly denied
    sc = IterableIdorScanner(FakeClient(responder), FakeAuth(), FakeConfig(),
                             {"backend": _id(IdentityRole.BACKEND)})
    out = list(sc.run(_ep("GET", "/api/v1/users/100")))
    check("iterable IDOR: no FP when neighbour ids are denied", out == [],
          str([f.title for f in out]))


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    total = len(results); passed = sum(1 for _, c in results if c)
    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)
