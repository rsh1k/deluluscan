"""Unit tests for v0.6: recon, verb tampering, race conditions, deep GraphQL,
and the session-handling engine. Pure logic with fakes.
Run: python -m tests.test_advanced_suite
"""
from __future__ import annotations
import sys, os, json, threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import RequestRecord
from deluluscan.active.recon import (ParamMiner, ContentDiscovery, VersionEnumerator,
                                  SupplyChainProbe)
from deluluscan.active.advanced import VerbTamper, RaceProbe, GraphQLAdvanced
from deluluscan.active.session_rules import (MatchReplaceRule, Macro, Extraction,
                                          SessionEngine)
from deluluscan.active.http_tools import RequestSpec, Repeater

results = []
def check(name, cond, extra=""):
    results.append((name, cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))

def rec(status=200, body="", headers=None):
    return RequestRecord(method="GET", url="http://h/x", identity="anon", status=status,
                         elapsed_ms=5.0, resp_headers=headers or {}, resp_body=body,
                         resp_len=len(body))


# ---- Param miner -----------------------------------------------------------
def test_paramminer_reflected():
    def send(name, marker):
        return rec(200, f"you searched for {marker}") if name == "q" else rec(200, "nothing")
    found = ParamMiner(["q", "debug", "x"]).mine(send, rec(200, "nothing"))
    check("param miner finds reflected param",
          any(p.name == "q" and p.signal == "reflected" for p in found))


# ---- Content discovery -----------------------------------------------------
def test_content_discovery():
    live = {"/api/internal", "/actuator/env"}
    def send(p):
        return rec(200, "ok") if p in live else rec(404, "nf")
    found = ContentDiscovery(["/api/internal", "/actuator/env", "/nope"]).discover(send)
    check("content discovery finds live shadow paths",
          {f.path for f in found} == live, str([f.path for f in found]))


# ---- Version enumeration ---------------------------------------------------
def test_version_sprawl():
    def send(p):
        return rec(200, "ok") if ("/v1/" in p or "/v2/" in p) else rec(404, "nf")
    vf = VersionEnumerator().enumerate("/api/v1/users/current", send)
    check("version enumerator flags multiple live versions",
          vf is not None and set(vf.live_versions) >= {1, 2}, str(vf))

def test_version_single_no_fp():
    def send(p):
        return rec(200, "ok") if "/v1/" in p else rec(404, "nf")
    vf = VersionEnumerator().enumerate("/api/v1/users/current", send)
    check("version enumerator: no FP for a single live version", vf is None)


# ---- Supply chain ----------------------------------------------------------
def test_supply_chain_exposure():
    exposed = {"/.git/config": "[core]", "/.env": "SECRET=1"}
    def send(p):
        return rec(200, exposed[p]) if p in exposed else rec(404, "nf")
    found = SupplyChainProbe(["/.git/config", "/.env", "/pom.xml"]).scan(send)
    kinds = {f.kind for f in found}
    check("supply-chain finds exposed vcs + secrets", {"vcs", "secrets"} <= kinds, str(kinds))


# ---- Verb tampering --------------------------------------------------------
def test_verb_tamper_alt_method():
    def send(method, extra):
        return rec(200, "admin op done") if method == "POST" else rec(403, "denied")
    out = VerbTamper(send).test("GET")
    check("verb tamper flags alt-method bypass", any(v.technique == "alt_method" for v in out),
          str([v.technique for v in out]))

def test_verb_tamper_clean():
    def send(method, extra):
        return rec(403, "denied")   # everything denied -> no bypass
    out = VerbTamper(send).test("GET")
    check("verb tamper: no FP when all denied", out == [])


# ---- Race conditions -------------------------------------------------------
def test_race_detected():
    def send_once():
        return rec(200, "ok")       # no locking -> every parallel req succeeds
    rf = RaceProbe().test(send_once, parallel=8, expected_successes=1)
    check("race probe flags TOCTOU (many successes)", rf is not None and rf.successes > 1)

def test_race_no_fp_when_serialized():
    lock = threading.Lock(); state = {"used": 0}
    def send_once():
        with lock:
            if state["used"] == 0:
                state["used"] = 1
                return rec(200, "ok")
            return rec(409, "already used")
    rf = RaceProbe().test(send_once, parallel=8, expected_successes=1)
    check("race probe: no FP when serialized (1 success)", rf is None)

def test_race_hard_capped():
    calls = {"n": 0}; lock = threading.Lock()
    def send_once():
        with lock: calls["n"] += 1
        return rec(200, "ok")
    RaceProbe().test(send_once, parallel=9999)
    check("race parallelism hard-capped (<=20)", calls["n"] <= 20, str(calls["n"]))


# ---- GraphQL advanced ------------------------------------------------------
def test_graphql_batching_and_depth():
    def send(raw):
        if raw.strip().startswith("["):
            n = len(json.loads(raw))
            return rec(200, json.dumps([{"data": {"__typename": "Query"}}] * n))
        if "a0:__typename" in raw:
            import re
            al = re.findall(r"(a\d+):__typename", raw)
            return rec(200, json.dumps({"data": {a: "Query" for a in al}}))
        return rec(200, json.dumps({"data": {"__type": {"fields": []}}}))  # accepts deep query
    out = GraphQLAdvanced().test(send)
    kinds = {g.kind for g in out}
    check("graphql advanced flags batching+alias+depth",
          {"batching", "alias_amplification", "no_depth_limit"} <= kinds, str(kinds))

def test_graphql_advanced_clean():
    def send(raw):
        if raw.strip().startswith("[") or "a0:__typename" in raw:
            return rec(400, '{"errors":["batching disabled"]}')
        return rec(400, '{"errors":["query depth 8 exceeds max depth 3"]}')
    out = GraphQLAdvanced().test(send)
    check("graphql advanced: no FP on hardened server", out == [], str([g.kind for g in out]))


# ---- Session engine --------------------------------------------------------
def test_match_replace_rule():
    spec = RequestSpec("GET", "http://h/api/user/OLD", headers={"X-Api": "v1"})
    r = MatchReplaceRule("path", "OLD", "NEW").apply(spec)
    check("match/replace rewrites path", r.path.endswith("/api/user/NEW"))
    r2 = MatchReplaceRule("header:X-Api", "v1", "v2").apply(spec)
    check("match/replace rewrites header", r2.headers["X-Api"] == "v2")

def test_macro_extract_and_substitute():
    class FakeClient:
        def request(self, method, path, *, identity_label="anonymous", headers=None,
                    params=None, json_body=None, data=None, allow_redirects=False, **k):
            if path.endswith("/login"):
                return rec(200, json.dumps({"entity": {"token": "TOK123"}}))
            # echo the Authorization header so we can confirm substitution happened
            return rec(200, json.dumps({"auth": (headers or {}).get("Authorization", "")}))
    rep = Repeater(FakeClient())
    macro = Macro("login",
                  steps=[RequestSpec("POST", "http://h/login",
                                     json_body={"userId": "u", "password": "p"})],
                  extractions=[Extraction("token", "body_json", "entity.token")])
    eng = SessionEngine(macros={"login": macro})
    ctx = eng.run_macro("login", rep)
    check("macro extracts token from response", ctx.get("token") == "TOK123", str(ctx))
    req = eng.substitute(RequestSpec("GET", "http://h/api/me",
                                     headers={"Authorization": "Bearer {{token}}"}))
    check("session engine substitutes {{token}}", req.headers["Authorization"] == "Bearer TOK123",
          req.headers.get("Authorization"))


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    total = len(results); passed = sum(1 for _, c in results if c)
    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)
