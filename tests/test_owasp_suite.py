"""Unit tests for the v0.5 OWASP-coverage analyzers and the lab provisioner.

Pure-logic tests with fakes; no live server, no Docker.
Run: python -m tests.test_owasp_suite
"""
from __future__ import annotations
import sys, os, json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import RequestRecord
from deluluscan.active.owasp_suite import (
    AuthorizationMatrix, PropertyMiner, TokenSequencer, FaultProbe, FlowProbe,
    GraphQLProbe, malformed_probes)

results = []
def check(name, cond, extra=""):
    results.append((name, cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))

def rec(status=200, body=""):
    return RequestRecord(method="GET", url="http://h/x", identity="anon", status=status,
                         elapsed_ms=5.0, resp_headers={}, resp_body=body, resp_len=len(body))


# ---- Authorization matrix --------------------------------------------------
def test_authz_matrix_flags_bypass():
    rank = {"anonymous": 0, "backend": 1, "admin": 2}
    admin_body = '{"users":[{"id":1},{"id":2}],"secret":true}'
    def send(key, label, headers):
        # VULNERABLE: everyone gets the admin listing
        return rec(200, admin_body)
    m = AuthorizationMatrix(send, rank)
    res = m.test("GET /api/admin/users",
                 {"anonymous": {}, "backend": {}, "admin": {}})
    check("authz matrix flags lower-priv bypass",
          res is not None and "anonymous" in res.bypass_identities, str(res))

def test_authz_matrix_clean_when_enforced():
    rank = {"anonymous": 0, "backend": 1, "admin": 2}
    def send(key, label, headers):
        return rec(200, '{"ok":1}') if label == "admin" else rec(403, "denied")
    m = AuthorizationMatrix(send, rank)
    res = m.test("GET /api/admin/users",
                 {"anonymous": {}, "backend": {}, "admin": {}})
    check("authz matrix clean when enforced (no FP)", res is None)


# ---- Property miner (BOPLA) ------------------------------------------------
def test_excessive_data_detected():
    body = json.dumps({"userId": "u1", "email": "e",
                       "passwordHash": "$2a$10$N9qo8uLOickgx2ZMRZoM1e",
                       "apiKey": "AKIA1234567890ABCDEF"})
    pf = PropertyMiner().check_excessive_data(body, 200)
    fields = {p.field for p in pf}
    check("excessive data exposure detects sensitive fields",
          "passwordhash" in fields and "apikey" in fields, str(fields))

def test_excessive_data_clean():
    body = json.dumps({"userId": "u1", "title": "hello", "count": 3})
    pf = PropertyMiner().check_excessive_data(body, 200)
    check("excessive data: no FP on benign response", pf == [])

def test_mass_assignment_readonly_overwrite():
    def send_write(field, value):
        return rec(200, json.dumps({field: value, "ok": True}))  # echoes -> vulnerable
    pf = PropertyMiner(send_write).check_mass_assignment({"isadmin", "owner"})
    check("mass assignment detects read-only overwrite", any(p.kind == "mass_assignment" for p in pf),
          str([p.field for p in pf]))


# ---- Token sequencer -------------------------------------------------------
def test_sequencer_strong():
    import secrets
    toks = [secrets.token_hex(32) for _ in range(10)]
    r = TokenSequencer().analyze(toks)
    check("sequencer rates strong random tokens as strong", r and r.verdict == "strong",
          str(r.verdict if r else None))

def test_sequencer_sequential():
    toks = [str(1000 + i) for i in range(8)]
    r = TokenSequencer().analyze(toks)
    check("sequencer flags sequential tokens as predictable", r and r.verdict == "predictable",
          str(r.verdict if r else None))

def test_sequencer_weak_short():
    toks = ["ab", "cd", "ef", "gh", "ij"]
    r = TokenSequencer().analyze(toks)
    check("sequencer flags short tokens as weak", r and r.verdict == "weak",
          str(r.verdict if r else None))


# ---- Fault probe (A10) -----------------------------------------------------
def test_fault_verbose_error():
    body = "java.lang.NullPointerException\n at com.example.rest.Foo(Foo.java:42)"
    ff = FaultProbe().classify("broken_json", rec(500, body), auth_required=False)
    check("fault probe flags verbose stack trace", any(f.kind == "verbose_error" for f in ff),
          str([f.kind for f in ff]))

def test_fault_clean():
    ff = FaultProbe().classify("broken_json", rec(400, '{"error":"bad request"}'),
                               auth_required=False)
    check("fault probe: no FP on clean 400", ff == [])

def test_fault_fail_open():
    ff = FaultProbe().classify("wrong_type", rec(200, '{"data":"secret stuff here"}'),
                               auth_required=True)
    check("fault probe flags fail-open", any(f.kind == "fail_open" for f in ff))

def test_malformed_probes_bounded():
    check("malformed probes are a small bounded set", 0 < len(malformed_probes()) <= 10)


# ---- Flow probe (API4/API6) ------------------------------------------------
def test_no_rate_limit_detected():
    def send_once():
        return rec(200, "ok")   # never 429
    ff = FlowProbe().check_rate_limit(send_once, burst=12)
    check("flow probe flags missing rate limit", ff is not None and ff.kind == "no_rate_limit")

def test_rate_limit_present_no_fp():
    calls = {"n": 0}
    def send_once():
        calls["n"] += 1
        return rec(429, "slow down") if calls["n"] > 3 else rec(200, "ok")
    ff = FlowProbe().check_rate_limit(send_once, burst=12)
    check("flow probe: no FP when 429 appears", ff is None)

def test_flow_burst_hard_capped():
    calls = {"n": 0}
    def send_once():
        calls["n"] += 1
        return rec(200, "ok")
    FlowProbe().check_rate_limit(send_once, burst=9999)
    check("flow burst is hard-capped (<=20)", calls["n"] <= 20, str(calls["n"]))

def test_pagination_cap_missing():
    def send_with_limit(n):
        return rec(200, "x" * (n * 10))
    ff = FlowProbe().check_pagination_cap(send_with_limit, huge=100000)
    check("flow probe flags missing pagination cap", ff is not None and ff.kind == "no_pagination_cap")


# ---- GraphQL ---------------------------------------------------------------
def test_graphql_introspection():
    body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}})
    gf = GraphQLProbe().classify_introspection(rec(200, body))
    check("graphql introspection detected", gf is not None and gf.kind == "introspection")

def test_graphql_disabled_no_fp():
    gf = GraphQLProbe().classify_introspection(rec(400, '{"errors":["introspection disabled"]}'))
    check("graphql: no FP when introspection disabled", gf is None)


# ---- Lab (construction only; no docker/live) -------------------------------



if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    total = len(results); passed = sum(1 for _, c in results if c)
    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)
