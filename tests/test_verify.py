"""Unit tests for the verification layer.

Uses a fake HTTP client whose responses are driven by the URL, so we can model
both true positives and each specific false-positive confounder without a live
server. Run: python -m tests.test_verify   (or pytest tests/test_verify.py)
"""
from __future__ import annotations

import sys
import os
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import Finding, RequestRecord, Severity, VulnClass
from deluluscan.verify import Verifier


# --- fakes -------------------------------------------------------------------
class FakeAuth:
    def headers_for(self, identity):
        return {}


class FakeClient:
    """responder(method, url, identity) -> RequestRecord"""
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def request(self, method, path, *, identity_label="anonymous", headers=None,
                params=None, json_body=None, **kw):
        self.calls.append((method, path, identity_label))
        return self.responder(method, path, identity_label)


def rec(url, *, status=200, body="", length=None, elapsed=30.0,
        headers=None, identity="anonymous", method="GET"):
    return RequestRecord(
        method=method, url=url, identity=identity, status=status,
        elapsed_ms=elapsed, resp_headers=headers or {}, resp_body=body,
        resp_len=length if length is not None else len(body))


def verify(finding, responder, identities=None):
    v = Verifier(FakeClient(responder), FakeAuth(),
                 identities or {"anonymous": object(), "backend": object(),
                                "admin": object()})
    v.verify_all([finding])
    return finding.detail["verification"], finding


results = []
def check(name, cond, extra=""):
    results.append((name, cond, extra))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))


# ============================================================================
# SQLi — error based
# ============================================================================
def test_sqli_error_true_positive():
    base = rec("http://h/api/x?q=1", body="ok normal page", length=100)
    payload = rec("http://h/api/x?q=1'", body="org.postgresql.util.PSQLException: syntax error", length=140)
    f = Finding(VulnClass.SQLI, Severity.CRITICAL, "SQL error via q", "GET /api/x",
                "desc", evidence=[base, payload],
                detail={"param": "q", "payload": "'", "signature": "org.postgresql.util.PSQLException"})

    def responder(method, url, ident):
        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        if "'" in q:  # metacharacter -> DB error
            return rec(url, body="org.postgresql.util.PSQLException: syntax error", length=140)
        return rec(url, body="ok normal page", length=100)  # benign control
    v, f = verify(f, responder)
    check("sqli_error TP verdict", v["verdict"] == "true_positive", v["verdict"])
    check("sqli_error TP exploitability", v["exploitability"] == "exploitable", v["exploitability"])

def test_sqli_error_orderby_echoed_sql_true_positive():
    # ORDER BY / identifier injection: ANY invalid value (benign OR quote) errors,
    # so the plain benign-vs-payload error-class comparison would call it FP. But
    # the error body ECHOES the constructed SQL — ground-truth proof the value is
    # concatenated unparameterized into the query. Must be a true positive.
    echoed = ('{"message":"ERROR: syntax error at or near \\"ASC\\"\\n'
              '\\"SQL\\":[\\"SELECT c.* FROM category c ORDER BY  ASC\\"]"}')
    base = rec("http://h/api/categories?orderby=name", body="", length=138)
    payload = rec("http://h/api/categories?orderby=name'", body=echoed, length=244)
    f = Finding(VulnClass.SQLI, Severity.HIGH, "SQL error via orderby", "GET /api/categories",
                "desc", evidence=[base, payload], detail={"param": "orderby", "signature": "syntax error"})

    def responder(method, url, ident):
        # both a benign invalid column and the quote produce a syntax error that
        # echoes the SQL — the ORDER BY case that used to false-negative.
        return rec(url, body=echoed, length=244)
    v, f = verify(f, responder)
    check("sqli_error orderby(echoed-SQL) TP verdict", v["verdict"] == "true_positive", v["verdict"])

def test_sqli_error_false_positive_baseline():
    # signature already in the benign baseline -> generic error page, not SQLi
    base = rec("http://h/api/x?q=1", body="Error: org.postgresql.util.PSQLException happened", length=140)
    payload = rec("http://h/api/x?q=1'", body="Error: org.postgresql.util.PSQLException happened", length=140)
    f = Finding(VulnClass.SQLI, Severity.CRITICAL, "SQL error via q", "GET /api/x",
                "desc", evidence=[base, payload],
                detail={"param": "q", "payload": "'", "signature": "org.postgresql.util.PSQLException"})
    v, f = verify(f, lambda m, u, i: base)
    check("sqli_error FP verdict", v["verdict"] == "false_positive", v["verdict"])
    check("sqli_error FP severity downgraded", f.severity == Severity.INFO, f.severity.value)


# ============================================================================
# SQLi — boolean differential
# ============================================================================
def test_sqli_boolean_true_positive():
    t = rec("http://h/api/x?q=T", body="A" * 800, length=800)
    fa = rec("http://h/api/x?q=F", body="A" * 200, length=200)
    f = Finding(VulnClass.SQLI, Severity.HIGH, "boolean diff", "GET /api/x", "d",
                evidence=[t, fa], detail={"param": "q", "true_len": 800, "false_len": 200})
    def responder(m, u, i):
        if "q=T" in u:
            return rec(u, body="A" * 805, length=805)  # stable, tiny jitter
        return rec(u, body="A" * 202, length=202)
    v, f = verify(f, responder)
    check("sqli_bool TP verdict", v["verdict"] == "true_positive", v["verdict"])

def test_sqli_boolean_false_positive_jitter():
    t = rec("http://h/api/x?q=T", body="A" * 800, length=800)
    fa = rec("http://h/api/x?q=F", body="A" * 600, length=600)
    f = Finding(VulnClass.SQLI, Severity.HIGH, "boolean diff", "GET /api/x", "d",
                evidence=[t, fa], detail={"param": "q", "true_len": 800, "false_len": 600})
    import random
    def responder(m, u, i):
        # both sides jitter wildly by ~400B regardless of true/false -> noise
        return rec(u, length=500 + random.randint(0, 400))
    v, f = verify(f, responder)
    check("sqli_bool FP(jitter) verdict", v["verdict"] == "likely_false_positive", v["verdict"])

def test_sqli_boolean_false_positive_waf():
    t = rec("http://h/api/x?q=T", body="A" * 800, length=800)
    fa = rec("http://h/api/x?q=F", status=403, body="Access Denied: request blocked by web application firewall", length=60)
    f = Finding(VulnClass.SQLI, Severity.HIGH, "boolean diff", "GET /api/x", "d",
                evidence=[t, fa], detail={"param": "q", "true_len": 800, "false_len": 60})
    v, f = verify(f, lambda m, u, i: t)
    check("sqli_bool FP(waf) verdict", v["verdict"] == "likely_false_positive", v["verdict"])
    check("sqli_bool FP(waf) confounder", any("WAF" in c or "block" in c for c in v["confounders"]))


# ============================================================================
# SQLi — time based
# ============================================================================
def test_sqli_time_true_positive():
    base = rec("http://h/api/x?q=1", elapsed=40.0)
    delayed = rec("http://h/api/x?q=sleep", elapsed=7200.0)
    f = Finding(VulnClass.SQLI, Severity.HIGH, "time based", "GET /api/x", "d",
                evidence=[base, delayed], detail={"param": "q", "sleep_s": 7})
    def responder(m, u, i):
        return rec(u, elapsed=7300.0 if "sleep" in u else 45.0)
    v, f = verify(f, responder)
    check("sqli_time TP verdict", v["verdict"] == "true_positive", v["verdict"])

def test_sqli_time_false_positive():
    base = rec("http://h/api/x?q=1", elapsed=40.0)
    delayed = rec("http://h/api/x?q=sleep", elapsed=7200.0)  # original spike was transient
    f = Finding(VulnClass.SQLI, Severity.HIGH, "time based", "GET /api/x", "d",
                evidence=[base, delayed], detail={"param": "q", "sleep_s": 7})
    v, f = verify(f, lambda m, u, i: rec(u, elapsed=50.0))  # nothing slow on re-test
    check("sqli_time FP verdict", v["verdict"] == "likely_false_positive", v["verdict"])


# ============================================================================
# XSS
# ============================================================================
def _reflecting_responder(headers):
    def responder(m, u, i):
        # reflect whatever value is in param q, unescaped, into an HTML body
        q = parse_qs(urlparse(u).query).get("q", [""])[0]
        return rec(u, body=f"<html><body>search: {q}</body></html>", headers=headers)
    return responder

def test_xss_exploitable():
    ev = rec("http://h/s?q=<deluluscanAAA>", body="<html>search: <deluluscanAAA></html>",
             headers={"Content-Type": "text/html"})
    f = Finding(VulnClass.XSS, Severity.MEDIUM, "reflect", "GET /s", "d",
                evidence=[ev], detail={"param": "q", "marker_kind": "html_tag", "content_type": "text/html"})
    v, f = verify(f, _reflecting_responder({"Content-Type": "text/html"}))
    check("xss exploitable verdict", v["verdict"] == "true_positive", v["verdict"])
    check("xss exploitable rating", v["exploitability"] == "exploitable", v["exploitability"])

def test_xss_mitigated_strong_csp():
    hdrs = {"Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc123'"}
    ev = rec("http://h/s?q=<deluluscanAAA>", body="<html>search: <deluluscanAAA></html>", headers=hdrs)
    f = Finding(VulnClass.XSS, Severity.MEDIUM, "reflect", "GET /s", "d",
                evidence=[ev], detail={"param": "q", "marker_kind": "html_tag"})
    v, f = verify(f, _reflecting_responder(hdrs))
    check("xss mitigated verdict", v["verdict"] == "true_positive", v["verdict"])
    check("xss mitigated rating", v["exploitability"] == "mitigated", v["exploitability"])

def test_xss_not_exploitable_content_type():
    hdrs = {"Content-Type": "application/json", "X-Content-Type-Options": "nosniff"}
    ev = rec("http://h/s?q=<deluluscanAAA>", body='{"q":"<deluluscanAAA>"}', headers=hdrs)
    f = Finding(VulnClass.XSS, Severity.MEDIUM, "reflect", "GET /s", "d",
                evidence=[ev], detail={"param": "q", "marker_kind": "html_tag"})
    def responder(m, u, i):
        q = parse_qs(urlparse(u).query).get("q", [""])[0]
        return rec(u, body=f'{{"q":"{q}"}}', headers=hdrs)
    v, f = verify(f, responder)
    check("xss not_exploitable rating", v["exploitability"] == "not_exploitable", v["exploitability"])

def test_xss_false_positive_static():
    ev = rec("http://h/s?q=<deluluscanAAA>", body="<html>a static <deluluscanAAA> string</html>",
             headers={"Content-Type": "text/html"})
    f = Finding(VulnClass.XSS, Severity.MEDIUM, "reflect", "GET /s", "d",
                evidence=[ev], detail={"param": "q", "marker_kind": "html_tag"})
    # fresh random markers are NOT reflected -> the original was a static string
    def responder(m, u, i):
        return rec(u, body="<html>a static string</html>", headers={"Content-Type": "text/html"})
    v, f = verify(f, responder)
    check("xss FP(static) verdict", v["verdict"] == "likely_false_positive", v["verdict"])


# ============================================================================
# IDOR
# ============================================================================
def test_idor_true_positive():
    oid = "11111111-2222-3333-4444-555555555555"
    ev = rec(f"http://h/api/user/{oid}", body='{"id":"x","email":"a@b.c","name":"Bob"}',
             length=90, identity="backend")
    f = Finding(VulnClass.IDOR, Severity.HIGH, "idor", "GET /api/user/{id}", "d",
                evidence=[ev], detail={"object_id": oid, "param": "id", "id_kind": "uuid"})
    def responder(m, u, i):
        if "0000000000ff" in u:  # bogus id -> not found
            return rec(u, status=404, body="not found", length=9, identity="backend")
        return rec(u, body='{"id":"x","email":"a@b.c","name":"Bob"}', length=90, identity="backend")
    v, f = verify(f, responder)
    check("idor TP verdict", v["verdict"] == "true_positive", v["verdict"])
    check("idor TP rating", v["exploitability"] == "exploitable", v["exploitability"])

def test_idor_false_positive_anyid():
    oid = "11111111-2222-3333-4444-555555555555"
    ev = rec(f"http://h/api/user/{oid}", body='{"page":"help","body":"same"}', length=90, identity="backend")
    f = Finding(VulnClass.IDOR, Severity.HIGH, "idor", "GET /api/user/{id}", "d",
                evidence=[ev], detail={"object_id": oid, "param": "id", "id_kind": "uuid"})
    # ANY id (including bogus) returns the same structure -> not object-scoped
    def responder(m, u, i):
        return rec(u, body='{"page":"help","body":"same"}', length=90, identity="backend")
    v, f = verify(f, responder)
    check("idor FP verdict", v["verdict"] == "likely_false_positive", v["verdict"])


# ============================================================================
# AUTHZ vertical
# ============================================================================
def test_authz_true_positive():
    anon = rec("http://h/api/roles", body='{"roles":[{"id":1,"name":"admin"}]}', length=120, identity="anonymous")
    admin = rec("http://h/api/roles", body='{"roles":[{"id":1,"name":"admin"}]}', length=120, identity="admin")
    f = Finding(VulnClass.AUTHZ, Severity.HIGH, "Privileged endpoint reachable as anonymous",
                "GET /api/roles", "d", evidence=[anon, admin], detail={"role": "anonymous", "resp_len": 120})
    v, f = verify(f, lambda m, u, i: anon)
    check("authz TP verdict", v["verdict"] == "true_positive", v["verdict"])

def test_authz_false_positive_login():
    anon = rec("http://h/api/roles", body='<html><form>login password</form></html>', length=120, identity="anonymous")
    f = Finding(VulnClass.AUTHZ, Severity.HIGH, "Privileged endpoint reachable as anonymous",
                "GET /api/roles", "d", evidence=[anon], detail={"role": "anonymous", "resp_len": 120})
    v, f = verify(f, lambda m, u, i: anon)
    check("authz FP(login) verdict", v["verdict"] == "likely_false_positive", v["verdict"])


def test_authz_refreshes_stale_session():
    # Regression: a long/state-changing scan can invalidate a credentialed
    # identity's session, so verification's re-issue gets a 401 with a STALE
    # token and would wrongly bury a real finding as a false positive. The
    # verifier must re-authenticate (auth.refresh) and retry once, then judge the
    # live response. Here the backend session is "stale" until refresh() runs.
    body = '{"entity":[{"key":"dotAI","configured":true}]}'
    state = {"refreshed": False}

    class RefreshAuth:
        def headers_for(self, identity):
            return {"Authorization": "Bearer live" if state["refreshed"] else "Bearer stale"}
        def refresh(self, identity):
            state["refreshed"] = True
            return {"Authorization": "Bearer live"}

    def responder(method, url, identity):
        if identity == "backend" and not state["refreshed"]:
            return rec(url, status=401, body="Invalid User", length=12, identity="backend")
        return rec(url, status=200, body=body, length=len(body), identity="backend")

    be = rec("http://h/api/v1/apps", status=200, body=body, length=len(body), identity="backend")
    admin = rec("http://h/api/v1/apps", status=200, body=body, length=len(body), identity="admin")
    f = Finding(VulnClass.AUTHZ, Severity.HIGH, "Admin-only endpoint accessible as backend",
                "GET /api/v1/apps", "d", evidence=[be, admin], detail={"role": "backend"})
    v = Verifier(FakeClient(responder), RefreshAuth(),
                 {"anonymous": object(), "backend": object(), "admin": object()})
    v.verify_all([f])
    vd = f.detail["verification"]
    check("verifier re-auths a stale session and does NOT bury the finding",
          state["refreshed"] and vd["verdict"] in ("true_positive", "likely_true_positive"),
          f"refreshed={state['refreshed']} verdict={vd['verdict']}")


# ============================================================================
# SSRF & CORS
# ============================================================================
def test_ssrf_confirmed():
    f = Finding(VulnClass.SSRF, Severity.CRITICAL, "OOB SSRF", "GET /fetch", "d",
                evidence=[rec("http://h/fetch?url=x")], confidence="confirmed",
                detail={"param": "url", "interactions": [{"proto": "dns"}]})
    v, f = verify(f, lambda m, u, i: rec(u))
    check("ssrf confirmed verdict", v["verdict"] == "true_positive", v["verdict"])
    check("ssrf confirmed rating", v["exploitability"] == "exploitable", v["exploitability"])

def test_ssrf_no_oob_inconclusive():
    f = Finding(VulnClass.SSRF, Severity.INFO, "url param manual review", "GET /fetch", "d",
                evidence=[], confidence="tentative", detail={"param": "url"})
    v, f = verify(f, lambda m, u, i: rec(u))
    check("ssrf no-oob verdict", v["verdict"] == "inconclusive", v["verdict"])

def test_cors_wildcard_creds_not_exploitable():
    ev = rec("http://h/api/x", headers={"Access-Control-Allow-Origin": "*",
                                        "Access-Control-Allow-Credentials": "true"})
    f = Finding(VulnClass.AUTHZ, Severity.LOW, "Permissive CORS headers", "GET /api/x",
                "d", evidence=[ev], confidence="firm")
    v, f = verify(f, lambda m, u, i: ev)
    check("cors not_exploitable rating", v["exploitability"] == "not_exploitable", v["exploitability"])


# ============================================================================
# SCA (supply_chain) — manifest/classpath findings, no live HTTP evidence
# ============================================================================
def test_sca_shipped_finding_not_downgraded_by_generic_reissue():
    # Regression: the target build 1.2.4 live scan. dependency_scanner grades a
    # shipped (classpath-confirmed) vulnerable dependency likely_true_positive,
    # with a sentinel RequestRecord (method="SCA", url=<manifest path>, status=0)
    # since there is no real HTTP response behind a dependency finding. The
    # generic reissue-and-compare verifier used to re-request that sentinel as
    # if it were a real endpoint, get back an unrelated real status from the
    # responder, call that a "status drift", and downgrade EVERY shipped SCA
    # finding to likely_false_positive — 24/24 in that run.
    f = Finding(VulnClass.SUPPLY_CHAIN, Severity.LOW,
                "Vulnerable dependency: netty-codec 4.1.118.Final (CVE-2026-59901)",
                "(dependencies)", "d",
                evidence=[rec("bom/application/pom.xml", status=0, method="SCA")],
                confidence="firm",
                detail={"test": "sca", "shipped": True},
                verdict="likely_true_positive", exploitability="conditional")
    v, f = verify(f, lambda m, u, i: rec(u, status=501))
    check("shipped SCA finding keeps its likely_true_positive verdict",
          v["verdict"] == "likely_true_positive", v["verdict"])
    check("shipped SCA finding is not reprobed as an HTTP request",
          v["probes"] == 0, v["probes"])


def test_sca_manifest_only_finding_stays_unverified():
    f = Finding(VulnClass.SUPPLY_CHAIN, Severity.INFO,
                "Vulnerable dependency: example-lib 1.0 (CVE-2099-0001)",
                "(dependencies)", "d",
                evidence=[rec("examples/thing/package.json", status=0, method="SCA")],
                confidence="tentative",
                detail={"test": "sca", "shipped": False},
                verdict="unverified", exploitability="unknown")
    v, f = verify(f, lambda m, u, i: rec(u, status=501))
    check("manifest-only SCA finding stays unverified, not downgraded to false_positive",
          v["verdict"] == "unverified", v["verdict"])


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    total = len(results); passed = sum(1 for _, c, _ in results if c)
    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)
