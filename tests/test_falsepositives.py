"""Regression tests built from the REAL responses observed on a live target
1.2.0 instance, which the old logic false-flagged. Locks in the NIST 800-115 /
OWASP WSTG 4.5 content-oracle fix.

Observed false positives being pinned:
  * GET /api/content/id/{id}     anon -> {"contentlets":[]}        (empty, NOT served)
  * GET /api/content/inode/{id}  anon -> {"message":"No Permissions"} (denied, 200)
  * GET /api/v1/system-table/    anon -> 401 "Invalid User"        (denied)
  * GET /api/v1/configuration    anon -> public login/timezone config (public-by-design)

Run: python -m tests.test_falsepositives
"""
from __future__ import annotations
import sys, os, json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import RequestRecord
from deluluscan.verify import evidence as E
from deluluscan.verify.evidence import (classify_response, is_public_by_design,
                                      served_protected_content, looks_sensitive_body,
                                      DISPOSITION_EMPTY, DISPOSITION_DENIED,
                                      DISPOSITION_CONTENT)
from deluluscan.active.authz_probe import AuthzProbe
from deluluscan.active.owasp_suite import AuthorizationMatrix
from deluluscan.active.http_tools import RequestSpec

results = []
def check(name, cond, extra=""):
    results.append((name, cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))

def rec(status=200, body="", headers=None):
    return RequestRecord(method="GET", url="http://h/x", identity="anon", status=status,
                         elapsed_ms=5.0, resp_headers=headers or {}, resp_body=body, resp_len=len(body))

# real observed bodies
EMPTY_CONTENTLETS = '{"contentlets":[]}'
NO_PERMISSIONS = '{"message":"No Permissions"}'
INVALID_USER = 'Invalid User'
REAL_CONTENT = '{"contentlets":[{"identifier":"a083","title":"Home","body":"real data here","modUser":"appuser"}]}'
PUBLIC_CONFIG = '{"config":{"logos":{},"colors":{"primary":"#426BF0"},"timezones":[{"id":"America/Dawson"},{"id":"Antarctica/Mawson"}],"languages":["en"]}}'


# ---- disposition classifier (the core fix) ---------------------------------
def test_empty_contentlets_is_not_served():
    check("empty {\"contentlets\":[]} classified as EMPTY (not served)",
          classify_response(rec(200, EMPTY_CONTENTLETS)) == DISPOSITION_EMPTY)

def test_no_permissions_200_is_denied():
    check("{\"message\":\"No Permissions\"} (HTTP 200) classified as DENIED",
          classify_response(rec(200, NO_PERMISSIONS)) == DISPOSITION_DENIED)

def test_invalid_user_401_is_denied():
    check("401 'Invalid User' classified as DENIED",
          classify_response(rec(401, INVALID_USER)) == DISPOSITION_DENIED)

def test_real_content_is_content():
    check("populated contentlet classified as CONTENT",
          classify_response(rec(200, REAL_CONTENT)) == DISPOSITION_CONTENT)

def test_empty_array_and_object():
    check("[] and {} classified as EMPTY",
          classify_response(rec(200, "[]")) == DISPOSITION_EMPTY and
          classify_response(rec(200, "{}")) == DISPOSITION_EMPTY)

def test_entity_wrapped_empty_is_not_served():
    # the target wraps payloads in {"entity": X, "errors":[], ...}. An empty inner
    # payload (e.g. someone else's empty token list) is a successful read that
    # returned NO data — NOT an access-control leak. Regression for the live
    # "backend can read admin's API tokens" false positive.
    empty_tokens = '{"entity":{"tokens":[]},"errors":[],"pagination":null}'
    real_tokens = '{"entity":{"tokens":[{"id":"api10","claims":{"label":"x"}}]},"errors":[]}'
    check("{\"entity\":{\"tokens\":[]}} classified as EMPTY (not a token leak)",
          classify_response(rec(200, empty_tokens)) == DISPOSITION_EMPTY)
    check("{\"entity\":{\"tokens\":[{...}]}} (real tokens) still CONTENT",
          classify_response(rec(200, real_tokens)) == DISPOSITION_CONTENT)


# ---- public-by-design ------------------------------------------------------
def test_public_config_recognized():
    check("/api/v1/configuration recognized as public-by-design",
          is_public_by_design("GET http://h/api/v1/configuration"))
    check("published content API recognized as public-by-design",
          is_public_by_design("http://h/api/content/id/abc"))

def test_public_config_not_sensitive():
    check("public timezone/branding config has no sensitive keys",
          looks_sensitive_body(PUBLIC_CONFIG) == [], str(looks_sensitive_body(PUBLIC_CONFIG)))

def test_timezone_substring_not_flagged():
    # 'Mawson'/'Dawson' must NOT trigger 'aws'/'secret'-style hits
    check("timezone names don't false-match sensitive keywords",
          looks_sensitive_body(PUBLIC_CONFIG) == [])

def test_real_secret_body_flagged():
    check("genuine password/apiKey body IS flagged",
          set(looks_sensitive_body('{"password":"x","apiKey":"y","name":"bob"}')) == {"apikey", "password"})


# ---- the OWASP oracle ------------------------------------------------------
def test_oracle_empty_anon_not_served():
    r = served_protected_content(rec(200, EMPTY_CONTENTLETS), rec(200, REAL_CONTENT))
    check("oracle: anon empty vs authed content -> NOT served", not r.served, r.reason)

def test_oracle_denied_anon_not_served():
    r = served_protected_content(rec(200, NO_PERMISSIONS), rec(200, REAL_CONTENT))
    check("oracle: anon 'No Permissions' -> NOT served", not r.served, r.reason)

def test_oracle_same_content_served():
    r = served_protected_content(rec(200, REAL_CONTENT), rec(200, REAL_CONTENT))
    check("oracle: anon gets SAME protected data as authed -> served (true positive)", r.served)

def test_oracle_no_baseline_not_served():
    r = served_protected_content(rec(200, REAL_CONTENT), rec(200, EMPTY_CONTENTLETS))
    check("oracle: no authorized baseline -> not confirmable", not r.served, r.reason)


# ---- AuthzProbe.test_missing_auth end-to-end (the actual scanner path) -----
class TargetLikeClient:
    """Reproduces the target behavior: anon gets empty/denied, authed gets content."""
    def __init__(self, public=False):
        self.public = public
    def request(self, method, path, *, identity_label="anonymous", headers=None,
                params=None, json_body=None, data=None, allow_redirects=False, **k):
        authed = any(kk.lower() == "authorization" for kk in (headers or {}))
        if self.public:
            return rec(200, PUBLIC_CONFIG)
        return rec(200, REAL_CONTENT) if authed else rec(200, EMPTY_CONTENTLETS)

def test_missing_auth_no_fp_on_protected():
    probe = AuthzProbe(TargetLikeClient())
    good = rec(200, REAL_CONTENT)
    spec = RequestSpec("GET", "http://h/api/roles", headers={"Authorization": "Bearer x"})
    res = probe.test_missing_auth(spec, good)
    check("missing_auth: NO false positive when anon gets empty", not res.granted, res.detail)

def test_missing_auth_skips_public():
    probe = AuthzProbe(TargetLikeClient(public=True))
    spec = RequestSpec("GET", "http://h/api/v1/configuration", headers={"Authorization": "Bearer x"})
    res = probe.test_missing_auth(spec, rec(200, PUBLIC_CONFIG))
    check("missing_auth: public-by-design endpoint skipped", not res.granted, res.detail)

def test_missing_auth_true_positive_still_fires():
    # a GENUINE leak: anon gets the same real content as authed on a private path
    class LeakyClient:
        def request(self, method, path, *, identity_label="anonymous", headers=None, **k):
            return rec(200, REAL_CONTENT)   # same content regardless of auth
    probe = AuthzProbe(LeakyClient())
    spec = RequestSpec("GET", "http://h/api/v1/secret-report", headers={"Authorization": "Bearer x"})
    res = probe.test_missing_auth(spec, rec(200, REAL_CONTENT))
    check("missing_auth: TRUE positive still fires on a real leak", res.granted, res.detail)


# ---- AuthorizationMatrix end-to-end ----------------------------------------
def test_matrix_no_fp_when_lowpriv_empty():
    rank = {"anonymous": 0, "backend": 1, "admin": 2}
    def send(key, label, headers):
        return rec(200, REAL_CONTENT) if label == "admin" else rec(200, EMPTY_CONTENTLETS)
    res = AuthorizationMatrix(send, rank).test("GET /api/v1/secret",
              {"anonymous": {}, "backend": {}, "admin": {}})
    check("authz matrix: NO bypass when lower roles get empty", res is None)

def test_matrix_no_fp_self_scoped_same_shape():
    # /users/current returns each caller's OWN identity — same shape, different data.
    rank = {"anonymous": 0, "backend": 1, "admin": 2}
    def send(key, label, headers):
        if label == "anonymous":
            return rec(401, INVALID_USER)
        return rec(200, json.dumps({"userId": label, "email": f"{label}@x.com"}))
    res = AuthorizationMatrix(send, rank).test("GET /api/v1/users/current",
              {"anonymous": {}, "backend": {}, "admin": {}})
    check("authz matrix: self-scoped /users/current not a bypass (anon denied)", res is None,
          str(res))

def test_matrix_true_positive_same_data():
    rank = {"anonymous": 0, "backend": 1, "admin": 2}
    def send(key, label, headers):
        return rec(200, REAL_CONTENT)   # everyone gets the SAME admin data
    res = AuthorizationMatrix(send, rank).test("GET /api/v1/admin/secret",
              {"anonymous": {}, "backend": {}, "admin": {}})
    check("authz matrix: TRUE positive when all get same protected data",
          res is not None and "anonymous" in res.bypass_identities)


# ---- 4xx / error-status false positives (from the live screenshots) --------
MISSING_PARAM = '{"message":"Missing required inode/identifier param"}'
BAD_ENUM = '{"message":"No enum constant com.example.portlets.workflows.business.WorkflowAPI.SystemAction.1"}'
BAD_JSON = '{"message":"A JSONObject text must begin with \'{\' at 1 [character 2 line 1]"}'

def test_400_missing_param_not_content():
    check("400 'Missing required param' is bad_request, not content",
          classify_response(rec(400, MISSING_PARAM)) == E.DISPOSITION_BAD_REQUEST)

def test_400_bad_enum_not_content():
    check("400 'No enum constant' is bad_request, not content",
          classify_response(rec(400, BAD_ENUM)) == E.DISPOSITION_BAD_REQUEST)

def test_400_bad_json_not_content():
    check("400 'JSONObject text must begin' is bad_request, not content",
          classify_response(rec(400, BAD_JSON)) == E.DISPOSITION_BAD_REQUEST)

def test_error_message_on_200_still_bad_request():
    check("a client-error message served as 200 is still bad_request",
          classify_response(rec(200, MISSING_PARAM)) == E.DISPOSITION_BAD_REQUEST)

def test_various_error_statuses():
    for st in (405, 406, 415, 422):
        if classify_response(rec(st, '{"message":"nope"}')) != E.DISPOSITION_BAD_REQUEST:
            return check(f"{st} classified as bad_request", False, str(st))
    check("405/406/415/422 all classified as bad_request", True)
    check("500 classified as server_error",
          classify_response(rec(500, "boom")) == E.DISPOSITION_SERVER_ERROR)
    check("429 classified as throttled",
          classify_response(rec(429, "slow down")) == E.DISPOSITION_THROTTLED)

def test_matrix_no_fp_on_shared_400():
    # the exact screenshot case: all three identities get the same 400
    rank = {"anonymous": 0, "backend": 1, "admin": 2}
    def send(key, label, headers):
        return rec(400, MISSING_PARAM)
    res = AuthorizationMatrix(send, rank).test(
        "GET /api/v1/content/resourcelinks/field/1",
        {"anonymous": {}, "backend": {}, "admin": {}})
    check("authz matrix: shared 400 is NOT a bypass (screenshot case)", res is None,
          str(res))

def test_oracle_bad_request_not_served():
    r = served_protected_content(rec(400, MISSING_PARAM), rec(400, MISSING_PARAM))
    check("oracle: shared 400 -> not served, explains malformed request",
          not r.served and "malformed" in r.reason.lower(), r.reason)

def test_verb_tamper_no_fp_on_400():
    from deluluscan.active.advanced import VerbTamper
    def send(method, extra):
        return rec(400, BAD_ENUM)   # every method returns the same 400
    out = VerbTamper(send).test("PUT")
    check("verb tamper: shared 400 is NOT a bypass", out == [], str([v.technique for v in out]))


# ---- request self-repair ---------------------------------------------------
def test_repair_suggests_missing_param():
    from deluluscan.active.repair import suggest_repairs
    spec = RequestSpec("GET", "http://h/api/v1/content/resourcelinks/field/1")
    fixes = suggest_repairs(rec(400, MISSING_PARAM), spec)
    check("repair suggests supplying the missing inode/identifier param",
          any("inode" in f.what or "identifier" in f.what for f in fixes),
          str([f.what for f in fixes]))

def test_repair_suggests_enum_fix():
    from deluluscan.active.repair import suggest_repairs
    spec = RequestSpec("PUT", "http://h/api/v1/workflow/actions/default/fire/1")
    fixes = suggest_repairs(rec(400, BAD_ENUM), spec)
    check("repair suggests replacing the invalid enum value",
          any("enum" in f.what for f in fixes), str([f.what for f in fixes]))

def test_repair_suggests_json_body():
    from deluluscan.active.repair import suggest_repairs
    spec = RequestSpec("PUT", "http://h/api/v2/contenttype/x/fields/id/0")
    fixes = suggest_repairs(rec(400, BAD_JSON), spec)
    check("repair suggests supplying a valid JSON body",
          any("json body" in f.what.lower() for f in fixes), str([f.what for f in fixes]))


def test_secret_detector_ignores_field_names_and_masked():
    from deluluscan.scanners.owasp import _is_masked
    from deluluscan.active.crawler import mine_secrets
    def flagged(body):
        return bool([(k,v) for (k,v) in mine_secrets(body) if not _is_masked(v)])
    fp_cases = ['{"apiKey":null}', '{"password":""}', '{"clientSecret":"********"}',
                '{"secret":"REDACTED"}', '{"token":"changeme"}', '{"msg":"set api_key here"}']
    tp_cases = ['{"k":"AKIA1234567890ABCDEF"}',
                '{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQ"}']
    ok = all(not flagged(b) for b in fp_cases) and all(flagged(b) for b in tp_cases)
    check("secret detector: field-name/masked ignored, real values flagged", ok,
          f"fp={[flagged(b) for b in fp_cases]} tp={[flagged(b) for b in tp_cases]}")


def test_excessive_data_value_aware():
    from deluluscan.active.owasp_suite import PropertyMiner
    m = PropertyMiner()
    masked = m.check_excessive_data('{"u":{"apiKey":null,"token":"","secret":"****","password":"REDACTED"}}', 200)
    real = m.check_excessive_data('{"u":{"apiKey":"AKIA1234567890ABCDEF"}}', 200)
    check("excessive-data: masked/empty sensitive fields NOT flagged", masked == [], str([f.field for f in masked]))
    check("excessive-data: real sensitive value IS flagged", [f.field for f in real] == ["apikey"], str([f.field for f in real]))

def test_proto_pollution_requires_persistence():
    from deluluscan.active.injection import classify_proto_pollution
    class R:
        def __init__(s, b, st=200): s.resp_body = b; s.status = st
    reflection = classify_proto_pollution(R('{"__proto__":{"deluluscanPolluted":true}}'), R('{"clean":1}'))
    persisted = classify_proto_pollution(R('{"ok":1}'), R('{"x":1,"deluluscanPolluted":true}'))
    check("proto-pollution: reflection alone is NOT flagged", reflection is None, str(reflection))
    check("proto-pollution: persistence in clean follow-up IS flagged",
          persisted is not None and persisted.kind == "proto_pollution", str(persisted))


def test_auth_login_cookie_does_not_bleed_to_anon():
    """Regression: admin login sets a JWT cookie in the shared session. After
    _login() returns, the cookie must be cleared so subsequent anonymous requests
    are not sent with the admin cookie (which made all authmatrix results appear
    as bypasses on a real the target instance)."""
    import requests
    from unittest.mock import MagicMock, patch
    from deluluscan.auth import AuthManager
    from deluluscan.http_client import HttpClient
    from deluluscan.models import Identity, IdentityRole

    # Build a real HttpClient with a mocked underlying session so no network needed
    client = HttpClient.__new__(HttpClient)
    client.base_url = "https://h"
    client.timeout = 5.0
    client.verify = False
    from deluluscan.http_client import RateLimiter
    client.limiter = RateLimiter(100)
    client.session = requests.Session()

    # Simulate the target login: set a JWT cookie on the session
    client.session.cookies.set("access_token", "fake-jwt-token", domain="h")

    admin_rec = MagicMock()
    admin_rec.status = 200
    admin_rec.resp_body = '{"entity":{"token":"fake-jwt-token"}}'

    auth = AuthManager.__new__(AuthManager)
    auth.client = client
    auth._header_cache = {}

    with patch.object(client, 'request', return_value=admin_rec):
        admin_id = Identity(username="admin@example.com", password="admin",
                            role=IdentityRole.ADMIN)
        auth._login(admin_id)

    remaining_cookies = list(client.session.cookies)
    check("auth login cookie purged from session after _login() (no bleed to anon requests)",
          remaining_cookies == [], str([c.name for c in remaining_cookies]))


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    total = len(results); passed = sum(1 for _, c in results if c)
    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)
