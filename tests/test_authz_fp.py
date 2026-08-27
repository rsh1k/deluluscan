"""Regression tests for the authorization-scanner false-positive fixes.

Pins the behaviour the user reported as broken: scanners must NOT flag an
authz finding when the response is an error (400 / 404 / 405 / 5xx), a denial,
or a 200-wrapped error envelope ({"errors":[...]}, {"message":"No Permissions"}).
Only a genuine grant — a 2xx write success, or substantive read CONTENT — is a
finding. See deluluscan/verify/evidence.classify_response for the shared oracle.

Run: python -m tests.test_authz_fp
"""
from __future__ import annotations
import sys, os, json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import RequestRecord, Endpoint, Identity, IdentityRole
from deluluscan.scanners.idor_write import IdorWriteScanner
from deluluscan.scanners.bopla import BoplaScanner
from deluluscan.scanners.owasp import OwaspBroadScanner

results = []
def check(name, cond, extra=""):
    results.append((name, cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))


def rec(status, body="", url="http://h/x", ident="backend"):
    return RequestRecord(method="GET", url=url, identity=ident, status=status,
                         elapsed_ms=5.0, resp_headers={}, resp_body=body, resp_len=len(body))


class FakeAuth:
    def headers_for(self, ident): return {"Authorization": "Bearer x"}

class FakeClient:
    def __init__(self, responder): self.responder = responder
    def request(self, method, path, *, identity_label=None, headers=None, **k):
        return self.responder(method, path, identity_label, k)

class _Scan:
    def __init__(self, allow_state_changing=True):
        self.allow_state_changing = allow_state_changing
class FakeConfig:
    def __init__(self, allow_state_changing=True):
        self.scan = _Scan(allow_state_changing)
        self.base_url = "http://h"

def _idents():
    return {"backend": Identity(role=IdentityRole.BACKEND, username="b", password="p"),
            "anonymous": Identity(role=IdentityRole.ANON),
            "admin": Identity(role=IdentityRole.ADMIN, username="a", password="p")}

def _run(scanner_cls, responder, ep, cfg=None):
    sc = scanner_cls(FakeClient(responder), FakeAuth(), cfg or FakeConfig(), _idents())
    return list(sc.run(ep))


# ---- idor_write: errors are not grants ------------------------------------
def test_idorwrite_500_not_flagged():
    # backend DELETE of admin user returns 500 -> server error, NOT "can delete".
    def responder(method, path, label, k):
        if label == "anonymous": return rec(403, "denied")
        return rec(500, '{"message":"Internal Server Error"}')
    out = _run(IdorWriteScanner, responder, Endpoint(method="DELETE", path="/api/v1/users/x"))
    bad = [f for f in out if "DELETE" in f.title and f.confidence == "firm"]
    check("idor_write: 500 on DELETE is NOT a firm 'can delete' finding", not bad,
          str([f.title for f in out]))

def test_idorwrite_error_envelope_read_not_flagged():
    # backend GET admin tokens returns 200 {"errors":[...]} -> denied envelope.
    def responder(method, path, label, k):
        return rec(200, '{"errors":[{"message":"No Permissions"}]}')
    out = _run(IdorWriteScanner, responder, Endpoint(method="GET", path="/api/tokens/x/tokens"))
    bad = [f for f in out if "read admin's API tokens" in f.title]
    check("idor_write: 200 error-envelope read is NOT flagged", not bad,
          str([f.title for f in out]))

def test_idorwrite_real_delete_success_still_flagged():
    # a genuine 200 success on cross-user delete MUST still be caught.
    def responder(method, path, label, k):
        if label == "anonymous": return rec(403, "denied")
        return rec(200, '{"entity":"deleted"}')
    out = _run(IdorWriteScanner, responder, Endpoint(method="DELETE", path="/api/v1/users/x"))
    good = [f for f in out if "DELETE" in f.title]
    check("idor_write: genuine 2xx cross-user delete IS still flagged", bool(good),
          str([f.title for f in out]))


# ---- bopla: mass-assignment requires value persistence --------------------
def test_bopla_field_name_in_email_not_flagged():
    # read-back contains "admin" (in the email) and "roles"/"active" as normal
    # fields, but our injected values did NOT persist -> NOT mass assignment.
    normal_user = json.dumps({"entity": {"userId": "u1", "email": "user@admin.example",
                                         "roles": ["Frontend"], "active": True,
                                         "admin": False, "additionalInfo": None}})
    def responder(method, path, label, k):
        return rec(200, normal_user)
    out = _run(BoplaScanner, responder, Endpoint(method="PUT", path="/api/v1/users/current"))
    bad = [f for f in out if "Mass assignment" in f.title]
    check("bopla: field-name substring ('admin' in email) is NOT mass assignment", not bad,
          str([f.title for f in out]))


# ---- owasp: admin-only endpoint needs real content ------------------------
def test_owasp_empty_entity_not_flagged():
    # a 200 with an empty entity to an unprivileged caller is not admin data.
    ep = Endpoint(method="GET", path="/api/v1/users/filter")
    def responder(method, path, label, k):
        return rec(200, '{"entity":[]}')
    # only assert no crash + no firm admin-access FP on an empty body
    try:
        out = _run(OwaspBroadScanner, responder, ep)
        bad = [f for f in out if "Admin-only endpoint accessible" in f.title]
        check("owasp: 200 empty entity is NOT flagged as admin access", not bad,
              str([f.title for f in out]))
    except Exception as e:
        check("owasp: 200 empty entity is NOT flagged as admin access", False, f"crash: {e}")


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            try:
                fn()
            except Exception as e:
                results.append((getattr(fn, "__name__"), False))
                print(f"FAIL  {fn.__name__}  [exception: {e}]")
    passed = sum(1 for _, c in results if c)
    print(f"\n{passed}/{len(results)} checks passed")
    sys.exit(0 if passed == len(results) else 1)
