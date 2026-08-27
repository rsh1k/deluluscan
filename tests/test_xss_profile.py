import sys, os
sys.path.insert(0, '/tmp/deluluscan')
from deluluscan.models import RequestRecord, Endpoint, Identity, IdentityRole
from deluluscan.scanners.xss import XssScanner

def rec(status=200, body="", headers=None):
    return RequestRecord(method="GET", url="http://h/x", identity="a", status=status,
                         elapsed_ms=5.0, resp_headers=headers or {}, resp_body=body, resp_len=len(body))

class FakeAuth:
    def headers_for(self, ident): return {"Authorization": "Bearer x"}
class FakeScan:
    allow_state_changing = True
class FakeConfig:
    scan = FakeScan(); base_url="http://h"
class FakeClient:
    def __init__(self): self.stored={}
    def request(self, method, path, *, identity_label=None, headers=None, json_body=None, params=None, **k):
        if path.endswith("/users/current") and method=="GET":
            gv=self.stored.get("givenName",""); sn=self.stored.get("surname","")
            return rec(200, f'{{"userId":"u1","givenName":"{gv}","surname":"{sn}"}}')
        if path.endswith("/users/current") and method=="PUT":
            if not json_body or "currentPassword" not in json_body:
                return rec(400, '{"message":"current password required"}')  # the target behavior
            self.stored["givenName"]=json_body.get("givenName","")
            self.stored["surname"]=json_body.get("surname","")
            return rec(200, "{}")
        return rec(404,"")

ident=Identity(role=IdentityRole.BACKEND, username="e", password="pw")
sc=XssScanner(FakeClient(), FakeAuth(), FakeConfig(), {"backend":ident})
ep=Endpoint(method="PUT", path="/api/v1/users/current")
out=list(sc.run(ep))
titles=[f.title for f in out]
ok = any("Profile name fields" in t for t in titles)
print(("PASS" if ok else "FAIL"), "- profile XSS detected when currentPassword required:", titles)
import sys as _s; _s.exit(0 if ok else 1)
