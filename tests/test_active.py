"""Unit tests for the active workbench: JWT manipulation and authz probing.

No live server — a fake client models vulnerable vs. secure server policies.
Run: python -m tests.test_active
"""
from __future__ import annotations
import sys, os, json, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import RequestRecord
from deluluscan.active import jwt_lab as J
from deluluscan.active.jwt_lab import JwtLab, decode
from deluluscan.active.http_tools import RequestSpec, Repeater, Intruder, Position
from deluluscan.active.authz_probe import AuthzProbe

results = []
def check(name, cond, extra=""):
    results.append((name, cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))

def rec(status=200, body="", headers=None, ident="anonymous", url="http://h/x", method="GET"):
    return RequestRecord(method=method, url=url, identity=ident, status=status,
                         elapsed_ms=10.0, resp_headers=headers or {}, resp_body=body,
                         resp_len=len(body))


# ---- helpers to build tokens & fake servers --------------------------------
SECRET = "secret"
def make_token(alg="HS256", role="backend", secret=SECRET, exp_offset=3600, extra=None):
    header = {"alg": alg, "typ": "JWT"}
    payload = {"sub": "user-1", "role": role, "exp": int(time.time()) + exp_offset}
    if extra:
        payload.update(extra)
    return J.encode(header, payload, secret=secret, alg=alg)

GOOD = rec(200, '{"userId":"user-1","role":"backend"}')
DENIED = rec(401, "unauthorized")

def server_no_verify(tok):
    """VULNERABLE: trusts claims, never checks the signature -> accepts none/strip/tamper/claims."""
    try:
        decode(tok)
        return rec(200, '{"userId":"user-1","role":"trusted"}')
    except Exception:
        return DENIED

def server_verify_hs256(tok):
    """SECURE: verify HS256 with SECRET and exp."""
    try:
        d = decode(tok)
        if d.header.get("alg") not in ("HS256", "HS384", "HS512"):
            return DENIED
        expected = J.b64url_encode(J._hs_sign(d.signing_input, SECRET, d.header["alg"]))
        if expected != d.parts()[2]:
            return DENIED
        if d.payload.get("exp", 0) < time.time():
            return DENIED
        return rec(200, '{"userId":"user-1","role":"%s"}' % d.payload.get("role"))
    except Exception:
        return DENIED

PUBKEY = "-----BEGIN PUBLIC KEY-----\nFAKEKEYMATERIAL\n-----END PUBLIC KEY-----"
def server_hs_confusion(tok):
    """VULNERABLE: verifies HS256 using the RSA PUBLIC KEY as the secret."""
    try:
        d = decode(tok)
        if not d.header.get("alg", "").startswith("HS"):
            return DENIED
        expected = J.b64url_encode(J._hs_sign(d.signing_input, PUBKEY, "HS256"))
        return rec(200, "ok") if expected == d.parts()[2] else DENIED
    except Exception:
        return DENIED


# ============================================================================
# JWT tests
# ============================================================================
def test_jwt_none_accepted():
    lab = JwtLab(server_no_verify, GOOD, DENIED)
    out = lab.run(make_token())
    check("jwt alg:none flagged on vulnerable server",
          any(r.test.startswith("alg_none") and r.accepted for r in out))
    check("jwt claim escalation demonstrated",
          any(r.test == "claim_tamper" and r.accepted for r in out))

def test_jwt_secure_server_clean():
    lab = JwtLab(server_verify_hs256, GOOD, DENIED)
    out = lab.run(make_token())
    accepted = [r.test for r in out if r.accepted]
    # SECRET is "secret" which IS in the weak list -> weak_secret should be the
    # only acceptance path, and claim tampering via the cracked secret.
    check("secure server: alg:none rejected",
          not any(r.test.startswith("alg_none") and r.accepted for r in out))
    check("secure server: strip/tamper rejected",
          not any(r.test in ("strip_signature", "tamper_signature") and r.accepted for r in out))
    check("weak secret detected (secret is guessable)",
          any(r.test == "weak_secret" and r.accepted for r in out), str(accepted))

def test_jwt_strong_secret_fully_clean():
    strong = "9f8c2b1a7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b"
    def server(tok):
        try:
            d = decode(tok)
            if d.header.get("alg") not in ("HS256",):
                return DENIED
            exp = J.b64url_encode(J._hs_sign(d.signing_input, strong, "HS256"))
            if exp != d.parts()[2] or d.payload.get("exp", 0) < time.time():
                return DENIED
            return rec(200, "ok")
        except Exception:
            return DENIED
    lab = JwtLab(server, GOOD, DENIED)
    out = lab.run(make_token(secret=strong))
    check("strong secret: nothing accepted", not any(r.accepted for r in out),
          str([r.test for r in out if r.accepted]))

def test_jwt_alg_confusion():
    # token presents as RS256; server verifies HS256 with the public key
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"sub": "user-1", "role": "backend", "exp": int(time.time()) + 3600}
    h = J.b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = J.b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    rs_token = f"{h}.{p}.QUFBQQ"  # dummy signature
    lab = JwtLab(server_hs_confusion, GOOD, DENIED, public_key_pem=PUBKEY)
    out = lab.run(rs_token)
    check("jwt RS->HS confusion flagged",
          any(r.test == "alg_confusion_rs_to_hs" and r.accepted for r in out))


# ============================================================================
# Active authz probe
# ============================================================================
class AuthzFakeClient:
    def __init__(self, policy):
        self.policy = policy
    def request(self, method, path, *, identity_label="anonymous", headers=None,
                params=None, json_body=None, data=None, allow_redirects=False, **kw):
        return self.policy(method, path, identity_label, headers or {}, json_body)

def test_missing_auth_detected():
    def policy(m, path, ident, headers, body):
        has_auth = any(k.lower() == "authorization" for k in headers) or \
                   any(k.lower() == "cookie" for k in headers)
        if has_auth:
            return rec(200, '{"data":"secret admin panel content here"}', method=m, url=path)
        # VULNERABLE: still serves without auth
        return rec(200, '{"data":"secret admin panel content here"}', method=m, url=path)
    probe = AuthzProbe(AuthzFakeClient(policy))
    good = rec(200, '{"data":"secret admin panel content here"}')
    spec = RequestSpec("GET", "http://h/api/admin", headers={"Authorization": "Bearer x"})
    res = probe.test_missing_auth(spec, good)
    check("missing_auth granted (vulnerable)", res.granted, res.detail)

def test_missing_auth_secure():
    def policy(m, path, ident, headers, body):
        has_auth = any(k.lower() == "authorization" for k in headers)
        return rec(200, '{"data":"ok"}') if has_auth else rec(401, "no")
    probe = AuthzProbe(AuthzFakeClient(policy))
    good = rec(200, '{"data":"ok"}')
    spec = RequestSpec("GET", "http://h/api/admin", headers={"Authorization": "Bearer x"})
    res = probe.test_missing_auth(spec, good)
    check("missing_auth denied (secure)", not res.granted, res.detail)

def test_mass_assignment_detected():
    def policy(m, path, ident, headers, body):
        # VULNERABLE: echoes back whatever fields were sent, including admin:true
        return rec(200, json.dumps(body or {}), method=m, url=path)
    probe = AuthzProbe(AuthzFakeClient(policy))
    spec = RequestSpec("PUT", "http://h/api/profile", headers={"Authorization": "Bearer x"},
                       json_body={"name": "bob"})
    out = probe.test_mass_assignment(spec, "backend", {"Authorization": "Bearer x"})
    check("mass_assignment detected", any(r.granted for r in out),
          str([r.detail for r in out]))

def test_bola_id_swap_detected():
    real_other = "22222222-3333-4444-5555-666666666666"
    def policy(m, path, ident, headers, body):
        if "0000000000ff" in path:      # bogus -> 404
            return rec(404, "not found", method=m, url=path)
        if real_other in path:          # another principal's object -> served
            return rec(200, '{"owner":"someone-else","balance":9999}', method=m, url=path)
        return rec(200, "{}", method=m, url=path)
    probe = AuthzProbe(AuthzFakeClient(policy))
    spec = RequestSpec("GET", f"http://h/api/order/11111111-2222-3333-4444-555555555555",
                       headers={"Authorization": "Bearer x"})
    res = probe.test_bola_id(spec, "11111111-2222-3333-4444-555555555555",
                             real_other, "backend", {"Authorization": "Bearer x"})
    check("bola_id_swap detected", res.granted, res.detail)


# ============================================================================
# Intruder / Repeater sanity
# ============================================================================
def test_intruder_flags_deviation():
    def policy(m, path, ident, headers, params, *a, **k):
        # id=42 returns a big body, everything else small
        val = (params or {}).get("id")
        body = "X" * 2000 if val == "42" else "X" * 100
        return rec(200, body, method=m, url=path)
    class C:
        def request(self, method, path, *, identity_label="anonymous", headers=None,
                    params=None, **kw):
            return policy(method, path, identity_label, headers, params)
    intr = Intruder(C())
    base = RequestSpec("GET", "http://h/api/item", params={"id": "1"})
    out = intr.attack(base, [Position("param", "id")], ["1", "2", "42", "7"],
                      attack_type="sniper")
    hits = [r for r in out if r.interesting]
    check("intruder flags the outlier payload",
          any(r.payload == "42" for r in hits), str([(r.payload, r.reason) for r in out]))


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    total = len(results); passed = sum(1 for _, c in results if c)
    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)
