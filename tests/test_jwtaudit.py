"""Offline tests for the JWT audit (structural + HS* secret cracking)."""
from __future__ import annotations

import base64, hashlib, hmac, json, time

from deluluscan.jwtaudit import audit_token, crack_hs, find_and_audit
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def _b64(d): return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
def mk(secret="secret", payload=None, alg="HS256", header=None):
    h = {"alg": alg, "typ": "JWT"}; h.update(header or {})
    hb = _b64(json.dumps(h).encode()); pb = _b64(json.dumps(payload or {"sub": "x"}).encode())
    algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    sig = hmac.new(secret.encode(), f"{hb}.{pb}".encode(), algo).digest() if algo else b""
    return f"{hb}.{pb}.{_b64(sig)}"


def rules(f): return {x.detail.get("rule") for x in f}


def test_crack_weak_secret():
    tok = mk("changeme", {"sub": "admin"})
    check("weak secret cracked", crack_hs(tok) == "changeme")
    f = audit_token(tok)
    ws = next((x for x in f if x.detail["rule"] == "jwt-weak-secret"), None)
    check("weak-secret CRITICAL crypto", ws and ws.severity == Severity.CRITICAL and ws.vuln_class == VulnClass.CRYPTO)


def test_strong_secret_not_cracked():
    tok = mk("Zx9$k2Lm!qR7vP3wN8tY6uH1cB4dF0gJ-random-long", {"sub": "admin", "exp": int(time.time()) + 600})
    check("strong secret not cracked", crack_hs(tok) is None)
    check("no weak-secret finding", "jwt-weak-secret" not in rules(audit_token(tok)))


def test_alg_none():
    hb = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    pb = _b64(json.dumps({"sub": "admin"}).encode())
    f = audit_token(f"{hb}.{pb}.")
    an = next((x for x in f if x.detail["rule"] == "jwt-alg-none"), None)
    check("alg:none CRITICAL", an and an.severity == Severity.CRITICAL, rules(f))


def test_expiry_hygiene():
    check("no exp flagged", "jwt-no-exp" in rules(audit_token(mk(payload={"sub": "x"}))))
    long_tok = mk(payload={"sub": "x", "iat": int(time.time()), "exp": int(time.time()) + 3600 * 240})
    check("long lifetime flagged", "jwt-long-lifetime" in rules(audit_token(long_tok)))
    ok_tok = mk("Zx9$k2Lm!qR7-long-random-key", payload={"sub": "x", "iat": int(time.time()), "exp": int(time.time()) + 900})
    check("short-lived strong token is clean", audit_token(ok_tok) == [], [x.title for x in audit_token(ok_tok)])


def test_sensitive_claims():
    f = audit_token(mk("k" * 40, {"sub": "x", "password": "p", "exp": int(time.time()) + 300}))
    sc = next((x for x in f if x.detail["rule"] == "jwt-sensitive-claims"), None)
    check("sensitive claim flagged HIGH info_leak",
          sc and sc.severity == Severity.HIGH and sc.vuln_class == VulnClass.INFO_LEAK, rules(f))


def test_kid_injection_and_jku():
    f = audit_token(mk("k" * 40, {"sub": "x", "exp": int(time.time()) + 300}, header={"kid": "../../etc/passwd"}))
    check("kid traversal flagged", "jwt-kid-injection" in rules(f), rules(f))
    f2 = audit_token(mk("k" * 40, {"sub": "x", "exp": int(time.time()) + 300}, header={"jku": "https://evil/jwks.json"}))
    j = next((x for x in f2 if x.detail["rule"] == "jwt-jku"), None)
    check("jku SSRF flagged", j and j.vuln_class == VulnClass.SSRF, rules(f2))


def test_find_and_audit_extracts():
    tok = mk("secret", {"sub": "x"})
    f = find_and_audit(f'Authorization: Bearer {tok}\nsome other text')
    check("JWT extracted + audited from text", any(x.detail["rule"] == "jwt-weak-secret" for x in f), rules(f))
    check("no JWT -> nothing", find_and_audit("just plain text, no token here") == [])


def test_passive_engine_audits_jwt_in_body():
    from deluluscan.passive import PassiveScan
    tok = mk("secret", {"sub": "x"})
    finds = PassiveScan().analyze(200, "http://t/", {"content-type": "application/json"},
                                  '{"access_token":"' + tok + '"}')
    check("passive engine cracks a JWT in the body",
          any(f.detail.get("rule") == "jwt-weak-secret" for f in finds), [f.title for f in finds])


def test_malformed_token_safe():
    check("garbage -> no findings/crash", audit_token("not.a.jwt") == [])
    check("two-part -> no crash", audit_token("eyJ.eyJ") == [])


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
