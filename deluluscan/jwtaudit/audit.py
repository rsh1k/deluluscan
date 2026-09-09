"""Static + offline audit of a captured JWT.

No live oracle needed: decode the token, flag structural/crypto weaknesses, and —
the headline — try to CRACK an HS256/384/512 signature against a list of common
secrets by recomputing the HMAC. A hit proves the signing key is guessable, so an
attacker can forge any token (full auth bypass). All offline, stdlib only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Optional

from ..models import Finding, RequestRecord, Severity, VulnClass
from .secrets_list import WEAK_SECRETS

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")
_HS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
_SENSITIVE_CLAIM = re.compile(r"(?i)(password|passwd|secret|api[_-]?key|ssn|social|credit[_-]?card|"
                              r"card[_-]?number|cvv|private[_-]?key|pin)$")


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _parse(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    return header, payload, parts


def crack_hs(token: str, wordlist=None) -> Optional[str]:
    """Return the secret if an HS* signature matches a wordlist entry, else None."""
    p = _parse(token)
    if not p:
        return None
    header, _, parts = p
    algo = _HS.get((header.get("alg") or "").upper())
    if not algo:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        want = _b64url_decode(parts[2])
    except Exception:
        return None
    for secret in (wordlist or WEAK_SECRETS):
        mac = hmac.new(secret.encode(), signing_input, algo).digest()
        if hmac.compare_digest(mac, want):
            return secret
    return None


def audit_token(token: str, *, wordlist=None, max_lifetime_h: int = 24, source: str = "jwtaudit") -> list:
    p = _parse(token)
    if not p:
        return []
    header, payload, _ = p
    out: list = []
    rec = RequestRecord(method="JWT", url=source, identity="anon", status=0, elapsed_ms=0.0,
                        resp_body=token[:120] + "…")

    def add(vc, sev, title, desc, rule, extra=None):
        out.append(Finding(vuln_class=vc, severity=sev, title=title, endpoint=source,
                           description=desc, evidence=[rec], confidence="firm",
                           verdict="true_positive", exploitability="conditional",
                           detail={"rule": rule, "alg": header.get("alg"), "source": source, **(extra or {})}))

    alg = (header.get("alg") or "").upper()

    # alg:none
    if alg in ("NONE", ""):
        add(VulnClass.CRYPTO, Severity.CRITICAL, "JWT uses alg:none (unsigned)",
            "The token header declares alg:none — it carries no signature, so any server that "
            "accepts it trusts fully attacker-controlled claims.", "jwt-alg-none")

    # HS* weak-secret crack (offline)
    if alg in _HS:
        secret = crack_hs(token, wordlist)
        if secret is not None:
            add(VulnClass.CRYPTO, Severity.CRITICAL, "JWT signed with a weak/guessable secret",
                f"The {alg} signature was cracked offline — the signing key is '{secret}'. An "
                "attacker can forge arbitrary tokens (full authentication bypass). Rotate to a "
                "long random key immediately.", "jwt-weak-secret", {"cracked_secret_masked":
                secret[:2] + "…" if len(secret) > 3 else "…", "cwe": "CWE-326"})

    # expiry hygiene
    now = int(time.time())
    if "exp" not in payload:
        add(VulnClass.CRYPTO, Severity.MEDIUM, "JWT has no expiry (exp)",
            "The token declares no exp claim, so a leaked token is valid forever.", "jwt-no-exp")
    else:
        try:
            lifetime_h = (int(payload["exp"]) - int(payload.get("iat", now))) / 3600
            if lifetime_h > max_lifetime_h:
                add(VulnClass.CRYPTO, Severity.LOW, "JWT lifetime is excessive",
                    f"The token is valid for ~{lifetime_h:.0f}h — a leaked token stays usable for a "
                    "long time. Prefer short-lived access tokens + refresh.", "jwt-long-lifetime",
                    {"lifetime_hours": round(lifetime_h, 1)})
        except Exception:
            pass

    # sensitive data in claims
    leaked = [k for k in payload if _SENSITIVE_CLAIM.search(str(k))]
    if leaked:
        add(VulnClass.INFO_LEAK, Severity.HIGH, "JWT payload carries sensitive claims",
            f"The token payload contains sensitive claim(s) {leaked} — a JWT payload is only "
            "base64, not encrypted, so anyone who sees the token reads them.", "jwt-sensitive-claims",
            {"claims": leaked, "cwe": "CWE-312"})

    # kid injection surface
    kid = str(header.get("kid", ""))
    if kid and re.search(r"[/\\]|\.\.|['\";]|\$\{|select |union ", kid, re.I):
        add(VulnClass.CRYPTO, Severity.MEDIUM, "JWT kid header contains injection metacharacters",
            f"The kid header ('{kid[:40]}') contains path/SQL metacharacters — if the server uses "
            "kid to locate a key, it may be vulnerable to path traversal or SQL injection.",
            "jwt-kid-injection", {"kid": kid[:80], "cwe": "CWE-91"})

    # jku/x5u point to fetchable URLs (SSRF / key-spoof surface)
    for h in ("jku", "x5u"):
        if header.get(h):
            add(VulnClass.SSRF, Severity.MEDIUM, f"JWT {h} header references an external URL",
                f"The {h} header ('{str(header[h])[:60]}') tells the server where to fetch the "
                "verification key — if not strictly allow-listed, an attacker can point it at a key "
                "they control (token forgery) or an internal URL (SSRF).", f"jwt-{h}",
                {h: str(header[h])[:120], "cwe": "CWE-918"})
    return out


def find_and_audit(text: str, *, wordlist=None, source: str = "response") -> list:
    """Extract JWTs from a blob of text and audit each (de-duplicated)."""
    out, seen = [], set()
    for tok in _JWT_RE.findall(text or ""):
        if tok in seen:
            continue
        seen.add(tok)
        out.extend(audit_token(tok, wordlist=wordlist, source=source))
    return out
