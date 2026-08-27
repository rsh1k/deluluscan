"""Response-disposition and access-control evidence primitives.

Grounded in NIST SP 800-115 (validate findings to eliminate false positives;
false positives commonly stem from existing mitigations) and OWASP WSTG 4.5
Authorization Testing, which defines the correct oracle for an access-control
finding: it is real only if "the weaker privileged session contains the same
data, or indicates successful operations on higher privileged functions" — NOT
merely an HTTP 200 with some body.

The old logic treated any 200 with a body over 8 bytes as "content served",
which false-flagged empty result sets (`{"contentlets":[]}`), permission errors
served as 200 (`{"message":"No Permissions"}`), and public-by-design endpoints
(login/config, published content). These helpers replace that with a
content-aware, oracle-based judgment.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

from ..semantic_diff import structural_similarity

# Bodies that mean "you were denied", even when served with HTTP 200.
_DENIAL_SIGNATURES = [
    "no permissions", "no permission", "permission denied", "not permitted",
    "access denied", "access is denied", "unauthorized", "unauthorised",
    "forbidden", "invalid user", "authentication required", "not authenticated",
    "please log in", "please login", "you must be logged in", "login required",
    "requires authentication", "insufficient privileges", "not allowed",
]
# Login form / auth-wall markers (an HTML login page returned instead of data).
_LOGIN_MARKERS = ["j_security_check", "name=\"password\"", "id=\"login",
                  "type=\"password\"", "target/login", "/admin/#/public/login"]

# JSON containers that, when empty, mean "no accessible data was returned".
_EMPTY_CONTAINER_KEYS = ("contentlets", "entity", "results", "items", "tags",
                         "errors", "data", "results")

# the target's endpoints (and general patterns) that are public BY DESIGN — returning
# data to anonymous callers here is documented, intended behavior, so a
# "served without auth" flag on them is a false positive unless the body is
# provably sensitive (handled separately by the excessive-data check).
_PUBLIC_BY_DESIGN = [
    "/api/v1/configuration", "/api/config", "/api/v1/languages",
    "/api/v1/language", "/api/content/", "/api/content/id/", "/api/content/query",
    "/api/template", "/api/v1/page/render", "/api/v1/profiles", "/dam/", "/assets/",
    "/api/v1/loginform", "/api/v1/logout", "/api/v1/authentication",
    "/.well-known/", "/robots.txt", "/api/openapi.json", "/api/swagger.json",
]

DISPOSITION_DENIED = "denied"        # auth/permission refused (401/403 or msg)
DISPOSITION_EMPTY = "empty"          # 200 but no accessible data returned
DISPOSITION_SERVER_ERROR = "server_error"   # 5xx
DISPOSITION_BAD_REQUEST = "bad_request"      # 4xx: the REQUEST was rejected, authz never evaluated
DISPOSITION_NOT_FOUND = "not_found"          # 404
DISPOSITION_THROTTLED = "throttled"          # 429
DISPOSITION_CONTENT = "content"      # substantive data actually returned

# "Not content" — none of these represent a successfully served resource, so an
# access-control finding can never be built on them.
_NON_CONTENT = {DISPOSITION_DENIED, DISPOSITION_EMPTY, DISPOSITION_SERVER_ERROR,
                DISPOSITION_BAD_REQUEST, DISPOSITION_NOT_FOUND, DISPOSITION_THROTTLED}

# Messages that mean "your REQUEST was malformed/invalid" (client error). These
# indicate the request never reached the resource logic — supply what's missing
# and retry before concluding anything. (RESTler/RestTestGen error-guided repair.)
_BAD_REQUEST_SIGNATURES = [
    "missing required", "required param", "required parameter", "is required",
    "no enum constant", "must begin with", "cannot deserialize", "not a valid",
    "invalid json", "malformed", "unrecognized field", "unexpected character",
    "bad request", "must not be null", "cannot be null", "failed to parse",
    "parameter is missing", "jsonobject text must", "jsonarray text must",
    "could not be parsed", "expected", "illegal", "constraint",
]


def _body(rec) -> str:
    return getattr(rec, "resp_body", "") or ""


def _is_empty_json(obj) -> bool:
    if obj is None:
        return True
    if isinstance(obj, (list, str)):
        return len(obj) == 0
    if isinstance(obj, dict):
        if not obj:
            return True
        # Unwrap the target {"entity": X, "errors":[], ...} envelope and judge X:
        # a response like {"entity":{"tokens":[]}} is a SUCCESSFUL read that
        # returned NO data (e.g. someone else's empty token list) — not a leak.
        # Without this, an empty payload nested one level under `entity` was
        # classified as CONTENT and produced "backend can read admin's tokens"
        # false positives.
        inner = obj.get("entity")
        if isinstance(inner, list) and len(inner) == 0:
            return True
        if isinstance(inner, dict) and inner:
            if all(v in (None, [], {}, "") for v in inner.values()):
                return True
        # entity/contentlets-style envelope with an empty payload
        for k in _EMPTY_CONTAINER_KEYS:
            if k in obj:
                v = obj[k]
                if v in (None, [], {}, ""):
                    # if the ONLY meaningful payload key is empty, treat as empty
                    meaningful = [kk for kk in obj
                                  if kk not in ("errors", "messages", "i18nMessagesMap",
                                                "pagination", "permissions")]
                    if all(obj.get(kk) in (None, [], {}, "") for kk in meaningful):
                        return True
        return False
    return False


def classify_response(rec) -> str:
    """Content-aware disposition across every status class (NIST 800-115
    validation). Crucially, a 4xx means the REQUEST was rejected — the resource
    was never served — so it can never be an access-control finding, no matter
    how similar the bodies are across identities."""
    if rec is None:
        return DISPOSITION_DENIED
    status = getattr(rec, "status", 0)
    body = _body(rec)
    low = body.lower()

    # explicit status handling first
    if status in (401, 403):
        return DISPOSITION_DENIED
    if status == 404:
        return DISPOSITION_NOT_FOUND
    if status == 429:
        return DISPOSITION_THROTTLED
    if status == 0:
        return DISPOSITION_DENIED
    if status >= 500:
        return DISPOSITION_SERVER_ERROR
    if 400 <= status < 500:
        # any other 4xx (400/405/406/415/422/…) = the request was invalid
        return DISPOSITION_BAD_REQUEST

    # 2xx/3xx: look at the body. A permission/error message served as 200 is a denial.
    if any(sig in low for sig in _DENIAL_SIGNATURES) and len(body) < 512:
        return DISPOSITION_DENIED
    if any(m in low for m in _LOGIN_MARKERS):
        return DISPOSITION_DENIED
    # a client-error message served with a 2xx still means the request was bad
    if any(sig in low for sig in _BAD_REQUEST_SIGNATURES) and len(body) < 512:
        return DISPOSITION_BAD_REQUEST

    stripped = body.strip()
    if not stripped:
        return DISPOSITION_EMPTY
    try:
        obj = json.loads(stripped)
        if _is_empty_json(obj):
            return DISPOSITION_EMPTY
    except Exception:
        if len(stripped) <= 2:
            return DISPOSITION_EMPTY
    return DISPOSITION_CONTENT


def is_public_by_design(url_or_key: str) -> bool:
    s = (url_or_key or "").lower()
    # url_or_key may be "GET https://host/path?x" or a bare path
    for pat in _PUBLIC_BY_DESIGN:
        if pat.lower() in s:
            return True
    return False


@dataclass
class OracleResult:
    served: bool                 # did anon receive the SAME real protected data?
    reason: str
    anon_disposition: str
    oracle_disposition: str
    similarity: Optional[float] = None


def _scalar_values(obj) -> set:
    """Collect the concrete scalar VALUES in a JSON body (not its structure), so
    two same-shaped responses with different data (e.g. each user's own profile
    from /users/current) are recognized as different data, not 'the same'."""
    out = set()

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o[:50]:
                walk(v)
        elif isinstance(o, bool):
            return
        elif isinstance(o, (str, int, float)):
            s = str(o)
            if len(s) >= 3:            # ignore trivial tokens/flags
                out.add(s)
    try:
        walk(obj)
    except Exception:
        pass
    return out


def _value_overlap(body_a: str, body_b: str) -> float:
    """Jaccard overlap of the actual scalar values in two JSON bodies."""
    try:
        a = _scalar_values(json.loads(body_a or ""))
        b = _scalar_values(json.loads(body_b or ""))
    except Exception:
        return 0.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def served_protected_content(anon_rec, oracle_rec, *, similarity_gate: float = 0.6) -> OracleResult:
    """OWASP WSTG 4.5 oracle: an access-control finding is real only if the
    unauthenticated (or lower-privileged) response contains the SAME real data
    the authenticated (privileged) response returns.

    We compare actual VALUES, not JSON structure — two responses that share a
    schema but carry each caller's own data (e.g. /users/current) are NOT the
    same protected data and must not be flagged as a bypass.
    """
    anon_disp = classify_response(anon_rec)
    oracle_disp = classify_response(oracle_rec)

    if anon_disp != DISPOSITION_CONTENT:
        why = {
            DISPOSITION_BAD_REQUEST: "the request was rejected as malformed/invalid "
                "(HTTP 4xx) before authorization was ever evaluated — supply the "
                "missing parameter/body and retest",
            DISPOSITION_NOT_FOUND: "the resource was not found (404)",
            DISPOSITION_DENIED: "access was denied — the control is enforced",
            DISPOSITION_EMPTY: "no accessible data was returned — the control is enforced",
            DISPOSITION_SERVER_ERROR: "the server errored (5xx); not an access grant",
            DISPOSITION_THROTTLED: "the request was throttled (429)",
        }.get(anon_disp, "no accessible data")
        return OracleResult(False,
            f"anonymous request returned '{anon_disp}': {why}", anon_disp, oracle_disp)
    if oracle_disp != DISPOSITION_CONTENT:
        return OracleResult(False,
            f"no authorized baseline to compare against (authorized request also "
            f"returned '{oracle_disp}', not real content); cannot confirm a bypass",
            anon_disp, oracle_disp)

    anon_body, oracle_body = _body(anon_rec), _body(oracle_rec)
    if anon_body == oracle_body:
        return OracleResult(True,
            "anonymous response is byte-identical to the authorized response — "
            "the same protected data is served without auth", anon_disp,
            oracle_disp, 1.0)
    overlap = _value_overlap(anon_body, oracle_body)
    if overlap >= similarity_gate:
        return OracleResult(True,
            f"anonymous response carries the same data values as the authorized "
            f"user ({overlap:.0%} value overlap) — access control is NOT enforced",
            anon_disp, oracle_disp, overlap)
    return OracleResult(False,
        f"anonymous response holds different data than the authorized response "
        f"({overlap:.0%} value overlap); not the same protected object "
        f"(e.g. self-scoped or public data)", anon_disp, oracle_disp, overlap)


def looks_sensitive_body(body: str) -> list[str]:
    """Exact-key detection of sensitive properties in a JSON body (BOPLA /
    excessive-data). Word-boundary matched to avoid substring false hits like
    'Mawson' matching 'aws'."""
    hits = []
    try:
        obj = json.loads(body or "")
    except Exception:
        return hits
    keys = set()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                keys.add(k.lower())
                walk(v)
        elif isinstance(o, list):
            for v in o[:10]:
                walk(v)
    walk(obj)
    sensitive = {"password", "passwordhash", "hash", "salt", "token",
                 "accesstoken", "refreshtoken", "secret", "apikey", "api_key",
                 "privatekey", "ssn", "creditcard", "cvv", "pin", "resettoken",
                 "mfasecret", "clientsecret"}
    return sorted(keys & sensitive)
