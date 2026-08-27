"""Detection of compensating / mitigating controls.

Pure analysis of response headers/bodies we already captured (plus, in the
verifier, one or two fresh benign probes). No control is *bypassed* here — we
only observe whether it is present and how strong it is, so the verifier can
decide whether a finding is exploitable as-is or is neutralized/mitigated.

References informing the heuristics:
- CSP as an XSS mitigant, and why unsafe-inline / wildcards weaken it
  (OWASP; PortSwigger Web Security Academy CSP labs).
- X-Content-Type-Options: nosniff preventing a non-HTML reflection from being
  rendered as HTML.
- The browser rule that Access-Control-Allow-Origin: * together with
  Allow-Credentials: true is rejected, so it is not directly exploitable.
- WAF block pages / status codes as a classic DAST false-positive source.
"""
from __future__ import annotations

import re
from typing import Optional

from ..models import RequestRecord
from .models import ControlObservation


# --- header case-insensitive access -----------------------------------------
def _h(record: RequestRecord, name: str) -> str:
    if not record or not record.resp_headers:
        return ""
    low = name.lower()
    for k, v in record.resp_headers.items():
        if k.lower() == low:
            return v or ""
    return ""


# --- Content-Security-Policy -------------------------------------------------
def parse_csp(header: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        out[toks[0].lower()] = [t.lower() for t in toks[1:]]
    return out


def csp_strength(header: str) -> tuple[str, str]:
    """Return (strength, human_reason).

    strong   : a script source is constrained to self/nonce/hash/strict-dynamic
               with no unsafe-inline and no wildcard.
    moderate : constrained but with a notable gap.
    weak     : effectively permissive for script (unsafe-inline, *, http:, data:).
    none     : no CSP, or no script-governing directive.
    """
    if not header.strip():
        return "none", "no Content-Security-Policy header"
    csp = parse_csp(header)
    script = csp.get("script-src") or csp.get("default-src")
    if script is None:
        return "none", "CSP present but no script-src/default-src to govern scripts"
    joined = " ".join(script)
    if "'unsafe-inline'" in script and "'nonce-" not in joined and "'strict-dynamic'" not in joined:
        return "weak", "script-src allows 'unsafe-inline' without nonce/strict-dynamic"
    if "*" in script or "http:" in joined or "https:" == joined.strip() or "data:" in script:
        return "weak", "script-src includes a wildcard/scheme source"
    has_nonce = "'nonce-" in joined or "'strict-dynamic'" in joined or any(s.startswith("'sha") for s in script)
    if has_nonce and "'unsafe-inline'" not in script:
        return "strong", "script-src uses nonce/hash/strict-dynamic, no unsafe-inline"
    if script == ["'self'"]:
        return "moderate", "script-src 'self' (blocks inline; same-origin upload/JSONP could still be abused)"
    return "moderate", "script-src constrained but not nonce/hash based"


def csp_control(record: RequestRecord) -> ControlObservation:
    header = _h(record, "content-security-policy")
    strength, reason = csp_strength(header)
    return ControlObservation("csp", present=bool(header.strip()),
                              strength=strength, detail=reason)


# --- X-Content-Type-Options / content type ----------------------------------
def nosniff_control(record: RequestRecord) -> ControlObservation:
    val = _h(record, "x-content-type-options").lower()
    present = "nosniff" in val
    return ControlObservation("nosniff", present=present,
                              strength="moderate" if present else "none",
                              detail="X-Content-Type-Options: nosniff set" if present
                              else "no nosniff; content may be MIME-sniffed to HTML")


def html_executable_context(record: RequestRecord) -> tuple[bool, str]:
    """Would a reflected marker plausibly execute as HTML in a browser?"""
    ctype = _h(record, "content-type").lower()
    body_head = (record.resp_body or "")[:512].lower()
    is_htmlish = "text/html" in ctype or "application/xhtml" in ctype \
        or (not ctype and "<html" in body_head)
    if is_htmlish:
        return True, f"response Content-Type is HTML ({ctype or 'inferred'})"
    # Non-HTML content type. nosniff decides whether a browser might still sniff.
    if nosniff_control(record).present:
        return False, (f"Content-Type {ctype or 'unknown'} is non-HTML and "
                       f"nosniff is set — the browser will not render it as HTML")
    return False, (f"Content-Type {ctype or 'unknown'} is non-HTML "
                   f"(execution would require MIME sniffing; no nosniff, so not fully ruled out)")


# --- other security headers --------------------------------------------------
def header_controls(record: RequestRecord) -> list[ControlObservation]:
    out = [csp_control(record), nosniff_control(record)]
    xfo = _h(record, "x-frame-options")
    out.append(ControlObservation("frame_options", present=bool(xfo),
                                   strength="moderate" if xfo else "none",
                                   detail=xfo or "no X-Frame-Options"))
    hsts = _h(record, "strict-transport-security")
    out.append(ControlObservation("hsts", present=bool(hsts),
                                   strength="moderate" if hsts else "none",
                                   detail=hsts or "no HSTS"))
    return out


def cookie_flags_control(record: RequestRecord) -> ControlObservation:
    setc = _h(record, "set-cookie")
    if not setc:
        return ControlObservation("cookie_flags", present=False, strength="n/a",
                                  detail="no Set-Cookie on this response")
    low = setc.lower()
    flags = [f for f in ("httponly", "secure", "samesite") if f in low]
    strong = "httponly" in flags
    return ControlObservation("cookie_flags", present=True,
                              strength="moderate" if strong else "weak",
                              detail=f"cookie flags: {', '.join(flags) or 'none'}")


# --- WAF ---------------------------------------------------------------------
_WAF_HEADER_SIGS = re.compile(
    r"(cf-ray|cloudflare|x-sucuri|incap_ses|x-cdn|akamai|barracuda|"
    r"x-iinfo|x-datadome|awselb|mod_security|modsecurity|x-waf)", re.IGNORECASE)
_WAF_BODY_SIGS = re.compile(
    r"(access denied|request blocked|blocked by|web application firewall|"
    r"attention required|cloudflare|incapsula|not acceptable|forbidden by rule|"
    r"your request has been blocked|security policy)", re.IGNORECASE)
_WAF_STATUSES = {403, 406, 419, 429, 501, 503}


def detect_waf(records: list[RequestRecord]) -> ControlObservation:
    """Look across evidence for signs a WAF/edge is inspecting requests.

    Important as BOTH a mitigating control AND a false-positive confounder: a WAF
    block page can masquerade as a boolean-difference or an injected 'error'.
    """
    hits: list[str] = []
    for r in records:
        if not r:
            continue
        hdrs = " ".join(f"{k}: {v}" for k, v in (r.resp_headers or {}).items())
        m = _WAF_HEADER_SIGS.search(hdrs)
        if m:
            hits.append(f"header signature '{m.group(0)}'")
        if r.status in _WAF_STATUSES and _WAF_BODY_SIGS.search(r.resp_body or ""):
            hits.append(f"block-page body at HTTP {r.status}")
    present = bool(hits)
    return ControlObservation("waf", present=present,
                              strength="moderate" if present else "none",
                              detail="; ".join(sorted(set(hits))) if present
                              else "no WAF/edge signatures observed")


def looks_like_block_page(record: RequestRecord) -> bool:
    if not record:
        return False
    if record.status in _WAF_STATUSES and _WAF_BODY_SIGS.search(record.resp_body or ""):
        return True
    return False


# --- CORS --------------------------------------------------------------------
def cors_assessment(record: RequestRecord) -> tuple[str, str]:
    """(exploitability, reason) for a permissive-CORS finding."""
    acao = _h(record, "access-control-allow-origin")
    acac = _h(record, "access-control-allow-credentials").lower()
    if acao == "*" and acac == "true":
        return "not_exploitable", ("ACAO '*' with Allow-Credentials true is "
                                   "rejected by browsers — not exploitable as-is")
    if acao and acao != "*" and acac == "true":
        return "conditional", ("origin appears reflected with credentials allowed "
                               "— cross-origin credentialed reads possible if the "
                               "reflection is attacker-controlled (verify manually)")
    if acao == "*":
        return "mitigated", ("ACAO '*' without credentials exposes only "
                             "unauthenticated data")
    return "unknown", "CORS headers not conclusively permissive"


# --- auth requirement (compensating control for authz/idor) ------------------
def auth_required(anon_status: Optional[int]) -> ControlObservation:
    if anon_status is None:
        return ControlObservation("auth_required", present=False, strength="n/a",
                                  detail="anonymous access not tested")
    denied = anon_status in (401, 403)
    return ControlObservation("auth_required", present=denied,
                              strength="strong" if denied else "none",
                              detail=(f"anonymous request returned HTTP {anon_status} "
                                      f"({'authentication enforced' if denied else 'no auth gate'})"))
