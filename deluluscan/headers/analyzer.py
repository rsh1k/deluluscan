"""HTTP security-header, CORS, and cookie-security analysis.

Standard, high-value web hardening checks that apply to any target: missing/weak
security headers (CSP, HSTS, X-Content-Type-Options, clickjacking protection,
Referrer-Policy, Permissions-Policy), dangerous CORS (wildcard or reflected Origin
combined with credentials, `null` origin trust), insecure cookies (missing
Secure / HttpOnly / SameSite), and version-disclosure headers. Detection only.

All functions take already-parsed data (status, a lower-cased header dict, an
optional CORS probe result) so they run fully offline in tests.
"""
from __future__ import annotations

import re
from typing import Optional

from ..models import Finding, Severity, VulnClass

_SEV = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
        "critical": Severity.CRITICAL, "info": Severity.INFO}


def _f(cls, sev, title, endpoint, desc, detail=None) -> Finding:
    return Finding(vuln_class=cls, severity=_SEV[sev], title=title, endpoint=endpoint,
                   description=desc, detail=detail or {}, confidence="firm",
                   verdict="likely_true_positive", exploitability="conditional")


def _lc(headers: dict) -> dict:
    return {str(k).lower(): v for k, v in (headers or {}).items()}


# ---------------------------------------------------------------------------
def check_security_headers(headers: dict, url: str) -> list:
    h = _lc(headers)
    out: list[Finding] = []
    ctype = h.get("content-type", "")
    is_html = "text/html" in ctype or ctype == ""

    if is_html and "content-security-policy" not in h:
        out.append(_f(VulnClass.MISCONFIG, "medium", "Missing Content-Security-Policy", url,
            "No CSP header — the primary defense-in-depth control against XSS/data-injection is absent.",
            {"header": "content-security-policy", "rule": "hdr-csp"}))
    else:
        csp = h.get("content-security-policy", "")
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            out.append(_f(VulnClass.MISCONFIG, "low", "Weak CSP (unsafe-inline/unsafe-eval)", url,
                "CSP permits unsafe-inline/unsafe-eval, largely defeating its XSS protection.",
                {"rule": "hdr-csp-weak"}))

    hsts = h.get("strict-transport-security", "")
    if url.startswith("https") and not hsts:
        out.append(_f(VulnClass.CRYPTO, "medium", "Missing HSTS", url,
            "No Strict-Transport-Security — connections can be downgraded to HTTP (MITM/SSL-strip).",
            {"rule": "hdr-hsts"}))
    elif hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15552000:
            out.append(_f(VulnClass.CRYPTO, "low", "Weak HSTS max-age", url,
                f"HSTS max-age is {m.group(1)}s (< 180 days).", {"rule": "hdr-hsts-weak"}))

    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(_f(VulnClass.MISCONFIG, "low", "Missing X-Content-Type-Options: nosniff", url,
            "Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
            {"rule": "hdr-nosniff"}))

    xfo = h.get("x-frame-options", "").lower()
    csp = h.get("content-security-policy", "")
    if is_html and not xfo and "frame-ancestors" not in csp:
        out.append(_f(VulnClass.MISCONFIG, "medium", "Missing clickjacking protection", url,
            "No X-Frame-Options and no CSP frame-ancestors — the page can be framed (clickjacking).",
            {"rule": "hdr-clickjacking"}))

    if is_html and "referrer-policy" not in h:
        out.append(_f(VulnClass.MISCONFIG, "low", "Missing Referrer-Policy", url,
            "No Referrer-Policy — full URLs (with tokens in query strings) may leak via Referer.",
            {"rule": "hdr-referrer"}))
    return out


def check_disclosure(headers: dict, url: str) -> list:
    h = _lc(headers)
    out = []
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                "x-generator", "x-runtime"):
        v = h.get(hdr)
        if v and re.search(r"\d", str(v)):     # only flag when a version is present
            out.append(_f(VulnClass.INFO_LEAK, "low", f"Version disclosure via {hdr}", url,
                f"Header '{hdr}: {v}' discloses software/version, aiding targeted exploitation.",
                {"header": hdr, "value": str(v), "rule": "hdr-version-disclosure"}))
    return out


def check_cookies(headers: dict, url: str) -> list:
    """headers may carry set-cookie as a str or a list of str."""
    h = _lc(headers)
    raw = h.get("set-cookie")
    if not raw:
        return []
    cookies = raw if isinstance(raw, list) else re.split(r",(?=[^;]+?=)", raw)
    out = []
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        session_like = bool(re.search(r"(sess|sid|token|auth|jwt|rme|csrf)", name, re.I))
        sev = "medium" if session_like else "low"
        missing = []
        if "secure" not in low and url.startswith("https"):
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            out.append(_f(VulnClass.MISCONFIG, sev, f"Insecure cookie flags: {name}", url,
                f"Cookie '{name}' is missing {', '.join(missing)}"
                + (" (session-like cookie — higher risk)." if session_like else "."),
                {"cookie": name, "missing": missing, "rule": "cookie-flags"}))
    return out


def check_cors(base_headers: dict, probe_result: Optional[dict], url: str) -> list:
    """probe_result: {'acao': <Access-Control-Allow-Origin from a foreign-Origin
    request>, 'acac': <Access-Control-Allow-Credentials>, 'sent_origin': <origin>}."""
    out = []
    h = _lc(base_headers)
    acao = h.get("access-control-allow-origin")
    acac = str(h.get("access-control-allow-credentials", "")).lower() == "true"
    if acao == "*" and acac:
        # (browsers actually block *+credentials, but servers that set both are misconfigured)
        out.append(_f(VulnClass.MISCONFIG, "medium", "CORS wildcard with credentials", url,
            "Access-Control-Allow-Origin: * together with Allow-Credentials: true is an invalid, "
            "dangerous CORS policy.", {"rule": "cors-wildcard-creds"}))
    elif acao == "*":
        out.append(_f(VulnClass.MISCONFIG, "low", "CORS allows any origin (*)", url,
            "Access-Control-Allow-Origin: * exposes responses to any site (fine only for public data).",
            {"rule": "cors-wildcard"}))
    if probe_result:
        sent = probe_result.get("sent_origin")
        r_acao = probe_result.get("acao")
        r_acac = str(probe_result.get("acac", "")).lower() == "true"
        if sent and r_acao == sent and r_acac:
            out.append(_f(VulnClass.MISCONFIG, "high", "CORS reflects arbitrary Origin with credentials", url,
                f"The server reflected a foreign Origin ({sent}) into Access-Control-Allow-Origin AND "
                "set Allow-Credentials: true — any malicious site can read authenticated responses.",
                {"reflected_origin": sent, "rule": "cors-reflect-creds"}))
            out[-1].verdict = "true_positive"; out[-1].exploitability = "exploitable"
            out[-1].severity = Severity.HIGH
        elif r_acao == "null" and r_acac:
            out.append(_f(VulnClass.MISCONFIG, "high", "CORS trusts 'null' origin with credentials", url,
                "Allow-Origin: null + credentials — reachable from sandboxed iframes/data: URLs.",
                {"rule": "cors-null-creds"}))
    return out


def analyze_all(status: int, headers: dict, url: str, cors_probe: Optional[dict] = None) -> list:
    out = []
    out += check_security_headers(headers, url)
    out += check_disclosure(headers, url)
    out += check_cookies(headers, url)
    out += check_cors(headers, cors_probe, url)
    return out
