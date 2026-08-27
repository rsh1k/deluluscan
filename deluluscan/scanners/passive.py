"""Passive scanner — Burp Suite passive-scan parity.

Passive checks never send extra attack traffic; they inspect responses the scan
already collected and flag issues that are true by observation: missing/weak
security headers, insecure cookie flags, cache-control on sensitive responses,
information leakage in headers/bodies, and permissive CORS. These are low-noise,
high-signal, and (being observational) are marked verified without extra probes.
"""
from __future__ import annotations

import re
from typing import Iterable

from .base import Scanner
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

_SEC_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy", Severity.LOW),
    "x-content-type-options": ("Missing X-Content-Type-Options: nosniff", Severity.LOW),
    "strict-transport-security": ("Missing HSTS (Strict-Transport-Security)", Severity.LOW),
    "x-frame-options": ("Missing X-Frame-Options / frame-ancestors", Severity.LOW),
    "referrer-policy": ("Missing Referrer-Policy", Severity.INFO),
}
_SERVER_LEAK = re.compile(r"(server|x-powered-by|x-aspnet-version|x-generator)", re.I)
_TOKEN_IN_URL = re.compile(r"[?&](token|access_token|apikey|api_key|sessionid|jwt|password)=", re.I)


def _h(headers: dict, name: str):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


class PassiveScanner(Scanner):
    name = "passive"
    vuln_classes = [VulnClass.MISCONFIG.value, VulnClass.INFO_LEAK.value]

    def applies_to(self, e: Endpoint) -> bool:
        return e.method.upper() == "GET"

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)
        if ident is None:
            return
        rec = self.fetch(endpoint, ident)
        if rec is None or rec.status == 0:
            return
        headers = rec.resp_headers or {}
        seen = getattr(self, "_seen_global", None)
        if seen is None:
            seen = self._seen_global = set()

        ctype = (_h(headers, "content-type") or "").lower()
        is_html = "text/html" in ctype
        is_json = "json" in ctype

        # 1) missing security headers (report once per host to avoid noise)
        for hdr, (title, sev) in _SEC_HEADERS.items():
            if hdr in ("content-security-policy", "x-frame-options") and not is_html:
                continue  # only meaningful for rendered HTML
            if _h(headers, hdr) is None and title not in seen:
                seen.add(title)
                yield self._passive(VulnClass.MISCONFIG, sev, title, endpoint, rec,
                    f"Response lacks {hdr}. Add it at the app/edge for defense in depth.",
                    "missing_security_header")

        # 2) insecure cookies
        setcookie = _h(headers, "set-cookie") or ""
        if setcookie:
            low = setcookie.lower()
            problems = []
            if "httponly" not in low:
                problems.append("HttpOnly")
            if "secure" not in low:
                problems.append("Secure")
            if "samesite" not in low:
                problems.append("SameSite")
            if problems and "cookie_flags" not in seen:
                seen.add("cookie_flags")
                yield self._passive(VulnClass.MISCONFIG, Severity.LOW,
                    f"Cookie missing flags: {', '.join(problems)}", endpoint, rec,
                    "Session cookies should set HttpOnly, Secure and SameSite.",
                    "cookie_flags")

        # 3) server/version banner leakage
        for hk in headers:
            if _SERVER_LEAK.match(hk) and headers[hk] and re.search(r"\d", str(headers[hk])):
                key = f"banner:{hk.lower()}"
                if key not in seen:
                    seen.add(key)
                    yield self._passive(VulnClass.INFO_LEAK, Severity.INFO,
                        f"Version banner in '{hk}' header", endpoint, rec,
                        f"The '{hk}: {headers[hk]}' header discloses software/version; suppress it.",
                        "version_banner")

        # 4) sensitive token in URL (query string)
        if _TOKEN_IN_URL.search(rec.url or ""):
            yield self._passive(VulnClass.INFO_LEAK, Severity.MEDIUM,
                "Sensitive token passed in URL query string", endpoint, rec,
                "Secrets in URLs leak via logs, referrers and history; move them to headers/body.",
                "secret_in_url")

        # 5) permissive CORS observed passively
        acao = _h(headers, "access-control-allow-origin")
        acac = _h(headers, "access-control-allow-credentials")
        if acao == "*" and (acac or "").lower() == "true" and "cors" not in seen:
            seen.add("cors")
            yield self._passive(VulnClass.MISCONFIG, Severity.LOW,
                "CORS: wildcard origin with credentials", endpoint, rec,
                "ACAO:* with Allow-Credentials:true is rejected by browsers but signals "
                "misconfiguration; scope allowed origins explicitly.", "cors_wildcard_creds")

        # 6) missing cache-control on a JSON API response with sensitive-looking data
        if is_json and _h(headers, "cache-control") is None and "cache" not in seen:
            body_low = (rec.resp_body or "")[:500].lower()
            if any(k in body_low for k in ("email", "token", "user", "role")):
                seen.add("cache")
                yield self._passive(VulnClass.MISCONFIG, Severity.INFO,
                    "No Cache-Control on a data API response", endpoint, rec,
                    "Add Cache-Control: no-store to responses carrying user data.",
                    "no_cache_control")

        # 7) response-BODY content rules (ZAP passive-scan parity): stack traces,
        # SQL errors, exposed debug consoles, directory listing, internal-IP
        # disclosure, HTML-comment leaks. Reuses the shared deluluscan.passive
        # rule set so a full scan analyzes every collected body for free.
        # Deduped once per scan per rule to stay low-noise.
        yield from self._body_rules(endpoint, rec, seen)

    def _body_rules(self, endpoint, rec, seen):
        from ..passive.engine import _compiled, _target_text
        from ..passive.rules import RULES
        _sev = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
                "high": Severity.HIGH, "critical": Severity.CRITICAL}
        headers = {str(k).lower(): str(v) for k, v in (rec.resp_headers or {}).items()}
        for rule in RULES:
            if rule.where == "url":
                continue  # token-in-URL already covered by check (4) above
            key = f"body:{rule.id}"
            if key in seen:
                continue
            text = _target_text(rule, rec.url or "", headers, rec.resp_body or "")
            if text and _compiled[rule.id].search(text):
                seen.add(key)
                yield self._passive(VulnClass(rule.vuln_class), _sev[rule.severity],
                    rule.title, endpoint, rec, rule.note, rule.id)

    def _passive(self, vc, sev, title, endpoint, rec, desc, test):
        f = Finding(vuln_class=vc, severity=sev, title=title, endpoint=endpoint.key,
                    description=desc, evidence=[rec],
                    detail={"test": test, "passive": True}, confidence="firm")
        # passive checks are true by observation; mark verified so they aren't re-probed
        f.verdict = "true_positive"; f.exploitability = "conditional"
        f.detail["verification"] = {"verdict": "true_positive", "exploitability": "conditional",
                                    "confidence_score": 0.8, "probes": 0,
                                    "reasons": ["observed directly in the response (passive check)"],
                                    "repro": "Inspect the response headers/body to confirm."}
        return f
