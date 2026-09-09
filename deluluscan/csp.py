"""Content-Security-Policy effectiveness analysis (à la Google CSP Evaluator).

Having a CSP header is not the same as having a CSP that stops XSS. This parses a
policy and flags the ways it is bypassable: unrestricted script sources, an
`unsafe-inline` that isn't neutralised by a nonce/hash/strict-dynamic, `data:`
script URIs, allowlisted CDNs that host JSONP/AngularJS gadgets, and missing
`object-src`/`base-uri` locks. Pure string analysis — offline, deterministic.
"""
from __future__ import annotations

from .models import Finding, RequestRecord, Severity, VulnClass

# CDNs known to host JSONP endpoints / AngularJS (allowlisting them defeats CSP).
# Curated subset of the Google CSP Evaluator bypass corpus.
_BYPASSABLE_HOSTS = {
    "ajax.googleapis.com", "www.google.com", "apis.google.com", "www.googletagmanager.com",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "code.jquery.com",
    "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com", "vjs.zencdn.net",
    "ajax.aspnetcdn.com", "cdn.ampproject.org", "www.youtube.com",
}


def parse_csp(text: str) -> dict:
    out: dict = {}
    for part in (text or "").split(";"):
        toks = part.strip().split()
        if not toks:
            continue
        out[toks[0].lower()] = toks[1:]
    return out


def _effective(csp: dict, directive: str):
    """script-src, falling back to default-src (CSP semantics)."""
    if directive in csp:
        return csp[directive], directive
    if "default-src" in csp:
        return csp["default-src"], "default-src (fallback)"
    return None, None


def analyze_csp(csp_text: str, url: str = "", report_only: bool = False) -> list:
    csp = parse_csp(csp_text)
    out: list = []
    rec = RequestRecord(method="GET", url=url or "-", identity="anon", status=0, elapsed_ms=0.0,
                        resp_headers={"content-security-policy": (csp_text or "")[:400]})
    ro = " (report-only — NOT enforced; monitoring only)" if report_only else ""

    def add(sev, title, desc, rule):
        # report-only policies don't protect anything → cap at LOW and annotate
        if report_only and sev in (Severity.HIGH, Severity.MEDIUM):
            sev = Severity.LOW
        out.append(Finding(vuln_class=VulnClass.MISCONFIG, severity=sev,
                           title=title + (" (report-only)" if report_only else ""),
                           endpoint=url or "-", description=desc + ro, evidence=[rec],
                           confidence="firm", detail={"rule": rule, "cwe": "CWE-693",
                                                      "report_only": report_only, "source": "csp"}))

    sources, origin = _effective(csp, "script-src")
    if sources is None:
        add(Severity.HIGH, "CSP does not restrict scripts",
            "The policy has neither script-src nor default-src, so it places no restriction on "
            "script execution — no XSS protection.", "csp-no-script-src")
        sources = []
    srcset = {s.strip("'").lower() if s.startswith("'") else s.lower() for s in sources}
    raw = [s for s in sources]
    has_nonce = any(s.startswith("'nonce-") for s in raw)
    has_hash = any(s.startswith(("'sha256-", "'sha384-", "'sha512-")) for s in raw)
    strict_dynamic = "strict-dynamic" in srcset

    if "*" in srcset:
        add(Severity.HIGH, "CSP script-src allows any host (*)",
            f"script-src ({origin}) contains a wildcard '*', permitting scripts from any origin — "
            "trivially bypassable.", "csp-wildcard")
    if "https:" in srcset or "http:" in srcset:
        add(Severity.HIGH, "CSP script-src allows any host over a scheme",
            "A bare scheme source (https:/http:) permits scripts from ANY host on that scheme.",
            "csp-scheme-src")
    if "data:" in srcset:
        add(Severity.HIGH, "CSP script-src allows data: URIs",
            "data: in script-src lets an attacker inject an inline script as a data URI.", "csp-data-uri")
    if "unsafe-inline" in srcset:
        if has_nonce or has_hash or strict_dynamic:
            add(Severity.LOW, "CSP has 'unsafe-inline' (neutralised by nonce/strict-dynamic)",
                "unsafe-inline is present but ignored by CSP3 browsers because a nonce/hash/"
                "strict-dynamic is set — still a risk for legacy browsers that honour it.",
                "csp-unsafe-inline-fallback")
        else:
            add(Severity.HIGH, "CSP allows 'unsafe-inline' scripts",
                "script-src permits unsafe-inline with no nonce/hash/strict-dynamic, so inline "
                "script injection executes — the policy does not stop XSS.", "csp-unsafe-inline")
    if "unsafe-eval" in srcset:
        add(Severity.MEDIUM, "CSP allows 'unsafe-eval'",
            "unsafe-eval permits eval()/Function(), enabling some script-gadget and template "
            "injection paths.", "csp-unsafe-eval")
    for s in raw:
        host = s.strip("'").split("//")[-1].split("/")[0].lower()
        if host in _BYPASSABLE_HOSTS and not strict_dynamic:
            add(Severity.MEDIUM, f"CSP allowlists a bypassable host ({host})",
                f"script-src allowlists {host}, which hosts JSONP/AngularJS gadgets that let an "
                "attacker execute arbitrary script within the policy.", "csp-bypassable-host")

    # object-src / base-uri hardening (only meaningful once scripts are restricted)
    obj, _ = _effective(csp, "object-src")
    if obj is None or {o.strip("'").lower() for o in obj} not in ({"none"},):
        if obj is None and "default-src" not in csp:
            add(Severity.MEDIUM, "CSP object-src not locked to 'none'",
                "Without object-src 'none', <object>/<embed> plugin content can bypass the policy.",
                "csp-object-src")
    if "base-uri" not in csp:
        add(Severity.MEDIUM, "CSP missing base-uri",
            "No base-uri directive — an injected <base> tag can rewrite relative script URLs to an "
            "attacker origin, bypassing an allowlist.", "csp-base-uri")
    return out
