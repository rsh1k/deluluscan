"""Offline tests for CSP effectiveness analysis + headers integration."""
from __future__ import annotations

from deluluscan.csp import analyze_csp, parse_csp
from deluluscan.models import Severity, VulnClass

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def rules(f):
    return {x.detail["rule"] for x in f}


def test_parse():
    p = parse_csp("default-src 'self'; script-src 'self' https://x")
    check("directives parsed", set(p) == {"default-src", "script-src"}, p)
    check("sources parsed", p["script-src"] == ["'self'", "https://x"])


def test_strong_policy_clean():
    f = analyze_csp("default-src 'none'; script-src 'nonce-r' 'strict-dynamic'; object-src 'none'; base-uri 'none'")
    check("hardened policy -> no findings", f == [], rules(f))


def test_unsafe_inline_high():
    f = analyze_csp("script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'")
    ui = next((x for x in f if x.detail["rule"] == "csp-unsafe-inline"), None)
    check("unsafe-inline flagged HIGH", ui and ui.severity == Severity.HIGH, ui and ui.severity)
    check("is MISCONFIG", ui and ui.vuln_class == VulnClass.MISCONFIG)


def test_unsafe_inline_neutralised_by_nonce():
    f = analyze_csp("script-src 'self' 'unsafe-inline' 'nonce-abc'; object-src 'none'; base-uri 'none'")
    check("unsafe-inline downgraded when nonce present",
          "csp-unsafe-inline" not in rules(f) and "csp-unsafe-inline-fallback" in rules(f), rules(f))


def test_wildcard_and_scheme():
    check("wildcard flagged", "csp-wildcard" in rules(analyze_csp("script-src *")))
    check("scheme-src flagged", "csp-scheme-src" in rules(analyze_csp("script-src https:")))
    check("data-uri flagged", "csp-data-uri" in rules(analyze_csp("script-src 'self' data:")))


def test_bypassable_host():
    f = analyze_csp("script-src 'self' https://ajax.googleapis.com; object-src 'none'; base-uri 'none'")
    check("bypassable CDN flagged", "csp-bypassable-host" in rules(f), rules(f))
    # strict-dynamic makes the allowlist irrelevant -> not flagged
    f2 = analyze_csp("script-src 'strict-dynamic' 'nonce-x' https://ajax.googleapis.com; object-src 'none'; base-uri 'none'")
    check("strict-dynamic suppresses host bypass", "csp-bypassable-host" not in rules(f2), rules(f2))


def test_missing_directives():
    check("no script-src/default-src -> flagged", "csp-no-script-src" in rules(analyze_csp("img-src 'self'")))
    check("missing base-uri flagged", "csp-base-uri" in rules(analyze_csp("script-src 'self'")))


def test_report_only_downgraded():
    f = analyze_csp("script-src 'self' 'unsafe-inline'", report_only=True)
    ui = next((x for x in f if x.detail["rule"] == "csp-unsafe-inline"), None)
    check("report-only caps severity at LOW", ui and ui.severity == Severity.LOW, ui and ui.severity)
    check("report-only flagged in detail", ui and ui.detail["report_only"] is True)


def test_headers_integration():
    from deluluscan.headers.analyzer import analyze_all
    f = analyze_all(200, {"content-type": "text/html",
                          "content-security-policy": "script-src 'self' 'unsafe-inline'"}, "http://t/")
    check("headers module runs deep CSP analysis",
          any(x.detail.get("source") == "csp" for x in f), [x.title for x in f])
    # a page with no CSP still reports 'missing'
    f2 = analyze_all(200, {"content-type": "text/html"}, "http://t/")
    check("missing CSP still reported", any("Missing Content-Security-Policy" in x.title for x in f2))


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
