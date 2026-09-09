"""Offline tests for SRI + mixed-content analysis."""
from __future__ import annotations

from deluluscan.subresource import analyze_resources
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")

def rules(f): return {x.detail["rule"] for x in f}


def test_sri_missing_on_cross_origin_script():
    f = analyze_resources("https://s.example/", '<script src="https://cdn.other.com/a.js"></script>')
    s = next((x for x in f if x.detail["rule"] == "sri-script"), None)
    check("cross-origin script w/o SRI flagged", s and s.severity == Severity.MEDIUM
          and s.vuln_class == VulnClass.SUPPLY_CHAIN, rules(f))


def test_sri_present_not_flagged():
    f = analyze_resources("https://s.example/",
                          '<script src="https://cdn.other.com/a.js" integrity="sha384-x"></script>')
    check("script with integrity not flagged", "sri-script" not in rules(f), rules(f))


def test_same_origin_and_relative_not_flagged():
    f = analyze_resources("https://s.example/",
                          '<script src="/local.js"></script><script src="https://s.example/x.js"></script>')
    check("same-origin/relative scripts not flagged", f == [], [x.title for x in f])


def test_active_mixed_content_high():
    f = analyze_resources("https://s.example/", '<iframe src="http://evil/x"></iframe>')
    m = next((x for x in f if x.detail["rule"] == "mixed-active"), None)
    check("http iframe on https -> HIGH active mixed", m and m.severity == Severity.HIGH, rules(f))
    f2 = analyze_resources("https://s.example/", '<script src="http://evil/x.js"></script>')
    check("http script -> active mixed", "mixed-active" in rules(f2))


def test_passive_mixed_content_low():
    f = analyze_resources("https://s.example/", '<img src="http://insecure/p.gif">')
    m = next((x for x in f if x.detail["rule"] == "mixed-passive"), None)
    check("http img on https -> LOW passive mixed", m and m.severity == Severity.LOW, rules(f))


def test_http_page_no_mixed_content():
    # on a plain-http page, http resources are not "mixed content"
    f = analyze_resources("http://s.example/", '<img src="http://x/p.gif">')
    check("http page -> no mixed-content finding", not any("mixed" in r for r in rules(f)), rules(f))


def test_protocol_relative_and_data_uri():
    f = analyze_resources("https://s.example/",
                          '<script src="//cdn.other.com/a.js"></script><script src="data:text/js,1"></script>')
    check("protocol-relative cross-origin flagged", "sri-script" in rules(f), rules(f))
    check("data: uri ignored", not any("data:" in x.detail["resource"] for x in f))


def test_dedup():
    body = '<script src="https://cdn.other.com/a.js"></script>' * 3
    check("same resource deduped", len(analyze_resources("https://s.example/", body)) == 1)


def test_passive_engine_integration():
    from deluluscan.passive import PassiveScan
    f = PassiveScan().analyze(200, "https://s.example/", {"content-type": "text/html"},
                              '<script src="https://cdn.other.com/a.js"></script>')
    check("passive engine runs subresource analysis",
          any(x.detail.get("rule") == "sri-script" for x in f), [x.title for x in f])


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
