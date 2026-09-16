"""Offline tests for Rules-of-Engagement governance."""
from __future__ import annotations

from datetime import datetime
from deluluscan.roe import RoEPolicy, parse_roe

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def test_scope_domain_and_subdomain():
    p = RoEPolicy(in_scope=["example.com"])
    check("apex in scope", p.target_in_scope("https://example.com/x")[0])
    check("subdomain in scope", p.target_in_scope("https://app.example.com")[0])
    check("unrelated out", not p.target_in_scope("https://evil.com")[0])
    check("lookalike not matched", not p.target_in_scope("https://notexample.com")[0])


def test_scope_cidr_and_ip():
    p = RoEPolicy(in_scope=["10.0.0.0/24", "192.168.1.5"])
    check("ip in CIDR", p.target_in_scope("http://10.0.0.9:8080")[0])
    check("ip outside CIDR", not p.target_in_scope("http://10.0.1.9")[0])
    check("exact ip in scope", p.target_in_scope("http://192.168.1.5")[0])


def test_out_of_scope_wins():
    p = RoEPolicy(in_scope=["example.com"], out_of_scope=["admin.example.com"])
    allowed, reason = p.target_in_scope("https://admin.example.com")
    check("explicit exclusion wins over in-scope domain", not allowed and "out of scope" in reason, reason)
    check("sibling still in scope", p.target_in_scope("https://app.example.com")[0])


def test_wildcard_and_no_scope():
    check("wildcard matches", RoEPolicy(in_scope=["*.example.com"]).target_in_scope("https://a.example.com")[0])
    check("no in-scope -> nothing allowed", not RoEPolicy().target_in_scope("https://x.com")[0])


def test_excluded_tests():
    p = RoEPolicy(in_scope=["x.com"], excluded_tests={"sqli", "resource_consumption"})
    check("excluded scanner blocked", not p.scanner_allowed("sqli"))
    check("substring match blocks", not p.scanner_allowed("resource_consumption"))
    check("other scanner allowed", p.scanner_allowed("xss"))


def test_time_window():
    p = RoEPolicy(window_start="09:00", window_end="17:00")
    check("inside window", p.within_window(datetime(2026, 1, 1, 12, 0)))
    check("outside window", not p.within_window(datetime(2026, 1, 1, 20, 0)))
    over = RoEPolicy(window_start="22:00", window_end="04:00")   # crosses midnight
    check("midnight window inside", over.within_window(datetime(2026, 1, 1, 23, 0)))
    check("midnight window outside", not over.within_window(datetime(2026, 1, 1, 12, 0)))
    check("no window -> always ok", RoEPolicy().within_window(datetime(2026, 1, 1, 3, 0)))


def test_parse_structured_yaml():
    p = parse_roe("in_scope: [app.example.com, 10.0.0.0/24]\nout_of_scope: [admin.example.com]\n"
                  "excluded_tests: [sqli]\nallow_remote: true\nrate_limit_rps: 5", "yaml")
    check("yaml in_scope", "app.example.com" in p.in_scope and "10.0.0.0/24" in p.in_scope)
    check("yaml out_of_scope", "admin.example.com" in p.out_of_scope)
    check("yaml excluded", "sqli" in p.excluded_tests)
    check("yaml allow_remote", p.allow_remote is True)
    check("yaml rate", p.rate_limit_rps == 5)


def test_parse_json():
    p = parse_roe('{"in_scope":["x.com"],"excluded_tests":["sqli"]}', "json")
    check("json parsed", "x.com" in p.in_scope and "sqli" in p.excluded_tests)


def test_parse_text_roe():
    text = ("# Rules of Engagement\nIn scope:\n - app.example.com\n - 10.0.0.0/24\n"
            "Out of scope:\n - admin.example.com\nDo not test: sqli, resource_consumption\n"
            "Testing window: 09:00 - 17:00\nRate limit: 5 rps\n")
    p = parse_roe(text, "auto")
    check("text in_scope hosts only", set(p.in_scope) == {"app.example.com", "10.0.0.0/24"}, p.in_scope)
    check("text out_of_scope host only", p.out_of_scope == ["admin.example.com"], p.out_of_scope)
    check("text excluded tests (bare words)", p.excluded_tests == {"sqli", "resource_consumption"}, p.excluded_tests)
    check("text window", (p.window_start, p.window_end) == ("09:00", "17:00"))
    check("text rate", p.rate_limit_rps == 5.0)
    check("no junk absorbed", "rps" not in p.out_of_scope and "Testing" not in p.out_of_scope)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
