"""tests.test_templates — declarative YAML detection templates.

Templates are the one place where a check can be added without code review, so
the loader is the security boundary. These tests assert three things:

1. **A template cannot execute code.** The DSL is a parsed grammar, not eval.
   `__import__(...)` in a template must be rejected at load time, not run.
2. **A template cannot change state.** Only safe methods are permitted; a
   template asking for DELETE is refused with an explanatory error.
3. **A template cannot match everything.** A block with no matchers would report
   every endpoint as a finding — the exact false-positive pattern this codebase
   spends its time refuting.

Offline by construction: matcher evaluation takes synthetic responses, so the
suite needs no Docker and no target.

Run: python3 -m tests.test_templates
"""
from __future__ import annotations

import os
import sys
import tempfile

from deluluscan import templates as tp

_checks = 0
_failures: list[str] = []


def check(cond: bool, label: str) -> None:
    global _checks
    _checks += 1
    if cond:
        print(f"PASS  {label}")
    else:
        _failures.append(label)
        print(f"FAIL  {label}")


def write(tmp: str, name: str, text: str) -> str:
    path = os.path.join(tmp, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


MINIMAL = """
id: t-minimal
info:
  name: Minimal
  severity: low
  vuln_class: misconfig
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: status
        status: [200]
"""


def parse(text: str):
    import yaml
    return tp.parse_template(yaml.safe_load(text))


# --- loader is the security boundary --------------------------------------
def test_state_changing_methods_are_refused():
    for method in ("DELETE", "PUT", "PATCH"):
        try:
            parse(MINIMAL.replace("method: GET", f"method: {method}"))
            check(False, f"{method} is refused in a template")
        except tp.TemplateError as e:
            check("detection-only" in str(e),
                  f"{method} refused with an explanation of why templates are detection-only")
    for method in ("GET", "HEAD", "OPTIONS", "POST"):
        try:
            parse(MINIMAL.replace("method: GET", f"method: {method}"))
            check(True, f"{method} is permitted")
        except tp.TemplateError:
            check(False, f"{method} is permitted")


def test_dsl_cannot_execute_code():
    """The DSL is parsed, not evaluated — a code payload must not run."""
    hostile = [
        "__import__('os').system('touch /tmp/pwned')",
        "open('/etc/passwd').read()",
        "len(body) > 0 and __import__('sys').exit()",
        "eval('1+1')",
    ]
    for expr in hostile:
        try:
            parse(MINIMAL.replace(
                "      - type: status\n        status: [200]",
                f"      - type: dsl\n        dsl: [\"{expr}\"]"))
            check(False, f"hostile DSL rejected at load: {expr[:40]}")
        except tp.TemplateError as e:
            check("unsupported DSL" in str(e),
                  f"hostile DSL rejected at load: {expr[:40]}")
    # And even if one reached the evaluator, it returns False rather than running.
    check(tp.evaluate_dsl("__import__('os').system('x')", status=200,
                          body="", headers={}) is False,
          "an unparseable DSL expression evaluates False rather than executing")
    check(not os.path.exists("/tmp/pwned"), "no side effect was produced by a hostile DSL")


def test_template_with_no_matchers_is_refused():
    try:
        parse("""
id: t-nomatch
info: {name: N, severity: low, vuln_class: misconfig}
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers: []
""")
        check(False, "a template with no matchers is refused")
    except tp.TemplateError as e:
        check("no matchers" in str(e),
              "a template with no matchers is refused (it would flag every endpoint)")


def test_matcher_with_no_values_is_refused():
    try:
        parse(MINIMAL.replace("        status: [200]", "        status: []"))
        check(False, "an empty matcher is refused")
    except tp.TemplateError as e:
        check("no values" in str(e), "a matcher with no values is refused")


def test_invalid_metadata_refused():
    for mutation, why in [
        ("severity: low", "severity: catastrophic"),
        ("vuln_class: misconfig", "vuln_class: not_a_class"),
    ]:
        try:
            parse(MINIMAL.replace(mutation, why))
            check(False, f"invalid metadata refused: {why}")
        except tp.TemplateError:
            check(True, f"invalid metadata refused: {why}")
    try:
        parse(MINIMAL.replace("id: t-minimal", "id: Bad ID!"))
        check(False, "a malformed id is refused")
    except tp.TemplateError:
        check(True, "a malformed id is refused")


def test_invalid_regex_refused_at_load():
    try:
        parse(MINIMAL.replace(
            "      - type: status\n        status: [200]",
            "      - type: regex\n        regex: [\"([unclosed\"]"))
        check(False, "an invalid regex is refused at load time")
    except tp.TemplateError as e:
        check("invalid regex" in str(e), "an invalid regex is refused at load time")


# --- matcher semantics -----------------------------------------------------
def resp(status=200, body="", headers=None):
    return {"status": status, "body": body, "headers": headers or {}}


def test_status_and_word_matchers():
    t = parse("""
id: t-sw
info: {name: N, severity: low, vuln_class: info_leak}
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["secret", "token"]
        condition: or
""")
    r = t.requests[0]
    check(r.evaluate(**resp(200, "has a token here")), "status+word matches when both hold")
    check(not r.evaluate(**resp(404, "has a token here")), "wrong status fails the AND")
    check(not r.evaluate(**resp(200, "nothing here")), "missing word fails the AND")


def test_word_condition_and_requires_all():
    t = parse("""
id: t-and
info: {name: N, severity: low, vuln_class: info_leak}
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: word
        words: ["alpha", "beta"]
        condition: and
""")
    r = t.requests[0]
    check(r.evaluate(**resp(200, "alpha and beta")), "condition:and matches when all words present")
    check(not r.evaluate(**resp(200, "alpha only")), "condition:and fails on a partial match")


def test_negative_matcher_inverts():
    t = parse("""
id: t-neg
info: {name: N, severity: low, vuln_class: misconfig}
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: word
        words: ["spa-index-marker"]
        negative: true
""")
    r = t.requests[0]
    check(r.evaluate(**resp(200, "real content")), "negative matcher passes when the word is absent")
    check(not r.evaluate(**resp(200, "spa-index-marker")),
          "negative matcher fails when the word is present (soft-404 guard)")


def test_header_part_is_searched():
    t = parse("""
id: t-hdr
info: {name: N, severity: low, vuln_class: misconfig}
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: word
        words: ["X-Powered-By"]
        part: header
""")
    r = t.requests[0]
    check(r.evaluate(**resp(200, "", {"X-Powered-By": "PHP"})), "header part is searched")
    check(not r.evaluate(**resp(200, "X-Powered-By")),
          "part:header does not match body content")


def test_matchers_condition_or():
    t = parse("""
id: t-or
info: {name: N, severity: low, vuln_class: misconfig}
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers-condition: or
    matchers:
      - type: status
        status: [500]
      - type: word
        words: ["marker"]
""")
    r = t.requests[0]
    check(r.evaluate(**resp(200, "marker")), "matchers-condition:or matches on either")
    check(not r.evaluate(**resp(200, "nothing")), "matchers-condition:or fails when neither holds")


def test_dsl_semantics():
    cases = [
        ("len(body) > 10", resp(200, "x" * 20), True),
        ("len(body) > 10", resp(200, "xx"), False),
        ("status == 200", resp(200, ""), True),
        ("status != 200", resp(200, ""), False),
        ("status >= 500", resp(503, ""), True),
        ("body contains secret", resp(200, "a secret here"), True),
        ("body contains secret", resp(200, "nothing"), False),
    ]
    for expr, r, expected in cases:
        got = tp.evaluate_dsl(expr, status=r["status"], body=r["body"], headers=r["headers"])
        check(got is expected, f"dsl {expr!r} -> {expected}")


# --- loading a directory ---------------------------------------------------
def test_load_directory_skips_broken_and_reports():
    with tempfile.TemporaryDirectory() as d:
        write(d, "good.yaml", MINIMAL)
        write(d, "broken.yaml", "id: t-broken\ninfo: {severity: nope}\n")
        write(d, "notyaml.txt", "ignored")
        loaded, errors = tp.load_templates(d)
        check(len(loaded) == 1, "a broken template does not prevent the good one loading")
        check(len(errors) == 1, "the broken template is reported")
        check("broken.yaml" in errors[0], "the error names the offending file")


def test_duplicate_ids_are_rejected():
    with tempfile.TemporaryDirectory() as d:
        write(d, "a.yaml", MINIMAL)
        write(d, "b.yaml", MINIMAL)
        loaded, errors = tp.load_templates(d)
        check(len(loaded) == 1, "a duplicate template id is loaded only once")
        check(any("duplicate" in e for e in errors), "the duplicate id is reported")


def test_missing_directory_is_not_an_error():
    loaded, errors = tp.load_templates("/nonexistent/path/xyz")
    check(loaded == [] and errors == [], "a missing template directory yields nothing, quietly")


def test_shipped_templates_are_valid():
    """The templates in the repo must all load — CI catches a bad commit."""
    loaded, errors = tp.load_templates()
    check(not errors, f"every shipped template loads cleanly (errors: {errors})")
    check(len(loaded) >= 3, f"the repo ships templates ({len(loaded)} found)")
    for t in loaded:
        check(bool(t.description), f"{t.id} has a description")
        check(bool(t.requests), f"{t.id} has at least one request")


def test_render_path_resolves_base_url():
    check(tp.render_path("{{BaseURL}}/api/x", "http://h:8080/") == "http://h:8080/api/x",
          "{{BaseURL}} resolves and the trailing slash is not doubled")


def main() -> int:
    print("== yaml templates ==")
    for fn in (test_state_changing_methods_are_refused,
               test_dsl_cannot_execute_code,
               test_template_with_no_matchers_is_refused,
               test_matcher_with_no_values_is_refused,
               test_invalid_metadata_refused,
               test_invalid_regex_refused_at_load,
               test_status_and_word_matchers,
               test_word_condition_and_requires_all,
               test_negative_matcher_inverts,
               test_header_part_is_searched,
               test_matchers_condition_or,
               test_dsl_semantics,
               test_load_directory_skips_broken_and_reports,
               test_duplicate_ids_are_rejected,
               test_missing_directory_is_not_an_error,
               test_shipped_templates_are_valid,
               test_render_path_resolves_base_url):
        fn()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks} checks:")
        for x in _failures:
            print("  -", x)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
