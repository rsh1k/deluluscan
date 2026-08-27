"""Deep-verification layer: prove/refute a stored-XSS -> privileged-action chain
instead of flagging a surface reflection.

Each check maps to a lesson from the live #651 investigation:
  * a per-field filter is beaten by SPLITTING the payload across fields;
  * the executing sink may be a surface the write-response never showed, so you
    must read the value back through EVERY echo point;
  * the same endpoint answers differently to cookie vs Bearer, so probe it every
    way; and whether an XSS can weaponize it depends on HttpOnly / storage.

Run: python3 -m tests.test_deep_verify
"""
from __future__ import annotations

import sys

from deluluscan.active.filter_bypass import (TARGET_XSS_REGEX, evades,
                                        is_attr_unquoted_safe, marker_img,
                                        mutations, split_for_concat)
from deluluscan.verify.readback import (ABSENT, HTML_ESCAPED, RAW, STRIPPED,
                                    classify_reflection, detect_concat_reassembly,
                                    readback_across_sinks)
from deluluscan.verify.exploitability import (AuthMatrix, CookieFacts, CredentialSurface,
                                         analyze_set_cookie,
                                         assess_privileged_action_via_xss,
                                         probe_auth_matrix)
from deluluscan.verify.deep_chain import DeepStoredXssChain

_checks = 0
_failures: list[str] = []


def check(cond, label):
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


# ---------------------------------------------------------------------------
# 1. filter-bypass engine
# ---------------------------------------------------------------------------
def test_field_split_beats_the_per_field_filter():
    markup = "<img src=x onerror=fetch('/m')>"
    check(not evades(markup, TARGET_XSS_REGEX),
          "the whole payload in ONE field is caught by the filter (baseline)")
    plan = split_for_concat(markup, separator=" ", max_fields=2)
    check(plan is not None, "a 2-field split exists")
    check(plan and plan.fragments[0] == "<img",
          f"the '<' lands alone in field 1 (got {plan.fragments[0]!r})" if plan else "no plan")
    check(plan and plan.all_evade(),
          "EVERY fragment individually evades the filter")
    check(plan and plan.reassembled == markup,
          "fragments rejoin with the separator into the exact payload")


def test_split_impossible_is_reported():
    # a single unsplittable token that trips the filter -> no plan
    check(split_for_concat("<a=b", separator=" ", max_fields=2) is None,
          "an unsplittable single token returns no plan (honest failure)")


def test_attr_safety_rules():
    check(is_attr_unquoted_safe("fetch('/m')"), "space-free/'>'-free handler is attr-safe")
    check(not is_attr_unquoted_safe("r => x"), "a space truncates an unquoted attribute")
    check(not is_attr_unquoted_safe("r=>x"), "a '>' (arrow) closes the tag -> not attr-safe")


def test_mutations_rank_verified_bypass_first():
    muts = mutations("<img src=x onerror=fetch('/m')>", max_fields=2)
    check(muts[0]["technique"] == "field-split" and muts[0]["evades_filter"],
          "strongest candidate is the verified field-split")


# ---------------------------------------------------------------------------
# 2. read-back classification
# ---------------------------------------------------------------------------
def test_reflection_classification():
    v = "<img src=x onerror=fetch('/m')>"
    check(classify_reflection(v, f"name: {v} end") == RAW, "verbatim -> RAW (live markup)")
    check(classify_reflection(v, "name: &lt;img src=x onerror=fetch('/m')&gt; end") == HTML_ESCAPED,
          "entity-encoded -> HTML_ESCAPED (inert)")
    check(classify_reflection(v, "name: imgsrcxonerror end") == STRIPPED,
          "markup stripped but alnum marker survives -> STRIPPED")
    check(classify_reflection(v, "totally other content") == ABSENT, "not present -> ABSENT")


def test_readback_finds_the_one_raw_sink_among_escaped():
    v = "<img src=x onerror=fetch('/m')>"
    bodies = {
        "/api/v1/users/filter": f'{{"name":"&lt;img src=x onerror=fetch(&#x27;/m&#x27;)&gt;"}}',  # grid escapes
        "/dwr/detail-frame": f"<span class=fullUserName>{v}</span>",   # legacy iframe: RAW
        "/api/v1/users/current": '{"givenName":"&lt;img"}',
    }
    sinks = [("angular-grid", "/api/v1/users/filter"),
             ("legacy-detail-frame", "/dwr/detail-frame"),
             ("rest-current", "/api/v1/users/current")]
    rep = readback_across_sinks(v, sinks, lambda p: (200, bodies[p]),
                                html_sinks={"legacy-detail-frame"})
    state, _ = rep.verdict()
    check(state == "served_raw_html", "raw render in an HTML sink -> served_raw_html (executes)")
    check([r.sink for r in rep.raw_html_sinks] == ["legacy-detail-frame"],
          "the exact executing HTML sink is identified (the legacy frame, not the grid)")
    check(rep.results[0].classification == HTML_ESCAPED,
          "the Angular grid is correctly seen as escaped (would fool a surface check)")


def test_json_api_raw_is_precondition_not_execution():
    """The bug the tool's own live run exposed: a value returned RAW by a JSON API
    is NOT executing XSS (JSON isn't an HTML context) — it must not be graded as
    execution. This is a regression guard on that exact conflation."""
    v = "<img src=x onerror=fetch('/m')>"
    sinks = [("rest-users-filter", "/api")]
    rep = readback_across_sinks(v, sinks, lambda p: (200, f'{{"name":"{v}"}}'),
                                html_sinks=set())   # a JSON API renders NO HTML
    state, reason = rep.verdict()
    check(state == "served_raw_api",
          f"raw in a JSON-only sink -> served_raw_api, NOT served_raw_html (got {state})")
    check(not rep.raw_html_sinks and rep.raw_api_sinks,
          "classified as API-raw (precondition), not an execution sink")
    check("not execution" in reason.lower() or "precondition" in reason.lower(),
          "reason states plainly it is a precondition, not execution")


def test_concat_reassembly_detection():
    frags = ["<img", "src=x onerror=fetch('/m')>"]
    body = "<div>" + " ".join(frags) + "</div>"
    check(detect_concat_reassembly(frags, " ", body),
          "individually-harmless fragments detected recombining into live markup")


# ---------------------------------------------------------------------------
# 3. exploitability analysis
# ---------------------------------------------------------------------------
def test_cookie_flag_parsing():
    # realistic-length JWT (the real rme is ~298 bytes); the regex requires a
    # plausible token, not a toy string.
    rme_jwt = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
               "eyJqdGkiOiI0NjE3NmUxMi02YzJkLTQwNmMifQ.CDy3zSHm-EgcoptYfM")
    facts = {c.name: c for c in analyze_set_cookie([
        "JSESSIONID=ABC0123456789; Path=/; Secure; HttpOnly; SameSite=Lax",
        f"rme={rme_jwt}; Path=/; Secure; HttpOnly; SameSite=Lax",
        "DWRSESSIONID=xyz$abc; Path=/",
    ])}
    check(facts["rme"].http_only and facts["rme"].looks_like_jwt,
          "rme parsed as HttpOnly JWT (unreadable by JS)")
    check(not facts["rme"].js_readable, "rme is not JS-readable")
    check(facts["DWRSESSIONID"].js_readable and not facts["DWRSESSIONID"].looks_like_jwt,
          "DWRSESSIONID is JS-readable but carries no token (useless to steal)")


def test_auth_matrix_shapes():
    m = AuthMatrix("/api/plugins", {"anonymous": 401, "session_cookie": 401,
                                    "bearer_jwt": 200, "basic": 200})
    check(m.requires_auth(), "endpoint requires auth")
    check(not m.cookie_authenticates(), "cookie does NOT authenticate it")
    check(m.header_only(), "header credential required (bearer/basic only)")


def test_weaponizable_when_endpoint_takes_cookie():
    # session-riding: browser auto-sends the cookie, HttpOnly irrelevant
    auth = probe_auth_matrix("/api/plugins",
                             lambda v: 200 if v in ("session_cookie", "bearer_jwt", "basic") else 401)
    a = assess_privileged_action_via_xss(auth, CredentialSurface())
    check(a.verdict == "weaponizable" and a.exploitability == "exploitable",
          "cookie-authenticated privileged endpoint -> weaponizable (session-riding)")


def test_weaponizable_when_token_is_js_readable():
    auth = AuthMatrix("/api/plugins", {"anonymous": 401, "session_cookie": 401,
                                       "bearer_jwt": 200, "basic": 200})
    creds = CredentialSurface(storage_tokens=["target.jwt"])   # token sitting in localStorage
    a = assess_privileged_action_via_xss(auth, creds)
    check(a.verdict == "weaponizable",
          "header-only endpoint + JS-readable token in storage -> weaponizable (replay as Bearer)")


def test_contained_when_creds_all_httponly():
    # the exact #651-on-this-build situation: OSGi wants a Bearer header, the only
    # usable JWT is an HttpOnly cookie, nothing readable in storage.
    auth = AuthMatrix("/api/plugins", {"anonymous": 401, "session_cookie": 401,
                                       "bearer_jwt": 200, "basic": 200})
    creds = CredentialSurface(
        cookies=analyze_set_cookie([
            "JSESSIONID=x; HttpOnly", "rme=eyJa.eyJb.sig; HttpOnly",
            "DWRSESSIONID=y",  # readable but not a token
        ]),
        storage_tokens=[])
    a = assess_privileged_action_via_xss(auth, creds)
    check(a.verdict == "contained" and a.exploitability == "not_exploitable",
          "header-only + all-HttpOnly creds + no storage token -> contained")
    check(any("HttpOnly" in r for r in a.reasons),
          "the reason explains WHY (no JS-readable credential)")


# ---------------------------------------------------------------------------
# 4. full deep chain
# ---------------------------------------------------------------------------
def _chain_env(bodies, html_sinks):
    """Build a DeepStoredXssChain whose write/read/restore are in-memory."""
    state = {"stored": {}, "restored": False}
    sinks = [(label, path) for label, path in bodies.keys_map]

    def write(vals): state["stored"] = dict(vals)
    def restore(): state["restored"] = True
    def fetch(path):
        return (200, bodies.render(path, state["stored"]))
    chain = DeepStoredXssChain(
        fields=["givenName", "surname"], read_sinks=sinks,
        write=write, fetch=fetch, restore=restore, html_sinks=html_sinks)
    return chain, state


class _Bodies:
    """Renders each sink from the currently-stored field values, so the test
    reflects the REAL data flow (write -> concatenated render)."""
    def __init__(self, keys_map, renderer):
        self.keys_map = keys_map
        self._renderer = renderer
    def render(self, path, stored):
        return self._renderer(path, stored)


def test_full_chain_contained_like_651_on_this_build():
    name = lambda s: (s.get("givenName", "") + " " + s.get("surname", "")).strip()
    def renderer(path, stored):
        n = name(stored)
        if path == "/legacy":            # legacy iframe: innerHTML -> RAW
            return f"<span class=fullUserName>{n}</span>"
        if path == "/grid":              # angular grid: escaped
            import html as _h
            return f'{{"name":"{_h.escape(n)}"}}'
        return "{}"
    bodies = _Bodies([("legacy-frame", "/legacy"), ("angular-grid", "/grid")], renderer)
    chain, state = _chain_env(bodies, html_sinks={"legacy-frame"})

    # OSGi: header-only auth; the only JWT is HttpOnly -> contained
    res = chain.run(
        marker_url="/RK", target_endpoint="/api/plugins",
        auth_probe=lambda v: 200 if v in ("bearer_jwt", "basic") else 401,
        set_cookie_lines=["JSESSIONID=x; HttpOnly", "rme=eyJa.eyJb.sig; HttpOnly",
                          "DWRSESSIONID=z"],
        storage_tokens=[])
    verdict, expl, headline = res.verdict()
    check(res.bypass and res.bypass["technique"] == "field-split",
          "chain chose the verified field-split bypass")
    check(res.execution == "served_raw_html", "chain found the raw render in the legacy HTML frame")
    check(verdict == "true_positive" and expl == "conditional",
          f"real stored XSS but contained -> (true_positive, conditional) [got {verdict},{expl}]")
    check("credential handling blocks" in headline, "headline states it's contained, with reason")
    check(state["restored"], "the stored payload was always restored")


def test_full_chain_weaponizable_when_cookie_authed():
    name = lambda s: (s.get("givenName", "") + " " + s.get("surname", "")).strip()
    bodies = _Bodies([("legacy-frame", "/legacy")],
                     lambda p, s: f"<b class=fullUserName>{name(s)}</b>")
    chain, state = _chain_env(bodies, html_sinks={"legacy-frame"})
    res = chain.run(
        marker_url="/RK", target_endpoint="/api/plugins",
        auth_probe=lambda v: 200 if v in ("session_cookie", "bearer_jwt", "basic") else 401,
        set_cookie_lines=["JSESSIONID=x; HttpOnly"], storage_tokens=[])
    verdict, expl, _ = res.verdict()
    check(verdict == "true_positive" and expl == "exploitable",
          "raw render + cookie-authed target -> (true_positive, exploitable)")
    check(res.exploit and res.exploit.verdict == "weaponizable", "exploit verdict weaponizable")
    check(state["restored"], "restored even on the exploitable path")


def test_full_chain_neutralised_is_not_a_finding():
    import html as _h
    name = lambda s: (s.get("givenName", "") + " " + s.get("surname", "")).strip()
    bodies = _Bodies([("grid", "/grid")],
                     lambda p, s: f'{{"name":"{_h.escape(name(s))}"}}')
    chain, state = _chain_env(bodies, html_sinks=set())   # JSON-only, nothing renders HTML
    res = chain.run(marker_url="/RK")
    verdict, expl, _ = res.verdict()
    check(res.execution == "neutralised", "everything escaped -> neutralised")
    check(verdict == "likely_false_positive" and expl == "not_exploitable",
          "escaped-everywhere -> not a real stored XSS")
    check(res.exploit is None, "no exploitability probing wasted on a neutralised value")
    check(state["restored"], "restored")


def test_full_chain_json_raw_plus_session_ridable_is_honest_conditional():
    """The exact headless live-scan case: the only read-back surfaces are JSON APIs
    (they return the payload raw = precondition), and the target OSGi endpoint is
    session-ridable. The tool must NOT claim execution it didn't observe: grade it
    likely_true_positive / conditional, headline pointing at the one browser step."""
    name = lambda s: (s.get("givenName", "") + " " + s.get("surname", "")).strip()
    bodies = _Bodies([("rest-filter", "/api/v1/users/filter")],
                     lambda p, s: f'{{"name":"{name(s)}"}}')   # JSON, raw, no HTML render
    chain, state = _chain_env(bodies, html_sinks=set())
    res = chain.run(
        marker_url="/RK", target_endpoint="/api/plugins",
        auth_probe=lambda v: 200 if v in ("session_cookie", "bearer_jwt", "basic") else 401,
        set_cookie_lines=["rme=eyJa.eyJb.sig; HttpOnly"], storage_tokens=[])
    verdict, expl, headline = res.verdict()
    check(res.execution == "served_raw_api",
          f"JSON-only raw -> served_raw_api (precondition, not execution) [got {res.execution}]")
    check(verdict == "likely_true_positive" and expl == "conditional",
          f"honest grade: likely_true_positive/conditional (not a hard exploitable) "
          f"[got {verdict},{expl}]")
    check("confirm" in headline.lower() and "render" in headline.lower(),
          "headline points at the remaining browser-render confirmation step")
    check(res.exploit and res.exploit.verdict == "weaponizable",
          "target reachability (session-riding) still analysed and flagged")
    check(state["restored"], "restored")


def main():
    print("== deep verification layer ==")
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks}:")
        for f in _failures:
            print("  -", f)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
