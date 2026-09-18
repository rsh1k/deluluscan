"""AI evidence-anchoring: the AI must cite the captured traffic, or be marked
unverified. Pure logic + a light analyst-integration check with a fake provider.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.ai.anchor import (extract_claims, check_claims, annotate, anchor_findings)
from deluluscan.ai.analyst import AIAnalyst
from deluluscan.models import Finding, RequestRecord, VulnClass, Severity

_PASS = 0
_FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  {detail}")


def _finding(status=200, url="http://h/api/v1/accounts/2", body='{"id":2,"owner":"globex"}',
             ident="anonymous"):
    ev = RequestRecord("GET", url, ident, status, 1.0, {}, "", {}, body, len(body))
    return Finding(vuln_class=VulnClass.IDOR, severity=Severity.HIGH,
                   title="IDOR", endpoint="GET /api/v1/accounts/{id}",
                   description="cross-tenant read", evidence=[ev],
                   detail={"accessed_ids": [2], "source": "idor_iter"})


def test_extract_claims():
    claims = extract_claims('An anonymous caller got HTTP 200 from /api/v1/accounts/2 '
                            'returning "id=2"; response took 350ms and cache was 100%. '
                            'It quoted "globex" as the owner.')
    check("extracts status 200", ("status", "200") in claims, claims)
    check("extracts path", ("path", "/api/v1/accounts/2") in claims, claims)
    check("extracts identity", ("identity", "anonymous") in claims, claims)
    check("extracts concrete quote id=2", ("quoted", "id=2") in claims, claims)
    # a plain-word quote is indistinguishable from emphasis -> deliberately NOT a
    # checkable claim (keeps false positives low; structured values still are)
    check("plain-word quote not extracted", ("quoted", "globex") not in claims, claims)
    check("ignores 350ms as status", ("status", "350") not in claims, claims)
    check("ignores 100% as status", ("status", "100") not in claims, claims)


def test_anchored_when_backed():
    f = _finding()
    res = check_claims("Anonymous got 200 at /api/v1/accounts/2 disclosing "
                       '"globex" — the other tenant.', f)
    check("all claims anchored", res.anchored, res.unanchored)
    check("coverage 1.0", res.coverage == 1.0, res.coverage)
    check("annotate is a no-op when anchored",
          annotate("Anonymous got 200 at /api/v1/accounts/2.", f)
          == "Anonymous got 200 at /api/v1/accounts/2.")


def test_unanchored_is_flagged():
    f = _finding(status=200)
    # The evidence has status 200 and path /accounts/2. The AI invents a 403 on
    # /admin and quotes a value never observed.
    text = 'The admin endpoint /admin/secrets returned 403 and leaked "AKIA1234EXAMPLE".'
    res = check_claims(text, f)
    check("not anchored", not res.anchored)
    kinds = {k for k, _ in res.unanchored}
    check("flags the invented status 403", ("status", "403") in res.unanchored, res.unanchored)
    check("flags the invented path", any(k == "path" and "/admin" in v for k, v in res.unanchored),
          res.unanchored)
    check("flags the invented quoted value",
          ("quoted", "AKIA1234EXAMPLE") in res.unanchored, res.unanchored)
    note = annotate(text, f)
    check("annotate appends the unverified marker", "⚠ unverified" in note, note)
    check("annotate keeps the original text", text in note)


def test_empty_and_generic_text():
    f = _finding()
    check("empty text unchanged", annotate("", f) == "")
    generic = "This looks like a genuine authorization gap worth manual review."
    check("generic prose makes no claims -> unchanged", annotate(generic, f) == generic)


def test_anchor_findings_batch():
    good = _finding(); good.ai_notes = "Anonymous read /api/v1/accounts/2 (200)."
    bad = _finding(); bad.ai_notes = "Also returned 500 from /internal/dump."
    flagged = anchor_findings([good, bad])
    check("batch flags only the hallucinated note", len(flagged) == 1, [f.title for f, _ in flagged])
    check("batch flag is the bad finding", flagged and flagged[0][0] is bad)


class _FakeProvider:
    def __init__(self, text): self.text = text
    def complete(self, system, user): return self.text


def _analyst_with(text):
    a = AIAnalyst.__new__(AIAnalyst)          # bypass provider build
    a.enabled = True
    a.provider = _FakeProvider(text)
    return a


def test_triage_annotates_hallucination():
    f = _finding(status=200)
    # provider hallucinates a 403 and an endpoint the finding never touched
    a = _analyst_with("Confirmed: /admin/panel returned 403 to the backend user.")
    note = a.triage(f)
    check("triage note carries the unverified marker", "⚠ unverified" in note, note)


def test_triage_leaves_anchored_note_clean():
    f = _finding(status=200)
    a = _analyst_with("Anonymous received 200 at /api/v1/accounts/2 — real cross-tenant read.")
    note = a.triage(f)
    check("anchored triage note is unmarked", "⚠ unverified" not in note, note)


def run():
    for fn in (test_extract_claims, test_anchored_when_backed, test_unanchored_is_flagged,
               test_empty_and_generic_text, test_anchor_findings_batch,
               test_triage_annotates_hallucination, test_triage_leaves_anchored_note_clean):
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    return _FAIL == 0


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
