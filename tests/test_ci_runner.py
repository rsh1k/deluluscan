"""Tests for ci_runner.py — the nightly CI adjudication glue.

Uses a duck-typed _FakeAI stand-in for deluluscan.ai.analyst.AIAnalyst so these
checks are deterministic and require no network access / AWS credentials —
only the merge/flagging logic in ci_runner.adjudicate_one is under test here.
The live recheck() path itself is already covered by test_claude_driver.py.
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.config import Config, ScanConfig, AIConfig  # noqa: E402
from deluluscan.models import Identity, IdentityRole  # noqa: E402
from tests.mock_target import serve  # noqa: E402

import ci_runner  # noqa: E402

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


_PORT = 8196
threading.Thread(target=serve, args=(_PORT,), daemon=True).start()
time.sleep(0.6)


def _cfg():
    c = Config(base_url=f"http://127.0.0.1:{_PORT}", verify_tls=False,
               output_dir="/tmp/ci_runner_test")
    c.identities = {"anonymous": Identity(role=IdentityRole.ANON)}
    c.scan = ScanConfig(rate_limit_rps=1000.0)
    c.ai = AIConfig(provider="none")
    return c


class _FakeAI:
    """Duck-typed stand-in for AIAnalyst.analyze_evidence — no network."""

    def __init__(self, canned):
        self.canned = canned

    def analyze_evidence(self, ctx):
        return self.canned


def _finding(**overrides):
    base = {
        "id": "f1", "vuln_class": "xss", "severity": "high",
        "title": "candidate", "endpoint": "GET /api/vuln/search",
        "description": "candidate xss", "detail": {"param": "q"},
        "evidence": [{"status": 200, "resp_body": "<script>"}],
        "verdict": "unverified", "confidence": "tentative",
        "exploitability": "unknown", "ai_notes": "",
    }
    base.update(overrides)
    return base


# ---- adjudicate_one --------------------------------------------------------

def test_already_resolved_finding_passes_through_untouched():
    f = _finding(verdict="true_positive")
    out = ci_runner.adjudicate_one(_cfg(), _FakeAI({"is_real": False, "reason": "n/a"}), f)
    check("resolved finding is untouched", out == f, str(out))


def test_recheck_reproduces_and_ai_confirms_true_positive():
    ai = _FakeAI({"is_real": True, "reason": "confirmed reflected in response"})
    out = ci_runner.adjudicate_one(_cfg(), ai, _finding())
    check("live-reproduced + AI-confirmed finding becomes true_positive",
          out["verdict"] == "true_positive", str(out))
    check("retest evidence is attached for a mapped vuln_class", "retest" in out, str(out))


def test_ai_cannot_overrule_a_live_retest():
    """The core discipline: a model reading stale evidence does not get to overwrite
    a probe that just ran. It used to — `is_real: False` unconditionally set
    false_positive, so an LLM could retract a live-reproduced finding (and
    `is_real: True` could promote one with no traffic behind it at all)."""
    ai = _FakeAI({"is_real": False, "reason": "the target correctly sanitized the input"})
    out = ci_runner.adjudicate_one(_cfg(), ai, _finding())
    check("live re-test verdict survives an AI disagreement",
          out["verdict"] == "true_positive", str(out))
    check("the disagreement is recorded rather than applied",
          out.get("ai_disagrees_with_retest") is True, str(out))
    check("the AI opinion is retained, marked advisory",
          out.get("ai_opinion", {}).get("advisory") is True, str(out))
    check("no scanner-bug flag when reasoning doesn't mention an artifact",
          "needs_scanner_review" not in out, str(out))


def test_artifact_shaped_reasoning_is_flagged_for_review():
    ai = _FakeAI({"is_real": False, "reason": "this is a false positive: the request was malformed"})
    out = ci_runner.adjudicate_one(_cfg(), ai, _finding())
    check("artifact-shaped AI reasoning is flagged for human review",
          out.get("needs_scanner_review") is True, str(out))


def test_registry_derived_scanners_widen_live_retest_coverage():
    """error_handling has no entry in the old 6-class hardcoded dict, so CI never
    live re-tested it. scanners_for_class() derives it from the registry."""
    ai = _FakeAI({"is_real": True, "reason": "genuine — no compensating control present"})
    f = _finding(vuln_class="error_handling", endpoint="GET /api/content/id/{identifier}")
    out = ci_runner.adjudicate_one(_cfg(), ai, f)
    check("a formerly-unmapped vuln_class IS now live re-tested", "retest" in out, str(out))
    check("and the scanners used are recorded",
          bool(out.get("retest", {}).get("scanners")), str(out))
    check("the live verdict stands, not the AI's",
          out["verdict"] == out["retest"]["verdict"], str(out))


def test_ai_cannot_promote_an_untested_finding_to_true_positive():
    """With no scanner covering the class, nothing probed the target. The AI saying
    'is_real' must not manufacture a confirmation."""
    ai = _FakeAI({"is_real": True, "reason": "looks genuine from the evidence"})
    f = _finding(vuln_class="totally_unknown_class", endpoint="GET /api/x")
    out = ci_runner.adjudicate_one(_cfg(), ai, f)
    check("no live re-test happened", "retest" not in out, str(out))
    check("verdict is NOT promoted to true_positive",
          out["verdict"] != "true_positive", str(out))
    check("and the report says why it was not re-tested",
          "not live re-tested" in (out.get("retest_note") or "").lower(), str(out))


def test_ai_doubt_without_a_live_retest_caps_at_inconclusive():
    """Nothing refuted it, so 'false_positive' would be as unearned as
    'true_positive'. The honest ceiling is inconclusive."""
    ai = _FakeAI({"is_real": False, "reason": "probably benign"})
    f = _finding(vuln_class="totally_unknown_class", endpoint="GET /api/x")
    out = ci_runner.adjudicate_one(_cfg(), ai, f)
    check("un-retested + AI doubt -> inconclusive, not false_positive",
          out["verdict"] == "inconclusive", str(out))


def test_no_ai_verdict_leaves_recheck_verdict_in_place():
    class _EmptyAI:
        def analyze_evidence(self, ctx):
            return {}
    out = ci_runner.adjudicate_one(_cfg(), _EmptyAI(), _finding())
    check("empty AI response doesn't crash and keeps the recheck-derived verdict",
          out["verdict"] in {"true_positive", "likely_true_positive", "conditional",
                             "inconclusive", "false_positive"}, str(out))


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            try:
                fn()
            except Exception as e:
                import traceback
                _FAIL += 1
                print(f"FAIL  {fn.__name__}  [exception: {e}]")
                traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed")
    sys.exit(1 if _FAIL else 0)
