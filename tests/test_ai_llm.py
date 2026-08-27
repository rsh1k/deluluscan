"""AI/LLM scanner — probes the target's /api/v1/ai/* for prompt injection (LLM01)
and system-prompt leakage (LLM07) with benign markers, and reports the surface
as UNTESTED (not clean) when AI is not configured.

Verified offline against a fake client that scripts the three cases:
model complies (injection), AI not configured, and model refuses.

Run: python3 -m tests.test_ai_llm
"""
from __future__ import annotations

import sys

from deluluscan.models import Endpoint, RequestRecord, VulnClass
from deluluscan.scanners.ai_llm_scanner import AiLlmScanner

_checks = 0
_failures: list[str] = []


def check(cond, label):
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


class _Ident:
    def __init__(self, label): self._l = label; self.username = label; self.bearer_token = None
    def label(self): return self._l


class _Auth:
    def headers_for(self, ident): return {}


class _Client:
    """Scripts the AI endpoint's behaviour by mode."""
    def __init__(self, mode): self.mode = mode; self.calls = 0
    def request(self, method, path, identity_label=None, headers=None, json_body=None, **kw):
        self.calls += 1
        prompt = ""
        if isinstance(json_body, dict):
            prompt = json_body.get("prompt") or json_body.get("query") or ""
            if not prompt and json_body.get("messages"):
                prompt = json_body["messages"][0].get("content", "")
        def rec(status, body):
            return RequestRecord(method=method, url=path, identity=identity_label or "",
                                 status=status, elapsed_ms=1.0, resp_headers={},
                                 resp_body=body, resp_len=len(body))
        if self.mode == "not_configured":
            return rec(400, "OpenAI API key not configured for this host")
        if self.mode == "inject":                 # model complies -> echoes the prompt (marker leaks)
            return rec(200, '{"response":"' + prompt.replace('"', "'") + '"}')
        if self.mode == "safe":                   # model refuses -> no marker
            return rec(200, '{"response":"I cannot comply with that request."}')
        return rec(200, "{}")


def _scanner(mode):
    s = AiLlmScanner(_Client(mode), _Auth(), config=None, identities={"admin": _Ident("admin")})
    return s


AI_EP = Endpoint("POST", "/api/v1/ai/completions", "AI", ["ai"])


def test_applies_only_to_prompt_endpoints():
    s = _scanner("safe")
    check(s.applies_to(AI_EP), "applies to /ai/completions")
    check(not s.applies_to(Endpoint("GET", "/api/v1/ai/completions/config")), "skips /ai/*/config")
    check(not s.applies_to(Endpoint("GET", "/api/v1/users/current")), "skips non-AI endpoints")


def test_prompt_injection_detected_when_marker_reflects():
    findings = list(_scanner("inject").run(AI_EP))
    inj = [f for f in findings if f.detail.get("llm_class") == "LLM01-prompt-injection"]
    check(len(inj) == 1, f"emits one prompt-injection finding (got {len(inj)})")
    check(inj and inj[0].vuln_class == VulnClass.AI_LLM, "finding is class ai_llm")
    check(inj and inj[0].verdict == "true_positive", "repeated marker reflection -> true_positive")
    check(inj and inj[0].exploitability == "conditional",
          "exploitability conditional (impact depends on the AI's agency)")


def test_untested_surface_when_not_configured():
    findings = list(_scanner("not_configured").run(AI_EP))
    check(len(findings) == 1 and findings[0].detail.get("llm_class") == "surface-present-untested",
          "not-configured AI reports one 'present but untested' surface finding")
    check(findings and findings[0].severity.value == "info", "untested surface is INFO severity")
    check(findings and "not proven clean" in findings[0].description,
          "untested surface is explicitly NOT called clean")


def test_no_false_positive_when_model_refuses():
    findings = list(_scanner("safe").run(AI_EP))
    inj = [f for f in findings if f.detail.get("llm_class") == "LLM01-prompt-injection"]
    check(not inj, "no injection finding when the marker never reflects")


def main():
    print("== ai/llm scanner ==")
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
