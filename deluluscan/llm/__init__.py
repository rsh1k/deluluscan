"""Deluluscan LLM / AI-system pentest pack (WS-3).

A bring-your-own-target assessment of an LLM-backed application or model against
the OWASP Top 10 for LLM Applications (2025). Point it at any chat endpoint you
are authorized to test.

    from deluluscan.llm import LLMTarget, LlmPentest
    target = LLMTarget.from_http("https://app/api/chat", preset="openai", model="gpt-x")
    result = LlmPentest(target).run()
    print(result.summary)

CLI:  python3 -m deluluscan.llm --url https://app/api/chat --preset openai --model gpt-x
"""
from .target import LLMTarget
from .probes import build_probes
from .engine import LlmPentest, LlmScanResult

__all__ = ["LLMTarget", "LlmPentest", "LlmScanResult", "build_probes"]
