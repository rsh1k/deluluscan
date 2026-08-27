"""Tests for deluluscan.ai.analyst's bedrock provider (Claude via AWS Bedrock).

No real AWS calls — boto3's bedrock-runtime client is monkeypatched so this
runs offline/deterministically, same spirit as test_ci_runner.py's _FakeAI.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.ai.analyst import AIAnalyst  # noqa: E402
from deluluscan.config import AIConfig  # noqa: E402

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


class _FakeBedrockClient:
    def __init__(self, response_text="genuine finding, no compensating control"):
        self.response_text = response_text
        self.last_call = None

    def converse(self, **kwargs):
        self.last_call = kwargs
        return {"output": {"message": {"content": [{"text": self.response_text}]}}}


def test_bedrock_provider_is_enabled():
    a = AIAnalyst(AIConfig(provider="bedrock", model="global.anthropic.claude-sonnet-4-6"))
    check("bedrock provider marks the analyst enabled", a.enabled is True)


def test_bedrock_completion_uses_converse_api_and_parses_text():
    fake_client = _FakeBedrockClient("hello from bedrock")

    class _FakeBoto3:
        @staticmethod
        def client(service, region_name=None):
            check("requests the bedrock-runtime service", service == "bedrock-runtime")
            check("passes through the configured region", region_name == "us-west-2")
            return fake_client

    # analyst.py does `import boto3` inside _bedrock(); inject a fake module
    # into sys.modules so that import resolves to our stub instead of the real
    # AWS SDK / a network call. Restore whatever was there before (this
    # environment has the real boto3 installed) so later tests aren't affected.
    real_boto3 = sys.modules.pop("boto3", None)
    sys.modules["boto3"] = _FakeBoto3()
    try:
        a = AIAnalyst(AIConfig(provider="bedrock", model="global.anthropic.claude-sonnet-4-6",
                               bedrock_region="us-west-2", max_tokens=777))
        out = a._complete("system prompt", "user prompt")
    finally:
        del sys.modules["boto3"]
        if real_boto3 is not None:
            sys.modules["boto3"] = real_boto3

    check("converse() response text is extracted", out == "hello from bedrock", out)
    check("system prompt is passed as Converse 'system' block",
          fake_client.last_call["system"] == [{"text": "system prompt"}])
    check("user prompt is passed as a Converse message",
          fake_client.last_call["messages"] == [{"role": "user", "content": [{"text": "user prompt"}]}])
    check("max_tokens flows into inferenceConfig",
          fake_client.last_call["inferenceConfig"]["maxTokens"] == 777)
    check("model id is passed through as modelId",
          fake_client.last_call["modelId"] == "global.anthropic.claude-sonnet-4-6")


def test_bedrock_missing_boto3_is_reported_not_raised():
    a = AIAnalyst(AIConfig(provider="bedrock", model="global.anthropic.claude-sonnet-4-6"))
    # Force `import boto3` to raise ImportError regardless of whether boto3 is
    # actually installed in this environment — setting the module to None in
    # sys.modules is the standard way to simulate a missing import.
    had_real_boto3 = sys.modules.pop("boto3", None)
    sys.modules["boto3"] = None
    try:
        out = a._complete("sys", "user")
    finally:
        del sys.modules["boto3"]
        if had_real_boto3 is not None:
            sys.modules["boto3"] = had_real_boto3
    check("missing boto3 degrades to an inline message, not an exception",
          "boto3" in out.lower(), out)


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
