"""Tests for the pluggable AI provider layer (deluluscan/ai/providers.py).

Fully offline: `requests` is monkeypatched, subprocess/boto3 are stubbed. Locks
down the factory, secret redaction-before-send, the request shapes for the
OpenAI-compatible + DeepSeek + Ollama backends, fail-soft behaviour, and that
the analyst delegates to the provider. Run: python3 -m tests.test_ai_providers
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.config import AIConfig  # noqa: E402
from deluluscan.ai import providers as P  # noqa: E402

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _FakeRequests:
    """Records the last POST and returns a canned OpenAI/Ollama-shaped body."""
    def __init__(self, payload):
        self.payload = payload
        self.last = None

    def post(self, url, headers=None, json=None, timeout=None):
        self.last = {"url": url, "headers": headers or {}, "json": json, "timeout": timeout}
        return _FakeResp(self.payload)

    def get(self, url, timeout=None):
        self.last = {"url": url, "timeout": timeout}
        return _FakeResp({"models": []})


def _inject_requests(monkey_payload):
    fake = _FakeRequests(monkey_payload)
    sys.modules["requests"] = fake  # providers do `import requests` lazily
    return fake


# ---------------------------------------------------------------------------
def test_factory_resolves_all_names():
    for name in ["none", "anthropic", "openai", "openai_compat", "deepseek",
                 "ollama", "claude_code", "codex", "bedrock"]:
        prov = P.build_provider(AIConfig(provider=name))
        check(f"factory builds provider '{name}'", prov.name == name or name == "openai_compat", prov.name)
    check("unknown provider falls back to NullProvider",
          P.build_provider(AIConfig(provider="does-not-exist")).name == "none")
    check("none provider reports unavailable",
          P.build_provider(AIConfig(provider="none")).available() is False)


def test_redaction_before_send():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123456"
    secretish = f"here is a token Bearer {('A'*30)} and password=SuperSecret123"
    r = P.redact_prompt(f"{jwt} {secretish}")
    check("JWT is redacted from prompt", jwt not in r, r)
    check("password value is redacted", "SuperSecret123" not in r, r)
    check("redaction leaves a marker", "<redacted:" in r, r)

    # end-to-end: the redacted content is what actually hits the wire
    fake = _inject_requests({"choices": [{"message": {"content": "ok"}}]})
    prov = P.build_provider(AIConfig(provider="openai_compat", model="m",
                                     endpoint="http://localhost:9/v1", redact_prompts=True))
    prov.complete("system", f"leak {jwt}")
    sent = str(fake.last["json"])
    check("JWT never leaves the host when redact_prompts=True", jwt not in sent, sent[:200])

    # redact_prompts=False sends raw (operator opt-out for local endpoints)
    fake2 = _inject_requests({"choices": [{"message": {"content": "ok"}}]})
    prov2 = P.build_provider(AIConfig(provider="openai_compat", model="m",
                                      endpoint="http://localhost:9/v1", redact_prompts=False))
    prov2.complete("system", f"leak {jwt}")
    check("redact_prompts=False sends the raw prompt", jwt in str(fake2.last["json"]))


def test_openai_compatible_request_shape():
    fake = _inject_requests({"choices": [{"message": {"content": "hi there"}}]})
    prov = P.build_provider(AIConfig(provider="openai", model="gpt-x",
                                     api_key_env="OPENAI_API_KEY", max_tokens=321))
    os.environ["OPENAI_API_KEY"] = "sk-test"
    out = prov.complete("SYS", "USER")
    check("openai response content parsed", out == "hi there", out)
    check("hits /chat/completions", fake.last["url"].endswith("/chat/completions"), fake.last["url"])
    check("bearer auth header set", fake.last["headers"].get("authorization") == "Bearer sk-test")
    body = fake.last["json"]
    check("model passed through", body["model"] == "gpt-x")
    check("max_tokens passed through", body["max_tokens"] == 321)
    check("system+user sent as messages",
          [m["role"] for m in body["messages"]] == ["system", "user"], body["messages"])
    del os.environ["OPENAI_API_KEY"]


def test_deepseek_defaults_to_its_endpoint():
    fake = _inject_requests({"choices": [{"message": {"content": "ds"}}]})
    os.environ["DEEPSEEK_API_KEY"] = "ds-key"
    prov = P.build_provider(AIConfig(provider="deepseek", model="deepseek-chat"))
    check("deepseek available with its key", prov.available() is True)
    prov.complete("s", "u")
    check("deepseek uses api.deepseek.com by default",
          "api.deepseek.com" in fake.last["url"], fake.last["url"])
    del os.environ["DEEPSEEK_API_KEY"]


def test_ollama_is_local_and_offline_shape():
    fake = _inject_requests({"message": {"content": "local answer"}})
    prov = P.build_provider(AIConfig(provider="ollama", ollama_model="llama3.1"))
    check("ollama marked local_only", prov.local_only is True)
    out = prov.complete("s", "u")
    check("ollama content parsed", out == "local answer", out)
    check("ollama hits /api/chat", fake.last["url"].endswith("/api/chat"), fake.last["url"])
    check("ollama uses its model", fake.last["json"]["model"] == "llama3.1")


def test_openai_missing_key_is_soft():
    _inject_requests({"choices": []})
    os.environ.pop("OPENAI_API_KEY", None)
    prov = P.build_provider(AIConfig(provider="openai", model="gpt-x"))
    check("openai without key reports unavailable", prov.available() is False)


def test_cli_providers_are_local_and_soft_when_missing():
    for name, attr in [("claude_code", "claude_code_path"), ("codex", "codex_path")]:
        cfg = AIConfig(provider=name, **{attr: "definitely-not-a-real-binary-xyz"})
        prov = P.build_provider(cfg)
        check(f"{name} is local_only", prov.local_only is True)
        check(f"{name} unavailable when binary missing", prov.available() is False)
        out = prov.complete("s", "u")
        check(f"{name} missing binary degrades to marker", out.startswith("[ai:"), out)


def test_analyst_delegates_to_provider():
    from deluluscan.ai.analyst import AIAnalyst
    fake = _inject_requests({"message": {"content": "42"}})
    a = AIAnalyst(AIConfig(provider="ollama", ollama_model="m"))
    check("analyst enabled for a real provider", a.enabled is True)
    check("analyst._complete routes through the provider", a._complete("s", "u") == "42")


if __name__ == "__main__":
    import types
    for fn in [v for v in list(globals().values())
               if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try:
            fn()
        except Exception as e:
            import traceback
            _FAIL += 1
            print(f"FAIL  {fn.__name__}  [exception: {e}]")
            traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed")
    sys.exit(1 if _FAIL else 0)
