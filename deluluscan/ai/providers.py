"""Pluggable AI provider layer — one interface, many backends.

The scanner's AI is *advisory*: it proposes what to test next and explains
evidence in plain language; the live differential verifier remains the sole
source of truth (an AI opinion never overwrites a re-test result). This module
generalises that AI access behind a single `AIProvider` interface so an
engagement can run against whatever intelligence the operator has:

    anthropic     Anthropic Messages API            (ANTHROPIC_API_KEY)
    openai        OpenAI-compatible /chat/completions (OPENAI_API_KEY)
    deepseek      DeepSeek (OpenAI-compatible)        (DEEPSEEK_API_KEY)
    openai_compat any OpenAI-compatible endpoint      (cfg.endpoint + cfg.api_key_env)
                  — vLLM, LM Studio, OpenRouter, Together, local gateways
    ollama        a LOCAL Ollama server               (no key; fully offline)
    claude_code   the local Claude Code CLI            (no key; user's session)
    codex         the local Codex CLI                  (no key; user's session)
    bedrock       Claude via AWS Bedrock Converse      (boto3 credential chain)

Design rules, in the spirit of the rest of the codebase:

* **Fail-soft.** The AI is best-effort. A missing key, an unreachable endpoint,
  or a bad response degrades to a short ``[ai: ...]`` marker string — it never
  raises into the scan. Callers already treat empty/marker output as "no AI".
* **Redaction before send.** Every prompt is run through the same
  ``redact_secrets`` used for the telemetry log plane BEFORE it leaves the host
  (JWTs, API keys, AWS keys, DB passwords, bearer tokens, session ids). A scan's
  evidence contains the target's secrets; those must not be shipped to a
  third-party model. ``ollama`` / ``claude_code`` / ``codex`` keep data on the
  host entirely — prefer them for sensitive engagements.
* **One transport.** All HTTP providers use ``requests`` (already a dependency),
  so a single timeout/retry/error story covers Anthropic, OpenAI, DeepSeek, and
  Ollama alike, and nothing new is pulled in for the common path. ``bedrock``
  lazy-imports boto3 only when selected.
* **`chat()` is the primitive.** A multi-turn ``chat(messages)`` underlies the
  convenience ``complete(system, user)`` — this is the seam a future agentic
  loop plugs into without touching provider code.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

try:  # redaction shared with the telemetry log plane
    from ..telemetry.signatures import redact_secrets as _redact_secrets
except Exception:  # pragma: no cover - telemetry is always present, but stay soft
    def _redact_secrets(line: str):  # type: ignore
        return line, []


Message = dict  # {"role": "system"|"user"|"assistant", "content": str}


def redact_prompt(text: str) -> str:
    """Strip credential/secret shapes from a prompt before it leaves the host."""
    if not text:
        return text
    out, _ = _redact_secrets(text)
    return out


def redact_messages(messages: list[Message]) -> list[Message]:
    return [{**m, "content": redact_prompt(str(m.get("content", "")))} for m in messages]


class AIProvider:
    """Base interface. A provider turns a chat transcript into assistant text.

    Subclasses implement ``_chat`` (raw call) and optionally override
    ``available``. ``chat``/``complete`` add redaction + fail-soft on top, so
    subclasses never have to.
    """

    name: str = "base"
    #: providers that keep all data on the local host (no third-party egress).
    local_only: bool = False

    def __init__(self, cfg):
        self.cfg = cfg
        self.redact = bool(getattr(cfg, "redact_prompts", True))
        self.max_tokens = int(getattr(cfg, "max_tokens", 1024))
        self.temperature = float(getattr(cfg, "temperature", 0.0))

    # -- public -------------------------------------------------------------
    def available(self) -> bool:
        return True

    def chat(self, messages: list[Message], *, max_tokens: Optional[int] = None,
             temperature: Optional[float] = None) -> str:
        msgs = redact_messages(messages) if self.redact else list(messages)
        try:
            return self._chat(msgs,
                              max_tokens=max_tokens or self.max_tokens,
                              temperature=self.temperature if temperature is None else temperature)
        except Exception as exc:  # AI is best-effort; never break the scan
            return f"[ai unavailable: {type(exc).__name__}: {str(exc)[:160]}]"

    def complete(self, system: str, user: str, **kw) -> str:
        return self.chat([{"role": "system", "content": system},
                          {"role": "user", "content": user}], **kw)

    # -- subclass hook ------------------------------------------------------
    def _chat(self, messages: list[Message], *, max_tokens: int, temperature: float) -> str:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def _split_system(messages: list[Message]) -> tuple[str, list[Message]]:
    """Anthropic takes `system` separately; pull leading system messages out."""
    system = "\n\n".join(m["content"] for m in messages if m.get("role") == "system")
    rest = [m for m in messages if m.get("role") != "system"]
    return system, rest


class NullProvider(AIProvider):
    name = "none"
    local_only = True

    def available(self) -> bool:
        return False

    def _chat(self, messages, *, max_tokens, temperature) -> str:
        return ""


class AnthropicProvider(AIProvider):
    """Anthropic Messages API over raw HTTP (matches the tool's requests-based
    transport; no extra SDK dependency for the common path)."""
    name = "anthropic"
    ENDPOINT = "https://api.anthropic.com/v1/messages"
    VERSION = "2023-06-01"

    def _key(self) -> Optional[str]:
        env = getattr(self.cfg, "api_key_env", "") or "ANTHROPIC_API_KEY"
        return os.getenv(env)

    def available(self) -> bool:
        return bool(self._key())

    def _chat(self, messages, *, max_tokens, temperature) -> str:
        import requests
        key = self._key()
        if not key:
            return "[ai: ANTHROPIC_API_KEY not set]"
        system, rest = _split_system(messages)
        endpoint = getattr(self.cfg, "endpoint", "") or self.ENDPOINT
        resp = requests.post(
            endpoint,
            headers={"x-api-key": key, "anthropic-version": self.VERSION,
                     "content-type": "application/json"},
            json={"model": self.cfg.model, "max_tokens": max_tokens,
                  "system": system,
                  "messages": [{"role": m["role"], "content": m["content"]} for m in rest]},
            timeout=getattr(self.cfg, "timeout_s", 60))
        data = resp.json()
        return "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text")


class OpenAICompatibleProvider(AIProvider):
    """OpenAI-compatible /chat/completions. Covers OpenAI, DeepSeek, and any
    OpenAI-compatible gateway (vLLM, LM Studio, OpenRouter, Together, local
    proxies) by pointing `endpoint` and `api_key_env` at them."""
    name = "openai_compat"
    DEFAULT_ENDPOINT = "https://api.openai.com/v1"
    DEFAULT_KEY_ENV = "OPENAI_API_KEY"

    def _base(self) -> str:
        return (getattr(self.cfg, "endpoint", "") or self.DEFAULT_ENDPOINT).rstrip("/")

    def _key(self) -> Optional[str]:
        env = getattr(self.cfg, "api_key_env", "") or self.DEFAULT_KEY_ENV
        return os.getenv(env)

    def available(self) -> bool:
        # A local gateway may need no key; require one only for known cloud hosts.
        base = self._base()
        needs_key = any(h in base for h in ("api.openai.com", "api.deepseek.com",
                                            "openrouter.ai", "api.together"))
        return (not needs_key) or bool(self._key())

    def _chat(self, messages, *, max_tokens, temperature) -> str:
        import requests
        headers = {"content-type": "application/json"}
        key = self._key()
        if key:
            headers["authorization"] = f"Bearer {key}"
        url = self._base() + "/chat/completions"
        resp = requests.post(
            url, headers=headers,
            json={"model": self.cfg.model,
                  "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
                  "max_tokens": max_tokens, "temperature": temperature, "stream": False},
            timeout=getattr(self.cfg, "timeout_s", 90))
        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            return f"[ai: no choices from {self.name}]"
        return (choices[0].get("message") or {}).get("content", "") or ""


class DeepSeekProvider(OpenAICompatibleProvider):
    name = "deepseek"
    DEFAULT_ENDPOINT = "https://api.deepseek.com"
    DEFAULT_KEY_ENV = "DEEPSEEK_API_KEY"


class OpenAIProvider(OpenAICompatibleProvider):
    name = "openai"


class OllamaProvider(AIProvider):
    """A LOCAL Ollama server — fully offline, no data egress."""
    name = "ollama"
    local_only = True

    def _host(self) -> str:
        return (getattr(self.cfg, "ollama_host", "") or "http://localhost:11434").rstrip("/")

    def available(self) -> bool:
        try:
            import requests
            requests.get(self._host() + "/api/tags", timeout=2)
            return True
        except Exception:
            return False

    def _chat(self, messages, *, max_tokens, temperature) -> str:
        import requests
        model = getattr(self.cfg, "ollama_model", "") or self.cfg.model
        resp = requests.post(
            self._host() + "/api/chat",
            json={"model": model, "stream": False,
                  "options": {"temperature": temperature, "num_predict": max_tokens},
                  "messages": [{"role": m["role"], "content": m["content"]} for m in messages]},
            timeout=getattr(self.cfg, "timeout_s", 180))
        return (resp.json().get("message") or {}).get("content", "") or ""


class _CLIProvider(AIProvider):
    """Shared base for CLI-driven local agents (Claude Code, Codex). These use
    the operator's own authenticated session — no API key in config — and keep
    data on the host."""
    name = "cli"
    local_only = True
    binary_attr = ""
    default_binary = ""

    def _binary(self) -> str:
        return getattr(self.cfg, self.binary_attr, None) or self.default_binary

    def available(self) -> bool:
        return shutil.which(self._binary()) is not None

    def _argv(self, system: str, user: str) -> list[str]:
        raise NotImplementedError

    def _extract(self, stdout: str, stderr: str) -> str:
        return stdout.strip() or stderr.strip()

    def _chat(self, messages, *, max_tokens, temperature) -> str:
        binary = self._binary()
        if shutil.which(binary) is None:
            return f"[ai: {self.name} CLI '{binary}' not found on PATH]"
        system, rest = _split_system(messages)
        user = "\n\n".join(m["content"] for m in rest)
        try:
            proc = subprocess.run(self._argv(system, user), capture_output=True,
                                  text=True, timeout=getattr(self.cfg, "timeout_s", 180))
        except subprocess.TimeoutExpired:
            return f"[ai: {self.name} timed out]"
        return self._extract(proc.stdout, proc.stderr)


class ClaudeCodeProvider(_CLIProvider):
    name = "claude_code"
    binary_attr = "claude_code_path"
    default_binary = "claude"

    def _argv(self, system, user):
        argv = [self._binary(), "-p", user, "--output-format", "json",
                "--append-system-prompt", system]
        if getattr(self.cfg, "model", None):
            argv += ["--model", self.cfg.model]
        return argv

    def _extract(self, stdout, stderr):
        out = stdout.strip()
        try:
            obj = json.loads(out)
            if isinstance(obj, dict):
                return obj.get("result") or obj.get("text") or out
        except json.JSONDecodeError:
            pass
        return out or stderr.strip()


class CodexProvider(_CLIProvider):
    """Drive the local Codex CLI in non-interactive/headless mode. Uses the
    operator's own Codex auth; system + user are concatenated into one prompt."""
    name = "codex"
    binary_attr = "codex_path"
    default_binary = "codex"

    def _argv(self, system, user):
        prompt = (system + "\n\n" + user).strip() if system else user
        argv = [self._binary(), "exec", prompt]
        if getattr(self.cfg, "model", None):
            argv += ["--model", self.cfg.model]
        return argv


class BedrockProvider(AIProvider):
    """Claude via AWS Bedrock Converse, using boto3's credential chain (OIDC
    role in CI or a local profile) — never static keys in config."""
    name = "bedrock"

    def available(self) -> bool:
        try:
            import boto3  # noqa: F401
            return True
        except Exception:
            return False

    def _chat(self, messages, *, max_tokens, temperature) -> str:
        try:
            import boto3
        except ImportError:
            return "[ai: boto3 not installed for provider: bedrock]"
        system, rest = _split_system(messages)
        client = boto3.client("bedrock-runtime",
                              region_name=getattr(self.cfg, "bedrock_region", "us-east-1"))
        resp = client.converse(
            modelId=self.cfg.model,
            system=([{"text": system}] if system else []),
            messages=[{"role": m["role"], "content": [{"text": m["content"]}]} for m in rest],
            inferenceConfig={"maxTokens": max_tokens, "temperature": temperature})
        blocks = resp.get("output", {}).get("message", {}).get("content", [])
        return "".join(b.get("text", "") for b in blocks if "text" in b)


_PROVIDERS = {
    "none": NullProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "openai_compat": OpenAICompatibleProvider,
    "deepseek": DeepSeekProvider,
    "ollama": OllamaProvider,
    "claude_code": ClaudeCodeProvider,
    "codex": CodexProvider,
    "bedrock": BedrockProvider,
}


def provider_names() -> list[str]:
    return sorted(_PROVIDERS)


def build_provider(cfg) -> AIProvider:
    """Instantiate the provider named by ``cfg.provider`` (default: none)."""
    cls = _PROVIDERS.get(getattr(cfg, "provider", "none"), NullProvider)
    return cls(cfg)
