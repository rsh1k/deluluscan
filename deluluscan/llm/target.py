"""LLMTarget — the thing under test in an LLM/AI-system assessment.

Deluluscan's LLM pentest is *bring-your-own-target*: point it at any LLM-backed
chat endpoint you are authorized to assess. A target is anything that turns a
prompt (or a multi-turn transcript) into text. Two backings ship:

* **HTTP** — a real app's chat API. You describe its request shape with a JSON
  body template containing the sentinel ``{{PROMPT}}`` (single-turn) and/or
  ``{{MESSAGES}}`` (multi-turn), and where the reply text lives with a dotted
  ``response_path`` (e.g. ``choices.0.message.content``). Presets cover the
  common OpenAI / Ollama / plain-``{"prompt":…}`` shapes.
* **Provider** — reuse the WS-1 `AIProvider` transport to assess a model or
  gateway directly (a local Ollama model, an OpenAI-compatible endpoint).

Both expose ``ask(prompt)`` and ``chat(messages)`` returning ``(text, RequestRecord)``
so every probe carries reproducible evidence. A ``from_callable`` backing exists
for offline tests. Everything routes through the same authorization boundary as
the rest of the tool — only assess targets you own or are permitted to test.
"""
from __future__ import annotations

import copy
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..models import RequestRecord

Message = dict  # {"role": ..., "content": ...}

# Request-shape presets: (body_template, response_path).
PRESETS: dict[str, tuple[Any, str]] = {
    "openai":  ({"model": "{{MODEL}}", "messages": "{{MESSAGES}}"},
                "choices.0.message.content"),
    "ollama":  ({"model": "{{MODEL}}", "stream": False, "messages": "{{MESSAGES}}"},
                "message.content"),
    "prompt":  ({"prompt": "{{PROMPT}}"}, "text"),
    "content": ({"content": "{{PROMPT}}"}, "content"),
}


def _extract(obj: Any, path: str) -> str:
    """Traverse a dotted path over dicts/lists; return '' if it doesn't resolve."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return ""
        elif isinstance(cur, dict):
            if part not in cur:
                return ""
            cur = cur[part]
        else:
            return ""
    return cur if isinstance(cur, str) else json.dumps(cur)


def _render(template: Any, *, prompt: Optional[str] = None,
            messages: Optional[list[Message]] = None, model: str = "") -> Any:
    """Substitute {{PROMPT}} / {{MESSAGES}} / {{MODEL}} sentinels in a template."""
    if isinstance(template, str):
        if template == "{{MESSAGES}}":
            return messages if messages is not None else []
        if template == "{{MODEL}}":
            return model
        out = template
        if prompt is not None:
            out = out.replace("{{PROMPT}}", prompt)
        return out
    if isinstance(template, list):
        return [_render(v, prompt=prompt, messages=messages, model=model) for v in template]
    if isinstance(template, dict):
        return {k: _render(v, prompt=prompt, messages=messages, model=model)
                for k, v in template.items()}
    return template


@dataclass
class LLMTarget:
    name: str = "llm-target"
    url: str = ""
    _ask: Optional[Callable[[str], tuple[str, RequestRecord]]] = field(default=None, repr=False)
    _chat: Optional[Callable[[list[Message]], tuple[str, RequestRecord]]] = field(default=None, repr=False)

    # -- public -------------------------------------------------------------
    def ask(self, prompt: str) -> tuple[str, RequestRecord]:
        if self._ask is not None:
            return self._ask(prompt)
        # default: single-user-message chat
        return self.chat([{"role": "user", "content": prompt}])

    def chat(self, messages: list[Message]) -> tuple[str, RequestRecord]:
        if self._chat is not None:
            return self._chat(messages)
        # default: collapse a transcript into one prompt for prompt-only backings
        prompt = "\n\n".join(f"{m.get('role','user')}: {m.get('content','')}" for m in messages)
        return self.ask(prompt)

    # -- constructors -------------------------------------------------------
    @classmethod
    def from_callable(cls, fn: Callable[[str], str], *, name: str = "callable",
                      chat_fn: Optional[Callable[[list[Message]], str]] = None) -> "LLMTarget":
        """Back the target with a plain function (used by tests and adapters)."""
        def ask(prompt: str):
            t0 = time.time()
            try:
                text = fn(prompt)
                err = None
            except Exception as exc:  # keep the engine soft
                text, err = "", str(exc)[:200]
            return text, RequestRecord(method="ASK", url=name, identity="probe",
                                       status=200 if err is None else 0,
                                       elapsed_ms=(time.time() - t0) * 1000,
                                       req_body=prompt[:2000], resp_body=text[:4000],
                                       resp_len=len(text), error=err)
        chat = None
        if chat_fn is not None:
            def chat(messages):
                t0 = time.time()
                try:
                    text = chat_fn(messages); err = None
                except Exception as exc:
                    text, err = "", str(exc)[:200]
                return text, RequestRecord(method="CHAT", url=name, identity="probe",
                                           status=200 if err is None else 0,
                                           elapsed_ms=(time.time() - t0) * 1000,
                                           req_body=json.dumps(messages)[:2000],
                                           resp_body=text[:4000], resp_len=len(text), error=err)
        return cls(name=name, _ask=ask, _chat=chat)

    @classmethod
    def from_provider(cls, provider, *, name: str = "") -> "LLMTarget":
        """Assess a WS-1 AIProvider directly (a model/gateway as the target)."""
        return cls.from_callable(
            lambda p: provider.complete("", p),
            name=name or f"provider:{getattr(provider, 'name', 'ai')}",
            chat_fn=lambda msgs: provider.chat(msgs))

    @classmethod
    def from_http(cls, url: str, *, method: str = "POST", headers: Optional[dict] = None,
                  body_template: Any = None, response_path: str = "text",
                  preset: str = "", model: str = "", timeout_s: int = 60) -> "LLMTarget":
        if preset:
            body_template, response_path = PRESETS[preset]
        if body_template is None:
            body_template, response_path = PRESETS["prompt"]
        headers = headers or {"content-type": "application/json"}

        def _post(prompt=None, messages=None):
            import requests
            body = _render(copy.deepcopy(body_template), prompt=prompt,
                           messages=messages, model=model)
            t0 = time.time()
            err = None; status = 0; text = ""
            try:
                resp = requests.request(method, url, headers=headers, json=body, timeout=timeout_s)
                status = resp.status_code
                try:
                    text = _extract(resp.json(), response_path)
                except Exception:
                    text = resp.text[:4000]
            except Exception as exc:
                err = str(exc)[:200]
            return text, RequestRecord(method=method, url=url, identity="probe",
                                       status=status, elapsed_ms=(time.time() - t0) * 1000,
                                       req_headers=dict(headers), req_body=json.dumps(body)[:2000],
                                       resp_body=(text or "")[:4000], resp_len=len(text or ""),
                                       error=err)
        return cls(name=url, url=url,
                   _ask=lambda p: _post(prompt=p, messages=[{"role": "user", "content": p}]),
                   _chat=lambda m: _post(prompt=None, messages=m))
