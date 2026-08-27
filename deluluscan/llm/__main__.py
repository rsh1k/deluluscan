"""CLI: run an LLM/AI-system pentest against an authorized target.

    # An OpenAI-compatible chat app you are authorized to test
    python3 -m deluluscan.llm --url https://app.local/api/chat --preset openai --model gpt-x

    # A plain {"prompt": ...} -> {"text": ...} endpoint
    python3 -m deluluscan.llm --url http://127.0.0.1:8080/generate --preset prompt

    # Assess a local model directly through a WS-1 provider (no app in between)
    python3 -m deluluscan.llm --provider ollama --model llama3.1

Authorization boundary applies: only test targets you own or are permitted to
assess. Probes are benign (canary markers) and bounded.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from urllib.parse import urlparse

from .target import LLMTarget, PRESETS
from .engine import LlmPentest


def _is_local(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        addr = ipaddress.ip_address(socket.gethostbyname(host))
        return bool(addr.is_loopback or addr.is_private)
    except Exception:
        return False


def _build_target(args) -> LLMTarget:
    if args.provider:
        from ..config import AIConfig
        from ..ai.providers import build_provider
        cfg = AIConfig(provider=args.provider, model=args.model or "",
                       endpoint=args.endpoint or "", ollama_model=args.model or "llama3.1")
        return LLMTarget.from_provider(build_provider(cfg))
    if not args.url:
        raise SystemExit("provide --url (an LLM chat endpoint) or --provider")
    headers = {"content-type": "application/json"}
    for h in args.header or []:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    return LLMTarget.from_http(
        args.url, method=args.method, headers=headers, preset=args.preset or "prompt",
        response_path=args.response_path or PRESETS.get(args.preset or "prompt", (None, "text"))[1],
        model=args.model or "", timeout_s=args.timeout)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="deluluscan.llm",
                                description="LLM / AI-system pentest (OWASP LLM Top 10)")
    p.add_argument("--url", help="target LLM chat endpoint")
    p.add_argument("--preset", choices=sorted(PRESETS), help="request-shape preset")
    p.add_argument("--response-path", help="dotted path to the reply text (e.g. choices.0.message.content)")
    p.add_argument("--method", default="POST")
    p.add_argument("--header", action="append", help="extra header 'K: V' (repeatable)")
    p.add_argument("--provider", help="assess a model directly via a provider: "
                   "ollama|openai|deepseek|openai_compat|anthropic|bedrock")
    p.add_argument("--endpoint", help="base URL for an openai-compatible provider target")
    p.add_argument("--model", help="model id for the target")
    p.add_argument("--max-repeats", type=int, default=None, help="cap per-probe repeats")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--allow-remote", action="store_true",
                   help="assert authorization to test a non-local target")
    p.add_argument("--json", action="store_true", help="print findings as JSON")
    args = p.parse_args(argv)

    target = _build_target(args)
    if args.url and not _is_local(args.url) and not args.allow_remote:
        raise SystemExit(f"[scope] {args.url} is not loopback/RFC1918. Re-run with "
                         "--allow-remote only if you are authorized to test it.")

    result = LlmPentest(target, max_repeats=args.max_repeats).run()
    if args.json:
        print(json.dumps({"summary": result.summary,
                          "findings": [f.to_dict() for f in result.findings]}, indent=2, default=str))
    else:
        s = result.summary
        print(f"[llm] target={s['target']}  probes={s['probes_run']}  "
              f"findings={s['findings']} (confirmed={s['confirmed']})  errors={s['errors']}")
        print(f"[llm] OWASP classes hit: {', '.join(s['owasp_classes_hit']) or 'none'}")
        for f in result.findings:
            print(f"  [{f.severity.value:>8}] {f.title:<38} {f.confidence}/{f.verdict}"
                  f"  ({f.detail.get('reproduction')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
