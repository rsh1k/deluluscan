"""Pluggable AI analyst.

Two jobs, both advisory:

1. **Prioritize** discovered endpoints so the scan spends its budget on the most
   promising attack surface first (id-bearing, privileged, URL-accepting, etc.).
2. **Triage** findings: explain the likely root cause in plain language, propose
   the exact manual reproduction step, and down-rank probable false positives.

It NEVER decides to fire destructive requests and never generates exploit
payloads; with advisory_only=True (the default) its output is text the human
reads. Two backends are supported behind one interface: Anthropic's API and a
local Ollama server (fully offline).
"""
from __future__ import annotations

import json
import os
from typing import Optional

from ..config import AIConfig
from ..models import Endpoint, Finding

_PRIORITIZE_SYS = (
    "You are a senior web application security reviewer helping triage an "
    "authorized API security scan of a target instance the operator controls. "
    "Given a list of endpoints, return ONLY a JSON array of the endpoint keys "
    "ordered most-promising-first for IDOR, injection, XSS, and SSRF testing. "
    "No prose, no code, no payloads.")

_TRIAGE_SYS = (
    "You are a senior security reviewer triaging one finding from an authorized "
    "scan. Respond with a short JSON object: {\"false_positive_risk\": "
    "\"low|medium|high\", \"root_cause\": \"...\", \"manual_repro\": \"one safe "
    "verification step\", \"report_worthy\": true|false}. Do not output exploit "
    "code or weaponized payloads; describe verification at a high level only.")


class AIAnalyst:
    def __init__(self, cfg: AIConfig):
        self.cfg = cfg
        from .providers import build_provider
        self.provider = build_provider(cfg)
        # Any configured provider (not "none") turns the AI on. The live
        # differential verifier stays authoritative regardless — AI is advisory.
        self.enabled = getattr(cfg, "provider", "none") != "none"

    # -- public API ---------------------------------------------------------
    def prioritize(self, endpoints: list[Endpoint]) -> list[Endpoint]:
        if not self.enabled or len(endpoints) < 3:
            return self._heuristic_order(endpoints)
        catalog = [{"key": e.key, "tags": e.tags, "id_bearing": e.id_bearing,
                    "summary": e.summary[:80]} for e in endpoints[:200]]
        prompt = ("Endpoints:\n" + json.dumps(catalog) +
                  "\n\nReturn the JSON array of keys, best targets first.")
        out = self._complete(_PRIORITIZE_SYS, prompt)
        order = self._parse_json(out)
        if isinstance(order, list) and order:
            rank = {k: i for i, k in enumerate(order)}
            return sorted(endpoints, key=lambda e: rank.get(e.key, 10_000))
        return self._heuristic_order(endpoints)

    # Allowlisted active tests the operator may schedule. As with the agent's
    # phase allowlist, the AI can only *order/select* from this fixed set — it
    # cannot invent new actions or emit payloads.
    ACTIVE_TESTS = [
        "jwt_alg_none", "jwt_strip_signature", "jwt_tamper_signature",
        "jwt_alg_confusion", "jwt_weak_secret", "jwt_claim_escalation",
        "authz_missing_auth", "authz_identity_swap", "authz_bola_id",
        "mass_assignment",
    ]

    _PLAN_ACTIVE_SYS = (
        "You are planning an AUTHORIZED active API test against a target the "
        "operator controls. Choose which checks to run, and in what order, ONLY "
        "from this allowlist: " + ", ".join(ACTIVE_TESTS) + ". Return ONLY a "
        "JSON array of test names, most-promising first. Do not invent tests or "
        "output payloads/exploit code.")

    def plan_active(self, endpoint_ctx: dict) -> list[str]:
        """Order the allowlisted active tests for one endpoint. Deterministic
        (all tests, sensible order) when AI is disabled."""
        if not self.enabled:
            return list(self.ACTIVE_TESTS)
        out = self._parse_json(self._complete(
            self._PLAN_ACTIVE_SYS, json.dumps(endpoint_ctx)))
        if isinstance(out, list) and out:
            allowed = [t for t in out if t in self.ACTIVE_TESTS]
            # append any omitted tests so nothing is silently skipped
            return allowed + [t for t in self.ACTIVE_TESTS if t not in allowed]
        return list(self.ACTIVE_TESTS)

    def interpret_active(self, ctx: dict) -> str:
        """Short plain-language read on an accepted/rejected manipulation."""
        if not self.enabled:
            return ""
        sys = ("Explain in one or two sentences what this authorized active-test "
               "result means for access control, and a safe manual re-check. No "
               "exploit code.")
        return self._complete(sys, json.dumps(ctx)).strip()

    def analyze_evidence(self, ctx: dict) -> dict:
        """Full-AI root-cause analysis of a finding's evidence. Returns
        {"is_real": bool, "reason": str, "missing": str, "repro": str}. Used to
        explain a result and catch artifacts the heuristics miss (e.g. a 4xx that
        means the request was malformed, not a vuln). No-op when AI is disabled."""
        if not self.enabled:
            return {}
        sys = (
            "You are a senior API pentester reviewing one candidate finding from "
            "an automated scanner of an AUTHORIZED target. Decide whether it is a "
            "REAL vulnerability or an ARTIFACT of a bad/malformed request or "
            "expected behavior. A 4xx (400/405/422) means the REQUEST was rejected "
            "before authorization ran, so identical responses across identities "
            "prove nothing. A finding is only real if a lower/anon caller receives "
            "the SAME protected data an authorized caller does, or a privileged "
            "action actually succeeds. Reply ONLY with compact JSON: "
            '{"is_real": true|false, "reason": "...", "missing": "what the request '
            'lacked, if any", "repro": "safe manual re-check"}. No prose, no code.')
        raw = self._complete(sys, json.dumps(ctx))
        parsed = self._parse_json(raw)
        return parsed if isinstance(parsed, dict) else {"reason": (raw or "").strip()[:300]}

    def triage(self, finding: Finding) -> str:
        if not self.enabled:
            return ""
        ev = finding.evidence[0] if finding.evidence else None
        ctx = {
            "vuln_class": finding.vuln_class.value,
            "title": finding.title,
            "endpoint": finding.endpoint,
            "description": finding.description,
            "detail": finding.detail,
            "evidence_status": getattr(ev, "status", None),
            "evidence_excerpt": (ev.resp_body[:600] if ev else ""),
        }
        out = self._complete(_TRIAGE_SYS, json.dumps(ctx))
        return out.strip()

    # -- backend (pluggable AIProvider) ------------------------------------
    def _complete(self, system: str, user: str) -> str:
        """Delegate to the configured provider (anthropic | openai | deepseek |
        openai_compat | ollama | claude_code | codex | bedrock). The provider
        redacts secrets before send and is fail-soft: a missing key or an
        unreachable endpoint returns a short marker string, never an exception.
        See deluluscan/ai/providers.py."""
        return self.provider.complete(system, user)

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _parse_json(text: str):
        text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        try:
            return json.loads(text)
        except Exception:
            return None

    @staticmethod
    def _heuristic_order(endpoints: list[Endpoint]) -> list[Endpoint]:
        def score(e: Endpoint) -> int:
            s = 0
            if e.id_bearing:
                s += 5
            if any(t in ("users", "roles", "apps", "maintenance", "system")
                   for t in e.tags):
                s += 3
            if e.query_params:
                s += 2
            return -s
        return sorted(endpoints, key=score)
