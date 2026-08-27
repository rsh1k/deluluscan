"""ExploitChainAgent — a bounded observe -> hypothesize -> act -> verify loop that
deepens ONE lead into a demonstrated, chained exploit.

Design (borrows from PentestGPT / HackingBuddyGPT / AutoPentest, and mirrors the
discipline of the rest of Deluluscan):

* **Allowlist only.** The action space is the injected capability set — no shell,
  no arbitrary payloads. An AI-proposed action not on the allowlist is REJECTED.
* **Budget.** At most ``max_steps`` capability calls; the loop always terminates.
* **Human-in-the-loop for state changes.** A state-changing capability runs only
  when BOTH the global ``allow_state_changing`` opt-in is set AND the ``approve``
  callback returns True (default: deny). Everything else is read-only.
* **Truth is deterministic.** The chain is ``proven`` only when the objective
  ``verify`` function (not the model) says so. The AI proposes; tools execute; the
  verifier decides. The model can never mark a chain proven.
* **Never weaponize.** Capabilities confirm to proof (reachability diff, read-back,
  OOB callback) — they do not exfiltrate, persist, or damage.

Fail-soft: with AI disabled (or unavailable) the loop falls back to a fixed,
sensible ordering (read-only capabilities first) so it still demonstrates chains.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Optional

from ..models import Severity, VulnClass
from .capabilities import Capability, CapabilityResult
from .chain import AttackChain, ChainStep

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_action(text: str) -> dict:
    if not text:
        return {}
    t = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    for candidate in (t, (_JSON_RE.search(t).group(0) if _JSON_RE.search(t) else "")):
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue
    return {}


def deny_state_changing(cap: Capability, args: dict) -> bool:
    """Default approval policy: never approve a state-changing action."""
    return False


def approve_all(cap: Capability, args: dict) -> bool:
    """Non-interactive approval for an authorized, operator-driven run."""
    return True


class ExploitChainAgent:
    def __init__(self, provider, capabilities: list, *, objective: str,
                 verify: Callable[[dict], tuple],
                 approve: Callable[[Capability, dict], bool] = deny_state_changing,
                 max_steps: int = 8, allow_state_changing: bool = False,
                 vuln_class: VulnClass = VulnClass.BUSINESS_LOGIC,
                 severity: Severity = Severity.HIGH):
        self.provider = provider
        self.caps = list(capabilities)
        self.by_name = {c.name: c for c in self.caps}
        self.objective = objective
        self.verify = verify
        self.approve = approve
        self.max_steps = max_steps
        self.allow_state_changing = allow_state_changing
        self.vuln_class = vuln_class
        self.severity = severity

    # -- decide the next action --------------------------------------------
    _SYS = ("You are deepening ONE confirmed lead on an AUTHORIZED target into a "
            "demonstrated exploitation chain. Choose the NEXT single action ONLY from "
            "the allowlist. Respond with compact JSON: {\"capability\": <name>, "
            "\"args\": {...}, \"rationale\": \"...\"} or {\"done\": true, \"reason\": \"...\"} "
            "when the objective is met or no safe progress remains. Never invent a "
            "capability, never output payloads or shell commands.")

    def _allowlist_text(self) -> str:
        lines = []
        for c in self.caps:
            flag = " [STATE-CHANGING: needs approval]" if c.state_changing else ""
            lines.append(f"- {c.name}({', '.join(c.args)}): {c.description}{flag}")
        return "\n".join(lines)

    def _decide(self, world: dict, ran: set) -> dict:
        if self.provider is None or not self.provider.available():
            # deterministic fallback: read-only caps first, each once, then state-changing
            for c in self.caps:
                if c.name in ran:
                    continue
                if c.state_changing and not self.allow_state_changing:
                    continue
                return {"capability": c.name, "args": {}, "rationale": "deterministic order"}
            return {"done": True, "reason": "all capabilities exhausted"}
        user = ("Objective: " + self.objective + "\n\nAllowlist:\n" + self._allowlist_text() +
                "\n\nObservations so far:\n" +
                "\n".join(world.get("_observations", [])[-8:] or ["(none yet)"]))
        return _parse_action(self.provider.complete(self._SYS, user))

    # -- run the loop -------------------------------------------------------
    def run(self, context: Optional[dict] = None) -> AttackChain:
        chain = AttackChain(self.objective, self.vuln_class, self.severity)
        world = {"objective": self.objective, "context": context or {},
                 "latest": {}, "results": [], "_observations": []}
        ran: set = set()
        for i in range(1, self.max_steps + 1):
            ok, reason = self.verify(world)
            if ok:
                chain.proven, chain.reason = True, reason
                break
            action = self._decide(world, ran)
            if action.get("done"):
                chain.reason = action.get("reason", "agent stopped")
                break
            name = action.get("capability", "")
            args = action.get("args", {}) if isinstance(action.get("args"), dict) else {}
            rationale = str(action.get("rationale", ""))[:300]
            cap = self.by_name.get(name)
            if cap is None:
                chain.add(ChainStep(i, name or "?", args, rationale,
                                    observation=f"REJECTED: '{name}' is not on the allowlist",
                                    ok=False, status="rejected"))
                world["_observations"].append(f"rejected off-allowlist action '{name}'")
                continue
            if cap.state_changing and not self.allow_state_changing:
                chain.add(ChainStep(i, name, args, rationale,
                                    observation="BLOCKED: state-changing action but "
                                    "allow_state_changing is off", ok=False,
                                    state_changing=True, status="blocked"))
                world["_observations"].append(f"blocked state-changing '{name}' (opt-in off)")
                continue
            if cap.state_changing and not self.approve(cap, args):
                chain.add(ChainStep(i, name, args, rationale,
                                    observation="DENIED by approval gate (human-in-the-loop)",
                                    ok=False, state_changing=True, status="denied"))
                world["_observations"].append(f"denied '{name}' at approval gate")
                continue
            # execute
            try:
                res: CapabilityResult = cap.run(args)
            except Exception as exc:
                res = CapabilityResult(False, f"error: {type(exc).__name__}: {str(exc)[:120]}")
            ran.add(name)
            step = chain.add(ChainStep(i, name, args, rationale, observation=res.observation,
                                       ok=res.ok, state_changing=cap.state_changing,
                                       status="executed", evidence=res.evidence))
            world["latest"][name] = res.data
            world["results"].append({"capability": name, "data": res.data})
            world["_observations"].append(f"step {i}: {res.observation}")
        # final verification (in case the last action completed the objective)
        if not chain.proven:
            ok, reason = self.verify(world)
            if ok:
                chain.proven, chain.reason = True, reason
        if not chain.reason:
            chain.reason = "objective not demonstrated within budget"
        return chain
