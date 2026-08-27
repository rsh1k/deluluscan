"""Tests for the agentic exploitation loop (deluluscan/agentic/, WS-2).

Fully offline: the target is a stateful fake toolbox; the AI is a scripted fake
provider. Locks down the SAFETY properties that matter most — allowlist
enforcement, the state-changing opt-in + human-in-the-loop approval gate, the
step budget, deterministic (not model-asserted) proof, and that an unproven chain
emits no finding. Run: python3 -m tests.test_agentic
"""
import json
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.agentic import (ExploitChainAgent, build_capabilities,  # noqa: E402
                                approve_all, deny_state_changing)
from deluluscan.models import RequestRecord, VulnClass  # noqa: E402

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


# --- fake target -----------------------------------------------------------
class FakeTarget:
    def __init__(self):
        self.escalated = False

    def probe(self, method, path, identity):
        return 200, "ok", RequestRecord(method, path, identity, 200, 1.0)

    def reachability(self, identity):
        base = {"read_own"}
        if identity == "low" and self.escalated:
            return base | {"admin:delete_all", "admin:read_all"}
        if identity == "admin":
            return {"read_own", "admin:delete_all", "admin:read_all"}
        return base

    def read_back(self, key):
        # a stored value that renders in an HTML sink (execution precondition met)
        return True, "html_sink", RequestRecord("GET", f"/render?{key}", "anon", 200, 1.0)

    def escalate(self, identity, action):
        self.escalated = True
        return True, "role added via layout composition", \
            RequestRecord("POST", "/api/escalate", identity, 200, 1.0)


def toolbox_for(t: FakeTarget) -> dict:
    return {"probe": t.probe, "reachability": t.reachability,
            "read_back": t.read_back, "escalate": t.escalate}


class ScriptedProvider:
    """Returns pre-scripted JSON actions in order (duck-typed AIProvider)."""
    name = "scripted"

    def __init__(self, actions):
        self._actions = [json.dumps(a) for a in actions]
        self.i = 0

    def available(self):
        return True

    def complete(self, system, user):
        if self.i < len(self._actions):
            out = self._actions[self.i]; self.i += 1
            return out
        return json.dumps({"done": True, "reason": "script exhausted"})


# --- verifiers (deterministic) ---------------------------------------------
def verify_privesc(world):
    reach = (world["latest"].get("reachability") or {}).get("reachable", [])
    if any(op.startswith("admin:") for op in reach):
        return True, "low-priv identity reached admin operations after escalation"
    return False, ""


def verify_readback(world):
    rb = world["latest"].get("read_back") or {}
    if rb.get("found") and "html" in (rb.get("context") or ""):
        return True, "stored value renders in an HTML execution sink"
    return False, ""


# ---------------------------------------------------------------------------
def test_deterministic_fallback_proves_readonly_chain():
    caps = build_capabilities(toolbox_for(FakeTarget()))
    agent = ExploitChainAgent(provider=None, capabilities=caps,
                              objective="stored value reaches HTML execution sink",
                              verify=verify_readback, vuln_class=VulnClass.XSS, max_steps=6)
    chain = agent.run()
    check("read-only chain is proven by the deterministic fallback", chain.proven, chain.reason)
    f = chain.to_finding()
    check("proven chain -> confirmed/true_positive finding",
          f and f.confidence == "confirmed" and f.verdict == "true_positive", f)


def test_ai_driven_privesc_chain_with_approval():
    t = FakeTarget()
    caps = build_capabilities(toolbox_for(t))
    prov = ScriptedProvider([
        {"capability": "reachability", "args": {"identity": "low"}, "rationale": "baseline"},
        {"capability": "escalate", "args": {"identity": "low", "action": "layout_compose"}, "rationale": "gain"},
        {"capability": "reachability", "args": {"identity": "low"}, "rationale": "measure blast radius"},
    ])
    agent = ExploitChainAgent(prov, caps, objective="horizontal->vertical privilege escalation",
                              verify=verify_privesc, approve=approve_all,
                              allow_state_changing=True, vuln_class=VulnClass.AUTHZ, max_steps=6)
    chain = agent.run()
    check("AI-driven privesc chain is proven", chain.proven, chain.reason)
    check("escalate step actually executed", any(s.capability == "escalate" and s.status == "executed"
                                                 for s in chain.steps))
    check("proven chain carries evidence records", len(chain.evidence_records()) >= 1)


def test_off_allowlist_action_is_rejected():
    caps = build_capabilities(toolbox_for(FakeTarget()))
    prov = ScriptedProvider([{"capability": "run_shell", "args": {"cmd": "id"}, "rationale": "nope"}])
    agent = ExploitChainAgent(prov, caps, objective="x", verify=lambda w: (False, ""),
                              allow_state_changing=True, approve=approve_all, max_steps=3)
    chain = agent.run()
    rej = [s for s in chain.steps if s.status == "rejected"]
    check("off-allowlist action is rejected", len(rej) >= 1 and rej[0].capability == "run_shell")
    check("rejected action is NOT executed", all(s.capability != "run_shell" or s.status == "rejected"
                                                 for s in chain.steps))
    check("chain with only a rejected action is not proven", chain.proven is False)


def test_state_changing_blocked_without_optin():
    t = FakeTarget()
    caps = build_capabilities(toolbox_for(t))
    prov = ScriptedProvider([{"capability": "escalate", "args": {"identity": "low", "action": "x"}}])
    agent = ExploitChainAgent(prov, caps, objective="x", verify=verify_privesc,
                              allow_state_changing=False, approve=approve_all, max_steps=3)
    chain = agent.run()
    blocked = [s for s in chain.steps if s.status == "blocked"]
    check("state-changing action blocked when opt-in is off", len(blocked) >= 1)
    check("target was NOT mutated (no escalation occurred)", t.escalated is False)


def test_approval_gate_denies_state_change():
    t = FakeTarget()
    caps = build_capabilities(toolbox_for(t))
    prov = ScriptedProvider([{"capability": "escalate", "args": {"identity": "low", "action": "x"}}])
    agent = ExploitChainAgent(prov, caps, objective="x", verify=verify_privesc,
                              allow_state_changing=True, approve=deny_state_changing, max_steps=3)
    chain = agent.run()
    denied = [s for s in chain.steps if s.status == "denied"]
    check("approval gate denies the state change", len(denied) >= 1)
    check("target was NOT mutated when approval denied", t.escalated is False)


def test_budget_terminates_loop():
    caps = build_capabilities(toolbox_for(FakeTarget()))
    prov = ScriptedProvider([{"capability": "probe", "args": {"path": "/"}}] * 50)  # never satisfies verify
    agent = ExploitChainAgent(prov, caps, objective="x", verify=lambda w: (False, ""), max_steps=3)
    chain = agent.run()
    check("loop terminates within the step budget", len(chain.steps) <= 3, len(chain.steps))
    check("unmet objective -> not proven", chain.proven is False)


def test_unproven_chain_emits_no_finding():
    caps = build_capabilities(toolbox_for(FakeTarget()))
    agent = ExploitChainAgent(None, caps, objective="x", verify=lambda w: (False, ""), max_steps=2)
    chain = agent.run()
    check("unproven chain yields no finding (report only asserts what was shown)",
          chain.to_finding() is None)


if __name__ == "__main__":
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
