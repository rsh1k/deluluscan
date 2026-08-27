"""Deluluscan agentic exploitation (WS-2): a bounded, allowlist-only loop that
deepens a lead into a demonstrated exploit chain.

    from deluluscan.agentic import ExploitChainAgent, build_capabilities, approve_all
    caps = build_capabilities(toolbox)   # wrap safe primitives
    agent = ExploitChainAgent(provider, caps, objective="…", verify=my_verifier,
                              allow_state_changing=True, approve=approve_all)
    chain = agent.run(context)
    finding = chain.to_finding()         # only if proven

The AI proposes; capabilities execute; a deterministic verifier decides truth.
No shell, no arbitrary payloads, human-in-the-loop for state changes.
"""
from .agent import ExploitChainAgent, approve_all, deny_state_changing
from .capabilities import Capability, CapabilityResult, build_capabilities
from .chain import AttackChain, ChainStep

__all__ = ["ExploitChainAgent", "approve_all", "deny_state_changing",
           "Capability", "CapabilityResult", "build_capabilities",
           "AttackChain", "ChainStep"]
