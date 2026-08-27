"""Capability allowlist for the exploitation agent.

The agent's entire action space is these capabilities — there is deliberately NO
"run shell", "exploit", "exfiltrate", or "persist" action. Each capability wraps
an existing SAFE, confirm-to-proof primitive (identity re-probe, reachability
measurement, read-back, OOB follow). The AI may only *select and order* these and
supply constrained args; it cannot invent actions or emit executed payloads.

Capabilities are constructed from an injected ``toolbox`` (plain callables), so
the loop is fully testable offline and the real wiring (HttpClient, Pivoter,
readback, identity matrix) is swapped in without touching agent logic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..models import RequestRecord


@dataclass
class CapabilityResult:
    ok: bool
    observation: str                       # short text the AI reads next turn
    data: dict = field(default_factory=dict)
    evidence: Optional[RequestRecord] = None


@dataclass
class Capability:
    name: str
    description: str
    state_changing: bool
    run: Callable[[dict], CapabilityResult]
    args: list = field(default_factory=list)   # allowed arg names (for the prompt)


def build_capabilities(toolbox: dict) -> list:
    """Wrap injected primitives as the agent's allowlisted capabilities.

    Expected (all optional) toolbox callables:
      probe(method, path, identity)         -> (status:int, body:str, record:RequestRecord)
      reachability(identity)                -> set[str]  (reachable operation labels)
      read_back(key)                        -> (found:bool, context:str, record)
      escalate(identity, action)            -> (ok:bool, detail:str, record)   [STATE-CHANGING]
      follow_oob(token)                     -> (hit:bool, detail:str)
    """
    caps: list[Capability] = []

    if "probe" in toolbox:
        def _probe(args):
            status, body, rec = toolbox["probe"](args.get("method", "GET"),
                                                 args.get("path", "/"),
                                                 args.get("identity", "anon"))
            return CapabilityResult(ok=(status < 500),
                                    observation=f"{args.get('method','GET')} {args.get('path')} as "
                                                f"{args.get('identity')} -> HTTP {status}, {len(body or '')}b",
                                    data={"status": status, "len": len(body or "")}, evidence=rec)
        caps.append(Capability("probe", "Send one request to a path as an identity (read-only).",
                               False, _probe, ["method", "path", "identity"]))

    if "reachability" in toolbox:
        def _reach(args):
            ops = sorted(toolbox["reachability"](args.get("identity", "anon")))
            return CapabilityResult(True, f"{args.get('identity')} can reach {len(ops)} sensitive "
                                          f"operations: {ops}", {"reachable": ops})
        caps.append(Capability("reachability", "Measure which sensitive operations an identity can "
                               "reach (read-only baseline for a privilege diff).", False, _reach,
                               ["identity"]))

    if "read_back" in toolbox:
        def _rb(args):
            found, ctx, rec = toolbox["read_back"](args.get("key", ""))
            return CapabilityResult(found, f"read-back {args.get('key')!r}: "
                                    f"{'FOUND in '+ctx if found else 'not found'}",
                                    {"found": found, "context": ctx}, rec)
        caps.append(Capability("read_back", "Read a previously stored value back across sinks to "
                               "classify render context (precondition vs execution).", False, _rb,
                               ["key"]))

    if "follow_oob" in toolbox:
        def _oob(args):
            hit, detail = toolbox["follow_oob"](args.get("token", ""))
            return CapabilityResult(hit, f"OOB {args.get('token')}: {'callback received' if hit else 'no callback'}",
                                    {"hit": hit})
        caps.append(Capability("follow_oob", "Check for an out-of-band callback (blind SSRF/RCE proof).",
                               False, _oob, ["token"]))

    if "escalate" in toolbox:
        def _esc(args):
            ok, detail, rec = toolbox["escalate"](args.get("identity", ""), args.get("action", ""))
            return CapabilityResult(ok, f"escalation {args.get('action')} as {args.get('identity')}: {detail}",
                                    {"ok": ok, "detail": detail}, rec)
        caps.append(Capability("escalate", "Perform a confirmed privilege gain, then a reachability "
                               "diff shows its blast radius. STATE-CHANGING — requires approval.",
                               True, _esc, ["identity", "action"]))

    return caps
