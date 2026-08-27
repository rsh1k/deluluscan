"""Agentic phase engine.

A lightweight autonomous loop that moves the assessment through phases, deciding
what to do next from a CONSTRAINED action space. The design borrows from recent
literature:

  * PentestGPT (USENIX Security 2024) -- an iteration loop that keeps a running
    context/state file and resumes from it.
  * VulnBot (2025) -- a penetration-testing *task graph* as the agent's memory.
  * ReAct / Self-Refine -- reason about state, act, observe, then validate.
  * AutoPentest (2025) -- emphasis on a validation pass to cut false positives.

Crucial safety property: the action space is an allowlist of ASSESSMENT actions
(recon, discover, prioritize, run a named detector, run an opt-in confirmation
integration, validate, report). There is deliberately NO "exploit", "deploy",
or "run shell" action. The LLM (any provider, including the local Claude Code
CLI) only chooses an *ordering* over these safe actions and writes triage notes;
when AI is disabled the engine falls back to a fixed, sensible plan. The agent
cannot invent new capabilities -- it can only schedule the ones below.
"""
from __future__ import annotations

import enum
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

from .ai.analyst import AIAnalyst
from .auth import AuthManager
from .config import Config
from .discovery import discover
from .http_client import HttpClient
from .integrations import InteractshClient, NucleiRunner, SqlmapRunner
from .models import Endpoint, Finding, IdentityRole, VulnClass
from .scanners import SCANNER_REGISTRY
from .scanners.ssrf import SsrfScanner

ProgressFn = Callable[[str, dict], None]


class Phase(str, enum.Enum):
    RECON = "recon"               # identity verification + version fingerprint
    DISCOVER = "discover"         # enumerate endpoints (openapi/seed)
    PRIORITIZE = "prioritize"     # order the surface (AI or heuristic)
    SCAN = "scan"                 # run detection scanners
    CONFIRM = "confirm"           # opt-in integrations (sqlmap/nuclei)
    VALIDATE = "validate"         # re-test findings to reduce false positives
    REPORT = "report"             # finalize


# The only phases the planner is allowed to schedule.
ALLOWED_ACTIONS = [p.value for p in Phase]

_PLAN_SYS = (
    "You are the planner for an AUTHORIZED, detection-only API security "
    "assessment of a target instance the operator controls. Given the current "
    "state, choose the next action ONLY from this allowlist: "
    + ", ".join(ALLOWED_ACTIONS) + ". Respond with a JSON object: "
    "{\"next\": \"<action>\", \"reason\": \"...\"}. You may not invent actions, "
    "request exploitation, or output payloads. If unsure, prefer the standard "
    "order recon -> discover -> prioritize -> scan -> confirm -> validate -> report."
)


@dataclass
class TaskNode:
    """A node in the agent's task graph (its memory of what it has done)."""
    phase: str
    status: str = "pending"        # pending | running | done | skipped | error
    note: str = ""
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    produced: dict = field(default_factory=dict)


@dataclass
class AgentState:
    target: str
    graph: list[TaskNode] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)   # serialized Endpoints
    findings: list[dict] = field(default_factory=list)
    version: str = "unknown"
    coverage: dict = field(default_factory=dict)          # endpoint -> scanners run
    cursor: int = 0
    done: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)


class Agent:
    """Autonomous assessment agent over a constrained action space."""

    def __init__(self, cfg: Config, progress: Optional[ProgressFn] = None,
                 session_path: Optional[str] = None):
        self.cfg = cfg
        self.progress = progress or (lambda ev, data: None)
        self.session_path = session_path or os.path.join(cfg.output_dir, "session.json")
        self.client = HttpClient(
            cfg.base_url, rate_limit_rps=cfg.scan.rate_limit_rps,
            timeout_s=cfg.scan.timeout_s, verify_tls=cfg.verify_tls)
        self.auth = AuthManager(self.client)
        self.ai = AIAnalyst(cfg.ai)
        self.state = AgentState(target=cfg.base_url)
        self._endpoint_objs: list[Endpoint] = []
        self._finding_objs: list[Finding] = []
        self._oob: Optional[InteractshClient] = None

    # ---- session persistence (resume across runs) -------------------------
    def save(self) -> None:
        os.makedirs(os.path.dirname(self.session_path) or ".", exist_ok=True)
        with open(self.session_path, "w") as fh:
            fh.write(self.state.to_json())

    def resume(self) -> bool:
        if not os.path.exists(self.session_path):
            return False
        with open(self.session_path) as fh:
            raw = json.load(fh)
        self.state = AgentState(**{**raw, "graph": [TaskNode(**n) for n in raw.get("graph", [])]})
        return True

    # ---- main loop --------------------------------------------------------
    def run(self, max_steps: int = 20) -> dict:
        self.cfg.assert_target_allowed()
        self.progress("agent_start", {"target": self.cfg.base_url,
                                      "ai": self.cfg.ai.provider})
        steps = 0
        completed: set[str] = {n.phase for n in self.state.graph if n.status == "done"}

        while not self.state.done and steps < max_steps:
            steps += 1
            nxt = self._decide_next(completed)
            self.progress("plan", {"step": steps, "next": nxt})
            node = TaskNode(phase=nxt, status="running", started_at=time.time())
            self.state.graph.append(node)
            try:
                self._execute(nxt, node)
                node.status = "done"
                completed.add(nxt)
            except Exception as exc:
                node.status = "error"
                node.note = str(exc)
                # Treat an errored phase as attempted so the planner advances
                # instead of retrying the same failing phase forever.
                completed.add(nxt)
                self.progress("agent_error", {"phase": nxt, "error": str(exc)})
            node.ended_at = time.time()
            self.save()
            if nxt == Phase.REPORT.value:
                self.state.done = True

        if self._oob:
            self._oob.stop()
        return {"state": json.loads(self.state.to_json()),
                "findings": self.state.findings}

    # ---- planner (AI with deterministic fallback) -------------------------
    def _decide_next(self, completed: set[str]) -> str:
        default_order = [Phase.RECON, Phase.DISCOVER, Phase.PRIORITIZE,
                         Phase.SCAN, Phase.CONFIRM, Phase.VALIDATE, Phase.REPORT]
        deterministic = next((p.value for p in default_order
                              if p.value not in completed), Phase.REPORT.value)
        if not self.ai.enabled:
            return deterministic
        state_summary = {
            "completed": sorted(completed),
            "endpoints_known": len(self.state.endpoints),
            "findings_so_far": len(self.state.findings),
            "version": self.state.version,
            "confirm_enabled": (self.cfg.integrations.enable_sqlmap or
                                self.cfg.integrations.enable_nuclei),
        }
        out = self.ai._complete(_PLAN_SYS, json.dumps(state_summary))
        choice = self.ai._parse_json(out) or {}
        nxt = choice.get("next")
        # Hard guardrail: only allow allowlisted, not-yet-done actions; else the
        # deterministic plan wins. The LLM can reorder but cannot escape the set.
        if nxt in ALLOWED_ACTIONS and (nxt not in completed or nxt == Phase.REPORT.value):
            self.progress("plan_reason", {"reason": choice.get("reason", "")[:200]})
            return nxt
        return deterministic

    # ---- phase implementations -------------------------------------------
    def _execute(self, phase: str, node: TaskNode) -> None:
        getattr(self, f"_phase_{phase}")(node)

    def _phase_recon(self, node: TaskNode) -> None:
        for role in (IdentityRole.ADMIN, IdentityRole.BACKEND, IdentityRole.ANON):
            ident = self.cfg.identities.get(role.value)
            if ident:
                ok, msg = self.auth.verify(ident)
                self.progress("identity", {"role": role.value, "ok": ok, "msg": msg})
        self.state.version = None
        node.produced = {"version": None}

    def _phase_discover(self, node: TaskNode) -> None:
        auth_attempts = []
        for role in (IdentityRole.ADMIN, IdentityRole.BACKEND):
            ident = self.cfg.identities.get(role.value)
            if ident and (ident.username or ident.bearer_token):
                auth_attempts.append({"label": role.value,
                                      "headers": self.auth.headers_for(ident)})
        eps, source = discover(self.client, self.cfg.openapi_path,
                               self.cfg.scan.methods, auth_attempts,
                               local_file=self.cfg.openapi_file)
        self._endpoint_objs = eps
        self.state.endpoints = [asdict(e) for e in eps]
        node.produced = {"count": len(eps), "source": source}
        self.progress("discovery", {"count": len(eps), "source": source})

    def _phase_prioritize(self, node: TaskNode) -> None:
        if not self._endpoint_objs:
            return
        ordered = self.ai.prioritize(self._endpoint_objs)
        self._endpoint_objs = ordered
        if self.cfg.scan.max_endpoints:
            self._endpoint_objs = ordered[: self.cfg.scan.max_endpoints]
        self.state.endpoints = [asdict(e) for e in self._endpoint_objs]
        node.produced = {"ordered": len(self._endpoint_objs)}

    def _phase_scan(self, node: TaskNode) -> None:
        if self.cfg.integrations.enable_interactsh and not self._oob:
            oob = InteractshClient(self.cfg)
            self._oob = oob if oob.start() else None
        oob_aware = (SsrfScanner,)
        scanners = []
        names = list(dict.fromkeys(self.cfg.scan.scanners + ["owasp"]))
        for name in names:
            cls = SCANNER_REGISTRY.get(name)
            if not cls:
                continue
            if cls in oob_aware:
                scanners.append(cls(self.client, self.auth, self.cfg,
                                    self.cfg.identities, oob=self._oob))
            else:
                scanners.append(cls(self.client, self.auth, self.cfg, self.cfg.identities))
        from .reporting.coverage import CoverageTracker
        if not hasattr(self, "cov_tracker"):
            self.cov_tracker = CoverageTracker()
        for ep in self._endpoint_objs:
            cov = self.state.coverage.setdefault(ep.key, [])
            for sc in scanners:
                if not sc.applies_to(ep):
                    self.cov_tracker.record(ep.key, sc.name, False, "not applicable")
                    continue
                cov.append(sc.name)
                self.cov_tracker.record(ep.key, sc.name, True)
                try:
                    for f in sc.run(ep):
                        self._finding_objs.append(f)
                        self.state.findings.append(f.to_dict())
                        self.progress("finding", {"title": f.title,
                                                  "severity": f.severity.value,
                                                  "class": f.vuln_class.value})
                except Exception as exc:
                    self.cov_tracker.record(ep.key, sc.name, False, f"error: {exc}")
                    self.progress("agent_error", {"phase": "scan",
                                                  "error": f"{sc.name}/{ep.key}: {exc}"})
        node.produced = {"findings": len(self._finding_objs)}

    def _phase_confirm(self, node: TaskNode) -> None:
        produced = {}
        if self.cfg.integrations.enable_nuclei:
            nf = NucleiRunner(self.cfg).run()
            self._finding_objs.extend(nf)
            self.state.findings.extend(f.to_dict() for f in nf)
            produced["nuclei"] = len(nf)
        if self.cfg.integrations.enable_sqlmap:
            runner = SqlmapRunner(self.cfg)
            confirmed = 0
            for f in [x for x in self._finding_objs if x.vuln_class is VulnClass.SQLI]:
                res = runner.confirm(f)
                f.detail["sqlmap"] = res
                if res.get("confirmed"):
                    f.confidence = "confirmed"
                    confirmed += 1
            produced["sqlmap_confirmed"] = confirmed
            # refresh serialized findings
            self.state.findings = [f.to_dict() for f in self._finding_objs]
        node.produced = produced

    def _phase_validate(self, node: TaskNode) -> None:
        """FP-reduction / exploitability pass. Uses the verification layer to
        corroborate each finding with benign control probes, detect compensating
        controls, rate exploitability, and downgrade false positives — then
        optional AI triage for a plain-language read. Detection-only."""
        verified = tp = fp = 0
        if getattr(self.cfg.scan, "verify", True) and self._finding_objs:
            from .verify import Verifier
            Verifier(self.client, self.auth, self.cfg.identities,
                     self.cfg).verify_all(self._finding_objs)
            verified = len(self._finding_objs)
            tp = sum(1 for f in self._finding_objs
                     if f.verdict in ("true_positive", "likely_true_positive"))
            fp = sum(1 for f in self._finding_objs
                     if f.verdict in ("false_positive", "likely_false_positive"))
        if self.ai.enabled:
            for f in self._finding_objs:
                f.ai_notes = self.ai.triage(f)
        self.state.findings = [f.to_dict() for f in self._finding_objs]
        node.produced = {"verified": verified, "true_positive": tp,
                         "false_positive": fp}

    def _phase_report(self, node: TaskNode) -> None:
        from .reporting import write_html, write_json
        from .reporting.sarif import write_sarif
        from .reporting.coverage import write_coverage
        result = {
            "meta": {
                "target": self.cfg.base_url, "version": self.state.version,
                "ai_provider": self.cfg.ai.provider, "mode": "agentic",
                "endpoints_scanned": len(self.state.endpoints),
                "phases": [n.phase for n in self.state.graph if n.status == "done"],
            },
            "findings": self.state.findings,
        }
        jp = write_json(result, self.cfg.output_dir)
        hp = write_html(result, self.cfg.output_dir)
        sp = write_sarif(result, self.cfg.output_dir)
        node.produced = {"json": jp, "html": hp, "sarif": sp}
        if hasattr(self, "cov_tracker"):
            cj, ch, summary = write_coverage(self.cov_tracker.as_dict(), self.cfg.output_dir)
            node.produced["coverage_json"] = cj
            node.produced["coverage_html"] = ch
            self.progress("coverage", summary)
        self.progress("report", node.produced)
