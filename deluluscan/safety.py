"""Destructive-operation policy — test everything, but don't lose the scan.

Some privileged surfaces are *destructive*: they shut the server down, wipe
data, terminate sessions, trigger a reindex, or dump the database. Their
authorization is exactly as much in scope as anything else — a DAST run against
a disposable local instance should absolutely find out who can call
`DELETE /admin/maintenance/_shutdown`.

The problem was never that we probed them. It was *when*. This bit us for real:
a bounded conformance scan run with `--allow-state-changing` sent
`DELETE /admin/maintenance/_shutdown` as the admin baseline. The request
succeeded — exactly as designed — and the target shut itself down cleanly (exit
code 0) mid-scan, taking the remaining endpoints with it.

So the rule here is about ORDERING, not exclusion:

  * Destructive operations are classified, not banned (`is_destructive`).
  * During the main sweep they are DEFERRED — refused at the HTTP layer so no
    scanner can end the run early, no matter which scanner grew a new code path.
  * Afterwards, the orchestrator re-runs them in a dedicated destructive pass
    (`DestructivePolicy.begin_destructive_phase`), restarting the target between
    probes when it stops answering. You get the shutdown endpoint's
    authorization verdict AND the other 739 endpoints.

Enforcement lives in `deluluscan.http_client`, the one choke point every scanner
already goes through, so the guarantee holds for scanners that don't know this
module exists.
"""
from __future__ import annotations

import re
from typing import Iterable, TypeVar

# Operations whose reachability we only want to test once the rest of the sweep
# is done. Matched against the path; a few are only destructive for mutating
# verbs, which _DESTRUCTIVE_BY_METHOD handles.
_DESTRUCTIVE = [
    r"_shutdown\b", r"\bshutdown\b", r"_restart\b", r"/_stop\b", r"/reboot\b",
    r"_undeploy\b", r"/_uninstall\b",
    r"/_delete\b", r"_deleteAll\b", r"/_purge\b", r"/_truncate\b",
    r"/_wipe\b", r"/_drop\b", r"/_clear\b", r"/_flush\b",
    r"/_reindex\b", r"/reindex\b",
    r"_dump\b", r"/dump\b", r"_backup\b", r"_pgDump\b",
]

# Destructive only when the verb mutates (the GET form may be a safe read).
_DESTRUCTIVE_BY_METHOD: list[tuple[set[str], str]] = [
    ({"DELETE"}, r"/(maintenance|admin|system)(/|$)"),
    ({"POST", "PUT", "DELETE"}, r"/(upgrade|migration)task"),
]

_COMPILED = [re.compile(p, re.I) for p in _DESTRUCTIVE]


def is_destructive(method: str, path: str) -> bool:
    """True if (method, path) can break the target or end the scan.

    This is a CLASSIFIER, not a verdict on whether to send. Ask a
    DestructivePolicy (or the HttpClient enforcing one) for that.
    """
    method = (method or "GET").upper()
    path = path or ""
    if any(rx.search(path) for rx in _COMPILED):
        return True
    for verbs, pat in _DESTRUCTIVE_BY_METHOD:
        if method in verbs and re.search(pat, path, re.I):
            return True
    return False


# Lifecycle operations shut the process down or bounce it. They matter separately
# from the rest of the destructive set because their death is DELAYED: a graceful
# shutdown keeps answering for many seconds after it has decided to exit, so a
# short liveness check after the probe still sees a healthy server and the outage
# gets blamed on whatever endpoint happened to be probed next.
_LIFECYCLE = [
    r"_shutdown\b", r"\bshutdown\b", r"_restart\b", r"/_stop\b", r"/reboot\b",
    r"_undeploy\b",
]
_LIFECYCLE_COMPILED = [re.compile(p, re.I) for p in _LIFECYCLE]


def is_lifecycle(method: str, path: str) -> bool:
    """True for destructive ops whose effect is a delayed process death, so the
    caller knows to wait longer before deciding the target survived."""
    return any(rx.search(path or "") for rx in _LIFECYCLE_COMPILED)


def destructive_reason(method: str, path: str) -> str:
    """Human-readable classification, for coverage records and the report."""
    if not is_destructive(method, path):
        return ""
    return ("destructive operation (service lifecycle, bulk deletion, session "
            "termination, reindex, or full data dump) — deferred out of the main "
            "sweep to protect availability of the run itself, then probed in a "
            "dedicated destructive pass that can restart the target")


_T = TypeVar("_T")


def split_destructive(endpoints: Iterable[_T]) -> tuple[list[_T], list[_T]]:
    """Partition endpoint-like objects (anything with .method/.path) into
    (normal, destructive), preserving order within each group."""
    normal: list[_T] = []
    destructive: list[_T] = []
    for ep in endpoints:
        target = destructive if is_destructive(
            getattr(ep, "method", "GET"), getattr(ep, "path", "")) else normal
        target.append(ep)
    return normal, destructive


class DestructivePolicy:
    """Decides whether a destructive request may be sent *right now*.

    Two axes:
      enabled — is destructive probing in scope for this run at all?
      phase   — "main" (defer them) or "destructive" (send them).

    A single instance is shared by the HttpClient and the orchestrator, so
    flipping the phase opens the gate everywhere at once.
    """

    MAIN = "main"
    DESTRUCTIVE = "destructive"

    def __init__(self, enabled: bool = False):
        self.enabled = bool(enabled)
        self.phase = self.MAIN
        # Every destructive request refused during the main sweep, so the report
        # can show what was deferred rather than silently under-reporting.
        self.deferred: list[str] = []

    def begin_destructive_phase(self) -> None:
        self.phase = self.DESTRUCTIVE

    def end_destructive_phase(self) -> None:
        self.phase = self.MAIN

    @property
    def in_destructive_phase(self) -> bool:
        return self.phase == self.DESTRUCTIVE

    def allows(self, method: str, path: str) -> tuple[bool, str]:
        """(may_send, reason_if_not). Non-destructive requests always pass."""
        if not is_destructive(method, path):
            return True, ""
        if not self.enabled:
            return False, ("destructive probing is not enabled for this run "
                           "(set scan.destructive.enabled / use --allow-destructive)")
        if not self.in_destructive_phase:
            return False, ("deferred to the dedicated destructive pass so it cannot "
                           "end the main sweep early")
        return True, ""

    def note_deferral(self, method: str, path: str) -> None:
        key = f"{(method or 'GET').upper()} {path or ''}"
        if key not in self.deferred:
            self.deferred.append(key)

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "phase": self.phase,
                "deferred_during_main_sweep": list(self.deferred)}


# A permissive policy for callers that construct an HttpClient directly (tests,
# ad-hoc tooling) and have no orchestrator to hand them one. It defers nothing
# because it classifies nothing as blocked — the *orchestrator* is what installs
# the real two-phase policy.
class UnrestrictedPolicy(DestructivePolicy):
    def __init__(self):
        super().__init__(enabled=True)
        self.phase = self.DESTRUCTIVE

    def allows(self, method: str, path: str) -> tuple[bool, str]:
        return True, ""
