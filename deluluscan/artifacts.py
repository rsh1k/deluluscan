"""deluluscan.artifacts — every object a scan creates must be removed again.

Some checks cannot be performed read-only. Proving that a content-editor can
author an open redirect, that a field regex is compiled without a timeout, or
that a stored template expression is evaluated on render all require CREATING something.

Left behind, those objects are not merely untidy — they are live vulnerabilities
the tool introduced. A vanity URL forwarding to an off-host target is an open
redirect that outlives the scan. Research during this engagement left exactly
three such vanity URLs on the target, discovered only because the agent
mentioned them in passing.

So: nothing is created without being registered here, cleanup runs in reverse
order in a finally block, every deletion is VERIFIED, and anything that could not
be removed is reported loudly with the manual command to finish the job. An
un-cleaned artifact is a finding in its own right.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Artifact:
    """One object created by the scan, and how to remove it."""
    kind: str                      # e.g. "redirect", "content_type", "field"
    identifier: str
    description: str = ""
    delete: Optional[Callable[[], bool]] = None
    verify_gone: Optional[Callable[[], Optional[bool]]] = None
    manual_hint: str = ""
    removed: Optional[bool] = None
    error: str = ""

    def summary(self) -> dict:
        return {"kind": self.kind, "identifier": self.identifier,
                "description": self.description, "removed": self.removed,
                "error": self.error, "manual_hint": self.manual_hint}


class ArtifactRegistry:
    """Track scan-created objects and guarantee an audited cleanup."""

    def __init__(self, progress: Optional[Callable[[str, dict], None]] = None):
        self._items: list[Artifact] = []
        self._progress = progress or (lambda ev, data: None)

    def register(self, artifact: Artifact) -> Artifact:
        self._items.append(artifact)
        self._progress("artifact_created",
                       {"kind": artifact.kind, "identifier": artifact.identifier})
        return artifact

    def track(self, kind: str, identifier: str, *, description: str = "",
              delete: Optional[Callable[[], bool]] = None,
              verify_gone: Optional[Callable[[], Optional[bool]]] = None,
              manual_hint: str = "") -> Artifact:
        return self.register(Artifact(kind=kind, identifier=identifier,
                                      description=description, delete=delete,
                                      verify_gone=verify_gone, manual_hint=manual_hint))

    @property
    def outstanding(self) -> list[Artifact]:
        return [a for a in self._items if a.removed is not True]

    def cleanup(self) -> dict:
        """Remove everything, newest first. Always safe to call more than once."""
        for a in reversed(self._items):
            if a.removed is True:
                continue
            if a.delete is None:
                a.removed = False
                a.error = "no delete callback was supplied"
                continue
            try:
                ok = bool(a.delete())
            except Exception as exc:
                ok = False
                a.error = f"delete raised: {str(exc)[:160]}"
            gone = None
            if a.verify_gone is not None:
                try:
                    gone = a.verify_gone()
                except Exception as exc:
                    a.error = (a.error + f"; verify raised: {str(exc)[:120]}").lstrip("; ")
            # Verification wins over the delete call's own return value: the target
            # has endpoints that answer 200 and change nothing (the user-level
            # layout removal is one), so a successful-looking call proves little.
            if gone is True:
                a.removed = True
            elif gone is False:
                a.removed = False
                if not a.error:
                    a.error = "deletion reported success but the object still exists"
            else:
                a.removed = ok
        return self.report()

    def report(self) -> dict:
        left = self.outstanding
        out = {
            "created": len(self._items),
            "removed": sum(1 for a in self._items if a.removed is True),
            "outstanding": len(left),
            "clean": not left,
            "artifacts": [a.summary() for a in self._items],
        }
        if left:
            out["messages"] = [
                (f"SCAN ARTIFACT NOT REMOVED — {a.kind} '{a.identifier}'"
                 + (f" ({a.description})" if a.description else "")
                 + (f": {a.error}" if a.error else "")
                 + (f" Remove it manually: {a.manual_hint}" if a.manual_hint else "")
                 + " Until removed this object was introduced by the assessment and may "
                   "itself be exploitable.")
                for a in left
            ]
            self._progress("artifact_leak", out)
        return out

    # Context-manager form so cleanup cannot be skipped by an early return or
    # an exception inside a scanner.
    def __enter__(self) -> "ArtifactRegistry":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.cleanup()
        return False        # never swallow the original exception
