"""Grey-box observability plane.

Deluluscan's black-box scanners see only what the API returns. This package adds a
second channel: the target's OWN telemetry (logs, memory/CPU) observed live
during the sweep and correlated with the exact request that caused each event —
turning suggestive HTTP responses into server-confirmed findings and surfacing
classes a black-box view is blind to (unlogged operations, secrets in logs,
memory exhaustion).

Opt-in (`--observe`), fail-soft (no Docker -> the scan runs black-box unchanged),
and local-only (the same authorization boundary as every HTTP probe). See
CLAUDE.md and deluluscan/telemetry/signatures.py for the discipline.
"""
from __future__ import annotations

from .recorder import Recorder, TelemetryEvent
from .correlator import Correlator, ProbeWindow, probe_windows_from
from .sources import (TelemetrySource, DockerLogSource, DockerStatsSource,
                      build_sources)
from . import signatures

__all__ = [
    "Recorder", "TelemetryEvent", "Correlator", "ProbeWindow",
    "probe_windows_from", "TelemetrySource", "DockerLogSource",
    "DockerStatsSource", "build_sources", "signatures",
]
