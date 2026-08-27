"""Telemetry sources: subscribe to the target's own runtime, no agent inside it.

Because the target runs in Docker on the same owned host, Deluluscan can tap the target's
logs and resource usage through the container runtime alone — the same
loopback/RFC1918 authorization boundary as every HTTP probe. Nothing is installed
in the target.

Every source is fail-soft: if `docker` is missing, the container is not found, or
the stream dies, `start()` returns False and the scan proceeds exactly as a
black-box run would. Observation is strictly additive.
"""
from __future__ import annotations

import shutil
import subprocess
import threading
import time
from typing import Optional

from .recorder import Recorder


class TelemetrySource:
    name = "base"

    def start(self, recorder: Recorder) -> bool:      # pragma: no cover - interface
        raise NotImplementedError

    def stop(self) -> None:                            # pragma: no cover - interface
        raise NotImplementedError


def _docker_ok(docker: str) -> bool:
    return shutil.which(docker) is not None


def _container_exists(docker: str, container: str) -> bool:
    try:
        p = subprocess.run([docker, "inspect", "-f", "{{.State.Running}}", container],
                           capture_output=True, text=True, timeout=10)
        return p.returncode == 0 and "true" in (p.stdout or "").lower()
    except Exception:
        return False


def _parse_docker_ts(line: str) -> tuple[Optional[float], str]:
    """`docker logs --timestamps` prefixes each line with an RFC3339Nano stamp.
    Return (epoch_or_None, remainder). The container shares the host clock, so
    this stamp is directly comparable to a probe's wall-clock window."""
    if not line:
        return None, line
    head, _, rest = line.partition(" ")
    if "T" in head and (head.endswith("Z") or "+" in head or head.count(":") >= 2):
        try:
            import datetime as _dt
            s = head.rstrip("Z")
            if "." in s:                       # trim nanoseconds to microseconds
                base, frac = s.split(".", 1)
                s = base + "." + (frac[:6])
            dt = _dt.datetime.fromisoformat(s).replace(tzinfo=_dt.timezone.utc)
            return dt.timestamp(), rest
        except Exception:
            return None, line
    return None, line


class DockerLogSource(TelemetrySource):
    """`docker logs -f --timestamps <container>` streamed into the Recorder.

    `--tail 0` means we capture only lines emitted from scan start onward — the
    correlator's baseline window handles pre-sweep noise, and we avoid replaying
    the whole historical log."""

    def __init__(self, container: str, *, docker: str = "docker", source: str = "log"):
        self.container = container
        self.docker = docker
        self.source = source
        self.name = f"docker-log:{container}"
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self, recorder: Recorder) -> bool:
        if not _docker_ok(self.docker) or not _container_exists(self.docker, self.container):
            return False
        try:
            self._proc = subprocess.Popen(
                [self.docker, "logs", "-f", "--since", "0s", "--timestamps",
                 "--tail", "0", self.container],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except Exception:
            return False
        self._thread = threading.Thread(target=self._pump, args=(recorder,), daemon=True)
        self._thread.start()
        return True

    def _pump(self, recorder: Recorder) -> None:
        assert self._proc and self._proc.stdout
        for line in self._proc.stdout:
            if self._stop.is_set():
                break
            wall, rest = _parse_docker_ts(line.rstrip("\n"))
            recorder.add_log(rest, source=self.source, wall=wall)

    def stop(self) -> None:
        self._stop.set()
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass


def _parse_mem(s: str) -> Optional[float]:
    """'1.23GiB / 4GiB' -> bytes for the used side."""
    if not s:
        return None
    used = s.split("/")[0].strip()
    units = {"B": 1, "KIB": 1024, "MIB": 1024**2, "GIB": 1024**3, "TIB": 1024**4,
             "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4}
    import re as _re
    m = _re.match(r"([0-9.]+)\s*([A-Za-z]+)", used)
    if not m:
        return None
    try:
        return float(m.group(1)) * units.get(m.group(2).upper(), 1)
    except ValueError:
        return None


def _parse_pct(s: str) -> Optional[float]:
    try:
        return float((s or "").strip().rstrip("%"))
    except ValueError:
        return None


class DockerStatsSource(TelemetrySource):
    """Poll `docker stats --no-stream` on an interval -> mem/CPU/PID samples.

    One-shot `--no-stream` per tick is far more robust to parse than the streaming
    table, and an interval of a couple of seconds is plenty to catch a heap step
    or CPU pin driven by a probe."""

    def __init__(self, container: str, *, docker: str = "docker", interval_s: float = 2.0):
        self.container = container
        self.docker = docker
        self.interval = max(interval_s, 0.5)
        self.name = f"docker-stats:{container}"
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self, recorder: Recorder) -> bool:
        if not _docker_ok(self.docker) or not _container_exists(self.docker, self.container):
            return False
        self._thread = threading.Thread(target=self._poll, args=(recorder,), daemon=True)
        self._thread.start()
        return True

    def _poll(self, recorder: Recorder) -> None:
        import json as _json
        while not self._stop.is_set():
            try:
                p = subprocess.run(
                    [self.docker, "stats", "--no-stream", "--format", "{{json .}}",
                     self.container], capture_output=True, text=True, timeout=10)
                if p.returncode == 0 and p.stdout.strip():
                    row = _json.loads(p.stdout.strip().splitlines()[0])
                    recorder.add_stats({
                        "mem_bytes": _parse_mem(row.get("MemUsage", "")),
                        "cpu_pct": _parse_pct(row.get("CPUPerc", "")),
                        "pids": int(row.get("PIDs", 0) or 0),
                    })
            except Exception:
                pass
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()


def build_sources(observe_cfg) -> list[TelemetrySource]:
    """Construct the sources implied by an ObserveConfig (not yet started)."""
    docker = getattr(observe_cfg, "docker_path", "docker")
    container = getattr(observe_cfg, "container", "")
    interval = getattr(observe_cfg, "stats_interval_s", 2.0)
    db = getattr(observe_cfg, "db_container", "")
    sources: list[TelemetrySource] = []
    if container:
        sources.append(DockerLogSource(container, docker=docker))
        sources.append(DockerStatsSource(container, docker=docker, interval_s=interval))
    if db:
        sources.append(DockerLogSource(db, docker=docker, source="pg"))
    return sources
