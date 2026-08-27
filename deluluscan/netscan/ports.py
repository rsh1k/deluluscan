"""Light port/service discovery + banner grab (nmap -sV--lite).

A bounded TCP-connect scan over a curated common-port set, with a short banner
read and service fingerprinting from (port, banner). This opens real sockets to
the target, so the CLI gates it to loopback/RFC1918 exactly like every other
active pass. The probe function is injectable (`connect`) so tests run fully
offline with a synthetic responder.

Not a replacement for nmap — it is a fast, in-scope situational-awareness pass so
the rest of the engagement knows which services are exposed and which of those
are dangerous (Docker API, Redis, Elasticsearch, DB ports, k8s API).
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Callable, Optional

from .signatures import SERVICE_HINTS, DANGEROUS_OPEN_PORTS

COMMON_PORTS = tuple(sorted(SERVICE_HINTS.keys()))


@dataclass
class PortResult:
    port: int
    open: bool
    service: str = ""
    banner: str = ""
    dangerous: str = ""              # note if this port is high-risk to expose


def _default_connect(host: str, port: int, timeout: float = 1.5):
    """Return banner string if the TCP port is open, else None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # nudge chatty services that wait for a line (HTTP especially)
            try:
                if port in (80, 8080, 8000, 3000, 5601, 9200, 5984, 8500, 15672):
                    s.sendall(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
            except OSError:
                pass
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            return data.decode("latin-1", "replace")
    except Exception:
        return None


def _fingerprint(port: int, banner: str) -> str:
    name, banner_re = SERVICE_HINTS.get(port, ("unknown", ""))
    if banner and banner_re and re.search(banner_re, banner):
        return name                  # banner confirms the port-implied service
    return name


class PortScan:
    def __init__(self, connect: Optional[Callable] = None, timeout: float = 1.5):
        self.connect = connect or _default_connect
        self.timeout = timeout

    def scan(self, host: str, ports=COMMON_PORTS) -> list:
        results: list = []
        for port in ports:
            banner = self.connect(host, port, self.timeout)
            if banner is None:
                continue             # closed/filtered -> omit (keep output signal-dense)
            svc = _fingerprint(port, banner)
            results.append(PortResult(
                port=port, open=True, service=svc,
                banner=(banner or "").strip()[:120],
                dangerous=DANGEROUS_OPEN_PORTS.get(port, "")))
        return results
