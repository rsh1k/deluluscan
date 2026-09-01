"""HTTP request-smuggling / desync detection — timing-only, non-destructive.

Front-end and back-end disagreeing on where a request ends (CL.TE / TE.CL) is
request smuggling (CWE-444). The SAFE way to detect it — the industry-standard
approach — is a **differential timing** probe: craft a request whose ambiguity,
IF the two ends disagree, leaves one of them waiting for bytes that never come,
so the response hangs. We measure that hang against a baseline. We deliberately do
NOT send a smuggled *prefix* that would attach to another visitor's request —
that is the exploitation/poisoning step, and this tool does detection only.

Because timing is noisy, findings are graded TENTATIVE and require manual
confirmation; a single slow response is re-probed before it's reported.

The raw sender is injected (`send`), so the whole detector is offline-testable;
the default opens a socket (optionally TLS) and writes the raw bytes itself,
because normal HTTP libraries normalise the very headers this test depends on.
"""
from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass

# PortSwigger-style timing payloads. Both are self-contained: they can only stall
# THIS connection's parser, not smuggle a prefix onto a subsequent request.
def _clte_payload(host: str, path: str) -> bytes:
    # If the back-end honours Transfer-Encoding (CL.TE), it reads chunk "1\r\nA",
    # then waits for the next chunk header that the CL-bounded front-end never
    # forwards -> hang.
    body = "1\r\nA\r\nX"
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n"
            f"Connection: close\r\n\r\n{body}").encode()


def _tecl_payload(host: str, path: str) -> bytes:
    # If the back-end honours Content-Length (TE.CL), the TE front-end forwards a
    # complete "0\r\n\r\n" while the back-end still waits for CL bytes -> hang.
    body = "0\r\n\r\nX"
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Transfer-Encoding: chunked\r\nContent-Length: 6\r\n"
            f"Connection: close\r\n\r\n{body}").encode()


def _baseline_payload(host: str, path: str) -> bytes:
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Length: 0\r\nConnection: close\r\n\r\n").encode()


@dataclass
class DesyncResult:
    variant: str                 # CL.TE | TE.CL
    baseline_s: float
    probe_s: float
    suspected: bool
    note: str = ""


def _default_send(host: str, port: int, use_tls: bool, raw: bytes,
                  timeout: float) -> float:
    """Send raw bytes, read until close/timeout, return elapsed seconds (== timeout
    if it hung). Raises on connection failure."""
    start = time.monotonic()
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(raw)
        try:
            while True:
                if not sock.recv(2048):
                    break
        except socket.timeout:
            return timeout          # hung waiting for more of the response
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return time.monotonic() - start


class SmugglingProbe:
    def __init__(self, send: Optional[Callable] = None, timeout: float = 8.0,
                 delay_factor: float = 3.0, min_gap_s: float = 4.0):
        self.send = send or _default_send
        self.timeout = timeout
        self.delay_factor = delay_factor    # probe must be >= factor x baseline
        self.min_gap_s = min_gap_s          # ...and at least this many seconds slower

    def _timed(self, host, port, use_tls, payload) -> float:
        try:
            return self.send(host, port, use_tls, payload, self.timeout)
        except Exception:
            return -1.0

    def test(self, host: str, port: int = 80, path: str = "/", use_tls: bool = False) -> list:
        results: list = []
        baseline = self._timed(host, port, use_tls, _baseline_payload(host, path))
        if baseline < 0:
            return results          # host unreachable; nothing to say
        for variant, mk in (("CL.TE", _clte_payload), ("TE.CL", _tecl_payload)):
            probe = self._timed(host, port, use_tls, mk(host, path))
            suspected = (probe >= 0 and baseline >= 0
                         and probe >= baseline * self.delay_factor
                         and (probe - baseline) >= self.min_gap_s)
            if suspected:
                # confirm once — a transient blip shouldn't be reported
                confirm = self._timed(host, port, use_tls, mk(host, path))
                suspected = confirm >= baseline * self.delay_factor and (confirm - baseline) >= self.min_gap_s
                probe = max(probe, confirm)
            results.append(DesyncResult(variant, baseline, probe, suspected,
                                        note=("probe hung vs a fast baseline" if suspected else "")))
        return results

    def to_findings(self, host: str, port: int, results: list) -> list:
        out: list = []
        for r in results:
            if not r.suspected:
                continue
            rec = RequestRecord(method="POST", url=f"{host}:{port}", identity="anon",
                                status=0, elapsed_ms=r.probe_s * 1000)
            out.append(Finding(
                vuln_class=VulnClass.MISCONFIG, severity=Severity.HIGH,
                title=f"Possible HTTP request smuggling ({r.variant} desync)",
                endpoint=f"{host}:{port}",
                description=(f"A {r.variant} timing probe hung ({r.probe_s:.1f}s) versus a "
                             f"{r.baseline_s:.1f}s baseline — the front-end and back-end appear to "
                             "disagree on request boundaries (CWE-444). TENTATIVE: timing is noisy; "
                             "confirm manually before reporting, and never weaponize."),
                evidence=[rec], confidence="tentative", verdict="inconclusive",
                exploitability="unknown",
                detail={"variant": r.variant, "baseline_s": r.baseline_s,
                        "probe_s": r.probe_s, "cwe": "CWE-444", "basis": "timing_differential",
                        "source": "active.smuggling",
                        "remediation": ("Use a single, unambiguous HTTP parser end-to-end (prefer "
                                        "HTTP/2 to the back-end); reject any request carrying both "
                                        "Content-Length and Transfer-Encoding, and normalise/close "
                                        "connections on ambiguous framing.")}))
        return out

    def run(self, host: str, port: int = 80, path: str = "/", use_tls: bool = False):
        results = self.test(host, port, path, use_tls)
        return results, self.to_findings(host, port, results)


def _main(argv=None) -> int:
    """CLI: python3 -m deluluscan.active.smuggling --url http://127.0.0.1:8080/"""
    import argparse, ipaddress, json, socket as _s, sys
    from urllib.parse import urlparse
    ap = argparse.ArgumentParser(prog="deluluscan.active.smuggling",
                                 description="timing-only HTTP request-smuggling detector")
    ap.add_argument("--url", required=True)
    ap.add_argument("--allow-remote", action="store_true")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    u = urlparse(a.url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        ip = ipaddress.ip_address(_s.gethostbyname(host))
        local = ip.is_loopback or ip.is_private
    except Exception:
        local = False
    if not local and not a.allow_remote:
        raise SystemExit(f"[scope] {a.url} is not loopback/RFC1918. Use --allow-remote only if "
                         "you are authorized (request-smuggling probes touch shared infrastructure).")
    probe = SmugglingProbe(timeout=a.timeout)
    results, findings = probe.run(host, port, u.path or "/", use_tls=(u.scheme == "https"))
    if a.json:
        print(json.dumps({"results": [r.__dict__ for r in results],
                          "findings": [f.to_dict() for f in findings]}, indent=2, default=str))
        return 0
    print(f"[smuggling] {host}:{port}")
    for r in results:
        print(f"  {r.variant}: baseline={r.baseline_s:.2f}s probe={r.probe_s:.2f}s "
              f"{'SUSPECTED' if r.suspected else 'ok'}")
    print(f"  findings: {len(findings)} (tentative — confirm manually)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
