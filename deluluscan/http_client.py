"""A thin, instrumented HTTP layer.

Every request returns a RequestRecord (our evidence object) regardless of
success or failure, so scanners can reason uniformly. A token-bucket rate
limiter keeps us polite to a live application, and response bodies are capped so
a misbehaving endpoint can't blow up memory.
"""
from __future__ import annotations

import re
import threading
import time
from typing import Any, Optional

import requests
import urllib3

from .models import RequestRecord
from .safety import DestructivePolicy, UnrestrictedPolicy

# We routinely test http/localhost; silence the noise but keep verify
# configurable for real targets.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_MAX_BODY = 256 * 1024   # keep at most 256 KiB of any response body as evidence

# Headers whose VALUES are live credentials — never keep them in evidence, or
# they leak into results.json and the published dashboard (a real credential
# disclosure). Applied to both request and response headers.
_SECRET_HEADERS = {"authorization", "cookie", "x-auth-token", "x-csrf-token",
                   "proxy-authorization", "www-authenticate"}


def _redact_set_cookie(value: str) -> str:
    """Mask cookie VALUES in a Set-Cookie header while preserving cookie names
    and security attributes (HttpOnly/Secure/SameSite). The attributes are
    themselves useful evidence for cookie-flag findings, but the value is a live
    session credential (JSESSIONID / the target JWT) and must never be retained.

    requests folds multiple Set-Cookie headers into one comma-joined string;
    split only on a comma that introduces a new `name=` pair (so the commas
    inside an `expires=Wed, 21 Oct ...` attribute are left intact)."""
    parts = re.split(r",\s*(?=[A-Za-z0-9!#$%&'*+.^_`|~-]+=)", value)
    out = []
    for part in parts:
        m = re.match(r"(\s*[^=;]+=)([^;]*)(.*)$", part, re.S)
        out.append(f"{m.group(1)}<redacted>{m.group(3)}" if m else part)
    return ", ".join(out)


def redact_headers(headers: dict) -> dict:
    """Return a copy of headers with credential values scrubbed."""
    out = {}
    for k, v in (headers or {}).items():
        lk = k.lower()
        if lk == "set-cookie":
            out[k] = _redact_set_cookie(v)
        elif lk in _SECRET_HEADERS:
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


# Live credentials that sometimes appear inside a response BODY (e.g. an issued
# API-token JWT returned as proof of a self-issuance finding, or a session id
# echoed in a debug payload). We mask the value but keep a marker so the finding
# is still legible ("a JWT was returned") without shipping a usable credential.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")
_JSESSION_RE = re.compile(r"(JSESSIONID=)[A-Fa-f0-9]{16,}")


def redact_body(body: Optional[str]) -> Optional[str]:
    """Mask JWTs and session identifiers embedded in a response/evidence body.
    Conservative: only clearly-credential-shaped tokens are touched, so the
    surrounding evidence stays intact."""
    if not body:
        return body
    body = _JWT_RE.sub("eyJ<redacted-jwt>", body)
    body = _JSESSION_RE.sub(r"\1<redacted>", body)
    return body


class RateLimiter:
    """Simple thread-safe token bucket."""

    def __init__(self, rps: float):
        self.capacity = max(rps, 0.1)
        self.tokens = self.capacity
        self.fill_rate = max(rps, 0.1)
        self.last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.fill_rate)
            self.last = now
            if self.tokens < 1:
                sleep_for = (1 - self.tokens) / self.fill_rate
                time.sleep(sleep_for)
                # Advance `last` past the sleep as well, otherwise the next
                # acquire() re-credits the interval we just waited out and lets a
                # burst through above the configured rate.
                self.last = time.monotonic()
                self.tokens = 0
            else:
                self.tokens -= 1


class HttpClient:
    def __init__(self, base_url: str, *, rate_limit_rps: float = 5.0,
                 timeout_s: float = 15.0, verify_tls: bool = True,
                 destructive_policy: Optional[DestructivePolicy] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_s
        self.verify = verify_tls
        # The one choke point for destructive-operation ordering. A sweep installs
        # a two-phase policy (deluluscan.safety) so no scanner can shut the target down
        # mid-run; a direct caller (deluluscan.recheck, tests) gets the unrestricted
        # policy, because a targeted single-endpoint re-test IS the operator
        # explicitly asking for that endpoint.
        self.destructive_policy = destructive_policy or UnrestrictedPolicy()
        self.limiter = RateLimiter(rate_limit_rps)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "deluluscan/0.1 (authorized-testing)"})
        # Probe telemetry. A verdict is only trustworthy if we can prove we
        # actually sent traffic — these counters are what distinguish
        # "tested and refuted" from "never tested". See deluluscan.recheck.
        self.request_count = 0          # requests attempted (incl. transport errors)
        self.response_count = 0         # responses actually received
        self.error_count = 0            # transport-level failures
        self.deferred_count = 0         # destructive requests held back by policy
        self.identities_probed: set[str] = set()
        # Grey-box observability (opt-in via --observe). When a list is installed
        # here, every SENT request records a wall-clock window {t0,t1} so the
        # telemetry correlator can attribute a server log line / memory spike to
        # the exact probe that caused it. None => zero overhead (black-box run).
        self.probe_log: Optional[list] = None

    def enable_probe_log(self) -> list:
        """Turn on probe-window capture and return the backing store."""
        from collections import deque
        self.probe_log = deque(maxlen=200_000)
        return self.probe_log

    def _maybe_log_probe(self, rec: RequestRecord) -> None:
        if self.probe_log is None:
            return
        # t1 is now; t0 is derived from the measured elapsed. Good enough for a
        # windowed correlation that already pads for async log flushing.
        t1 = time.time()
        self.probe_log.append({
            "method": rec.method, "url": rec.url, "status": rec.status,
            "identity": rec.identity, "t0": t1 - (rec.elapsed_ms / 1000.0), "t1": t1})

    def probe_stats(self) -> dict:
        """Snapshot of what this client actually sent — evidence for a verdict."""
        return {"requests": self.request_count, "responses": self.response_count,
                "errors": self.error_count, "deferred": self.deferred_count,
                "identities": sorted(self.identities_probed)}

    def _deferred_record(self, method: str, path: str, identity_label: str,
                         reason: str) -> RequestRecord:
        """A request the policy held back. Status 0 with an explicit reason, so a
        scanner sees 'not sent' rather than a fake denial — and so coverage can
        distinguish 'deferred' from 'tested and refused by the server'."""
        self.deferred_count += 1
        self.destructive_policy.note_deferral(method, path)
        return RequestRecord(
            method=(method or "GET").upper(), url=self.url_for(path),
            identity=identity_label, status=0, elapsed_ms=0.0,
            error=f"not sent — {reason}")

    def url_for(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    def status_probe(self, method: str, path: str, *, identity_label: str = "anonymous",
                     headers: Optional[dict] = None, params: Optional[dict] = None,
                     read_timeout: float = 4.0, max_bytes: int = 2048) -> RequestRecord:
        """Capture status + a small body sample WITHOUT draining the response.

        Streaming endpoints (Server-Sent Events, chunked tails, downloads) never
        close their body, so a normal request() times out and reports a transport
        error — which made the whole endpoint invisible to authorization testing.
        the target's log tail (GET /api/v1/logs/{file}/_tail, text/event-stream) is
        exactly that shape, and its missing admin gate was being skipped as a
        result.

        Here we read response HEADERS, take at most `max_bytes` of body, then
        close the connection. That is enough to decide "was this caller served or
        denied", which is all an authorization check needs.
        """
        may_send, why = self.destructive_policy.allows(method, path)
        if not may_send:
            return self._deferred_record(method, path, identity_label, why)
        self.limiter.acquire()
        url = self.url_for(path)
        merged_headers = dict(self.session.headers)
        if headers:
            merged_headers.update(headers)
        self.request_count += 1
        self.identities_probed.add(identity_label)
        start = time.perf_counter()
        resp = None
        try:
            resp = self.session.request(
                method.upper(), url, headers=headers, params=params,
                timeout=(self.timeout, read_timeout), verify=self.verify,
                allow_redirects=False, stream=True)
            self.session.cookies.clear()
            self.response_count += 1
            sample = b""
            try:
                for chunk in resp.iter_content(chunk_size=512):
                    sample += chunk
                    if len(sample) >= max_bytes:
                        break
            except Exception:
                pass          # a stream that yields nothing is still a valid status
            elapsed = (time.perf_counter() - start) * 1000
            text = redact_body(sample.decode("utf-8", "replace"))
            rec = RequestRecord(
                method=method.upper(), url=resp.url, identity=identity_label,
                status=resp.status_code, elapsed_ms=round(elapsed, 1),
                req_headers=redact_headers(merged_headers),
                resp_headers=redact_headers(dict(resp.headers)),
                resp_body=text, resp_len=len(sample),
            )
            self._maybe_log_probe(rec)
            return rec
        except requests.RequestException as exc:
            self.error_count += 1
            elapsed = (time.perf_counter() - start) * 1000
            rec = RequestRecord(
                method=method.upper(), url=url, identity=identity_label,
                status=0, elapsed_ms=round(elapsed, 1), error=str(exc))
            self._maybe_log_probe(rec)
            return rec
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass

    def request(self, method: str, path: str, *, identity_label: str = "anonymous",
                headers: Optional[dict] = None, params: Optional[dict] = None,
                json_body: Any = None, data: Any = None,
                files: Any = None, allow_redirects: bool = False) -> RequestRecord:
        may_send, why = self.destructive_policy.allows(method, path)
        if not may_send:
            return self._deferred_record(method, path, identity_label, why)
        self.limiter.acquire()
        url = self.url_for(path)
        merged_headers = dict(self.session.headers)
        if headers:
            merged_headers.update(headers)

        body_repr: Optional[str] = None
        if json_body is not None:
            import json as _json
            body_repr = _json.dumps(json_body)[:4096]
        elif data is not None:
            body_repr = str(data)[:4096]

        self.request_count += 1
        self.identities_probed.add(identity_label)
        start = time.perf_counter()
        try:
            resp = self.session.request(
                method.upper(), url, headers=headers, params=params,
                json=json_body, data=data, files=files,
                timeout=self.timeout, verify=self.verify,
                allow_redirects=allow_redirects,
            )
            # Purge any cookies the target set in this response so they cannot
            # bleed into subsequent requests made under a different identity.
            # Auth is carried via Authorization header (Bearer), never via cookies.
            self.session.cookies.clear()
            self.response_count += 1
            elapsed = (time.perf_counter() - start) * 1000
            text = redact_body(resp.text[:_MAX_BODY])
            rec = RequestRecord(
                method=method.upper(), url=resp.url, identity=identity_label,
                status=resp.status_code, elapsed_ms=round(elapsed, 1),
                req_headers=redact_headers(merged_headers),
                req_body=redact_body(body_repr),
                resp_headers=redact_headers(dict(resp.headers)),
                resp_body=text, resp_len=len(resp.content),
            )
            self._maybe_log_probe(rec)
            return rec
        except requests.RequestException as exc:
            self.error_count += 1
            elapsed = (time.perf_counter() - start) * 1000
            rec = RequestRecord(
                method=method.upper(), url=url, identity=identity_label,
                status=0, elapsed_ms=round(elapsed, 1),
                # Redact here too: the success path already does, and a transport
                # error is exactly when a credential-bearing body would otherwise
                # be written to results.json verbatim.
                req_body=redact_body(body_repr), error=str(exc),
            )
            self._maybe_log_probe(rec)
            return rec
