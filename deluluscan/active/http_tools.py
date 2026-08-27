"""Interactive request workbench — the Burp Repeater/Intruder + Postman core.

Everything here operates on a ``RequestSpec`` (an editable, serializable HTTP
request) and sends it through the existing instrumented ``HttpClient`` (so the
rate limiter, timeouts, redaction and evidence recording all still apply, and
every send is bound to the same authorized-target safety gate as the scanners).

- ``RequestSpec``  — an editable request you can clone and mutate (like a
  Postman request or a Burp Repeater tab).
- ``Repeater``     — send / resend-with-edits.
- ``Intruder``     — mark payload positions and iterate payload sets over them
  (sniper / battering-ram / pitchfork), then flag responses that deviate from a
  baseline. This is how the tool "changes parameters and tries".
- ``Collection``   — save/load/replay an ordered set of requests.

This is active testing against a target you are authorized to test; it is not a
weaponization framework. Payload *sets* are supplied by the caller — the active
testing modules supply security-*test* probes (id swaps, mass-assignment flags,
tampered tokens), not attacks on third parties or data-exfiltration engines.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from ..models import RequestRecord

_MARK = re.compile(r"§([^§]*)§")   # Burp-style position markers: §value§


@dataclass
class RequestSpec:
    method: str = "GET"
    path: str = "/"                      # path or full URL (HttpClient passes http(s):// through)
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    json_body: Any = None
    data: Optional[str] = None
    name: str = ""

    def clone(self) -> "RequestSpec":
        return RequestSpec(
            method=self.method, path=self.path,
            headers=dict(self.headers), params=dict(self.params),
            json_body=copy.deepcopy(self.json_body), data=self.data,
            name=self.name)

    # -- ergonomic editors (return a modified clone) -----------------------
    def with_header(self, name: str, value: Optional[str]) -> "RequestSpec":
        c = self.clone()
        # case-insensitive replace / delete
        for k in list(c.headers):
            if k.lower() == name.lower():
                del c.headers[k]
        if value is not None:
            c.headers[name] = value
        return c

    def with_param(self, name: str, value: Optional[str]) -> "RequestSpec":
        c = self.clone()
        if value is None:
            c.params.pop(name, None)
        else:
            c.params[name] = value
        return c

    def with_json_field(self, dotted_key: str, value: Any) -> "RequestSpec":
        c = self.clone()
        if not isinstance(c.json_body, dict):
            c.json_body = {} if c.json_body is None else c.json_body
        node = c.json_body
        parts = dotted_key.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
        return c

    def to_dict(self) -> dict[str, Any]:
        return {"method": self.method, "path": self.path, "headers": self.headers,
                "params": self.params, "json_body": self.json_body,
                "data": self.data, "name": self.name}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "RequestSpec":
        return RequestSpec(
            method=d.get("method", "GET"), path=d.get("path", "/"),
            headers=dict(d.get("headers", {})), params=dict(d.get("params", {})),
            json_body=d.get("json_body"), data=d.get("data"),
            name=d.get("name", ""))

    @staticmethod
    def from_record(rec: RequestRecord) -> "RequestSpec":
        """Reconstruct an editable request from a captured response record."""
        return RequestSpec(method=rec.method, path=rec.url,
                           headers=dict(rec.req_headers or {}),
                           data=rec.req_body, name=f"{rec.method} {rec.url}")


class Repeater:
    """Send a RequestSpec and get a RequestRecord back (Burp Repeater)."""

    def __init__(self, client):
        self.client = client

    def send(self, spec: RequestSpec, *, identity_label: str = "anonymous",
             extra_headers: Optional[dict] = None,
             allow_redirects: bool = False) -> RequestRecord:
        headers = dict(spec.headers)
        if extra_headers:
            headers.update(extra_headers)
        return self.client.request(
            spec.method, spec.path, identity_label=identity_label,
            headers=headers or None, params=spec.params or None,
            json_body=spec.json_body, data=spec.data,
            allow_redirects=allow_redirects)


# ---- Intruder ---------------------------------------------------------------
@dataclass
class Position:
    """Where a payload is injected."""
    kind: str            # "param" | "header" | "json" | "path_token"
    key: str             # param name / header name / dotted json key / token to replace


@dataclass
class IntruderResult:
    payload: Any
    positions: list[str]
    record: RequestRecord
    interesting: bool = False
    reason: str = ""


def set_at(spec: RequestSpec, pos: Position, value: Any) -> RequestSpec:
    if pos.kind == "param":
        return spec.with_param(pos.key, value)
    if pos.kind == "header":
        return spec.with_header(pos.key, str(value))
    if pos.kind == "json":
        return spec.with_json_field(pos.key, value)
    if pos.kind == "path_token":
        c = spec.clone()
        c.path = c.path.replace(pos.key, str(value))
        return c
    raise ValueError(f"unknown position kind {pos.kind}")


class Intruder:
    """Iterate payloads over marked positions (sniper / battering-ram /
    pitchfork), then flag responses that deviate from the unmodified baseline."""

    def __init__(self, client):
        self.repeater = Repeater(client)

    def attack(self, base: RequestSpec, positions: list[Position],
               payloads, *, attack_type: str = "sniper",
               identity_label: str = "anonymous",
               max_requests: int = 200) -> list[IntruderResult]:
        baseline = self.repeater.send(base, identity_label=identity_label)
        results: list[IntruderResult] = []

        def run(spec, pl, pos_names):
            rec = self.repeater.send(spec, identity_label=identity_label)
            r = IntruderResult(payload=pl, positions=pos_names, record=rec)
            self._flag(r, baseline)
            results.append(r)

        if attack_type == "sniper":
            for pos in positions:
                for pl in payloads:
                    if len(results) >= max_requests:
                        return results
                    run(set_at(base, pos, pl), pl, [pos.key])
        elif attack_type == "battering_ram":
            for pl in payloads:
                if len(results) >= max_requests:
                    return results
                spec = base
                for pos in positions:
                    spec = set_at(spec, pos, pl)
                run(spec, pl, [p.key for p in positions])
        elif attack_type == "pitchfork":
            # payloads is a list of lists, one per position
            for combo in zip(*payloads):
                if len(results) >= max_requests:
                    return results
                spec = base
                for pos, pl in zip(positions, combo):
                    spec = set_at(spec, pos, pl)
                run(spec, list(combo), [p.key for p in positions])
        else:
            raise ValueError(f"unknown attack_type {attack_type}")
        return results

    @staticmethod
    def _flag(r: IntruderResult, baseline: RequestRecord) -> None:
        """Mark responses that stand out from the baseline (status change or a
        large size change) — the classic Intruder triage signal."""
        if r.record.status != baseline.status:
            r.interesting = True
            r.reason = f"status {baseline.status} -> {r.record.status}"
            return
        if baseline.resp_len and abs(r.record.resp_len - baseline.resp_len) > max(
                128, int(0.25 * baseline.resp_len)):
            r.interesting = True
            r.reason = (f"length {baseline.resp_len} -> {r.record.resp_len} "
                        f"({r.record.resp_len - baseline.resp_len:+d}B)")


# ---- Collections ------------------------------------------------------------
class Collection:
    """An ordered, saveable set of requests (a simplified Postman collection)."""

    def __init__(self, name: str = "deluluscan-collection"):
        self.name = name
        self.requests: list[RequestSpec] = []

    def add(self, spec: RequestSpec) -> "Collection":
        self.requests.append(spec)
        return self

    def to_json(self) -> str:
        return json.dumps({"name": self.name,
                           "requests": [r.to_dict() for r in self.requests]},
                          indent=2)

    @staticmethod
    def from_json(text: str) -> "Collection":
        d = json.loads(text)
        c = Collection(d.get("name", "collection"))
        c.requests = [RequestSpec.from_dict(r) for r in d.get("requests", [])]
        return c

    def replay(self, client, *, identity_label: str = "anonymous") -> list[RequestRecord]:
        rep = Repeater(client)
        return [rep.send(r, identity_label=identity_label) for r in self.requests]


def parse_markers(text: str) -> tuple[str, list[str]]:
    """Turn 'id=§123§' into ('id=123', ['123']) — extract Burp-style markers."""
    marks = _MARK.findall(text)
    return _MARK.sub(lambda m: m.group(1), text), marks
