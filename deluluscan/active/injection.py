"""Injection & traversal detection suite (v0.8).

Safe, high-signal detection for the vulnerability classes not yet covered. Every
classifier requires a *strong* confirmation signal to keep false positives low
(the whole point of this project): a traversal must return an OS file signature,
SSTI must return the computed value while the raw payload is gone, open redirect
must actually redirect off-host, CRLF must reflect the injected header, and the
blind classes (command injection, XXE) only confirm on an out-of-band callback.

Authorized target only. Payloads are benign probes (a DNS/HTTP canary, a bounded
sleep, an arithmetic marker) — never destructive commands or real data theft.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

# ---- payloads --------------------------------------------------------------
TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd", "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini", "%2e%2e%2fetc%2fpasswd",
]
_TRAVERSAL_HIT = re.compile(r"root:.*?:0:0:|\[extensions\]|for 16-bit app support|"
                            r"daemon:.*?:/usr/sbin", re.I)

# distinctive arithmetic so a coincidental "49" doesn't cause a false hit
SSTI_PAYLOADS = [("${{{a}*{b}}}", ), ("{{{a}*{b}}}", ), ("#{{{a}*{b}}}", ),
                 ("${{'{a}'*1}}", ), ("<%= {a}*{b} %>", )]
_SSTI_A, _SSTI_B = 1337, 1331          # product = 1779547 (rare in normal output)
_SSTI_PRODUCT = str(_SSTI_A * _SSTI_B)

OPEN_REDIRECT_PAYLOADS = [
    "https://deluluscan-oob.example/", "//deluluscan-oob.example/",
    "/\\deluluscan-oob.example", "https:deluluscan-oob.example",
]
_REDIRECT_PARAMS = {"redirect", "redirect_uri", "redirecturl", "url", "next",
                    "return", "returnurl", "returnto", "dest", "destination",
                    "continue", "goto", "rurl", "target", "to", "out", "link"}

CRLF_PAYLOAD = "%0d%0aX-Deluluscan-Injected:%20pwned"
_CRLF_HIT = re.compile(r"^x-deluluscan-injected:\s*pwned", re.I | re.M)

NOSQL_PAYLOADS = ['{"$gt":""}', '{"$ne":null}', "[$ne]=1", "'||'1'=='1"]
_NOSQL_ERR = re.compile(r"mongo|bson|\$where|unexpected token.*json|casterror", re.I)

PROTO_POLLUTION_BODY = {"__proto__": {"deluluscanPolluted": True},
                        "constructor": {"prototype": {"deluluscanPolluted": True}}}

_FILE_PARAM_HINTS = {"file", "path", "template", "tpl", "doc", "document",
                     "download", "name", "page", "include", "view", "load",
                     "read", "filename", "filepath", "dir", "folder", "img", "image"}
_CMD_PARAM_HINTS = {"cmd", "command", "exec", "run", "ping", "host", "ip",
                    "domain", "query", "search", "name", "target"}

# URL-looking params worth an SSRF/metadata probe (bug-bounty naming)
_SSRF_URL_PARAMS = {"url", "uri", "link", "src", "source", "dest", "target",
                    "callback", "webhook", "feed", "proxy", "fetch", "import",
                    "preview", "unfurl", "endpoint", "next", "redirect", "load",
                    "image", "img", "avatar", "remote", "path", "domain", "host"}
# cloud metadata endpoints (AWS/GCP/Azure/DO) + localhost variants & bypasses
METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://0xA9FEA9FE/latest/meta-data/",
]
_METADATA_HIT = re.compile(
    r"ami-id|instance-id|iam/security-credentials|accessKeyId|"
    r"computeMetadata|managed-identity|placement/availability-zone|"
    r"security-credentials|\"AccessKeyId\"|meta-data/", re.I)


@dataclass
class InjectionFinding:
    kind: str            # traversal | ssti | open_redirect | crlf | host_header | nosql | proto_pollution | cmd_injection | xxe
    param: str
    payload: str
    detail: str
    confidence: str = "firm"   # firm | tentative
    evidence_status: Optional[int] = None


def _h(headers: dict, name: str):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


# ---- classifiers (each takes the probe response record) --------------------
def classify_traversal(rec, param, payload) -> Optional[InjectionFinding]:
    if rec and _TRAVERSAL_HIT.search(rec.resp_body or ""):
        return InjectionFinding("traversal", param, payload,
            "response returned an OS file signature (e.g. /etc/passwd) — path "
            "traversal / local file inclusion confirmed", "firm", rec.status)
    return None


def classify_ssti(rec, param, payload) -> Optional[InjectionFinding]:
    body = rec.resp_body or "" if rec else ""
    # evaluated result present AND the literal payload expression gone => executed
    if _SSTI_PRODUCT in body and payload not in body:
        return InjectionFinding("ssti", param, payload,
            f"template expression was evaluated (returned {_SSTI_PRODUCT}) — "
            f"server-side template injection; can escalate to RCE", "firm", rec.status)
    return None


def classify_open_redirect(rec, param, payload) -> Optional[InjectionFinding]:
    if not rec:
        return None
    loc = _h(rec.resp_headers, "location") or ""
    if "deluluscan-oob.example" in loc.lower():
        return InjectionFinding("open_redirect", param, payload,
            f"Location header redirects off-site to attacker-controlled host "
            f"({loc[:80]}) — open redirect (phishing / OAuth token theft vector)",
            "firm", rec.status)
    return None


def classify_crlf(rec, param, payload) -> Optional[InjectionFinding]:
    if rec and _CRLF_HIT.search("\n".join(f"{k}: {v}" for k, v in (rec.resp_headers or {}).items())):
        return InjectionFinding("crlf", param, payload,
            "injected CRLF added an attacker-controlled response header — HTTP "
            "response splitting / header injection", "firm", rec.status)
    return None


def classify_host_header(rec, evil_host) -> Optional[InjectionFinding]:
    if not rec:
        return None
    body = rec.resp_body or ""
    loc = _h(rec.resp_headers, "location") or ""
    if evil_host in loc or (evil_host in body and body.count(evil_host) >= 1):
        return InjectionFinding("host_header", "Host", evil_host,
            "attacker-supplied Host/X-Forwarded-Host is reflected in the response/"
            "redirect — cache poisoning & password-reset-link poisoning risk",
            "tentative", rec.status)
    return None


def classify_nosql(baseline, rec, param, payload) -> Optional[InjectionFinding]:
    if not rec:
        return None
    body = rec.resp_body or ""
    if _NOSQL_ERR.search(body):
        return InjectionFinding("nosql", param, payload,
            "NoSQL/BSON error signature triggered by an operator payload — "
            "possible NoSQL injection", "tentative", rec.status)
    # auth/logic bypass: operator payload flips a denied baseline into success
    if baseline and baseline.status in (401, 403) and rec.status == 200 and rec.resp_len > 16:
        return InjectionFinding("nosql", param, payload,
            "operator payload turned a denied request into a success — likely "
            "NoSQL auth/logic bypass", "firm", rec.status)
    return None


def classify_proto_pollution(rec, followup) -> Optional[InjectionFinding]:
    # Reflection is NOT pollution: a server echoing back your __proto__ payload in
    # its response is normal and proves nothing. Real prototype pollution shows up
    # in a SEPARATE, clean follow-up request (one that never sent the property) that
    # nonetheless exhibits the injected marker / changed behavior.
    if followup is not None:
        fbody = (getattr(followup, "resp_body", "") or "").lower()
        if getattr(followup, "status", 500) < 400 and "deluluscanpolluted" in fbody:
            return InjectionFinding("proto_pollution", "body", "__proto__",
                "a clean follow-up request (which did not include __proto__) returned the "
                "injected marker — prototype pollution persisted server-side", "firm",
                getattr(followup, "status", 200))
    # marker only echoed in the same response we sent it in => reflection, not
    # pollution. Do not flag (avoids the false positive).
    return None


def classify_metadata_ssrf(rec, param, url) -> Optional[InjectionFinding]:
    """Confirmed SSRF when a metadata URL returns cloud-metadata content."""
    if rec and rec.status < 400 and _METADATA_HIT.search(rec.resp_body or ""):
        return InjectionFinding("ssrf", param, url,
            "response returned cloud instance-metadata content — SSRF reaching the "
            "metadata service (169.254.169.254); a direct path to credential theft",
            "firm", rec.status)
    return None
