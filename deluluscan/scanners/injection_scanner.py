"""Injection/traversal scanner + file-upload scanner (v0.8)."""
from __future__ import annotations

import json
import time
from typing import Iterable, Optional

from .base import Scanner
from ..active.http_tools import RequestSpec, Repeater
from ..active import injection as I
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

_SEV = {
    "traversal": Severity.HIGH, "ssti": Severity.CRITICAL,
    "open_redirect": Severity.MEDIUM, "crlf": Severity.MEDIUM,
    "host_header": Severity.MEDIUM, "nosql": Severity.HIGH,
    "proto_pollution": Severity.MEDIUM, "cmd_injection": Severity.CRITICAL,
    "xxe": Severity.HIGH, "file_upload": Severity.HIGH,
}
_VC = {
    "traversal": VulnClass.SQLI, "ssti": VulnClass.SQLI, "cmd_injection": VulnClass.SQLI,
    "nosql": VulnClass.SQLI, "xxe": VulnClass.SSRF, "open_redirect": VulnClass.MISCONFIG,
    "crlf": VulnClass.MISCONFIG, "host_header": VulnClass.MISCONFIG,
    "proto_pollution": VulnClass.MISCONFIG, "file_upload": VulnClass.MISCONFIG,
}


def _upload_accepted(body: str) -> bool:
    """True only if an upload response carries a real stored-resource identifier
    FIELD with a value (id / identifier / inode / tempFileId / assetId). This
    means the file was accepted and persisted — unlike a substring match on
    'id', which hits 'valid', 'hidden', and virtually any JSON body."""
    _ID_KEYS = {"id", "identifier", "inode", "tempfileid", "tempresourceid",
                "assetid", "asseturl", "filename", "filelink"}
    try:
        obj = json.loads(body or "")
    except Exception:
        return False
    found = False

    def walk(o):
        nonlocal found
        if found:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                if (k.lower() in _ID_KEYS and isinstance(v, (str, int))
                        and str(v).strip() and str(v).strip().lower() not in ("null", "0")):
                    found = True
                    return
                walk(v)
        elif isinstance(o, list):
            for v in o[:20]:
                walk(v)

    walk(obj)
    return found


def _mk(kind, title, endpoint, desc, evidence, detail, sev=None, conf="firm", active=True):
    d = dict(detail); d["test"] = kind
    if active:
        d["active"] = True
    return Finding(vuln_class=_VC.get(kind, VulnClass.MISCONFIG),
                   severity=sev or _SEV.get(kind, Severity.MEDIUM),
                   title=title, endpoint=endpoint, description=desc,
                   evidence=list(evidence), detail=d, confidence=conf)


class InjectionScanner(Scanner):
    name = "injection"
    vuln_classes = [VulnClass.SQLI.value, VulnClass.MISCONFIG.value]

    def __init__(self, *a, oob=None, **k):
        super().__init__(*a, **k)
        self.oob = oob
        self.rep = Repeater(self.client)

    def applies_to(self, e: Endpoint) -> bool:
        return e.method.upper() in ("GET", "POST", "PUT")

    def _params(self, e: Endpoint) -> list[str]:
        names = [p.get("name") for p in (e.query_params or []) if p.get("name")]
        return names[:8]

    def _ident(self):
        return self.identities.get(IdentityRole.BACKEND.value) or \
            self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self._ident()
        if ident is None:
            return
        label = ident.label()
        path = self.concrete_path(endpoint)
        base_headers = dict(self.auth.headers_for(ident))
        params = self._params(endpoint)

        def send(spec):
            return self.rep.send(spec, identity_label=label)

        base_spec = RequestSpec(method=endpoint.method, path=path, headers=base_headers)
        baseline = send(base_spec)

        # per-parameter injection probes
        for p in params:
            low = p.lower()
            # path traversal / LFI (file-ish params)
            if any(h in low for h in I._FILE_PARAM_HINTS):
                for pl in I.TRAVERSAL_PAYLOADS[:4]:
                    r = send(base_spec.with_param(p, pl))
                    hit = I.classify_traversal(r, p, pl)
                    if hit:
                        yield self._finding(hit, endpoint, [r]); break
            # SSTI (reflected-ish params)
            for tmpl in I.SSTI_PAYLOADS:
                pl = tmpl[0].format(a=I._SSTI_A, b=I._SSTI_B)
                r = send(base_spec.with_param(p, pl))
                hit = I.classify_ssti(r, p, pl)
                if hit:
                    yield self._finding(hit, endpoint, [r]); break
            # open redirect (redirect-ish params)
            if low in I._REDIRECT_PARAMS:
                for pl in I.OPEN_REDIRECT_PAYLOADS:
                    r = self.rep.send(base_spec.with_param(p, pl), identity_label=label,
                                      allow_redirects=False)
                    hit = I.classify_open_redirect(r, p, pl)
                    if hit:
                        yield self._finding(hit, endpoint, [r]); break
            # CRLF / header injection
            r = send(base_spec.with_param(p, I.CRLF_PAYLOAD))
            hit = I.classify_crlf(r, p, I.CRLF_PAYLOAD)
            if hit:
                yield self._finding(hit, endpoint, [r])
            # NoSQL
            for pl in I.NOSQL_PAYLOADS[:2]:
                r = send(base_spec.with_param(p, pl))
                hit = I.classify_nosql(baseline, r, p, pl)
                if hit:
                    yield self._finding(hit, endpoint, [r]); break
            # blind command injection via OOB (only if a collaborator is live)
            if self.oob and any(h in low for h in I._CMD_PARAM_HINTS):
                cy = self._canary({"kind": "cmd_injection", "endpoint": endpoint.key, "param": p})
                if cy:
                    token, host, _ = cy
                    for tpl in (";nslookup {c}", "|nslookup {c}", "$(curl {c})",
                                "`curl {c}`", "; curl {c}"):
                        send(base_spec.with_param(p, tpl.format(c=host)))
                    if self._oob_hits(token):
                        yield _mk("cmd_injection", "Command injection (OOB-confirmed)",
                            endpoint.key,
                            f"An OS-command payload in param '{p}' triggered an out-of-band "
                            f"callback to the collaborator ({host}) — remote command execution "
                            f"confirmed.", [baseline], {"param": p, "oob": host},
                            sev=Severity.CRITICAL, conf="firm")

        # host header injection (once per endpoint)
        evil = "deluluscan-oob.example"
        for hh in ("Host", "X-Forwarded-Host"):
            r = send(base_spec.with_header(hh, evil))
            hit = I.classify_host_header(r, evil)
            if hit:
                yield self._finding(hit, endpoint, [r]); break

        # cloud-metadata SSRF via URL-looking params (read-based confirmation)
        for p in params:
            if p.lower() in I._SSRF_URL_PARAMS:
                for murl in I.METADATA_URLS:
                    r = send(base_spec.with_param(p, murl))
                    m = I.classify_metadata_ssrf(r, p, murl)
                    if m:
                        yield _mk("ssrf", "SSRF to cloud metadata endpoint", endpoint.key,
                            f"{m.detail} (param '{p}').", [r], {"param": p, "payload": murl},
                            sev=Severity.CRITICAL, conf="firm"); break

        # header-based blind SSRF via OOB (X-Forwarded-For / Referer / True-Client-IP)
        if self.oob:
            cy = self._canary({"kind": "header_ssrf", "endpoint": endpoint.key})
            if cy:
                token, host, _ = cy
                spec = base_spec
                for hdr in ("Referer", "X-Forwarded-For", "True-Client-IP",
                            "X-Forwarded-Host", "X-Client-IP"):
                    spec = spec.with_header(hdr, f"http://{host}/" if "referer" in hdr.lower() else host)
                send(spec)
                if self._oob_hits(token):
                    yield _mk("ssrf", "Header-based blind SSRF (OOB-confirmed)", endpoint.key,
                        f"A collaborator callback ({host}) fired after injecting the canary into "
                        f"request headers (Referer/X-Forwarded-For/etc.) — the server dereferences "
                        f"attacker-controlled header URLs (blind SSRF).", [baseline],
                        {"oob": host}, sev=Severity.HIGH, conf="firm")

        # prototype pollution + XXE on JSON/XML writes
        if endpoint.method.upper() in ("POST", "PUT", "PATCH"):
            pp = base_spec.clone(); pp.json_body = I.PROTO_POLLUTION_BODY
            r = send(pp)
            # clean follow-up that does NOT carry __proto__; if the injected marker
            # appears HERE, pollution persisted server-side (real). Mere reflection
            # in `r` alone is not flagged.
            clean = base_spec.clone(); clean.json_body = {"deluluscan": "probe"}
            fr = send(clean)
            hit = I.classify_proto_pollution(r, fr)
            if hit:
                yield self._finding(hit, endpoint, [r, fr])
            if self.oob:
                cy = self._canary({"kind": "xxe", "endpoint": endpoint.key, "param": "body"})
                if cy:
                    token, host, _ = cy
                    xxe = base_spec.clone()
                    xxe.headers = {**base_headers, "Content-Type": "application/xml"}
                    xxe.data = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                                f'"http://{host}/xxe">]><r>&x;</r>')
                    send(xxe)
                    if self._oob_hits(token):
                        yield _mk("xxe", "XML external entity (XXE, OOB-confirmed)",
                            endpoint.key,
                            f"An XML external-entity payload caused the server to fetch an "
                            f"attacker URL ({host}) — XXE confirmed (file read / SSRF vector).",
                            [baseline], {"oob": host}, sev=Severity.HIGH, conf="firm")

    def _oob_hits(self, token: str) -> bool:
        try:
            return bool(self.oob.poll_for(token, timeout_s=6.0))
        except Exception:
            return False

    def _canary(self, meta):
        try:
            return self.oob.new_canary(meta)
        except Exception:
            return None

    def _finding(self, hit: "I.InjectionFinding", endpoint, evidence) -> Finding:
        return _mk(hit.kind,
                   {"traversal": "Path traversal / local file inclusion",
                    "ssti": "Server-side template injection (SSTI)",
                    "open_redirect": "Open redirect",
                    "crlf": "CRLF / HTTP response header injection",
                    "host_header": "Host header injection",
                    "nosql": "NoSQL injection",
                    "proto_pollution": "Prototype pollution"}.get(hit.kind, hit.kind),
                   endpoint.key, f"{hit.detail} (param '{hit.param}').",
                   evidence, {"param": hit.param, "payload": hit.payload[:80]},
                   conf=hit.confidence)


class FileUploadScanner(Scanner):
    name = "fileupload"
    vuln_classes = [VulnClass.MISCONFIG.value]

    # benign files with dangerous types; content is inert (no real payload run)
    _CASES = [
        ("deluluscan.svg", "image/svg+xml",
         b'<svg xmlns="http://www.w3.org/2000/svg"><text>deluluscan</text></svg>'),
        ("deluluscan.html", "text/html", b"<!doctype html><b>deluluscan-marker</b>"),
        ("deluluscan.jsp", "application/x-jsp", b"deluluscan-marker-jsp"),
        ("deluluscan.svg.png", "image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg"/>'),
        # CVE-2022-26352: multipart filename path traversal (inert marker content,
        # NOT a webshell). If accepted, the file can escape the intended dir.
        ("../../../../../ROOT/deluluscan_trav.txt", "text/plain", b"deluluscan-traversal-marker"),
        ("..%2f..%2f..%2fROOT%2fdeluluscan_trav.txt", "text/plain", b"deluluscan-traversal-marker"),
    ]
    _UPLOAD_PATHS = ["/api/v1/temp", "/api/content/file", "/api/v1/upload"]

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._done = False

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if self._done:
            return
        self._done = True
        ident = self.identities.get(IdentityRole.BACKEND.value) or \
            self.identities.get(IdentityRole.ADMIN.value)
        if not ident:
            return
        label = ident.label()
        headers = dict(self.auth.headers_for(ident))
        for upath in self._UPLOAD_PATHS:
            for fname, ctype, content in self._CASES:
                rec = self.client.request(
                    "POST", upath, identity_label=label, headers=headers,
                    files={"file": (fname, content, ctype)})
                if rec is None or rec.status in (0, 404):
                    break  # endpoint absent, try next path
                # Confirm the upload was actually ACCEPTED and STORED — the
                # response must return a stored-resource identifier FIELD (the target
                # /temp yields {"tempFiles":[{"id":"temp_..."}]}). The old check
                # substring-matched "id", which is present in "valid"/"hidden"/
                # any JSON, so nearly every 2xx response was flagged (critical FP).
                if rec.status < 400 and _upload_accepted(rec.resp_body):
                    is_traversal = ".." in fname or "%2f" in fname.lower()
                    dangerous = fname.rsplit(".", 1)[-1] in ("svg", "html", "jsp") or is_traversal
                    if is_traversal:
                        yield _mk("file_upload",
                            "File upload accepts path-traversal filename (CVE-2022-26352 class)",
                            f"POST {upath}",
                            f"The upload endpoint accepted a multipart filename containing a "
                            f"path traversal ('{fname}') at {upath}. the target CVE-2022-26352 was a "
                            f"pre-auth RCE where the unsanitized multipart filename let an "
                            f"attacker write a .jsp into Tomcat's ROOT and execute code. Sanitize "
                            f"/ canonicalize the filename and store uploads off the web root.",
                            [rec], {"path": upath, "filename": fname, "content_type": ctype,
                                    "traversal": True}, sev=Severity.CRITICAL, conf="tentative")
                        break
                    if dangerous:
                        yield _mk("file_upload",
                            f"Unrestricted file upload accepted ({fname})", f"POST {upath}",
                            f"The server accepted an upload of a dangerous type "
                            f"({ctype}, name {fname}) at {upath}. If this file is later "
                            f"served with its content-type or executed, it enables stored "
                            f"XSS (SVG/HTML) or code execution (JSP). Enforce an extension/"
                            f"content-type allowlist and store uploads off the web root.",
                            [rec], {"path": upath, "filename": fname, "content_type": ctype},
                            conf="tentative")
                        break
