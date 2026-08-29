"""SMB / LDAP posture detection — the internal-network misconfigs a pentest and a
blue team both care about. DETECTION ONLY: we read a service's advertised posture
and emit findings; we never authenticate with stolen material, enumerate users,
harvest hashes, relay, or move laterally. Those exploitation steps are out of
scope and are not implemented here.

Checks:
  - SMB message signing NOT required  -> NTLM-relay / MITM risk (CWE-287)
  - SMBv1 (CIFS) enabled              -> EternalBlue-class exposure, deprecated
  - LDAP anonymous bind allowed       -> directory info disclosure (CWE-200)

The protocol probes are INJECTED, so the finding logic is fully offline-testable.
The default probes are best-effort over a raw socket (SMB2 NEGOTIATE) / optional
`ldap3` (anonymous bind); if a probe can't run it fails soft (no finding), never
crashing a scan.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass


@dataclass
class AdProfile:
    host: str
    smb: Optional[dict] = None       # {reachable, dialect, signing_required, smbv1}
    ldap: Optional[dict] = None      # {reachable, anonymous_bind, naming_contexts}

    def to_dict(self) -> dict:
        return {"host": self.host, "smb": self.smb, "ldap": self.ldap}


# ---- default SMB2 NEGOTIATE probe (raw, no external dep) --------------------
def _default_smb_probe(host: str, port: int = 445, timeout: float = 5.0) -> Optional[dict]:
    """Send one SMB2 NEGOTIATE and read the SecurityMode / dialect. Best-effort:
    returns None if the host isn't speaking SMB2. Detection only."""
    # SMB2 NEGOTIATE requesting dialects 0x0202..0x0311 (and SMB1 handled by fallback)
    smb2 = bytes.fromhex(
        "fe534d4240000100000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "24000500010000007f000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000"
    )
    # dialects: 0x0202 0x0210 0x0300 0x0302 0x0311
    dialects = struct.pack("<5H", 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    body = smb2 + dialects
    packet = struct.pack(">I", len(body)) + body
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(packet)
            resp = s.recv(1024)
    except Exception:
        return None
    if len(resp) < 72 or resp[4:8] != b"\xfeSMB":
        return {"reachable": True, "dialect": None, "signing_required": None, "smbv1": None}
    # SMB2 header is 64 bytes after the 4-byte NetBIOS length; NEGOTIATE response
    # SecurityMode is a 2-byte field at offset 4+64+2 ; bit0x02 = signing required.
    try:
        sec_mode = resp[4 + 64 + 2]
        dialect = struct.unpack_from("<H", resp, 4 + 64 + 4)[0]
    except Exception:
        return {"reachable": True, "dialect": None, "signing_required": None, "smbv1": None}
    return {"reachable": True, "dialect": hex(dialect),
            "signing_required": bool(sec_mode & 0x02), "smbv1": False}


# ---- default LDAP anonymous-bind probe (optional ldap3) ---------------------
def _default_ldap_probe(host: str, port: int = 389, timeout: float = 5.0) -> Optional[dict]:
    try:
        from ldap3 import Server, Connection, ALL
    except Exception:
        return None                  # optional dep absent -> fail soft
    try:
        srv = Server(host, port=port, get_info=ALL, connect_timeout=timeout)
        conn = Connection(srv, auto_bind=True)   # anonymous simple bind
        ncs = list(getattr(srv.info, "naming_contexts", []) or []) if srv.info else []
        conn.unbind()
        return {"reachable": True, "anonymous_bind": True, "naming_contexts": ncs}
    except Exception:
        return {"reachable": True, "anonymous_bind": False, "naming_contexts": []}


class AdIntel:
    def __init__(self, smb_probe: Optional[Callable] = None, ldap_probe: Optional[Callable] = None):
        self.smb_probe = smb_probe or _default_smb_probe
        self.ldap_probe = ldap_probe or _default_ldap_probe

    def scan(self, host: str, *, do_smb: bool = True, do_ldap: bool = True) -> AdProfile:
        prof = AdProfile(host=host)
        if do_smb:
            try:
                prof.smb = self.smb_probe(host)
            except Exception:
                prof.smb = None
        if do_ldap:
            try:
                prof.ldap = self.ldap_probe(host)
            except Exception:
                prof.ldap = None
        return prof

    def to_findings(self, prof: AdProfile) -> list:
        out: list = []

        def add(vc, sev, title, desc, detail, port):
            rec = RequestRecord(method="PROBE", url=f"{prof.host}:{port}", identity="anon",
                                status=0, elapsed_ms=0.0)
            out.append(Finding(vuln_class=vc, severity=sev, title=title, endpoint=f"{prof.host}:{port}",
                               description=desc, evidence=[rec], confidence="firm",
                               verdict="likely_true_positive", exploitability="conditional",
                               detail={**detail, "source": "netscan.adintel"}))

        smb = prof.smb or {}
        if smb.get("reachable"):
            if smb.get("signing_required") is False:
                add(VulnClass.MISCONFIG, Severity.MEDIUM, "SMB signing not required",
                    f"SMB on {prof.host} does not require message signing, exposing it to NTLM-relay "
                    "and man-in-the-middle attacks. Require SMB signing on the server and clients.",
                    {"dialect": smb.get("dialect")}, 445)
            if smb.get("smbv1"):
                add(VulnClass.MISCONFIG, Severity.HIGH, "SMBv1 (CIFS) enabled",
                    f"{prof.host} still speaks SMBv1, a deprecated protocol with critical known "
                    "vulnerabilities (EternalBlue/MS17-010 class). Disable SMBv1.",
                    {}, 445)

        ldap = prof.ldap or {}
        if ldap.get("reachable") and ldap.get("anonymous_bind"):
            ncs = ldap.get("naming_contexts") or []
            sev = Severity.MEDIUM if ncs else Severity.LOW
            add(VulnClass.INFO_LEAK, sev, "LDAP anonymous bind allowed",
                f"The LDAP directory on {prof.host} accepts an anonymous bind, disclosing directory "
                f"information (naming contexts: {', '.join(ncs[:3]) or 'n/a'}). Require authentication "
                "and restrict anonymous reads.", {"naming_contexts": ncs}, 389)
        return out

    def run(self, host: str, **kw):
        prof = self.scan(host, **kw)
        return prof, self.to_findings(prof)


def _main(argv=None) -> int:
    """CLI: python3 -m deluluscan.netscan.adintel --host 127.0.0.1"""
    import argparse, ipaddress, json, sys
    ap = argparse.ArgumentParser(prog="deluluscan.netscan.adintel",
                                 description="SMB/LDAP posture detection (detection only)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--no-smb", action="store_true")
    ap.add_argument("--no-ldap", action="store_true")
    ap.add_argument("--allow-remote", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        ip = ipaddress.ip_address(a.host)
        local = ip.is_loopback or ip.is_private
    except Exception:
        local = False
    if not local and not a.allow_remote:
        raise SystemExit(f"[scope] {a.host} is not loopback/RFC1918. Use --allow-remote only if "
                         "you are authorized to test it.")
    prof, findings = AdIntel().run(a.host, do_smb=not a.no_smb, do_ldap=not a.no_ldap)
    if a.json:
        print(json.dumps({"profile": prof.to_dict(),
                          "findings": [f.to_dict() for f in findings]}, indent=2, default=str))
        return 0
    print(f"[adintel] {a.host}: smb={prof.smb} ldap={prof.ldap}")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.title}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
