"""TLS/SSL configuration scanner (sslscan / testssl.sh-lite).

Covers WSTG-CRYP-01 (weak transport crypto), which Deluluscan otherwise leaves
untested. Two evidence sources:

  1. protocol matrix — attempt a handshake pinned to each protocol version;
     SSLv2/SSLv3/TLS 1.0/1.1 succeeding is a deprecated-protocol finding.
  2. certificate + negotiated cipher — from a modern handshake: expiry,
     self-signed, hostname mismatch, weak public key (<2048-bit RSA), weak
     signature (SHA-1/MD5), and no forward secrecy in the negotiated cipher.

The connector is injected (`connect`) so the whole scanner runs offline in tests;
the default uses the stdlib `ssl` module + `cryptography` (already a dependency)
to parse the peer certificate. Opening a TLS socket is an active pass, so the CLI
gates it to loopback/RFC1918 like everything else. Detection only.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass

# protocol label -> (ssl.TLSVersion, is_deprecated)
_PROTOCOLS = [
    ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None), True),
    ("TLSv1.0", ssl.TLSVersion.TLSv1, True),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, True),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, False),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, False),
]
_PFS_TOKENS = ("ECDHE", "DHE")   # forward-secrecy key exchanges


@dataclass
class TlsProfile:
    host: str
    port: int
    protocols: dict = field(default_factory=dict)   # label -> bool (handshaked)
    cipher: Optional[tuple] = None                   # (name, proto, bits)
    cert: Optional[dict] = None                      # parsed cert facts
    error: str = ""

    def to_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "protocols": self.protocols,
                "cipher": self.cipher, "cert": self.cert, "error": self.error}


def _default_connect(host: str, port: int, version_label: str, tls_version,
                     timeout: float = 6.0) -> Optional[dict]:
    """Handshake pinned to one protocol. Returns {cipher, cert_der} or None."""
    if tls_version is None:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
    except (ValueError, OSError):
        return None                     # this OpenSSL build can't pin that version
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return {"cipher": ss.cipher(),
                        "cert_der": ss.getpeercert(binary_form=True)}
    except Exception:
        return None


class TlsScan:
    def __init__(self, connect: Optional[Callable] = None, timeout: float = 6.0):
        self.connect = connect or _default_connect
        self.timeout = timeout

    def scan(self, host: str, port: int = 443) -> TlsProfile:
        prof = TlsProfile(host=host, port=port)
        best = None
        for label, ver, _dep in _PROTOCOLS:
            res = self.connect(host, port, label, ver, self.timeout)
            prof.protocols[label] = res is not None
            if res is not None:
                best = res              # keep the last (highest) successful handshake
        if best:
            prof.cipher = best.get("cipher")
            prof.cert = _parse_cert(best.get("cert_der"))
            if prof.cert is not None:
                prof.cert["hostname_mismatch"] = not hostname_matches(host, prof.cert.get("san"))
        elif not any(prof.protocols.values()):
            prof.error = "no TLS handshake succeeded (port closed or not TLS)"
        return prof

    def to_findings(self, prof: TlsProfile) -> list:
        out: list = []
        ep = f"{prof.host}:{prof.port}"
        rec = RequestRecord(method="TLS", url=ep, identity="anon", status=0, elapsed_ms=0.0)

        def add(sev, title, desc, detail):
            out.append(Finding(vuln_class=VulnClass.CRYPTO, severity=sev, title=title,
                               endpoint=ep, description=desc, evidence=[rec],
                               detail={**detail, "source": "netscan.tls"}, confidence="firm",
                               verdict="true_positive", exploitability="conditional"))

        for label, ver, dep in _PROTOCOLS:
            if dep and prof.protocols.get(label):
                sev = Severity.HIGH if label in ("SSLv3", "TLSv1.0") else Severity.MEDIUM
                add(sev, f"Deprecated TLS protocol enabled: {label}",
                    f"The server completed a handshake over {label}, a deprecated protocol with "
                    "known weaknesses (POODLE/BEAST/downgrade). Disable everything below TLS 1.2.",
                    {"protocol": label})
        if prof.protocols and not prof.protocols.get("TLSv1.2") and not prof.protocols.get("TLSv1.3"):
            if any(prof.protocols.values()):
                add(Severity.HIGH, "No modern TLS (1.2/1.3) offered",
                    "The server negotiates only legacy TLS; modern clients will fail or downgrade.",
                    {"protocols": prof.protocols})

        c = prof.cert or {}
        if c.get("expired"):
            add(Severity.HIGH, "TLS certificate expired",
                f"The certificate expired on {c.get('not_after')}.", {"not_after": c.get("not_after")})
        elif c.get("days_to_expiry") is not None and c["days_to_expiry"] < 15:
            add(Severity.LOW, "TLS certificate expiring soon",
                f"The certificate expires in {c['days_to_expiry']} day(s) ({c.get('not_after')}).",
                {"days_to_expiry": c["days_to_expiry"]})
        if c.get("self_signed"):
            add(Severity.MEDIUM, "Self-signed TLS certificate",
                "The certificate is self-signed (issuer == subject); clients can't establish trust.",
                {"subject": c.get("subject")})
        if c.get("hostname_mismatch"):
            add(Severity.MEDIUM, "TLS certificate hostname mismatch",
                f"The certificate does not cover '{prof.host}' (SAN: {c.get('san')}).",
                {"host": prof.host, "san": c.get("san")})
        if c.get("weak_key"):
            add(Severity.MEDIUM, f"Weak certificate key ({c.get('key_bits')}-bit {c.get('key_type')})",
                "The certificate public key is below 2048-bit RSA-equivalent strength.",
                {"key_bits": c.get("key_bits"), "key_type": c.get("key_type")})
        if c.get("weak_sig"):
            add(Severity.MEDIUM, f"Weak certificate signature ({c.get('sig_algo')})",
                "The certificate is signed with a broken hash (SHA-1/MD5) — forgeable.",
                {"sig_algo": c.get("sig_algo")})

        # Forward secrecy: TLS 1.3 ALWAYS uses ephemeral key exchange (the cipher
        # name, e.g. TLS_AES_256_GCM_SHA384, just doesn't spell out ECDHE) — never
        # flag it. Only pre-1.3 ciphers without an (EC)DHE token lack PFS.
        cname, cproto = (prof.cipher[0], prof.cipher[1]) if prof.cipher else ("", "")
        is_tls13 = cproto == "TLSv1.3" or (cname or "").startswith("TLS_")
        if cname and not is_tls13 and not any(t in cname for t in _PFS_TOKENS):
            add(Severity.LOW, "No forward secrecy in negotiated cipher",
                f"The negotiated cipher '{cname}' lacks (EC)DHE key exchange; a future "
                "key compromise decrypts captured traffic.", {"cipher": cname})
        return out

    def run(self, host: str, port: int = 443):
        prof = self.scan(host, port)
        return prof, self.to_findings(prof)


def _parse_cert(der: Optional[bytes]) -> Optional[dict]:
    if not der:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, dsa
        from cryptography.x509.oid import ExtensionOID, NameOID
    except Exception:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    now = datetime.now(timezone.utc)
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    days = (not_after - now).days
    # SANs
    san = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        pass
    key = cert.public_key()
    key_bits = getattr(key, "key_size", None)
    key_type = type(key).__name__.replace("PublicKey", "")
    sig = (cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "").lower()
    subject = cert.subject.rfc4822_dn() if hasattr(cert.subject, "rfc4822_dn") else str(cert.subject)
    return {
        "subject": subject, "issuer": str(cert.issuer.rfc4822_dn()
                                          if hasattr(cert.issuer, "rfc4822_dn") else cert.issuer),
        "not_after": not_after.isoformat(), "days_to_expiry": days, "expired": days < 0,
        "self_signed": cert.issuer == cert.subject,
        "san": san,
        "key_bits": key_bits, "key_type": key_type,
        "weak_key": bool(isinstance(key, (rsa.RSAPublicKey, dsa.DSAPublicKey))
                         and key_bits and key_bits < 2048),
        "sig_algo": sig, "weak_sig": sig in ("sha1", "md5"),
    }


def hostname_matches(host: str, sans: list) -> bool:
    for pat in sans or []:
        p = pat.lower()
        h = host.lower()
        if p == h:
            return True
        if p.startswith("*.") and h.split(".", 1)[-1] == p[2:]:
            return True
    return False
