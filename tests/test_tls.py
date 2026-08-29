"""Offline tests for the TLS/SSL scanner — an injected connector serves synthetic
handshakes + a self-generated weak cert, so no network and no live TLS server."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

from deluluscan.netscan.tls import TlsScan, hostname_matches
from deluluscan.models import VulnClass, Severity

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  {detail}")


def _make_cert(*, host="good.test", days=365, key_bits=2048, sig="sha256",
               self_signed=False, san=None):
    """Build a real DER cert with the given properties (cryptography lib)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    issuer = subj if self_signed else x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Real CA")])
    algo = {"sha256": hashes.SHA256(), "sha1": hashes.SHA1()}[sig]
    not_after = datetime.now(timezone.utc) + timedelta(days=days)
    not_before = min(datetime.now(timezone.utc) - timedelta(days=1),
                     not_after - timedelta(days=1))
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issuer)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(not_before).not_valid_after(not_after))
    if san is not None:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
                            critical=False)
    cert = b.sign(key, algo)
    return cert.public_bytes(serialization.Encoding.DER)


def _connector(*, protocols_ok, cert_der, cipher=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)):
    def connect(host, port, label, ver, timeout=6.0):
        if label in protocols_ok:
            return {"cipher": cipher, "cert_der": cert_der}
        return None
    return connect


def ids(findings):
    return {f.title for f in findings}


def test_deprecated_protocols():
    cert = _make_cert(san=["good.test"])
    conn = _connector(protocols_ok={"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}, cert_der=cert)
    prof, finds = TlsScan(connect=conn).run("good.test", 443)
    titles = ids(finds)
    check("flags TLSv1.0", any("TLSv1.0" in t for t in titles), titles)
    check("flags TLSv1.1", any("TLSv1.1" in t for t in titles), titles)
    check("does not flag TLSv1.2", not any("TLSv1.2 enabled" in t for t in titles), titles)
    tls10 = next((f for f in finds if "TLSv1.0" in f.title), None)
    check("TLSv1.0 is HIGH", tls10 and tls10.severity == Severity.HIGH)
    check("all TLS findings are CRYPTO", all(f.vuln_class == VulnClass.CRYPTO for f in finds))


def test_only_modern_is_clean():
    cert = _make_cert(san=["good.test"])
    conn = _connector(protocols_ok={"TLSv1.2", "TLSv1.3"}, cert_der=cert)
    prof, finds = TlsScan(connect=conn).run("good.test", 443)
    check("no deprecated-protocol findings", not any("Deprecated" in f.title for f in finds), ids(finds))
    check("modern protocols recorded", prof.protocols["TLSv1.3"] and prof.protocols["TLSv1.2"])


def test_expired_cert():
    cert = _make_cert(host="good.test", days=-5, san=["good.test"])
    conn = _connector(protocols_ok={"TLSv1.2"}, cert_der=cert)
    prof, finds = TlsScan(connect=conn).run("good.test", 443)
    check("expired cert flagged HIGH",
          any(f.title == "TLS certificate expired" and f.severity == Severity.HIGH for f in finds),
          ids(finds))


def test_self_signed_and_hostname_mismatch():
    cert = _make_cert(host="other.test", self_signed=True, san=["other.test"])
    conn = _connector(protocols_ok={"TLSv1.3"}, cert_der=cert)
    prof, finds = TlsScan(connect=conn).run("good.test", 443)
    titles = ids(finds)
    check("self-signed flagged", any("Self-signed" in t for t in titles), titles)
    check("hostname mismatch flagged", any("hostname mismatch" in t for t in titles), titles)


def test_weak_key():
    cert = _make_cert(host="good.test", key_bits=1024, sig="sha256", san=["good.test"])
    conn = _connector(protocols_ok={"TLSv1.2"}, cert_der=cert)
    prof, finds = TlsScan(connect=conn).run("good.test", 443)
    check("weak 1024-bit key flagged", any("Weak certificate key" in f.title for f in finds), ids(finds))
    check("key_bits recorded", prof.cert.get("key_bits") == 1024, prof.cert.get("key_bits"))


def test_weak_signature_finding_logic():
    # This OpenSSL build won't sign with SHA-1, so exercise the finding logic on a
    # synthetic profile whose parsed cert reports a broken signature hash.
    from deluluscan.netscan.tls import TlsProfile
    prof = TlsProfile(host="good.test", port=443, protocols={"TLSv1.2": True},
                      cipher=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256),
                      cert={"sig_algo": "sha1", "weak_sig": True, "san": ["good.test"],
                            "hostname_mismatch": False, "days_to_expiry": 300})
    finds = TlsScan().to_findings(prof)
    check("weak SHA-1 signature flagged", any("Weak certificate signature" in f.title for f in finds),
          ids(finds))


def test_no_forward_secrecy():
    cert = _make_cert(san=["good.test"])
    conn = _connector(protocols_ok={"TLSv1.2"}, cert_der=cert,
                      cipher=("AES256-GCM-SHA384", "TLSv1.2", 256))  # RSA kx, no PFS
    prof, finds = TlsScan(connect=conn).run("good.test", 443)
    check("no-PFS flagged", any("forward secrecy" in f.title for f in finds), ids(finds))
    conn2 = _connector(protocols_ok={"TLSv1.2"}, cert_der=cert)  # ECDHE default
    _, finds2 = TlsScan(connect=conn2).run("good.test", 443)
    check("PFS cipher not flagged", not any("forward secrecy" in f.title for f in finds2))


def test_tls13_not_flagged_for_pfs():
    # TLS 1.3 ciphers (TLS_AES_256_GCM_SHA384) always have forward secrecy even
    # though the name lacks "ECDHE" — must NOT be flagged (regression).
    cert = _make_cert(san=["good.test"])
    conn = _connector(protocols_ok={"TLSv1.3"}, cert_der=cert,
                      cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))
    prof, finds = TlsScan(connect=conn).run("good.test", 443)
    check("TLS1.3 not flagged for no-PFS", not any("forward secrecy" in f.title for f in finds),
          ids(finds))


def test_no_tls_at_all():
    conn = _connector(protocols_ok=set(), cert_der=b"")
    prof, finds = TlsScan(connect=conn).run("good.test", 443)
    check("no handshake -> error recorded", "no TLS handshake" in prof.error, prof.error)
    check("no handshake -> no crash", isinstance(finds, list))


def test_hostname_matches_helper():
    check("exact match", hostname_matches("a.example.com", ["a.example.com"]))
    check("wildcard match", hostname_matches("a.example.com", ["*.example.com"]))
    check("wildcard no deep match", not hostname_matches("a.b.example.com", ["*.example.com"]))
    check("no match", not hostname_matches("evil.com", ["example.com"]))


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
