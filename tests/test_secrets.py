"""Tests for secret/credential exposure scanning (deluluscan/secrets/)."""
import os, sys, json, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from deluluscan.secrets import scan_text, SecretScan  # noqa: E402
from deluluscan.models import VulnClass  # noqa: E402
_PASS = 0; _FAIL = 0
def check(n, c, d=""):
    global _PASS, _FAIL
    if c: _PASS += 1; print(f"PASS  {n}")
    else: _FAIL += 1; print(f"FAIL  {n}  [{d}]")
def names(fs): return {f.detail["rule"] for f in fs}

def test_detects_provider_secrets():
    blob = ("AKIAIOSFODNN7EXAMPLE ghp_" + "a"*36 + " AIza" + "b"*35 +
            " sk_live_" + "c"*24 + " -----BEGIN RSA PRIVATE KEY-----")
    n = names(scan_text(blob, "app.js"))
    for rule in ["AWS Access Key ID", "GitHub Token", "Google API Key",
                 "Stripe Live Key", "Private Key"]:
        check(f"detects {rule}", rule in n, n)

def test_redaction_no_raw_secret():
    fs = scan_text("AKIAIOSFODNN7EXAMPLE", "x")
    check("finding is produced", len(fs) == 1)
    check("raw secret not in finding json",
          "AKIAIOSFODNN7EXAMPLE" not in json.dumps(fs[0].to_dict(), default=str))
    check("masked value present", "…" in fs[0].detail["masked"] or "***" in fs[0].detail["masked"])

def test_private_key_is_crypto_and_critical():
    fs = scan_text("-----BEGIN OPENSSH PRIVATE KEY-----", "x")
    check("private key -> crypto/critical",
          fs and fs[0].vuln_class == VulnClass.CRYPTO and fs[0].severity.value == "critical")

def test_entropy_gate_reduces_false_positives():
    # a generic assignment with a LOW-entropy value should be skipped
    lo = 'apiKey: "aaaaaaaaaaaaaaaaaaaa"'
    check("low-entropy generic value skipped", scan_text(lo) == [], scan_text(lo))
    hi = 'apiKey: "kJ8sHvN2pQ7wXcR4tYuIoP1aSdFgHjK"'
    check("high-entropy generic value flagged", len(scan_text(hi)) == 1)

def test_no_false_positive_on_prose():
    check("plain prose yields nothing",
          scan_text("The quick brown fox jumps over the lazy dog. Nothing secret here.") == [])

def test_dedup_same_secret():
    fs = scan_text("AKIAIOSFODNN7EXAMPLE and again AKIAIOSFODNN7EXAMPLE", "x")
    check("same secret reported once", len(fs) == 1)

def test_engine_scans_linked_js():
    pages = {
        "https://t/": (200, '<html><script src="/static/app.js"></script>'
                            '<script src="https://cdn.other.com/x.js"></script></html>'),
        "https://t/static/app.js": (200, 'const K="AKIAIOSFODNN7EXAMPLE";'),
    }
    def fetch(u): return pages.get(u, (404, ""))
    fs = SecretScan().scan_site(fetch, "https://t/")
    check("engine finds secret in same-origin JS", any(f.endpoint == "https://t/static/app.js" for f in fs))
    check("engine did not fetch cross-origin JS", all("cdn.other.com" not in f.endpoint for f in fs))

if __name__ == "__main__":
    for fn in [v for v in list(globals().values()) if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try: fn()
        except Exception as e:
            import traceback; _FAIL += 1; print(f"FAIL  {fn.__name__}  [exc: {e}]"); traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed"); sys.exit(1 if _FAIL else 0)
