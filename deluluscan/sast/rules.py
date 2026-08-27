"""Lightweight SAST rule corpus — high-signal dangerous-code patterns per language.

Detection only: each rule flags a risky construct for a human to review (with
file:line evidence). Kept as data so coverage grows without engine changes.
Patterns are deliberately specific to keep false positives low; secrets are
handled separately by `deluluscan.secrets`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class SastRule:
    id: str
    langs: tuple            # file extensions this applies to (without dot); () = all
    pattern: re.Pattern
    vuln_class: str
    severity: str
    message: str
    remediation: str = ""


def _r(p):
    return re.compile(p)


RULES = [
    # ---- Python ----------------------------------------------------------
    SastRule("py-eval-exec", ("py",), _r(r"\b(eval|exec)\s*\("), "misconfig", "high",
             "Use of eval()/exec() on possibly-tainted input enables code injection.",
             "Avoid eval/exec; use ast.literal_eval or explicit dispatch."),
    SastRule("py-os-system", ("py",), _r(r"\bos\.system\s*\("), "misconfig", "high",
             "os.system() invokes a shell — command injection if input is tainted.",
             "Use subprocess.run([...]) without shell=True."),
    SastRule("py-shell-true", ("py",), _r(r"subprocess\.(?:run|call|Popen|check_output)\([^)]*shell\s*=\s*True"),
             "misconfig", "high", "subprocess with shell=True is command-injection-prone.",
             "Pass an argument list and shell=False."),
    SastRule("py-pickle", ("py",), _r(r"\bpickle\.loads?\s*\("), "supply_chain", "high",
             "pickle.load/loads on untrusted data executes arbitrary code.",
             "Use JSON or a safe serialization format for untrusted input."),
    SastRule("py-yaml-load", ("py",), _r(r"\byaml\.load\s*\((?![^)]*Safe)"), "supply_chain", "high",
             "yaml.load without SafeLoader can construct arbitrary objects.",
             "Use yaml.safe_load()."),
    SastRule("py-flask-debug", ("py",), _r(r"\.run\([^)]*debug\s*=\s*True"), "misconfig", "medium",
             "Flask debug=True exposes the Werkzeug console (RCE) in production.",
             "Disable debug in production."),
    SastRule("py-sql-format", ("py",), _r(r'(?i)(execute|executemany)\s*\(\s*[f"\'].*(%s.*%|\+|\.format|\{)'),
             "sqli", "high", "SQL built with string formatting/concatenation — SQL injection.",
             "Use parameterized queries (placeholders), never string interpolation."),
    SastRule("py-tls-verify-false", ("py",), _r(r"verify\s*=\s*False"), "crypto", "medium",
             "TLS certificate verification disabled (verify=False) — MITM risk.",
             "Verify certificates; pin a CA bundle if needed."),
    SastRule("py-weak-hash", ("py",), _r(r"hashlib\.(md5|sha1)\s*\("), "crypto", "low",
             "MD5/SHA1 are weak; unsafe for passwords/signatures.",
             "Use SHA-256+; for passwords use bcrypt/argon2/scrypt."),
    # ---- JavaScript / TypeScript ----------------------------------------
    SastRule("js-eval", ("js", "ts", "jsx", "tsx"), _r(r"\beval\s*\("), "misconfig", "high",
             "eval() executes arbitrary JS — injection risk.", "Avoid eval; parse explicitly."),
    SastRule("js-new-function", ("js", "ts", "jsx", "tsx"), _r(r"\bnew\s+Function\s*\("), "misconfig", "high",
             "new Function() is eval-equivalent.", "Avoid dynamic code construction."),
    SastRule("js-child-exec", ("js", "ts"), _r(r"child_process[.\s]*\.?\s*exec\s*\("), "misconfig", "high",
             "child_process.exec runs a shell — command injection.", "Use execFile/spawn with an arg array."),
    SastRule("js-dang-html", ("js", "ts", "jsx", "tsx"), _r(r"dangerouslySetInnerHTML"), "xss", "medium",
             "dangerouslySetInnerHTML injects raw HTML — XSS if unsanitized.",
             "Sanitize (DOMPurify) or avoid raw HTML."),
    SastRule("js-innerhtml", ("js", "ts", "jsx", "tsx"), _r(r"\.innerHTML\s*="), "xss", "medium",
             "Assigning innerHTML with dynamic data is an XSS sink.",
             "Use textContent or sanitize the HTML."),
    SastRule("js-document-write", ("js", "ts"), _r(r"document\.write\s*\("), "xss", "low",
             "document.write with dynamic data is an XSS sink.", "Build DOM nodes safely."),
    # ---- Java ------------------------------------------------------------
    SastRule("java-runtime-exec", ("java",), _r(r"Runtime\.getRuntime\(\)\.exec\s*\("), "misconfig", "high",
             "Runtime.exec with tainted input — command injection.", "Use ProcessBuilder with a fixed arg list."),
    SastRule("java-objectinputstream", ("java",), _r(r"\bObjectInputStream\b"), "supply_chain", "high",
             "Java native deserialization (ObjectInputStream) of untrusted data → RCE.",
             "Avoid native deserialization; use a safe format + allowlist."),
    SastRule("java-weak-cipher", ("java",), _r(r'Cipher\.getInstance\(\s*"(?:DES|RC4|.*ECB)'), "crypto", "medium",
             "Weak cipher/mode (DES/RC4/ECB).", "Use AES-GCM (or AES-CBC with HMAC)."),
    SastRule("java-sql-concat", ("java",), _r(r'(?i)(statement|executeQuery|executeUpdate)\s*\(\s*"[^"]*"\s*\+'),
             "sqli", "high", "SQL built by string concatenation — SQL injection.",
             "Use PreparedStatement with bind parameters."),
    # ---- generic ---------------------------------------------------------
    SastRule("generic-private-key-file", (), _r(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
             "crypto", "critical", "A private key is committed in source.",
             "Remove it, rotate the key, and load secrets from a vault/env."),
]
