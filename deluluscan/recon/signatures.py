"""Recon signatures — web tech/library fingerprints, known-vulnerable-library
rules, and content-discovery wordlists.

Kept as data so coverage grows without touching engine logic. Fingerprints are
passive (they read markup/headers a normal client already receives); the
vuln-library rules map a detected library+version to a PUBLICLY known issue so
the scanner knows where to look deeper — detection only, no exploitation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TechSig:
    name: str
    category: str                     # js-lib | framework | server | cms | analytics | waf | build
    # each detector: ("where", regex). where ∈ header:<h> | header-any | cookie | body | script-src | meta-generator
    detectors: list = field(default_factory=list)
    version_re: Optional[str] = None  # optional regex with group(1) = version, run over body+script srcs


# --- frontend libraries / frameworks / stacks ------------------------------
TECH_SIGS: list[TechSig] = [
    TechSig("jQuery", "js-lib",
            [("script-src", r"jquery[.-]?([0-9]+\.[0-9]+[0-9.]*)?(?:\.min)?\.js"),
             ("body", r"jQuery\.fn\.jquery")],
            version_re=r"jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)"),
    TechSig("jQuery UI", "js-lib", [("script-src", r"jquery-ui[.-]?([0-9.]+)?")],
            version_re=r"jquery-ui[.-]([0-9]+\.[0-9]+\.[0-9]+)"),
    TechSig("Bootstrap", "framework",
            [("script-src", r"bootstrap(?:\.bundle)?(?:\.min)?\.js"),
             ("body", r"bootstrap(?:\.min)?\.css")],
            version_re=r"bootstrap[/@-]([0-9]+\.[0-9]+\.[0-9]+)"),
    TechSig("Lodash", "js-lib", [("script-src", r"lodash(?:\.min)?\.js")],
            version_re=r"lodash[@-]([0-9]+\.[0-9]+\.[0-9]+)"),
    TechSig("AngularJS", "framework", [("body", r"ng-(?:app|version|controller)")],
            version_re=r'ng-version="([0-9]+\.[0-9]+\.[0-9]+)"'),
    TechSig("React", "framework", [("body", r"data-reactroot|__REACT_DEVTOOLS|react(?:-dom)?(?:\.min)?\.js")]),
    TechSig("Next.js", "framework", [("body", r"__NEXT_DATA__"), ("header:x-powered-by", r"Next\.js")]),
    TechSig("Vue.js", "framework", [("body", r"data-v-[0-9a-f]{8}|__vue__|vue(?:\.min)?\.js")]),
    TechSig("Moment.js", "js-lib", [("script-src", r"moment(?:\.min)?\.js")],
            version_re=r"moment[@-]([0-9]+\.[0-9]+\.[0-9]+)"),
    TechSig("DOMPurify", "js-lib", [("script-src", r"purify(?:\.min)?\.js|dompurify")]),
    # servers / platforms / cms
    TechSig("nginx", "server", [("header:server", r"nginx")], version_re=r"nginx/([0-9.]+)"),
    TechSig("Apache", "server", [("header:server", r"apache")], version_re=r"Apache/([0-9.]+)"),
    TechSig("Tomcat", "server", [("header:server", r"(?i)coyote|tomcat")], version_re=r"Tomcat/([0-9.]+)"),
    TechSig("Express", "framework", [("header:x-powered-by", r"Express")]),
    TechSig("PHP", "server", [("header:x-powered-by", r"PHP")], version_re=r"PHP/([0-9.]+)"),
    TechSig("WordPress", "cms", [("body", r"/wp-content/|/wp-includes/"), ("meta-generator", r"WordPress")],
            version_re=r'WordPress ([0-9.]+)'),
    TechSig("Drupal", "cms", [("header-any", r"(?i)drupal"), ("meta-generator", r"Drupal")]),
    TechSig("Cloudflare", "waf", [("header:server", r"cloudflare"), ("header-any", r"cf-ray")]),
    TechSig("Akamai", "waf", [("header-any", r"(?i)akamai")]),
]


@dataclass
class VulnLibRule:
    lib: str
    max_vulnerable: Optional[str]      # versions < this are affected (None -> any version, e.g. EOL)
    identifier: str                    # CVE or advisory id
    note: str
    severity: str = "medium"


# versions strictly LESS THAN max_vulnerable are flagged.
VULN_LIB_RULES: list[VulnLibRule] = [
    VulnLibRule("jQuery", "3.5.0", "CVE-2020-11022/11023",
                "jQuery < 3.5.0 — XSS via htmlPrefilter in .html()/.append().", "medium"),
    VulnLibRule("jQuery", "1.9.0", "CVE-2012-6708",
                "jQuery < 1.9 — selector-based XSS; very outdated.", "high"),
    VulnLibRule("jQuery UI", "1.13.2", "CVE-2022-31160",
                "jQuery UI < 1.13.2 — XSS in the checkboxradio widget.", "medium"),
    VulnLibRule("Bootstrap", "3.4.1", "CVE-2019-8331",
                "Bootstrap < 3.4.1 (or 4.x < 4.3.1) — XSS in data-* tooltip/popover.", "medium"),
    VulnLibRule("Lodash", "4.17.21", "CVE-2021-23337 / CVE-2020-8203",
                "Lodash < 4.17.21 — command injection / prototype pollution.", "high"),
    VulnLibRule("Moment.js", "2.29.4", "CVE-2022-31129",
                "Moment.js < 2.29.4 — ReDoS in string parsing.", "medium"),
    VulnLibRule("AngularJS", None, "EOL",
                "AngularJS (1.x) is end-of-life (unsupported since 2022) — many client-side "
                "template-injection/XSS classes; migrate to a supported framework.", "medium"),
]


def _ver_tuple(v: str):
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts[:4]) or (0,)


def lib_is_vulnerable(lib: str, version: Optional[str]) -> list[VulnLibRule]:
    """Return the rules a detected library+version trips."""
    hits = []
    for r in VULN_LIB_RULES:
        if r.lib != lib:
            continue
        if r.max_vulnerable is None:        # EOL / any version
            hits.append(r)
        elif version and _ver_tuple(version) < _ver_tuple(r.max_vulnerable):
            hits.append(r)
    return hits


# --- content discovery ------------------------------------------------------
# High-signal files whose mere presence is interesting (secrets/exposure/recon).
INTERESTING_PATHS: list[tuple[str, str]] = [
    ("/.git/HEAD", "exposed .git repository (source/secret disclosure)"),
    ("/.git/config", "exposed .git config"),
    ("/.env", "exposed environment file (credentials)"),
    ("/.svn/entries", "exposed .svn metadata"),
    ("/.DS_Store", "macOS directory listing metadata"),
    ("/backup.zip", "exposed backup archive"),
    ("/config.php.bak", "exposed backup of config"),
    ("/phpinfo.php", "phpinfo() disclosure"),
    ("/server-status", "Apache mod_status disclosure"),
    ("/actuator", "Spring Boot Actuator (may expose env/heapdump)"),
    ("/actuator/env", "Spring Actuator env (secrets)"),
    ("/.well-known/security.txt", "security.txt (informational)"),
    ("/robots.txt", "robots.txt (path hints)"),
    ("/sitemap.xml", "sitemap (endpoint hints)"),
    ("/swagger.json", "Swagger/OpenAPI spec (API surface)"),
    ("/openapi.json", "OpenAPI spec (API surface)"),
    ("/graphql", "GraphQL endpoint (introspection surface)"),
    ("/api", "API root"),
    ("/admin", "admin surface"),
    ("/.aws/credentials", "exposed AWS credentials"),
    ("/wp-login.php", "WordPress login"),
]

# Small, generic directory wordlist (kept short; a full list is a wordlist file).
DIR_WORDLIST: list[str] = [
    "admin", "api", "app", "assets", "backup", "config", "dashboard", "dev",
    "docs", "files", "images", "internal", "login", "private", "static",
    "test", "tmp", "upload", "uploads", "user", "v1", "v2", ".git", ".well-known",
]
