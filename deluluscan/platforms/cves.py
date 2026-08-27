"""Version-gated known-CVE corpus — the Nessus "plugin" model for platforms.

Once a platform profile fingerprints an exact version (via version_path/
version_regex), this maps that version to publicly-known CVEs whose affected
range it falls in. Data-driven: add coverage by appending a `CveRule`.

HONESTY CONTRACT: a version match is a *lead*, not proof. These findings are
graded confidence="firm" (the version genuinely matches a known-vulnerable
range) but exploitability="unknown" — they are NOT live-verified. The report
must say "the running version is in the affected range for CVE-X", never "the
target is exploitable via CVE-X", unless a live probe later confirms it. This
mirrors how a credentialed Nessus check reports version-inferred findings.

Ranges use comma-separated constraints (AND), each `OP VERSION` with OP in
< <= > >= == ; "*" matches any version. Numeric-dotted comparison only (LTS
branch nuances are noted in the summary, not encoded).
"""
from __future__ import annotations

import re
from dataclasses import dataclass


def _ver_tuple(v: str) -> tuple:
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts[:4]) or (0,)


def _cmp(a: tuple, b: tuple) -> int:
    # pad to equal length so (2,4) vs (2,4,2) compares correctly
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


_OPS = {
    "<=": lambda c: c <= 0, ">=": lambda c: c >= 0,
    "==": lambda c: c == 0, "<": lambda c: c < 0, ">": lambda c: c > 0,
}


def version_in_range(version: str, spec: str) -> bool:
    """True if `version` satisfies every constraint in `spec` (AND-joined)."""
    if not version:
        return False
    spec = spec.strip()
    if spec == "*":
        return True
    v = _ver_tuple(version)
    for clause in spec.split(","):
        clause = clause.strip()
        m = re.match(r"(<=|>=|==|<|>)\s*([0-9][0-9.]*)", clause)
        if not m:
            return False
        op, target = m.group(1), _ver_tuple(m.group(2))
        if not _OPS[op](_cmp(v, target)):
            return False
    return True


@dataclass
class CveRule:
    platform: str
    cve: str
    severity: str                    # info|low|medium|high|critical
    affected: str                    # version spec
    summary: str
    cwe: str = ""
    fixed_in: str = ""


# Curated, real, version-gated CVEs for platforms we fingerprint a version on.
CVE_CORPUS: list[CveRule] = [
    # -- Drupal ------------------------------------------------------------
    CveRule("Drupal", "CVE-2018-7600", "critical", "<7.58",
            "Drupalgeddon2: unauthenticated remote code execution via form API.",
            "CWE-20", "7.58 / 8.5.1"),
    CveRule("Drupal", "CVE-2019-6340", "critical", ">=8,<8.6.10",
            "REST module unauthenticated RCE via unserialize on entity endpoints.",
            "CWE-502", "8.6.10 / 8.5.11"),
    # -- Joomla ------------------------------------------------------------
    CveRule("Joomla", "CVE-2023-23752", "high", ">=4.0.0,<4.2.8",
            "Improper access check exposes Joomla webservice config incl. DB creds.",
            "CWE-284", "4.2.8"),
    # -- Apache Tomcat -----------------------------------------------------
    CveRule("Apache Tomcat", "CVE-2020-1938", "critical", "<9.0.31",
            "Ghostcat: AJP request smuggling → file read / potential RCE (also <8.5.51/<7.0.100).",
            "CWE-269", "9.0.31 / 8.5.51 / 7.0.100"),
    CveRule("Apache Tomcat", "CVE-2017-12617", "high", "<9.0.1",
            "JSP upload → RCE when HTTP PUT (readonly=false) is enabled (also <8.5.23).",
            "CWE-434", "9.0.1 / 8.5.23"),
    # -- Spring ------------------------------------------------------------
    CveRule("Spring Boot (Java)", "CVE-2022-22965", "critical", "*",
            "Spring4Shell: RCE via data binding on JDK9+ (verify Spring Framework "
            "<5.2.20/<5.3.18 behind this Boot build).", "CWE-94", "Spring 5.3.18 / 5.2.20"),
    # -- Jenkins -----------------------------------------------------------
    CveRule("Jenkins", "CVE-2024-23897", "critical", "<2.442",
            "Arbitrary file read via the built-in CLI (args4j @-expansion); LTS <2.426.3.",
            "CWE-27", "2.442 / LTS 2.426.3"),
    # -- GitLab ------------------------------------------------------------
    CveRule("GitLab", "CVE-2021-22205", "critical", "<13.10.3",
            "Unauthenticated RCE via ExifTool image parsing (also <13.9.6/<13.8.8).",
            "CWE-94", "13.10.3 / 13.9.6 / 13.8.8"),
    CveRule("GitLab", "CVE-2023-7028", "critical", ">=16.1.0,<16.7.2",
            "Account takeover: password-reset email delivered to unverified address "
            "(also 16.1–16.6 branches).", "CWE-640", "16.7.2 / 16.6.4 / 16.5.6"),
    # -- Grafana -----------------------------------------------------------
    CveRule("Grafana", "CVE-2021-43798", "high", ">=8.0.0,<8.3.1",
            "Directory traversal via plugin path → arbitrary local file read.",
            "CWE-22", "8.3.1 / 8.2.7 / 8.1.8 / 8.0.7"),
    # -- Atlassian ---------------------------------------------------------
    CveRule("Atlassian (Jira/Confluence)", "CVE-2022-26134", "critical", "<7.4.17",
            "Confluence OGNL injection → unauthenticated RCE (multiple 7.x branches).",
            "CWE-917", "7.4.17 / 7.13.7 / 7.18.1"),
    CveRule("Atlassian (Jira/Confluence)", "CVE-2023-22515", "critical", ">=8.0.0,<8.5.2",
            "Confluence broken access control → create admin accounts unauthenticated.",
            "CWE-284", "8.5.2 / 8.4.3 / 8.3.3"),
    # -- Elasticsearch -----------------------------------------------------
    CveRule("Elasticsearch", "CVE-2015-1427", "critical", "<1.4.3",
            "Groovy scripting sandbox bypass → RCE via _search script (also <1.3.8).",
            "CWE-284", "1.4.3 / 1.3.8"),
    # -- Kubernetes --------------------------------------------------------
    CveRule("Kubernetes API", "CVE-2018-1002105", "critical", "<1.10.11",
            "API server proxy upgrade → privilege escalation to any backend "
            "(also <1.11.5/<1.12.3).", "CWE-295", "1.10.11 / 1.11.5 / 1.12.3 / 1.13.0"),
    # -- Magento -----------------------------------------------------------
    CveRule("Magento", "CVE-2022-24086", "critical", "<2.4.4",
            "Adobe Commerce/Magento unauthenticated RCE via template injection in "
            "checkout (also 2.4.3-p1 branch).", "CWE-20", "2.4.3-p2 / 2.4.4"),
]


def match_cves(platform: str, version: str) -> list:
    """Known CVEs whose affected range contains this platform+version."""
    if not version:
        return []
    return [r for r in CVE_CORPUS
            if r.platform == platform and version_in_range(version, r.affected)]
