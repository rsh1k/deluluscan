"""A small, high-impact list of known-vulnerable packages to cross-reference an
SBOM against. Not exhaustive (that is a full vuln DB) — the marquee, still-common
supply-chain CVEs that an SBOM audit should never miss. version ranges reuse
platforms.cves.version_in_range spec syntax."""

# (ecosystem_hint, package_name_lower, affected_spec, cve, severity, summary)
KNOWN_VULN_PACKAGES = [
    ("maven", "log4j-core", "<2.17.1", "CVE-2021-44228", "critical",
     "Log4Shell — unauthenticated RCE via JNDI lookup."),
    ("maven", "log4j", "<2.17.1", "CVE-2021-44228", "critical", "Log4Shell (log4j 1.x is also EOL)."),
    ("maven", "spring-core", "<5.3.18", "CVE-2022-22965", "critical", "Spring4Shell — RCE via data binding."),
    ("maven", "spring-beans", "<5.3.18", "CVE-2022-22965", "critical", "Spring4Shell — RCE via data binding."),
    ("maven", "commons-text", "<1.10.0", "CVE-2022-42889", "critical",
     "Text4Shell — RCE via StringSubstitutor interpolation."),
    ("maven", "commons-collections", "<3.2.2", "CVE-2015-7501", "critical",
     "Unsafe deserialization gadget chain (ysoserial)."),
    ("maven", "snakeyaml", "<2.0", "CVE-2022-1471", "high", "RCE via unsafe YAML deserialization."),
    ("maven", "jackson-databind", "<2.9.10.7", "CVE-2019-14540", "high",
     "Polymorphic deserialization gadget (many CVEs; upgrade)."),
    ("maven", "struts2-core", "<2.5.30", "CVE-2021-31805", "critical", "Apache Struts OGNL RCE."),
    ("npm", "lodash", "<4.17.21", "CVE-2021-23337", "high", "Command injection via template / prototype pollution."),
    ("npm", "minimist", "<1.2.6", "CVE-2021-44906", "high", "Prototype pollution."),
    ("npm", "node-fetch", "<2.6.7", "CVE-2022-0235", "high", "Exposure of sensitive info to a redirect target."),
    ("npm", "async", "<3.2.2", "CVE-2021-43138", "high", "Prototype pollution in mapValues."),
    ("npm", "ejs", "<3.1.7", "CVE-2022-29078", "critical", "Server-side template injection → RCE."),
    ("pypi", "pyyaml", "<5.4", "CVE-2020-14343", "critical", "Arbitrary code execution via full_load/unsafe load."),
    ("pypi", "django", "<3.2.14", "CVE-2022-34265", "high", "SQL injection via Trunc/Extract."),
    ("pypi", "requests", "<2.31.0", "CVE-2023-32681", "medium", "Proxy-Authorization leak on redirect."),
    ("pypi", "cryptography", "<39.0.1", "CVE-2023-23931", "medium", "Cipher.update_into buffer overflow."),
    ("pypi", "werkzeug", "<2.2.3", "CVE-2023-23934", "medium", "Cookie parsing issue."),
    ("gem", "nokogiri", "<1.13.9", "CVE-2022-29181", "high", "Improper handling of unexpected data type."),
]
