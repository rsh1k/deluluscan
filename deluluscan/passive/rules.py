"""Passive-analysis rule set (ZAP passive-scan parity).

Data-driven rules matched against a response's body / headers / URL — no extra
requests, so this can run over *every* response the scanner already collected.
Covers what the headers/ (header+cookie+CORS) and secrets/ (credential patterns)
modules don't: verbose error & stack-trace disclosure, SQL error leakage,
internal-IP/hostname disclosure, directory listing, sensitive data carried in the
URL, exposed debug consoles, and information-bearing HTML comments.

Each rule is high-precision by design (passive findings should be low-noise).
Add coverage by appending a `PassiveRule`.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PassiveRule:
    id: str
    where: str                       # body | header:<name> | url
    pattern: str                     # regex
    vuln_class: str                  # VulnClass value
    severity: str                    # info|low|medium|high|critical
    title: str
    note: str
    cwe: str = ""
    confidence: str = "firm"


RULES: list[PassiveRule] = [
    # -- stack traces / framework error disclosure -------------------------
    PassiveRule("java-stacktrace", "body",
                r"(?:^|\n)\s*at [\w.$]+\([\w.]+\.java:\d+\)|Exception in thread \"",
                "error_handling", "medium", "Java stack trace disclosed",
                "A Java stack trace leaks class names, file paths, and internal structure.",
                "CWE-209"),
    PassiveRule("python-traceback", "body",
                r"Traceback \(most recent call last\):|File \"[^\"]+\", line \d+, in ",
                "error_handling", "medium", "Python traceback disclosed",
                "A Python traceback leaks source paths, framework internals, and logic.",
                "CWE-209"),
    PassiveRule("php-error", "body",
                r"<b>(?:Warning|Fatal error|Notice|Parse error)</b>:|on line <b>\d+</b>|"
                r"Stack trace:\s*#0",
                "error_handling", "medium", "PHP error/warning disclosed",
                "A verbose PHP error leaks absolute paths and code structure.",
                "CWE-209"),
    PassiveRule("ruby-error", "body",
                r"\.rb:\d+:in [`']|ActionController::|RAILS_ENV",
                "error_handling", "medium", "Ruby/Rails error disclosed",
                "A Ruby/Rails error trace leaks gem paths and app internals.",
                "CWE-209"),
    PassiveRule("dotnet-error", "body",
                r"System\.[A-Za-z.]+Exception|Microsoft\.AspNetCore|at System\.\w+\.\w+\(",
                "error_handling", "medium", ".NET exception disclosed",
                "A .NET exception/stack trace leaks framework internals.",
                "CWE-209"),
    PassiveRule("node-error", "body",
                r"at Object\.\<anonymous\> \([^)]+\.js:\d+|node_modules[/\\][^\s]+\.js:\d+",
                "error_handling", "medium", "Node.js stack trace disclosed",
                "A Node.js stack trace leaks server file paths and module structure.",
                "CWE-209"),
    # -- SQL error leakage (passive; complements the active sqli scanner) ---
    PassiveRule("sql-error", "body",
                r"(?i)SQL syntax.*MySQL|PostgreSQL.*ERROR|ORA-\d{5}|SQLSTATE\[|"
                r"Unclosed quotation mark after the character string|"
                r"org\.postgresql\.util\.PSQLException|SQLite3::",
                "info_leak", "medium", "Database error message disclosed",
                "A raw SQL error in the response reveals the DBMS and hints at injection.",
                "CWE-209"),
    # -- exposed debug consoles (interactive = high) -----------------------
    PassiveRule("werkzeug-debugger", "body",
                r"Werkzeug Debugger|The debugger caught an exception|__debugger__",
                "misconfig", "high", "Werkzeug interactive debugger exposed",
                "Flask/Werkzeug debug console allows arbitrary code execution if the PIN is bypassed.",
                "CWE-489"),
    PassiveRule("whoops-symfony", "body",
                r"Whoops\\Handler|Symfony\\Component\\.*Exception|laravel/framework",
                "misconfig", "high", "PHP debug page (Whoops/Symfony) exposed",
                "A framework debug page leaks env, config, and full stack context.",
                "CWE-489"),
    PassiveRule("django-debug", "body",
                r"You're seeing this error because you have <code>DEBUG = True|"
                r"Django Version:|Request Method:.*Request URL:",
                "misconfig", "high", "Django DEBUG=True error page exposed",
                "Django debug page leaks settings, SQL, and environment.",
                "CWE-489"),
    # -- directory listing --------------------------------------------------
    PassiveRule("dir-listing", "body",
                r"<title>Index of /|<h1>Index of /|Directory listing for /",
                "misconfig", "medium", "Directory listing enabled",
                "An auto-index page exposes the file layout and possibly sensitive files.",
                "CWE-548"),
    # -- internal / private host disclosure --------------------------------
    PassiveRule("private-ip", "body",
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
                r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
                "info_leak", "low", "Internal/private IP address disclosed",
                "A private RFC1918 address in the response leaks internal network topology.",
                "CWE-200", "tentative"),
    # -- sensitive data carried in the URL ---------------------------------
    PassiveRule("secret-in-url", "url",
                r"(?i)[?&](?:password|passwd|pwd|token|access_token|api_?key|"
                r"secret|sessionid|session_id|auth)=[^&\s]+",
                "info_leak", "medium", "Sensitive data in URL query string",
                "Secrets in the URL land in logs, history, and Referer headers.",
                "CWE-598"),
    # -- information-bearing HTML comments ---------------------------------
    PassiveRule("html-comment-leak", "body",
                r"<!--[^>]*?(?i:password|passwd|api[_-]?key|secret|todo|fixme|hack|"
                r"username|backdoor|debug|internal)[^>]*?-->",
                "info_leak", "low", "Information-bearing HTML comment",
                "An HTML comment mentions credentials, TODOs, or internal notes.",
                "CWE-615", "tentative"),
]
