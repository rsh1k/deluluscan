"""High-signal secret/credential patterns for response & JS scanning.

Each rule targets a provider-specific shape (low false positives). The `entropy`
gate on generic rules avoids flagging obvious non-secrets. Matched secret values
are ALWAYS masked before they enter a finding — the tool proves exposure without
storing the secret.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass
class SecretRule:
    name: str
    provider: str
    pattern: re.Pattern
    severity: str = "high"
    min_entropy: float = 0.0        # 0 = no entropy gate (pattern is specific enough)
    group: int = 0                  # capture group holding the secret span


RULES = [
    SecretRule("AWS Access Key ID", "aws", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "high"),
    SecretRule("AWS Secret Access Key", "aws",
               re.compile(r"(?i)aws.{0,20}?(?:secret|key).{0,5}?[=:\"']\s*([A-Za-z0-9/+]{40})"),
               "high", group=1),
    SecretRule("GitHub Token", "github", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b"), "high"),
    SecretRule("GitHub Fine-grained PAT", "github", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})\b"), "high"),
    SecretRule("Slack Token", "slack", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), "high"),
    SecretRule("Slack Webhook", "slack",
               re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,})"), "medium"),
    SecretRule("Google API Key", "google", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), "high"),
    SecretRule("Stripe Live Key", "stripe", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"), "critical"),
    SecretRule("Private Key", "generic",
               re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)"), "critical"),
    SecretRule("JWT", "generic",
               re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "medium"),
    SecretRule("Google OAuth Client Secret", "google",
               re.compile(r"\b(GOCSPX-[A-Za-z0-9_-]{20,})\b"), "high"),
    SecretRule("Twilio API Key", "twilio", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), "high"),
    SecretRule("Generic API key/secret assignment", "generic",
               re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
                          r"client[_-]?secret|password)\s*[=:]\s*[\"']([A-Za-z0-9_\-./+]{16,})[\"']"),
               "medium", min_entropy=3.0, group=1),
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def mask(secret: str) -> str:
    s = secret or ""
    if len(s) <= 8:
        return s[:2] + "***"
    return f"{s[:4]}…{s[-2:]} (len {len(s)})"
