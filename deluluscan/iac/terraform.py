"""Static Terraform (HCL) misconfiguration checks — Checkov-lite, dependency-free.

Extracts resource blocks by brace-matching and applies high-signal rules for the
recurring cloud-IaC failure categories: public storage, network rules open to the
world, missing encryption, wildcard IAM, IMDSv1, and hardcoded secrets. Regex-
based (no HCL parser) so it stays dependency-free; tuned for precision over an
exhaustive policy set. Detection only, offline.
"""
from __future__ import annotations

import re

from ..models import Finding, RequestRecord, Severity, VulnClass

_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL}
_RES_HEADER = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.I)


def _blocks(text: str):
    """Yield (rtype, name, body) for each resource block via brace matching."""
    for m in _RES_HEADER.finditer(text):
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        yield m.group(1), m.group(2), text[start:i - 1]


def _f(sev, title, desc, source, rtype, name, rule, cwe="CWE-1032"):
    ep = f"{source}:{rtype}.{name}"
    return Finding(vuln_class=VulnClass.MISCONFIG, severity=_SEV[sev], title=title,
                   endpoint=ep, description=desc,
                   evidence=[RequestRecord(method="IAC", url=ep, identity="anon", status=0, elapsed_ms=0.0)],
                   confidence="firm", verdict="likely_true_positive", exploitability="conditional",
                   detail={"rule": rule, "resource": f"{rtype}.{name}", "cwe": cwe,
                           "file": source, "source": "iac.terraform"})


_OPEN_CIDR = re.compile(r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"', re.I)
_SENSITIVE_PORT = re.compile(r'(from_port\s*=\s*(22|3389|3306|5432|6379|9200|27017|0)\b)|(to_port\s*=\s*(22|3389))', re.I)
_SECRET_LIKE = re.compile(r'(?i)\b(password|secret|access_key|secret_key|private_key|api_key|token)\s*=\s*"[^"${}\s]{6,}"')


def analyze_terraform(text: str, source: str = "main.tf") -> list:
    out: list = []
    for rtype, name, body in _blocks(text or ""):
        t = rtype.lower()

        # ---- public S3 ----
        if t == "aws_s3_bucket":
            if re.search(r'acl\s*=\s*"public-read(-write)?"', body, re.I):
                out.append(_f("high", "Public S3 bucket ACL",
                    f"aws_s3_bucket.{name} sets a public-read/-write ACL — the bucket is world-readable.",
                    source, rtype, name, "tf-s3-public-acl", "CWE-284"))
        if t == "aws_s3_bucket_public_access_block":
            if re.search(r'block_public_acls\s*=\s*false', body, re.I) or \
               re.search(r'restrict_public_buckets\s*=\s*false', body, re.I):
                out.append(_f("high", "S3 public-access block disabled",
                    f"{name} disables an S3 public-access-block control, allowing public bucket policies/ACLs.",
                    source, rtype, name, "tf-s3-pab-off", "CWE-284"))

        # ---- open security group ----
        if t in ("aws_security_group", "aws_security_group_rule") and _OPEN_CIDR.search(body):
            sev = "high" if _SENSITIVE_PORT.search(body) else "medium"
            out.append(_f(sev, "Security group open to 0.0.0.0/0",
                f"{rtype}.{name} allows ingress from 0.0.0.0/0"
                + (" on a sensitive/admin port (SSH/RDP/DB)" if sev == "high" else "")
                + " — exposed to the whole internet.", source, rtype, name, "tf-sg-open", "CWE-284"))

        # ---- missing/disabled encryption ----
        if t in ("aws_db_instance", "aws_rds_cluster", "aws_ebs_volume", "aws_dynamodb_table") \
                and re.search(r'(storage_encrypted|encrypted)\s*=\s*false', body, re.I):
            out.append(_f("high", f"Unencrypted {rtype}",
                f"{rtype}.{name} sets encryption = false — data at rest is stored unencrypted.",
                source, rtype, name, "tf-unencrypted", "CWE-311"))
        if t in ("aws_db_instance", "aws_rds_cluster") and re.search(r'publicly_accessible\s*=\s*true', body, re.I):
            out.append(_f("high", "Publicly accessible database",
                f"{rtype}.{name} is publicly_accessible = true — the DB is reachable from the internet.",
                source, rtype, name, "tf-db-public", "CWE-284"))

        # ---- IMDSv1 allowed (SSRF -> credential theft) ----
        if t in ("aws_instance", "aws_launch_template") and re.search(r'http_tokens\s*=\s*"optional"', body, re.I):
            out.append(_f("medium", "IMDSv1 allowed (metadata service not hardened)",
                f"{rtype}.{name} sets metadata http_tokens = optional — IMDSv1 is permitted, so an SSRF "
                "can read instance credentials. Require IMDSv2 (http_tokens = \"required\").",
                source, rtype, name, "tf-imdsv1", "CWE-918"))

        # ---- wildcard IAM ----
        if "iam" in t and re.search(r'"Action"\s*:\s*"\*"', body) and re.search(r'"Resource"\s*:\s*"\*"', body):
            out.append(_f("high", "Wildcard IAM policy (Action:* on Resource:*)",
                f"{rtype}.{name} grants Action \"*\" on Resource \"*\" — full administrative access; "
                "scope it to the minimum needed.", source, rtype, name, "tf-iam-wildcard", "CWE-269"))

        # ---- hardcoded secret ----
        m = _SECRET_LIKE.search(body)
        if m:
            out.append(_f("high", "Hardcoded secret in Terraform",
                f"{rtype}.{name} contains a hardcoded credential ({m.group(1)}) — move it to a variable/"
                "secret store; committed IaC secrets leak into VCS history.",
                source, rtype, name, "tf-hardcoded-secret", "CWE-798"))
    return out
