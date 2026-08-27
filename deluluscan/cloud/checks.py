"""Cloud posture (CSPM) checks over a COLLECTED inventory — offline, no cloud SDK.

Rather than require live cloud credentials, these checks evaluate a described
inventory (from `aws ... describe-*` JSON, a Prowler/ScoutSuite export, Terraform
state, or your own collector) against high-signal misconfiguration rules — the
same classes Prowler / ScoutSuite flag: public storage, world-open security
groups on sensitive ports, over-permissive IAM (Action:* Resource:*), users
without MFA, root access keys, unencrypted / publicly-reachable databases, and
disabled audit logging. Detection only; findings, not changes.

Inventory shape (all keys optional; robust to missing data):
  aws: {
    s3_buckets:[{name, public:bool, acl_public:bool, policy_public:bool, encrypted:bool}],
    security_groups:[{id, ingress:[{cidr, from_port, to_port, protocol}]}],
    iam:{users:[{name, mfa:bool, access_keys:[{active:bool}]}],
         policies:[{name, document:{Statement:[{Effect,Action,Resource}]}}],
         root_access_keys:bool},
    rds:[{id, publicly_accessible:bool, encrypted:bool}],
    cloudtrail_enabled:bool,
  }
  gcp: {storage_buckets:[{name, public:bool}], firewalls:[{name, source_ranges:[...], allowed:[{ports:[...]}]}]}
  azure:{storage_accounts:[{name, allow_blob_public_access:bool}],
         nsgs:[{name, rules:[{source, dest_port, access}]}]}
"""
from __future__ import annotations

from typing import Optional

from ..models import Finding, Severity, VulnClass

_SEV = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
        "critical": Severity.CRITICAL}

# ports that must never be open to 0.0.0.0/0
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                   6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
                   2379: "etcd", 23: "Telnet", 445: "SMB", 1433: "MSSQL"}
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _f(cls, sev, title, endpoint, desc, detail=None, expl="conditional") -> Finding:
    return Finding(vuln_class=cls, severity=_SEV[sev], title=title, endpoint=endpoint,
                   description=desc, detail=detail or {}, confidence="firm",
                   verdict="true_positive", exploitability=expl)


def _port_range(rule) -> range:
    lo = rule.get("from_port", rule.get("dest_port", 0)) or 0
    hi = rule.get("to_port", rule.get("dest_port", lo)) or lo
    try:
        return range(int(lo), int(hi) + 1)
    except Exception:
        return range(0, 0)


# ---------------------------------------------------------------------------
def check_aws(inv: dict) -> list:
    findings: list[Finding] = []
    # S3
    for b in inv.get("s3_buckets") or []:
        name = b.get("name", "bucket")
        if b.get("public") or b.get("acl_public") or b.get("policy_public"):
            findings.append(_f(VulnClass.INFO_LEAK, "high", "Public S3 bucket", f"s3://{name}",
                "Bucket is publicly accessible (ACL/policy grants to everyone) — data exposure.",
                {"bucket": name, "rule": "aws-s3-public"}, expl="exploitable"))
        if b.get("encrypted") is False:
            findings.append(_f(VulnClass.CRYPTO, "medium", "S3 bucket without encryption",
                f"s3://{name}", "Default encryption is disabled.", {"bucket": name, "rule": "aws-s3-enc"}))
    # Security groups
    for sg in inv.get("security_groups") or []:
        sid = sg.get("id", "sg")
        for rule in sg.get("ingress") or []:
            if rule.get("cidr") in _OPEN_CIDRS:
                all_open = (str(rule.get("protocol")) in ("-1", "all") or
                            (rule.get("from_port") in (0, None) and
                             rule.get("to_port") in (65535, None)))
                if all_open:
                    label = "ALL ports"
                else:
                    ports = _port_range(rule)
                    hit = [p for p in SENSITIVE_PORTS if p in ports]
                    label = ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in hit) if hit else ""
                if label:
                    findings.append(_f(VulnClass.MISCONFIG, "high",
                        f"Security group open to the internet ({label})", sid,
                        f"{sid} allows 0.0.0.0/0 to {label} — exposed to the whole internet.",
                        {"sg": sid, "ports": label, "rule": "aws-sg-open"}, expl="exploitable"))
    # IAM
    iam = inv.get("iam") or {}
    if iam.get("root_access_keys"):
        findings.append(_f(VulnClass.AUTHZ, "critical", "Root account has active access keys", "iam:root",
            "The AWS root user has access keys — a single leak is total account compromise. "
            "Delete them and use IAM roles.", {"rule": "aws-root-keys"}, expl="exploitable"))
    for u in iam.get("users") or []:
        un = u.get("name", "user")
        active = [k for k in (u.get("access_keys") or []) if k.get("active")]
        if active and u.get("mfa") is False:
            findings.append(_f(VulnClass.AUTHZ, "medium", "IAM user without MFA", f"iam:user/{un}",
                f"{un} has active access keys but no MFA.", {"user": un, "rule": "aws-user-nomfa"}))
    for pol in iam.get("policies") or []:
        for stmt in ((pol.get("document") or {}).get("Statement") or []):
            if stmt.get("Effect") == "Allow":
                acts = stmt.get("Action"); res = stmt.get("Resource")
                acts = acts if isinstance(acts, list) else [acts]
                res = res if isinstance(res, list) else [res]
                if "*" in acts and "*" in res:
                    findings.append(_f(VulnClass.AUTHZ, "high",
                        "Over-permissive IAM policy (Action:* Resource:*)", f"iam:policy/{pol.get('name','p')}",
                        "Policy grants all actions on all resources — effectively admin.",
                        {"policy": pol.get("name"), "rule": "aws-iam-star"}, expl="exploitable"))
                    break
    # RDS
    for db in inv.get("rds") or []:
        did = db.get("id", "db")
        if db.get("publicly_accessible"):
            findings.append(_f(VulnClass.MISCONFIG, "high", "RDS instance publicly accessible", f"rds:{did}",
                f"{did} is reachable from the internet.", {"db": did, "rule": "aws-rds-public"}, expl="exploitable"))
        if db.get("encrypted") is False:
            findings.append(_f(VulnClass.CRYPTO, "medium", "RDS instance not encrypted at rest", f"rds:{did}",
                f"{did} storage is unencrypted.", {"db": did, "rule": "aws-rds-enc"}))
    # Audit logging
    if inv.get("cloudtrail_enabled") is False:
        findings.append(_f(VulnClass.LOGGING_FAILURE, "medium", "CloudTrail disabled", "cloudtrail",
            "No account-wide audit trail — attacker actions go unrecorded.", {"rule": "aws-no-cloudtrail"}))
    return findings


def check_gcp(inv: dict) -> list:
    findings: list[Finding] = []
    for b in inv.get("storage_buckets") or []:
        if b.get("public"):
            findings.append(_f(VulnClass.INFO_LEAK, "high", "Public GCS bucket", f"gs://{b.get('name','b')}",
                "Bucket grants allUsers/allAuthenticatedUsers — public data exposure.",
                {"bucket": b.get("name"), "rule": "gcp-gcs-public"}, expl="exploitable"))
    for fw in inv.get("firewalls") or []:
        if set(fw.get("source_ranges") or []) & _OPEN_CIDRS:
            for a in fw.get("allowed") or []:
                ports = a.get("ports") or []
                hit = [int(p) for p in ports if str(p).isdigit() and int(p) in SENSITIVE_PORTS]
                if hit or not ports:
                    lbl = ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in hit) or "ALL ports"
                    findings.append(_f(VulnClass.MISCONFIG, "high",
                        f"GCP firewall open to the internet ({lbl})", f"fw:{fw.get('name','fw')}",
                        "Firewall allows 0.0.0.0/0 to sensitive ports.",
                        {"rule": "gcp-fw-open"}, expl="exploitable"))
                    break
    return findings


def check_azure(inv: dict) -> list:
    findings: list[Finding] = []
    for sa in inv.get("storage_accounts") or []:
        if sa.get("allow_blob_public_access"):
            findings.append(_f(VulnClass.INFO_LEAK, "high", "Azure storage allows public blob access",
                f"storage:{sa.get('name','sa')}", "Public blob access is enabled — data exposure.",
                {"rule": "azure-blob-public"}, expl="exploitable"))
    for nsg in inv.get("nsgs") or []:
        for r in nsg.get("rules") or []:
            if r.get("access") == "Allow" and str(r.get("source")) in ("*", "Internet", "0.0.0.0/0"):
                port = r.get("dest_port")
                try:
                    port = int(port)
                except Exception:
                    port = None
                if port in SENSITIVE_PORTS:
                    findings.append(_f(VulnClass.MISCONFIG, "high",
                        f"NSG opens {port}/{SENSITIVE_PORTS[port]} to the internet", f"nsg:{nsg.get('name','nsg')}",
                        "Network Security Group allows the internet to a sensitive port.",
                        {"rule": "azure-nsg-open"}, expl="exploitable"))
    return findings


PROVIDERS = {"aws": check_aws, "gcp": check_gcp, "azure": check_azure}
