"""Tests for cloud posture checks (deluluscan/cloud/, WS-5).

Fully offline. Locks down AWS/GCP/Azure CSPM checks, sensitive-port logic,
SSRF->IMDS credential exposure WITH redaction (no secret leaks into the finding),
clean-inventory behaviour, auto provider detection, and VulnClass mapping.
Run: python3 -m tests.test_cloud
"""
import json
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.cloud import CloudScan, check_aws, check_gcp, check_azure, check_imds  # noqa: E402
from deluluscan.models import VulnClass  # noqa: E402

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


def titles(fs):
    return {f.title for f in fs}


BAD_AWS = {
    "s3_buckets": [{"name": "data", "public": True, "encrypted": False}],
    "security_groups": [{"id": "sg-1", "ingress": [
        {"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"}]}],
    "iam": {"root_access_keys": True,
            "users": [{"name": "bob", "mfa": False, "access_keys": [{"active": True}]}],
            "policies": [{"name": "admin", "document": {"Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]},
    "rds": [{"id": "db1", "publicly_accessible": True, "encrypted": False}],
    "cloudtrail_enabled": False,
}

GOOD_AWS = {
    "s3_buckets": [{"name": "data", "public": False, "encrypted": True}],
    "security_groups": [{"id": "sg-1", "ingress": [
        {"cidr": "10.0.0.0/8", "from_port": 22, "to_port": 22, "protocol": "tcp"},
        {"cidr": "0.0.0.0/0", "from_port": 443, "to_port": 443, "protocol": "tcp"}]}],
    "iam": {"root_access_keys": False,
            "users": [{"name": "bob", "mfa": True, "access_keys": [{"active": True}]}],
            "policies": [{"name": "ro", "document": {"Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data/*"}]}}]},
    "rds": [{"id": "db1", "publicly_accessible": False, "encrypted": True}],
    "cloudtrail_enabled": True,
}


def test_aws_bad_inventory():
    t = titles(check_aws(BAD_AWS))
    for expect in ["Public S3 bucket", "S3 bucket without encryption",
                   "Security group open to the internet (22/SSH)",
                   "Root account has active access keys", "IAM user without MFA",
                   "Over-permissive IAM policy (Action:* Resource:*)",
                   "RDS instance publicly accessible", "RDS instance not encrypted at rest",
                   "CloudTrail disabled"]:
        check(f"AWS flags: {expect}", expect in t, t)


def test_aws_good_inventory_is_clean():
    fs = check_aws(GOOD_AWS)
    check("hardened AWS inventory yields no findings", len(fs) == 0, [f.title for f in fs])


def test_sensitive_port_logic():
    # 0.0.0.0/0 to a NON-sensitive port (8080) should NOT flag
    inv = {"security_groups": [{"id": "sg", "ingress": [
        {"cidr": "0.0.0.0/0", "from_port": 8080, "to_port": 8080, "protocol": "tcp"}]}]}
    check("open non-sensitive port is not flagged", len(check_aws(inv)) == 0)
    # all-ports (-1) open should flag
    inv2 = {"security_groups": [{"id": "sg", "ingress": [
        {"cidr": "0.0.0.0/0", "from_port": 0, "to_port": 65535, "protocol": "-1"}]}]}
    check("all-ports-open is flagged", any("ALL ports" in t for t in titles(check_aws(inv2))))


def test_gcp_and_azure():
    g = titles(check_gcp({"storage_buckets": [{"name": "b", "public": True}],
                          "firewalls": [{"name": "fw", "source_ranges": ["0.0.0.0/0"],
                                         "allowed": [{"ports": ["3306"]}]}]}))
    check("GCP public bucket flagged", "Public GCS bucket" in g)
    check("GCP open firewall flagged", any("firewall open" in t for t in g), g)
    a = titles(check_azure({"storage_accounts": [{"name": "sa", "allow_blob_public_access": True}],
                            "nsgs": [{"name": "nsg", "rules": [
                                {"source": "Internet", "dest_port": "3389", "access": "Allow"}]}]}))
    check("Azure public blob flagged", "Azure storage allows public blob access" in a)
    check("Azure NSG open RDP flagged", any("3389/RDP" in t for t in a), a)


def test_imds_credential_exposure_and_redaction():
    def fake(url, headers):
        if url.endswith("/security-credentials/"):
            return 200, "ec2-role"
        if "security-credentials/ec2-role" in url:
            return 200, ('{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":'
                         '"SUPERSECRETVALUE","Token":"tok"}')
        return 404, ""
    fs = check_imds(fake, clouds=("aws",))
    check("AWS IMDS credential exposure detected", len(fs) == 1)
    check("finding is critical/exploitable",
          fs and fs[0].severity.value == "critical" and fs[0].exploitability == "exploitable")
    check("credential value is NOT leaked into the finding",
          "SUPERSECRETVALUE" not in json.dumps(fs[0].to_dict(), default=str))

    fs2 = check_imds(lambda u, h: (404, ""), clouds=("aws",))
    check("no metadata service -> no finding", len(fs2) == 0)


def test_imds_gcp_azure():
    def gcp(url, headers):
        return (200, '{"access_token":"ya29.x","expires_in":3599}') if "metadata.google" in url else (404, "")
    check("GCP token exposure detected", len(check_imds(gcp, clouds=("gcp",))) == 1)

    def az(url, headers):
        return (200, '{"access_token":"eyJ0"}') if "oauth2/token" in url else (404, "")
    check("Azure token exposure detected", len(check_imds(az, clouds=("azure",))) == 1)


def test_engine_autodetect_and_file():
    scan = CloudScan()
    fs = scan.scan_inventory({"aws": BAD_AWS})
    check("engine auto-detects the aws provider key", any("S3" in f.title for f in fs))
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"aws": GOOD_AWS}, f); path = f.name
    try:
        check("engine scan_file on a good inventory is clean", len(scan.scan_file(path)) == 0)
    finally:
        os.unlink(path)


def test_class_mapping():
    fs = check_aws(BAD_AWS)
    by = {f.title: f.vuln_class for f in fs}
    check("public S3 -> info_leak", by["Public S3 bucket"] == VulnClass.INFO_LEAK)
    check("root keys -> authz", by["Root account has active access keys"] == VulnClass.AUTHZ)
    check("unencrypted S3 -> crypto", by["S3 bucket without encryption"] == VulnClass.CRYPTO)
    check("no cloudtrail -> logging_failure", by["CloudTrail disabled"] == VulnClass.LOGGING_FAILURE)


if __name__ == "__main__":
    for fn in [v for v in list(globals().values())
               if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try:
            fn()
        except Exception as e:
            import traceback
            _FAIL += 1
            print(f"FAIL  {fn.__name__}  [exception: {e}]")
            traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed")
    sys.exit(1 if _FAIL else 0)
