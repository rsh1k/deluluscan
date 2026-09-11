"""Offline tests for Terraform + CloudFormation IaC scanning."""
from __future__ import annotations

import os, tempfile

from deluluscan.iac import IacScan, analyze_terraform, analyze_cloudformation
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")

def rules(f): return {x.detail["rule"] for x in f}


def test_terraform_public_s3_and_open_sg():
    tf = ('resource "aws_s3_bucket" "d" { acl = "public-read" }\n'
          'resource "aws_security_group" "w" { ingress { from_port = 22 to_port = 22 '
          'cidr_blocks = ["0.0.0.0/0"] } }')
    f = analyze_terraform(tf, "main.tf")
    check("public S3 ACL flagged", "tf-s3-public-acl" in rules(f), rules(f))
    sg = next((x for x in f if x.detail["rule"] == "tf-sg-open"), None)
    check("open SG on port 22 -> HIGH", sg and sg.severity == Severity.HIGH, sg and sg.severity)


def test_terraform_encryption_imds_secret():
    tf = ('resource "aws_db_instance" "db" { storage_encrypted = false publicly_accessible = true '
          'password = "hunter2pass" }\n'
          'resource "aws_instance" "a" { metadata_options { http_tokens = "optional" } }')
    r = rules(analyze_terraform(tf, "db.tf"))
    check("unencrypted DB", "tf-unencrypted" in r, r)
    check("public DB", "tf-db-public" in r, r)
    check("hardcoded secret", "tf-hardcoded-secret" in r, r)
    check("IMDSv1", "tf-imdsv1" in r, r)


def test_terraform_wildcard_iam():
    tf = ('resource "aws_iam_role_policy" "p" { policy = <<EOF\n'
          '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\nEOF\n}')
    check("wildcard IAM flagged", "tf-iam-wildcard" in rules(analyze_terraform(tf, "iam.tf")))


def test_terraform_clean():
    tf = 'resource "aws_s3_bucket" "s" { acl = "private" }\nresource "aws_db_instance" "d" { storage_encrypted = true }'
    check("hardened terraform -> no findings", analyze_terraform(tf, "ok.tf") == [], [x.title for x in analyze_terraform(tf, "ok.tf")])


def test_terraform_gcp():
    tf = ('resource "google_storage_bucket_iam_member" "p" { role = "roles/viewer" member = "allUsers" }\n'
          'resource "google_compute_firewall" "fw" { source_ranges = ["0.0.0.0/0"] allow { ports = ["22"] } }\n'
          'resource "google_sql_database_instance" "db" { authorized_networks { value = "0.0.0.0/0" } }\n')
    r = rules(analyze_terraform(tf, "gcp.tf"))
    check("gcp public bucket", "tf-gcp-public-bucket" in r, r)
    check("gcp firewall open", "tf-gcp-fw-open" in r, r)
    check("gcp public sql", "tf-gcp-sql-public" in r, r)
    fw = next(x for x in analyze_terraform(tf, "gcp.tf") if x.detail["rule"] == "tf-gcp-fw-open")
    check("gcp firewall on port 22 -> HIGH", fw.severity == Severity.HIGH, fw.severity)


def test_terraform_azure():
    tf = ('resource "azurerm_storage_container" "c" { container_access_type = "blob" }\n'
          'resource "azurerm_network_security_rule" "r" { access = "Allow" source_address_prefix = "*" '
          'destination_port_range = "3389" }\n'
          'resource "azurerm_kubernetes_cluster" "aks" { role_based_access_control_enabled = false }\n'
          'resource "azurerm_storage_account" "sa" { enable_https_traffic_only = false }\n')
    r = rules(analyze_terraform(tf, "az.tf"))
    check("azure public container", "tf-az-container-public" in r, r)
    check("azure nsg open", "tf-az-nsg-open" in r, r)
    check("azure aks no-rbac", "tf-az-aks-norbac" in r, r)
    check("azure storage http", "tf-az-storage-http" in r, r)


def test_gcp_azure_clean():
    tf = ('resource "google_storage_bucket" "b" { uniform_bucket_level_access = true }\n'
          'resource "azurerm_storage_container" "c" { container_access_type = "private" }\n')
    check("hardened GCP/Azure -> no findings", analyze_terraform(tf, "ok.tf") == [],
          [x.title for x in analyze_terraform(tf, "ok.tf")])


def test_cloudformation_yaml_with_intrinsics():
    cfn = ("Resources:\n"
           "  D: { Type: AWS::S3::Bucket, Properties: { AccessControl: PublicRead } }\n"
           "  DB:\n"
           "    Type: AWS::RDS::DBInstance\n"
           "    Properties: { StorageEncrypted: false, MasterUserPassword: hunter2pass, Engine: !Ref E }\n")
    r = rules(analyze_cloudformation(cfn, "t.yaml"))
    check("cfn public S3", "cfn-s3-public" in r, r)
    check("cfn unencrypted RDS", "cfn-rds-unencrypted" in r, r)
    check("cfn hardcoded secret (with !Ref present)", "cfn-hardcoded-secret" in r, r)


def test_cloudformation_json():
    import json as _j
    cfn = _j.dumps({"Resources": {"SG": {"Type": "AWS::EC2::SecurityGroup",
        "Properties": {"SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 3389, "ToPort": 3389}]}}}})
    sg = next((x for x in analyze_cloudformation(cfn, "t.json") if x.detail["rule"] == "cfn-sg-open"), None)
    check("cfn open SG on RDP -> HIGH", sg and sg.severity == Severity.HIGH, sg and sg.severity)


def test_engine_autodetect_and_skips_k8s():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "main.tf"), "w").write('resource "aws_s3_bucket" "x" { acl = "public-read" }')
        # a K8s manifest must NOT be treated as CloudFormation
        open(os.path.join(d, "deploy.yaml"), "w").write("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: x}")
        f = IacScan().scan_path(d)
        check("terraform picked up", any(x.detail["rule"] == "tf-s3-public-acl" for x in f), rules(f))
        check("k8s yaml not misread as CFN", all(x.detail.get("source") != "iac.cloudformation" for x in f))


def test_all_misconfig_class():
    f = analyze_terraform('resource "aws_s3_bucket" "d" { acl = "public-read" }', "m.tf")
    check("IaC findings are MISCONFIG", all(x.vuln_class == VulnClass.MISCONFIG for x in f))


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
