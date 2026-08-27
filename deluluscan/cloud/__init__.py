"""Deluluscan cloud security (WS-5): CSPM checks over a collected inventory
(AWS/GCP/Azure) + SSRF->IMDS->credentials exposure detection.

    from deluluscan.cloud import CloudScan
    findings = CloudScan().scan_file("aws-inventory.json", provider="aws")

CLI: python3 -m deluluscan.cloud --inventory aws.json --provider aws
"""
from .engine import CloudScan
from .checks import check_aws, check_gcp, check_azure, PROVIDERS
from .imds import check_imds

__all__ = ["CloudScan", "check_aws", "check_gcp", "check_azure", "PROVIDERS", "check_imds"]
