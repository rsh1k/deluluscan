"""Cloud instance-metadata credential exposure (SSRF -> IMDS -> cloud creds).

The classic cloud-escalation path: an SSRF (or being ON the instance) can reach
the link-local metadata service (169.254.169.254 / metadata.google.internal) and
read the instance role's temporary CREDENTIALS. This module drives a `fetch`
primitive (inject your SSRF request function, or the default direct fetch when
running on the instance) against AWS/GCP/Azure metadata and reports if credentials
are reachable.

Discipline: it CONFIRMS reachability (the marker is present) but **redacts the
credential values** — the finding proves the exposure without storing/printing the
secret. Detection, never exfiltration.
"""
from __future__ import annotations

import re
from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass

Fetch = Callable[[str, dict], tuple]   # (url, headers) -> (status:int, body:str)

_AWS = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
_GCP = ("http://metadata.google.internal/computeMetadata/v1/instance/"
        "service-accounts/default/token")
_AZURE = ("http://169.254.169.254/metadata/identity/oauth2/token"
          "?api-version=2018-02-01&resource=https://management.azure.com/")

_CRED_MARKERS = re.compile(r'"(AccessKeyId|SecretAccessKey|access_token|Token)"', re.I)


def _finding(cloud, endpoint, detail) -> Finding:
    return Finding(
        vuln_class=VulnClass.INFO_LEAK, severity=Severity.CRITICAL,
        title=f"{cloud} instance credentials reachable via metadata (SSRF->IMDS)",
        endpoint=endpoint,
        description=(f"The {cloud} instance metadata service returned live role credentials to "
                     "an unauthenticated metadata request. Via an SSRF this is a direct path to "
                     "assuming the instance's cloud role. (Credential values redacted.)"),
        detail={**detail, "rule": "imds-cred-exposure", "note": "credential values redacted"},
        confidence="confirmed", verdict="true_positive", exploitability="exploitable")


def check_imds(fetch: Optional[Fetch] = None, *, clouds=("aws", "gcp", "azure")) -> list:
    """Probe metadata endpoints through `fetch`. Returns Findings (creds redacted)."""
    if fetch is None:
        fetch = _default_fetch
    out: list[Finding] = []

    if "aws" in clouds:
        try:
            status, body = fetch(_AWS, {})
            if status == 200 and body and body.strip():
                role = body.strip().splitlines()[0].strip()
                s2, b2 = fetch(_AWS + role, {})
                if s2 == 200 and _CRED_MARKERS.search(b2 or ""):
                    out.append(_finding("AWS", _AWS + role,
                                        {"cloud": "aws", "role": role, "imds": "v1"}))
        except Exception:
            pass

    if "gcp" in clouds:
        try:
            status, body = fetch(_GCP, {"Metadata-Flavor": "Google"})
            if status == 200 and re.search(r'"access_token"', body or ""):
                out.append(_finding("GCP", _GCP, {"cloud": "gcp"}))
        except Exception:
            pass

    if "azure" in clouds:
        try:
            status, body = fetch(_AZURE, {"Metadata": "true"})
            if status == 200 and re.search(r'"access_token"', body or ""):
                out.append(_finding("Azure", _AZURE, {"cloud": "azure"}))
        except Exception:
            pass
    return out


def _default_fetch(url, headers):
    import requests
    r = requests.get(url, headers=headers, timeout=3)
    return r.status_code, r.text[:8000]
