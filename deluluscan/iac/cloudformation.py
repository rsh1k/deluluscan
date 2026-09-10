"""Static AWS CloudFormation misconfiguration checks (YAML/JSON templates).

Structured analysis of the Resources map, mirroring the Terraform rule set:
public S3, world-open security groups, unencrypted/public databases, wildcard
IAM, and hardcoded secrets. YAML is parsed with a loader tolerant of the CFN
short-form intrinsics (!Ref/!Sub/!GetAtt/…). Detection only, offline.
"""
from __future__ import annotations

import json
import re

from ..models import Finding, RequestRecord, Severity, VulnClass

_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL}
_SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 9200, 27017, 0}
_SECRET_KEY = re.compile(r"(?i)(password|secret|masteruserpassword|access.?key|private.?key|api.?key|token)")


def load_template(text: str):
    """Parse a CFN template (JSON or YAML incl. !Ref/!Sub short forms)."""
    text = text or ""
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        import yaml
    except Exception:
        return None

    class _CfnLoader(yaml.SafeLoader):
        pass

    def _any_tag(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    _CfnLoader.add_multi_constructor("!", _any_tag)
    try:
        return yaml.load(text, Loader=_CfnLoader)
    except Exception:
        return None


def _f(sev, title, desc, source, logical, rtype, rule, cwe="CWE-1032"):
    ep = f"{source}:{logical}"
    return Finding(vuln_class=VulnClass.MISCONFIG, severity=_SEV[sev], title=title,
                   endpoint=ep, description=desc,
                   evidence=[RequestRecord(method="IAC", url=ep, identity="anon", status=0, elapsed_ms=0.0)],
                   confidence="firm", verdict="likely_true_positive", exploitability="conditional",
                   detail={"rule": rule, "resource": f"{logical} ({rtype})", "cwe": cwe,
                           "file": source, "source": "iac.cloudformation"})


def _flatten(obj):
    """Yield all scalar leaves as strings (for hardcoded-secret / wildcard scan)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from _flatten(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _flatten(v)


def _has_wildcard_policy(props) -> bool:
    txt = json.dumps(props, default=str)
    return '"Action": "*"' in txt.replace("'", '"') or '"Action":"*"' in txt or \
           ('*' in str(props) and '"Resource"' in txt and re.search(r'Action["\']?\s*:\s*["\']?\*', txt))


def analyze_cloudformation(data, source: str = "template.yaml") -> list:
    if isinstance(data, str):
        data = load_template(data)
    if not isinstance(data, dict):
        return []
    resources = data.get("Resources")
    if not isinstance(resources, dict):
        return []
    out: list = []
    for logical, res in resources.items():
        if not isinstance(res, dict):
            continue
        rtype = res.get("Type", "")
        props = res.get("Properties", {}) or {}
        pjson = json.dumps(props, default=str)

        if rtype == "AWS::S3::Bucket":
            if re.search(r'"AccessControl"\s*:\s*"Public', pjson):
                out.append(_f("high", "Public S3 bucket", f"{logical} sets a public AccessControl.",
                              source, logical, rtype, "cfn-s3-public", "CWE-284"))

        if rtype in ("AWS::EC2::SecurityGroup",):
            for ing in props.get("SecurityGroupIngress", []) or []:
                if isinstance(ing, dict) and str(ing.get("CidrIp")) == "0.0.0.0/0":
                    port = ing.get("FromPort")
                    try:
                        sensitive = int(port) in _SENSITIVE_PORTS
                    except (TypeError, ValueError):
                        sensitive = False
                    out.append(_f("high" if sensitive else "medium",
                        "Security group open to 0.0.0.0/0",
                        f"{logical} allows ingress from 0.0.0.0/0"
                        + (f" on sensitive port {port}" if sensitive else "") + ".",
                        source, logical, rtype, "cfn-sg-open", "CWE-284"))

        if rtype in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster"):
            if props.get("StorageEncrypted") in (False, "false"):
                out.append(_f("high", "Unencrypted RDS database",
                    f"{logical} has StorageEncrypted false.", source, logical, rtype, "cfn-rds-unencrypted", "CWE-311"))
            if props.get("PubliclyAccessible") in (True, "true"):
                out.append(_f("high", "Publicly accessible RDS database",
                    f"{logical} is PubliclyAccessible.", source, logical, rtype, "cfn-rds-public", "CWE-284"))

        if rtype in ("AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::ManagedPolicy") and _has_wildcard_policy(props):
            out.append(_f("high", "Wildcard IAM policy (Action:*)",
                f"{logical} grants a wildcard Action — least-privilege it.",
                source, logical, rtype, "cfn-iam-wildcard", "CWE-269"))

        # hardcoded secret: a secret-named property with an inline string literal
        for k, v in _flatten(props):
            if isinstance(k, str) and _SECRET_KEY.search(k) and isinstance(v, str) and len(v) >= 6 \
                    and not v.startswith(("{", "!")):
                out.append(_f("high", "Hardcoded secret in CloudFormation",
                    f"{logical} property '{k}' contains an inline secret literal — use a "
                    "parameter with NoEcho or Secrets Manager.", source, logical, rtype,
                    "cfn-hardcoded-secret", "CWE-798"))
                break
    return out
