"""MITRE ATT&CK technique tagging — map each finding to the adversary technique it
enables, so the report speaks the language SOC/threat-intel teams use.

A vulnerability isn't just an OWASP class; it's a foothold for a specific ATT&CK
technique (an SSRF that reaches IMDS is T1552.005 Cloud Instance Metadata API; a
leaked key is T1552 Unsecured Credentials). Tagging findings with technique +
tactic lets defenders map coverage to their threat model and lets the report tie
each issue to a real attacker action.

Data-driven and offline: a VulnClass -> technique base map, refined for the
network-posture classes (which are all MISCONFIG/INFO_LEAK/CRYPTO and too generic
on their own) by the finding's producing module. `attach_attack` sets
detail["attack"]. Nothing is fetched.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    tactic: str
    id: str
    name: str

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"

    def to_dict(self) -> dict:
        return {"tactic": self.tactic, "id": self.id, "name": self.name, "url": self.url}


# reusable techniques
T_EXPLOIT_PUBLIC = Technique("Initial Access", "T1190", "Exploit Public-Facing Application")
T_SCRIPTING = Technique("Execution", "T1059", "Command and Scripting Interpreter")
T_JS = Technique("Execution", "T1059.007", "JavaScript")
T_IMDS = Technique("Credential Access", "T1552.005", "Cloud Instance Metadata API")
T_UNSECURED_CREDS = Technique("Credential Access", "T1552", "Unsecured Credentials")
T_STEAL_COOKIE = Technique("Credential Access", "T1539", "Steal Web Session Cookie")
T_BRUTE = Technique("Credential Access", "T1110", "Brute Force")
T_PRIVESC = Technique("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation")
T_DATA_REPO = Technique("Collection", "T1213", "Data from Information Repositories")
T_SUPPLY = Technique("Initial Access", "T1195", "Supply Chain Compromise")
T_ACTIVE_SCAN = Technique("Reconnaissance", "T1595", "Active Scanning")
T_GATHER_NET = Technique("Reconnaissance", "T1590", "Gather Victim Network Information")
T_NET_SVC_DISC = Technique("Discovery", "T1046", "Network Service Discovery")
T_SNIFF = Technique("Credential Access", "T1040", "Network Sniffing")
T_AITM = Technique("Collection", "T1557", "Adversary-in-the-Middle")
T_SMB_RELAY = Technique("Credential Access", "T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay")
T_ACCOUNT_DISC = Technique("Discovery", "T1087", "Account Discovery")
T_PHISH_INFO = Technique("Reconnaissance", "T1598", "Phishing for Information")
T_COMPROMISE_DOMAIN = Technique("Resource Development", "T1584.001", "Domains")
T_IMPAIR_LOGS = Technique("Defense Evasion", "T1562.008", "Disable or Modify Cloud Logs")
T_INDICATOR_REMOVAL = Technique("Defense Evasion", "T1070", "Indicator Removal")
T_DATA_MANIP = Technique("Impact", "T1565", "Data Manipulation")
T_LLM_INJECT = Technique("ATLAS: ML Attack Staging", "AML.T0051", "LLM Prompt Injection")


CLASS_TECHNIQUES: dict[str, list] = {
    "authz": [T_EXPLOIT_PUBLIC, T_PRIVESC],
    "idor": [T_EXPLOIT_PUBLIC, T_DATA_REPO],
    "bopla": [T_EXPLOIT_PUBLIC, T_DATA_REPO],
    "sqli": [T_EXPLOIT_PUBLIC],
    "ssti": [T_EXPLOIT_PUBLIC, T_SCRIPTING],
    "ssrf": [T_EXPLOIT_PUBLIC, T_IMDS],
    "xss": [T_JS, T_STEAL_COOKIE],
    "info_leak": [T_UNSECURED_CREDS],
    "rate_limit": [T_BRUTE],
    "business_logic": [T_EXPLOIT_PUBLIC],
    "misconfig": [T_EXPLOIT_PUBLIC],
    "inventory": [T_ACTIVE_SCAN, T_GATHER_NET],
    "supply_chain": [T_SUPPLY],
    "crypto": [T_SNIFF, T_AITM],
    "error_handling": [T_EXPLOIT_PUBLIC],
    "graphql": [T_EXPLOIT_PUBLIC],
    "ai_llm": [T_LLM_INJECT],
    "logging_failure": [T_IMPAIR_LOGS, T_INDICATOR_REMOVAL],
    "log_injection": [T_DATA_MANIP, T_INDICATOR_REMOVAL],
    "memory_disclosure": [T_UNSECURED_CREDS],
}

# Refinements keyed by detail["source"] — more specific than the class for the
# network-posture detectors (all of which fall under MISCONFIG/INFO_LEAK/CRYPTO).
SOURCE_TECHNIQUES: dict[str, list] = {
    "netscan.tls": [T_SNIFF, T_AITM],
    "recon.dnsintel": [T_PHISH_INFO],
    "recon.takeover": [T_COMPROMISE_DOMAIN],
    "active.smuggling": [T_EXPLOIT_PUBLIC],
    "netscan.adintel": [T_SMB_RELAY, T_ACCOUNT_DISC],
    "netscan.ports": [T_NET_SVC_DISC],
    "netscan.waf": [T_ACTIVE_SCAN],
    "netscan.honeypot": [T_ACTIVE_SCAN],
    "netscan.ids_ips": [T_ACTIVE_SCAN],
    "recon.jsanalysis": [T_ACTIVE_SCAN, T_GATHER_NET],
    "crawler": [T_ACTIVE_SCAN, T_GATHER_NET],
    "platforms.cves": [T_EXPLOIT_PUBLIC],
}


def _class_value(f) -> str:
    vc = getattr(f, "vuln_class", None)
    return getattr(vc, "value", vc) or ""


def techniques_for(f) -> list:
    """The ATT&CK techniques a finding enables — source-specific if we have a more
    precise mapping, otherwise the vuln-class base map."""
    src = (getattr(f, "detail", None) or {}).get("source", "")
    if src in SOURCE_TECHNIQUES:
        return SOURCE_TECHNIQUES[src]
    return CLASS_TECHNIQUES.get(_class_value(f), [])


def attach_attack(findings: list) -> int:
    """Set detail['attack'] = [{tactic, id, name, url}] on each finding. Returns the
    count annotated (findings with no known technique are skipped)."""
    n = 0
    for f in findings:
        d = getattr(f, "detail", None)
        if not isinstance(d, dict):
            continue
        techs = techniques_for(f)
        if not techs:
            continue
        d["attack"] = [t.to_dict() for t in techs]
        n += 1
    return n
