"""Active, AI-assisted testing — the Burp/Postman-style workbench.

Unlike the passive scanners, these modules mutate requests (tokens, parameters,
object ids, bodies) and replay them to confirm whether the server accepts the
manipulation. Authorized-target only; confirms vulnerabilities by exercising
them without weaponizing into third-party attacks or bulk data exfiltration.
"""
from .http_tools import (RequestSpec, Repeater, Intruder, Position,
                         IntruderResult, Collection, parse_markers, set_at)
from .jwt_lab import JwtLab, decode as jwt_decode, JwtTestResult
from .authz_probe import AuthzProbe, AuthzResult
from .recon import (ParamMiner, ContentDiscovery, VersionEnumerator,
                    SupplyChainProbe)
from .advanced import VerbTamper, RaceProbe, GraphQLAdvanced
from .session_rules import MatchReplaceRule, Macro, Extraction, SessionEngine

__all__ = [
    "RequestSpec", "Repeater", "Intruder", "Position", "IntruderResult",
    "Collection", "parse_markers", "set_at",
    "JwtLab", "jwt_decode", "JwtTestResult",
    "AuthzProbe", "AuthzResult",
    "ParamMiner", "ContentDiscovery", "VersionEnumerator", "SupplyChainProbe",
    "VerbTamper", "RaceProbe", "GraphQLAdvanced",
    "MatchReplaceRule", "Macro", "Extraction", "SessionEngine",
]
