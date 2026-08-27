from .base import Scanner
from .idor import IdorScanner
from .xss import XssScanner
from .sqli import SqliScanner
from .ssrf import SsrfScanner
from .owasp import OwaspBroadScanner
from .bopla import BoplaScanner
from .bodyfuzz import BodyFuzzScanner
from .jwt_scanner import JwtActiveScanner
from .owasp_suite_scanner import (AuthMatrixScanner, BoplaMinerScanner,
                                  SequencerScanner, FaultScanner, FlowScanner,
                                  GraphQLScanner)
from .advanced_scanner import (ContentDiscoveryScanner, ParamMinerScanner,
                               VerbTamperScanner, RaceScanner, GraphQLAdvScanner)
from .passive import PassiveScanner
from .injection_scanner import InjectionScanner, FileUploadScanner
from .misc_scanner import CorsScanner, CsrfScanner as CsrfScannerMisc
from .bodyinject import BodyInjectScanner
from .idor_write import IdorWriteScanner
from .csrf_scanner import CsrfScanner
from .auth_enum_scanner import AuthEnumScanner
from .cache_scanner import CacheScanner
from .logic_scanner import LogicScanner
from .auth_flow_scanner import AuthFlowScanner
from .oauth_scanner import OAuthScanner
from .idor_iter_scanner import IterableIdorScanner
from .graphql_cache import GraphQLCacheScanner
from .search_exposure import SearchExposureScanner
from .vanity_redirect import VanityRedirectScanner
from .regex_dos import RegexDosScanner
from .ai_llm_scanner import AiLlmScanner
from .deser_scanner import DeserScanner
from .memory_disclosure_scanner import MemoryDisclosureScanner
from .log_injection_scanner import LogInjectionScanner
from .resource_consumption_scanner import ResourceConsumptionScanner
from .dependency_scanner import DependencyScanner

SCANNER_REGISTRY = {
    "idor": IdorScanner,
    "xss": XssScanner,
    "sqli": SqliScanner,
    "ssrf": SsrfScanner,
    "owasp": OwaspBroadScanner,
    "bopla": BoplaScanner,
    "bodyfuzz": BodyFuzzScanner,
    "jwt": JwtActiveScanner,
    "authmatrix": AuthMatrixScanner,
    "bopla_miner": BoplaMinerScanner,
    "sequencer": SequencerScanner,
    "faults": FaultScanner,
    "flows": FlowScanner,
    "graphql": GraphQLScanner,
    "content_discovery": ContentDiscoveryScanner,
    "paramminer": ParamMinerScanner,
    "verbtamper": VerbTamperScanner,
    "race": RaceScanner,
    "graphql_adv": GraphQLAdvScanner,
    "passive": PassiveScanner,
    "injection": InjectionScanner,
    "fileupload": FileUploadScanner,
    "cors": CorsScanner,
    "csrf": CsrfScanner,
    "bodyinject": BodyInjectScanner,
    "idor_write": IdorWriteScanner,
    "auth_enum": AuthEnumScanner,
    "cache": CacheScanner,
    "logic": LogicScanner,
    "authflow": AuthFlowScanner,
    "oauth": OAuthScanner,
    "idor_iter": IterableIdorScanner,
    "graphql_cache": GraphQLCacheScanner,
    "search_exposure": SearchExposureScanner,
    "vanity_redirect": VanityRedirectScanner,
    "regex_dos": RegexDosScanner,
    "ai_llm": AiLlmScanner,
    "deser": DeserScanner,
    "memory_disclosure": MemoryDisclosureScanner,
    "log_injection": LogInjectionScanner,
    "resource_consumption": ResourceConsumptionScanner,
    "dependency": DependencyScanner,
    # Declarative YAML checks (deluluscan/templates.py). Imported lazily inside
    # the factory below so a PyYAML problem cannot break the whole registry.
    "templates": None,
}

def _resolve_template_scanner():
    """Bind the YAML template scanner into the registry, lazily.

    Kept out of the module-level imports so that a missing PyYAML or a broken
    template directory degrades to "templates unavailable" rather than making
    every scanner unimportable.
    """
    try:
        from ..templates import TemplateScanner
    except Exception:
        SCANNER_REGISTRY.pop("templates", None)
        return None
    SCANNER_REGISTRY["templates"] = TemplateScanner
    return TemplateScanner


_resolve_template_scanner()

__all__ = ["Scanner", "SCANNER_REGISTRY", "IdorScanner", "XssScanner",
           "SqliScanner", "SsrfScanner", "OwaspBroadScanner",
           "BoplaScanner", "BodyFuzzScanner",
           "JwtActiveScanner", "AuthMatrixScanner", "BoplaMinerScanner",
           "SequencerScanner", "FaultScanner", "FlowScanner", "GraphQLScanner",
           "ContentDiscoveryScanner", "ParamMinerScanner", "VerbTamperScanner",
           "RaceScanner", "GraphQLAdvScanner", "PassiveScanner",
           "InjectionScanner", "FileUploadScanner", "CorsScanner", "CsrfScanner",
           "BodyInjectScanner", "IdorWriteScanner", "AuthEnumScanner",
           "CacheScanner",
           "LogicScanner", "AuthFlowScanner", "OAuthScanner", "IterableIdorScanner",
           
           
           "GraphQLCacheScanner",
           "SearchExposureScanner",
           "VanityRedirectScanner",
           "RegexDosScanner",
           
           "AiLlmScanner", "DeserScanner"]
