"""Configuration handling.

Config can come from a YAML file (see config.example.yaml) and is overlaid with
environment variables. A deliberate guardrail lives here: by default the tool
refuses to run against anything that is not loopback / RFC-1918, because this is
an authorized-testing tool meant for your own instance. Override with
`allow_remote: true` only when you have written permission for the target.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import yaml

from .models import Identity, IdentityRole


@dataclass
class AIConfig:
    provider: str = "none"          # none | anthropic | ollama | claude_code | bedrock
    model: str = "claude-opus-4-8"
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    claude_code_path: str = "claude"   # local Claude Code CLI, no API key needed
    codex_path: str = "codex"          # local Codex CLI, no API key needed
    # OpenAI-compatible providers (openai | deepseek | openai_compat): base URL and
    # the ENV VAR NAME holding the key. Empty -> the provider's own default
    # (e.g. api.openai.com + OPENAI_API_KEY, api.deepseek.com + DEEPSEEK_API_KEY).
    # A key is NEVER stored in config — only the name of the env var to read.
    endpoint: str = ""
    api_key_env: str = ""
    temperature: float = 0.0
    timeout_s: int = 90
    # Redact secret/credential shapes (JWTs, API keys, AWS keys, DB passwords,
    # bearer/session tokens) from every prompt BEFORE it leaves the host. Keep on
    # for any cloud provider; local providers (ollama/claude_code/codex) never egress.
    redact_prompts: bool = True
    max_tokens: int = 1024
    # When True the AI only ever *reads* request/response text and proposes
    # what to test next; it never auto-fires destructive requests.
    advisory_only: bool = True
    # provider: bedrock — calls AWS Bedrock's Converse API via boto3. `model`
    # should be a Bedrock model id / cross-region inference profile (e.g.
    # "global.anthropic.claude-sonnet-4-6" or "us.anthropic.claude-*"), matching
    # the convention already used by the target/ai-workflows for Claude-via-Bedrock.
    # Credentials come from boto3's normal chain (env vars set by
    # aws-actions/configure-aws-credentials via OIDC role assumption in CI, or
    # a local AWS profile) — never static keys stored in this config.
    bedrock_region: str = "us-east-1"


@dataclass
class IntegrationsConfig:
    sqlmap_path: str = "sqlmap"
    nuclei_path: str = "nuclei"
    interactsh_client_path: str = "interactsh-client"
    # Public Interactsh server is fine for a lab; for real work run your own.
    interactsh_server: str = ""
    enable_sqlmap: bool = False
    enable_nuclei: bool = False
    enable_interactsh: bool = False
    enable_local_oast: bool = False  # loopback-only OAST fallback (confirms HTTP OOB from a LOCAL target)


@dataclass
class DestructiveConfig:
    """Destructive-operation testing (shutdown, bulk delete, reindex, DB dump).

    These are in scope like anything else — the only question is ordering, since
    sending one mid-sweep ends the run. They are deferred to a dedicated pass
    after the main sweep; see deluluscan/safety.py.

    `enabled` defaults to None = "follow scan.allow_state_changing", so
    `--allow-state-changing` against a local dev instance gets you the full
    surface with no extra flag. Set it explicitly to force either way.

    `restart_command` is run when the target stops answering after a destructive
    probe (e.g. the shutdown endpoint actually worked). Without it, the pass
    stops at the first probe that takes the target down and says so.
    """
    enabled: Optional[bool] = None
    restart_command: str = ""
    health_path: str = "/"
    wait_timeout_s: int = 240
    # Destructive probing of a REMOTE (non-loopback) target needs its own explicit
    # yes. "I authorized a remote pentest" is not "shut my server down".
    allow_remote: bool = False


@dataclass
class ObserveConfig:
    """Grey-box observability (deluluscan/telemetry). When enabled, Deluluscan taps the
    target container's OWN logs and resource usage DURING the scan and correlates
    them with the exact probe that caused each event — confirming SQLi/SSTI from
    the server's stack trace, catching secrets written to logs, flagging
    state-changing operations that leave no audit trail, and spotting heap growth.

    Opt-in and fail-soft: if Docker isn't reachable or the container isn't found,
    the scan simply runs black-box as before. Local-only — the same authorization
    boundary as every HTTP probe (the container is on the owned host).
    """
    enabled: bool = False
    container: str = "deluluscan-target-1"    # container/name to observe (docker logs/stats)
    db_container: str = ""               # optional DB container (e.g. deluluscan-db-1) for pg logs
    stats_interval_s: float = 2.0
    docker_path: str = "docker"


@dataclass
class ScanConfig:
    # Conservative defaults: this is a fuzzer pointed at a live app.
    rate_limit_rps: float = 5.0
    timeout_s: float = 15.0
    max_endpoints: int = 0          # 0 = no cap
    methods: list[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH"])
    # Scanners that mutate state are opt-in.
    allow_state_changing: bool = False
    scanners: list[str] = field(default_factory=lambda: ["idor", "idor_write", "xss", "sqli", "ssrf", "owasp", "bopla", "bodyfuzz", "bodyinject", "jwt", "authmatrix", "bopla_miner", "sequencer", "faults", "flows", "graphql", "content_discovery", "paramminer", "verbtamper", "race", "graphql_adv", "passive", "injection", "fileupload", "cors", "csrf", "auth_enum", "cache", "logic", "authflow", "oauth", "idor_iter", "ai_llm", "deser", "memory_disclosure", "log_injection", "resource_consumption", "dependency"])
    enable_browser: bool = True
    enable_crawler: bool = True    # SPA/JS crawler augments discovery (static always; render if Playwright)    # headless-browser XSS execution confirmation (auto-noop if Playwright absent)
    # Time-based SQLi sleep length; the detector flags responses that take
    # roughly this much longer than the baseline.
    sqli_sleep_s: int = 7
    # Verification layer: corroborate findings, detect compensating controls,
    # rate exploitability, cut false positives. On by default; bounded probes.
    verify: bool = True
    verify_max_probes: int = 6
    # Bounded burst size for the (safe) rate-limit / business-flow probe.
    flow_burst: int = 12
    # Bounded parallelism for the race-condition prober (hard-capped at 20).
    race_parallel: int = 8
    # Destructive operations: deferred to a final pass rather than excluded.
    destructive: DestructiveConfig = field(default_factory=DestructiveConfig)


@dataclass
class Config:
    base_url: str = "http://localhost:8080"
    openapi_path: str = "/api/openapi.json"
    openapi_file: str = ""   # local spec saved from the authenticated browser
    allow_remote: bool = False
    verify_tls: bool = True
    identities: dict[str, Identity] = field(default_factory=dict)
    ai: AIConfig = field(default_factory=AIConfig)
    integrations: IntegrationsConfig = field(default_factory=IntegrationsConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    observe: ObserveConfig = field(default_factory=ObserveConfig)
    output_dir: str = "./deluluscan-out"
    # Optional RSA public key (PEM) for the JWT RS256->HS256 confusion test.
    jwt_public_key: str = ""
    # Source-informed scanning: read the target source to find dangerous patterns and
    # auto-generate targeted live probes. enable_source_scan turns it on;
    # source_root points at a local clone (preferred); if empty, specific files are
    # fetched from github raw. source_scan_ai gates the optional AI review pass.
    enable_source_scan: bool = False
    source_root: str = ""
    source_scan_ai: bool = False
    source_max_files: int = 60
    # Findings from a prior Mantis (github.com/google/mantis) code-scan campaign
    # run against source_root (see .claude/skills/deluluscan-codescan). When set,
    # each finding is mapped to its target REST endpoint and merged into the
    # same targeted live-probe plan the regex patterns above produce.
    mantis_findings_dir: str = ""
    # Fuzzing / anomaly detection (opt-in): surface candidate unknown-bug leads by
    # mutating inputs and flagging deviation from baseline. Leads, not verdicts.
    fuzz: bool = False
    fuzz_max_endpoints: int = 40
    # Engagement memory: persist cross-scan learnings (which endpoints were
    # exploitable, verified filter bypasses, per-build gotchas like JWT rotation)
    # keyed by target product+version, and feed them back into the next scan
    # (re-probe known-vulnerable endpoints first; annotate repeats/regressions).
    # On by default; stays local (one JSON file, no network). memory_file empty =
    # <output_dir>/engagement_memory.json.
    memory_enabled: bool = True
    memory_file: str = ""

    # ---- safety -----------------------------------------------------------
    def _resolve_all(self) -> list:
        """Every address the target hostname resolves to, v4 and v6.

        gethostbyname() returns only the FIRST A record, but the connection uses
        getaddrinfo() and may pick any of them — including an AAAA record
        gethostbyname cannot even see. Checking one address while connecting to
        another is not a boundary, so validate the whole set.
        """
        host = urlparse(self.base_url).hostname or ""
        try:                                    # a literal IP needs no lookup
            return [ipaddress.ip_address(host)]
        except ValueError:
            pass
        infos = socket.getaddrinfo(host, None)
        addrs = []
        for *_ , sockaddr in infos:
            try:
                ip = ipaddress.ip_address(sockaddr[0])
            except (ValueError, IndexError):
                continue
            if ip not in addrs:
                addrs.append(ip)
        return addrs

    def target_is_local(self) -> bool:
        """True only if EVERY address the target resolves to is loopback/private."""
        try:
            addrs = self._resolve_all()
        except (socket.gaierror, ValueError):
            return False
        return bool(addrs) and all(a.is_loopback or a.is_private for a in addrs)

    def assert_target_allowed(self) -> None:
        host = urlparse(self.base_url).hostname or ""
        if self.allow_remote:
            return
        try:
            addrs = self._resolve_all()
        except (socket.gaierror, ValueError) as exc:
            raise SystemExit(
                f"[abort] cannot resolve target host '{host}': {exc}. "
                "Set allow_remote: true only if you are authorized to test it."
            )
        if not addrs:
            raise SystemExit(
                f"[abort] target host '{host}' resolved to no usable address. "
                "Set allow_remote: true only if you are authorized to test it.")
        offenders = [a for a in addrs if not (a.is_loopback or a.is_private)]
        if offenders:
            raise SystemExit(
                f"[abort] target {host} resolves to {', '.join(str(a) for a in addrs)}; "
                f"{', '.join(str(a) for a in offenders)} is not loopback/private and "
                "allow_remote is false. This tool is for authorized testing of "
                "your own instance. Set allow_remote: true to override."
            )

    def destructive_enabled(self) -> tuple[bool, str]:
        """(enabled, why_not). Defaults to following allow_state_changing so a
        local `--allow-state-changing` run covers the full surface."""
        d = self.scan.destructive
        enabled = self.scan.allow_state_changing if d.enabled is None else d.enabled
        if not enabled:
            return False, ("destructive probing disabled (scan.destructive.enabled is "
                           "false, or --allow-state-changing was not given)")
        if not (self.target_is_local() or d.allow_remote):
            return False, ("target is not loopback/RFC1918 — destructive probing of a "
                           "remote target needs scan.destructive.allow_remote: true, "
                           "since authorizing a pentest is not authorizing an outage")
        return True, ""


def _load_identities(raw: dict) -> dict[str, Identity]:
    out: dict[str, Identity] = {}
    for role in IdentityRole:
        spec = (raw or {}).get(role.value, {})
        if not spec:
            if role is IdentityRole.ANON:
                out[role.value] = Identity(role=role)  # anon always exists
            continue
        out[role.value] = Identity(
            role=role,
            username=spec.get("username"),
            password=spec.get("password"),
            bearer_token=spec.get("bearer_token"),
            extra_headers=spec.get("extra_headers", {}),
        )
    out.setdefault(IdentityRole.ANON.value, Identity(role=IdentityRole.ANON))
    return out


def load_config(path: Optional[str] = None) -> Config:
    raw: dict = {}
    if path and os.path.exists(path):
        with open(path) as fh:
            raw = yaml.safe_load(fh) or {}

    cfg = Config()
    cfg.base_url = os.getenv("DELULUSCAN_BASE_URL", raw.get("base_url", cfg.base_url))
    cfg.openapi_path = raw.get("openapi_path", cfg.openapi_path)
    cfg.openapi_file = raw.get("openapi_file", cfg.openapi_file)
    cfg.allow_remote = bool(raw.get("allow_remote", False))
    cfg.verify_tls = bool(raw.get("verify_tls", True))
    cfg.output_dir = raw.get("output_dir", cfg.output_dir)
    cfg.jwt_public_key = raw.get("jwt_public_key", cfg.jwt_public_key)
    src = raw.get("source_scan", {})
    cfg.enable_source_scan = bool(src.get("enabled", raw.get("enable_source_scan", False)))
    cfg.source_root = src.get("source_root", raw.get("source_root", ""))
    cfg.source_scan_ai = bool(src.get("ai_review", raw.get("source_scan_ai", False)))
    cfg.source_max_files = int(src.get("max_files", 60))
    cfg.mantis_findings_dir = src.get("mantis_findings_dir", raw.get("mantis_findings_dir", ""))
    fz = raw.get("fuzz", {})
    if isinstance(fz, dict):
        cfg.fuzz = bool(fz.get("enabled", False))
        cfg.fuzz_max_endpoints = int(fz.get("max_endpoints", 40))
    else:
        cfg.fuzz = bool(fz)
    mem = raw.get("memory", {})
    if isinstance(mem, dict):
        cfg.memory_enabled = bool(mem.get("enabled", True))
        cfg.memory_file = mem.get("file", raw.get("memory_file", ""))
    else:
        cfg.memory_enabled = bool(mem)
    cfg.identities = _load_identities(raw.get("identities", {}))

    ai = raw.get("ai", {})
    cfg.ai = AIConfig(
        provider=os.getenv("DELULUSCAN_AI_PROVIDER", ai.get("provider", "none")),
        model=os.getenv("DELULUSCAN_AI_MODEL", ai.get("model", AIConfig.model)),
        ollama_host=ai.get("ollama_host", AIConfig.ollama_host),
        ollama_model=ai.get("ollama_model", AIConfig.ollama_model),
        claude_code_path=ai.get("claude_code_path", "claude"),
        codex_path=ai.get("codex_path", "codex"),
        endpoint=os.getenv("DELULUSCAN_AI_ENDPOINT", ai.get("endpoint", "")),
        api_key_env=ai.get("api_key_env", ""),
        temperature=float(ai.get("temperature", 0.0)),
        timeout_s=int(ai.get("timeout_s", 90)),
        redact_prompts=bool(ai.get("redact_prompts", True)),
        max_tokens=int(ai.get("max_tokens", 1024)),
        advisory_only=bool(ai.get("advisory_only", True)),
        bedrock_region=os.getenv("AWS_REGION", ai.get("bedrock_region", AIConfig.bedrock_region)),
    )

    integ = raw.get("integrations", {})
    cfg.integrations = IntegrationsConfig(
        sqlmap_path=integ.get("sqlmap_path", "sqlmap"),
        nuclei_path=integ.get("nuclei_path", "nuclei"),
        interactsh_client_path=integ.get("interactsh_client_path", "interactsh-client"),
        interactsh_server=integ.get("interactsh_server", ""),
        enable_sqlmap=bool(integ.get("enable_sqlmap", False)),
        enable_nuclei=bool(integ.get("enable_nuclei", False)),
        enable_interactsh=bool(integ.get("enable_interactsh", False)),
        enable_local_oast=bool(integ.get("enable_local_oast", False)),
    )

    scan = raw.get("scan", {})
    cfg.scan = ScanConfig(
        rate_limit_rps=float(scan.get("rate_limit_rps", 5.0)),
        timeout_s=float(scan.get("timeout_s", 15.0)),
        max_endpoints=int(scan.get("max_endpoints", 0)),
        methods=scan.get("methods", ScanConfig().methods),
        allow_state_changing=bool(scan.get("allow_state_changing", False)),
        scanners=scan.get("scanners", ScanConfig().scanners),
        sqli_sleep_s=int(scan.get("sqli_sleep_s", 7)),
        verify=bool(scan.get("verify", True)),
        verify_max_probes=int(scan.get("verify_max_probes", 6)),
        flow_burst=int(scan.get("flow_burst", 12)),
        race_parallel=int(scan.get("race_parallel", 8)),
    )
    obs = raw.get("observe", {}) or {}
    cfg.observe = ObserveConfig(
        enabled=bool(obs.get("enabled", False)),
        container=obs.get("container", ObserveConfig.container),
        db_container=obs.get("db_container", ""),
        stats_interval_s=float(obs.get("stats_interval_s", 2.0)),
        docker_path=obs.get("docker_path", "docker"),
    )

    dest = scan.get("destructive", {}) or {}
    cfg.scan.destructive = DestructiveConfig(
        enabled=(None if dest.get("enabled") is None else bool(dest["enabled"])),
        restart_command=dest.get("restart_command", ""),
        health_path=dest.get("health_path", DestructiveConfig.health_path),
        wait_timeout_s=int(dest.get("wait_timeout_s", 240)),
        allow_remote=bool(dest.get("allow_remote", False)),
    )
    return cfg
