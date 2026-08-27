"""Static container / IaC security analyzers — Dockerfile, Kubernetes manifests,
docker-compose.

Detection only, offline: each analyzer reads a config and emits `Finding`s for
security misconfigurations (privileged containers, host namespaces, docker-socket
mounts = escape, root user, dangerous capabilities, unpinned images, secrets in
env/ARG). Modeled on the checks Trivy / kubescape / kube-hunter run, kept as
readable per-field logic so coverage grows without a rule engine. No exploitation.
"""
from __future__ import annotations

import re
from typing import Optional

from ..models import Finding, Severity, VulnClass

_SEV = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
        "critical": Severity.CRITICAL, "info": Severity.INFO}

_SECRET_KEY = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
                         r"private[_-]?key|credential)", re.I)
_SECRET_VAL = re.compile(r"(AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{6,}\.|-----BEGIN|[A-Za-z0-9/+]{24,})")
_DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE", "SYS_MODULE", "ALL", "DAC_OVERRIDE"}


def _f(cls, sev, title, endpoint, desc, detail=None) -> Finding:
    return Finding(vuln_class=cls, severity=_SEV[sev], title=title, endpoint=endpoint,
                   description=desc, detail=detail or {}, confidence="firm",
                   verdict="true_positive", exploitability="conditional")


# ---------------------------------------------------------------------------
def analyze_dockerfile(text: str, name: str = "Dockerfile") -> list:
    findings: list[Finding] = []
    # join line continuations
    lines = []
    buf = ""
    for raw in (text or "").splitlines():
        s = raw.rstrip()
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        buf += s
        lines.append(buf)
        buf = ""
    if buf:
        lines.append(buf)

    last_user = None
    for i, line in enumerate(lines, 1):
        st = line.strip()
        if not st or st.startswith("#"):
            continue
        instr, _, rest = st.partition(" ")
        instr = instr.upper(); rest = rest.strip()
        if instr == "FROM":
            image = rest.split()[0] if rest else ""
            if image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
                findings.append(_f(VulnClass.SUPPLY_CHAIN, "medium",
                    "Unpinned base image", f"{name}:{i}",
                    f"FROM {image} is untagged/':latest' — builds are non-reproducible and "
                    "may pull a vulnerable image. Pin to a digest or fixed version.",
                    {"line": i, "image": image, "rule": "docker-unpinned-base"}))
        elif instr == "USER":
            last_user = rest.split()[0] if rest else None
        elif instr == "ADD" and re.search(r"https?://", rest):
            findings.append(_f(VulnClass.SUPPLY_CHAIN, "medium",
                "ADD from remote URL", f"{name}:{i}",
                "ADD <url> fetches over the network without integrity checks — use COPY "
                "with a verified artifact.", {"line": i, "rule": "docker-add-url"}))
        elif instr == "RUN":
            if re.search(r"(curl|wget)\s+[^|&;]*\|\s*(sudo\s+)?(sh|bash)", rest):
                findings.append(_f(VulnClass.SUPPLY_CHAIN, "high",
                    "Pipe-to-shell in build", f"{name}:{i}",
                    "RUN curl|wget ... | sh executes unverified remote code at build time.",
                    {"line": i, "rule": "docker-pipe-to-shell"}))
            if re.search(r"chmod\s+777", rest):
                findings.append(_f(VulnClass.MISCONFIG, "low", "World-writable permissions",
                    f"{name}:{i}", "chmod 777 grants world write.", {"line": i, "rule": "docker-chmod-777"}))
            m = _SECRET_VAL.search(rest)
            if m and _SECRET_KEY.search(rest):
                findings.append(_f(VulnClass.INFO_LEAK, "high", "Possible hardcoded secret in RUN",
                    f"{name}:{i}", "A credential-shaped value appears in a build layer (persists "
                    "in image history).", {"line": i, "rule": "docker-secret-run"}))
        elif instr in ("ENV", "ARG"):
            # KEY=VALUE or KEY VALUE; flag a secret-shaped KEY with a real literal
            # VALUE (strong secret shape, or a non-trivial literal that is not a
            # $VAR reference / obvious path). Baked into image history either way.
            m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*(.+)$", rest)
            if m:
                k, v = m.group(1), m.group(2).strip().strip('"\'')
                literal = v and not v.startswith(("$", "${")) and len(v) >= 6
                if _SECRET_KEY.search(k) and (literal or _SECRET_VAL.search(v)):
                    findings.append(_f(VulnClass.INFO_LEAK, "high",
                        f"Possible secret in {instr}", f"{name}:{i}",
                        f"{instr} {k} defines a credential-shaped value baked into the image "
                        "(persists in image history).",
                        {"line": i, "rule": "docker-secret-env", "key": k}))
        elif instr == "EXPOSE" and re.search(r"\b22\b", rest):
            findings.append(_f(VulnClass.MISCONFIG, "low", "SSH port exposed",
                f"{name}:{i}", "EXPOSE 22 — running sshd in a container is an anti-pattern.",
                {"line": i, "rule": "docker-expose-ssh"}))

    if last_user in (None, "root", "0"):
        findings.append(_f(VulnClass.MISCONFIG, "medium", "Container runs as root",
            name, "No non-root USER set (or USER root) — the container process runs as UID 0. "
            "A container escape then starts as root. Add a non-root USER.",
            {"rule": "docker-runs-as-root", "user": last_user}))
    return findings


# ---------------------------------------------------------------------------
def _pod_spec(doc: dict):
    """Return (podSpec, resource_name) for a k8s workload doc, or (None, name)."""
    kind = (doc.get("kind") or "").lower()
    name = (doc.get("metadata") or {}).get("name", kind or "resource")
    spec = doc.get("spec") or {}
    if kind == "pod":
        return spec, name
    if kind in ("deployment", "daemonset", "statefulset", "replicaset", "job"):
        return ((spec.get("template") or {}).get("spec") or {}), name
    if kind == "cronjob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}, name
    return None, name


def analyze_k8s(docs, source: str = "manifest") -> list:
    findings: list[Finding] = []
    if isinstance(docs, dict):
        docs = [docs]
    for doc in docs or []:
        if not isinstance(doc, dict):
            continue
        pod, name = _pod_spec(doc)
        if pod is None:
            continue
        ep = f"{source}:{name}"
        if pod.get("hostNetwork"):
            findings.append(_f(VulnClass.MISCONFIG, "high", "hostNetwork enabled", ep,
                "Pod shares the host network namespace — can sniff/spoof host traffic and reach "
                "loopback services.", {"rule": "k8s-hostnetwork", "resource": name}))
        if pod.get("hostPID"):
            findings.append(_f(VulnClass.MISCONFIG, "high", "hostPID enabled", ep,
                "Pod shares the host PID namespace — can see/signal host processes.",
                {"rule": "k8s-hostpid", "resource": name}))
        if pod.get("hostIPC"):
            findings.append(_f(VulnClass.MISCONFIG, "medium", "hostIPC enabled", ep,
                "Pod shares the host IPC namespace.", {"rule": "k8s-hostipc", "resource": name}))
        if pod.get("automountServiceAccountToken", True) is not False:
            findings.append(_f(VulnClass.MISCONFIG, "low", "ServiceAccount token auto-mounted", ep,
                "automountServiceAccountToken is not disabled — a compromised pod gets API creds. "
                "Set it to false unless the pod needs the API.", {"rule": "k8s-sa-token", "resource": name}))
        # host path volumes (docker socket = escape)
        for vol in pod.get("volumes") or []:
            hp = (vol.get("hostPath") or {}).get("path", "")
            if hp:
                sock = "docker.sock" in hp or hp in ("/", "/var/run", "/proc", "/var/lib/kubelet")
                findings.append(_f(VulnClass.MISCONFIG, "critical" if sock else "high",
                    "docker socket / sensitive hostPath mount" if sock else "hostPath volume mount", ep,
                    f"hostPath {hp} is mounted into the pod." + (" Mounting the Docker socket (or /) "
                    "is a direct container-escape to full host control." if sock else ""),
                    {"rule": "k8s-hostpath", "path": hp, "resource": name}))
        # per-container checks
        containers = (pod.get("containers") or []) + (pod.get("initContainers") or [])
        pod_sc = pod.get("securityContext") or {}
        for c in containers:
            cn = c.get("name", "container")
            sc = {**pod_sc, **(c.get("securityContext") or {})}
            cep = f"{ep}/{cn}"
            if sc.get("privileged"):
                findings.append(_f(VulnClass.MISCONFIG, "critical", "Privileged container", cep,
                    "securityContext.privileged=true grants nearly all host capabilities — trivial "
                    "escape. Remove it.", {"rule": "k8s-privileged", "resource": name, "container": cn}))
            if sc.get("allowPrivilegeEscalation") is not False:
                findings.append(_f(VulnClass.MISCONFIG, "medium", "allowPrivilegeEscalation not disabled",
                    cep, "Set allowPrivilegeEscalation:false to block setuid privilege gain.",
                    {"rule": "k8s-allowprivesc", "resource": name, "container": cn}))
            if sc.get("runAsNonRoot") is not True and sc.get("runAsUser", 0) == 0:
                findings.append(_f(VulnClass.MISCONFIG, "medium", "Container may run as root", cep,
                    "runAsNonRoot is not true and runAsUser is 0/unset.",
                    {"rule": "k8s-runasroot", "resource": name, "container": cn}))
            caps = ((sc.get("capabilities") or {}).get("add")) or []
            bad = _DANGEROUS_CAPS.intersection({str(x).upper() for x in caps})
            if bad:
                findings.append(_f(VulnClass.MISCONFIG, "high", f"Dangerous capabilities: {', '.join(sorted(bad))}",
                    cep, "Added Linux capabilities enable host-level actions / escape.",
                    {"rule": "k8s-caps", "resource": name, "container": cn, "caps": sorted(bad)}))
            image = c.get("image", "")
            if image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
                findings.append(_f(VulnClass.SUPPLY_CHAIN, "low", "Unpinned image", cep,
                    f"image {image} is ':latest'/untagged — pin to a digest.",
                    {"rule": "k8s-unpinned", "resource": name, "container": cn, "image": image}))
            for env in c.get("env") or []:
                if _SECRET_KEY.search(env.get("name", "")) and isinstance(env.get("value"), str) \
                        and env.get("value"):
                    findings.append(_f(VulnClass.INFO_LEAK, "high", "Secret in plaintext env", cep,
                        f"env {env['name']} carries a literal value — use a Secret + valueFrom.",
                        {"rule": "k8s-env-secret", "resource": name, "container": cn, "env": env["name"]}))
            if not (c.get("resources") or {}).get("limits"):
                findings.append(_f(VulnClass.RATE_LIMIT, "low", "No resource limits", cep,
                    "No resources.limits — a compromised/buggy container can starve the node (DoS).",
                    {"rule": "k8s-no-limits", "resource": name, "container": cn}))
    return findings


# ---------------------------------------------------------------------------
def analyze_compose(data: dict, source: str = "docker-compose.yml") -> list:
    findings: list[Finding] = []
    services = (data or {}).get("services") or {}
    for sname, svc in services.items():
        if not isinstance(svc, dict):
            continue
        ep = f"{source}:{sname}"
        if svc.get("privileged"):
            findings.append(_f(VulnClass.MISCONFIG, "critical", "Privileged compose service", ep,
                "privileged:true grants host capabilities — escape risk.",
                {"rule": "compose-privileged", "service": sname}))
        if svc.get("network_mode") == "host":
            findings.append(_f(VulnClass.MISCONFIG, "high", "Host network mode", ep,
                "network_mode:host shares the host network namespace.",
                {"rule": "compose-hostnet", "service": sname}))
        if svc.get("pid") == "host":
            findings.append(_f(VulnClass.MISCONFIG, "high", "Host PID namespace", ep,
                "pid:host shares host processes.", {"rule": "compose-hostpid", "service": sname}))
        for vol in svc.get("volumes") or []:
            v = vol if isinstance(vol, str) else f"{vol.get('source','')}:{vol.get('target','')}"
            if "docker.sock" in v:
                findings.append(_f(VulnClass.MISCONFIG, "critical", "Docker socket mounted", ep,
                    "Mounting /var/run/docker.sock gives the container full control of the Docker "
                    "daemon = host takeover.", {"rule": "compose-docker-sock", "service": sname}))
        for cap in svc.get("cap_add") or []:
            if str(cap).upper() in _DANGEROUS_CAPS:
                findings.append(_f(VulnClass.MISCONFIG, "high", f"Dangerous capability: {cap}", ep,
                    "cap_add grants host-level capabilities.",
                    {"rule": "compose-caps", "service": sname, "cap": str(cap)}))
        for opt in svc.get("security_opt") or []:
            if "unconfined" in str(opt):
                findings.append(_f(VulnClass.MISCONFIG, "medium", f"Confinement disabled: {opt}", ep,
                    "seccomp/apparmor:unconfined removes syscall/LSM confinement.",
                    {"rule": "compose-unconfined", "service": sname, "opt": str(opt)}))
        image = svc.get("image", "")
        if image and (":" not in str(image).split("/")[-1] or str(image).endswith(":latest")):
            findings.append(_f(VulnClass.SUPPLY_CHAIN, "low", "Unpinned image", ep,
                f"image {image} is ':latest'/untagged.", {"rule": "compose-unpinned", "service": sname}))
        env = svc.get("environment") or {}
        items = env.items() if isinstance(env, dict) else [
            (str(e).split("=", 1)[0], str(e).split("=", 1)[1] if "=" in str(e) else "") for e in env]
        for k, v in items:
            if _SECRET_KEY.search(str(k)) and _SECRET_VAL.search(str(v)):
                findings.append(_f(VulnClass.INFO_LEAK, "medium", "Secret in compose environment", ep,
                    f"environment {k} carries a credential-shaped literal.",
                    {"rule": "compose-env-secret", "service": sname, "key": str(k)}))
    return findings
