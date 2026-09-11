"""Offline tests for Kubernetes RBAC analysis."""
from __future__ import annotations

from deluluscan.k8srbac import K8sRbacScan, analyze_rbac
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")

def rules(f): return {x.detail["rule"] for x in f}


def test_wildcard_clusterrole_critical():
    f = analyze_rbac([{"kind": "ClusterRole", "metadata": {"name": "god"},
                       "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}])
    w = next((x for x in f if x.detail["rule"] == "rbac-wildcard"), None)
    check("wildcard ClusterRole CRITICAL authz", w and w.severity == Severity.CRITICAL
          and w.vuln_class == VulnClass.AUTHZ, rules(f))


def test_wildcard_namespaced_role_high_not_critical():
    f = analyze_rbac([{"kind": "Role", "metadata": {"name": "nsadmin"},
                       "rules": [{"resources": ["*"], "verbs": ["*"]}]}])
    w = next((x for x in f if x.detail["rule"] == "rbac-wildcard"), None)
    check("namespaced wildcard Role is HIGH", w and w.severity == Severity.HIGH, w and w.severity)


def test_escalation_verbs():
    f = analyze_rbac([{"kind": "ClusterRole", "metadata": {"name": "e"},
                       "rules": [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"],
                                  "verbs": ["escalate", "bind"]}]}])
    check("escalate/bind flagged", "rbac-escalation-verb" in rules(f), rules(f))


def test_secret_read_scope():
    cr = analyze_rbac([{"kind": "ClusterRole", "metadata": {"name": "s"},
                        "rules": [{"resources": ["secrets"], "verbs": ["get", "list"]}]}])
    sr = next((x for x in cr if x.detail["rule"] == "rbac-secret-read"), None)
    check("cluster-wide secret read HIGH", sr and sr.severity == Severity.HIGH, sr and sr.severity)
    ns = analyze_rbac([{"kind": "Role", "metadata": {"name": "s"},
                        "rules": [{"resources": ["secrets"], "verbs": ["get"]}]}])
    check("namespaced secret read MEDIUM",
          next(x for x in ns if x.detail["rule"] == "rbac-secret-read").severity == Severity.MEDIUM)


def test_pod_exec():
    check("pods/exec flagged", "rbac-pod-exec" in rules(analyze_rbac(
        [{"kind": "Role", "metadata": {"name": "x"}, "rules": [{"resources": ["pods/exec"], "verbs": ["create"]}]}])))
    check("pods create flagged", "rbac-pod-exec" in rules(analyze_rbac(
        [{"kind": "Role", "metadata": {"name": "x"}, "rules": [{"resources": ["pods"], "verbs": ["create"]}]}])))


def test_anonymous_binding_critical():
    f = analyze_rbac([{"kind": "ClusterRoleBinding", "metadata": {"name": "b"},
                       "roleRef": {"name": "cluster-admin"},
                       "subjects": [{"kind": "Group", "name": "system:unauthenticated"}]}])
    b = next((x for x in f if x.detail["rule"] == "rbac-broad-subject"), None)
    check("anonymous binding CRITICAL", b and b.severity == Severity.CRITICAL, rules(f))
    check("does not double-report as admin-binding", "rbac-admin-binding" not in rules(f))


def test_all_authenticated_binding_high():
    f = analyze_rbac([{"kind": "ClusterRoleBinding", "metadata": {"name": "b"},
                       "roleRef": {"name": "edit"},
                       "subjects": [{"kind": "Group", "name": "system:authenticated"}]}])
    b = next((x for x in f if x.detail["rule"] == "rbac-broad-subject"), None)
    check("all-authenticated binding HIGH", b and b.severity == Severity.HIGH, b and b.severity)


def test_cluster_admin_binding_to_sa():
    f = analyze_rbac([{"kind": "ClusterRoleBinding", "metadata": {"name": "b"},
                       "roleRef": {"name": "cluster-admin"},
                       "subjects": [{"kind": "ServiceAccount", "name": "ci"}]}])
    check("cluster-admin binding to SA flagged HIGH", any(x.detail["rule"] == "rbac-admin-binding"
          and x.severity == Severity.HIGH for x in f), rules(f))


def test_benign_role_and_binding_clean():
    f = analyze_rbac([
        {"kind": "Role", "metadata": {"name": "view"}, "rules": [{"resources": ["pods"], "verbs": ["get", "list"]}]},
        {"kind": "RoleBinding", "metadata": {"name": "vb"}, "roleRef": {"name": "view"},
         "subjects": [{"kind": "ServiceAccount", "name": "app"}]}])
    check("benign RBAC -> no findings", f == [], [x.title for x in f])


def test_engine_yaml():
    text = ("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: god}\n"
            "rules:\n  - apiGroups: ['*']\n    resources: ['*']\n    verbs: ['*']\n")
    check("engine parses YAML RBAC", "rbac-wildcard" in rules(K8sRbacScan().scan_text(text, "r.yaml")))


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
