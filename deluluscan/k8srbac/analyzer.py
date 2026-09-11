"""Kubernetes RBAC misconfiguration analysis.

The pod-spec checks in container/ cover a workload's own privileges; this covers
who can do WHAT in the cluster — the RBAC layer, a top cluster-takeover path.
Flags over-permissive Roles/ClusterRoles (wildcard verbs+resources, the privilege-
escalation verbs escalate/bind/impersonate, cluster-wide secret read, pod
create/exec) and dangerous bindings (cluster-admin, or any role granted to
anonymous / all-authenticated subjects). Static, offline, detection only.
"""
from __future__ import annotations

from ..models import Finding, RequestRecord, Severity, VulnClass

_ESCALATION_VERBS = {"escalate", "bind", "impersonate"}
_READ_VERBS = {"get", "list", "watch"}
_ANON_SUBJECTS = {"system:anonymous", "system:unauthenticated"}
_ALL_AUTH = {"system:authenticated"}


def _f(vc, sev, title, desc, source, obj, rule, cwe="CWE-269", extra=None):
    ep = f"{source}:{obj}"
    return Finding(vuln_class=vc, severity=sev, title=title, endpoint=ep, description=desc,
                   evidence=[RequestRecord(method="RBAC", url=ep, identity="anon", status=0, elapsed_ms=0.0)],
                   confidence="firm", verdict="likely_true_positive", exploitability="conditional",
                   detail={"rule": rule, "object": obj, "cwe": cwe, "file": source,
                           "source": "k8srbac", **(extra or {})})


def _norm(x) -> set:
    if isinstance(x, list):
        return {str(i).lower() for i in x}
    if x is None:
        return set()
    return {str(x).lower()}


def analyze_rbac(docs, source: str = "manifest") -> list:
    out: list = []
    for doc in docs if isinstance(docs, list) else []:
        if not isinstance(doc, dict):
            continue
        kind = (doc.get("kind") or "").lower()
        meta = doc.get("metadata") or {}
        name = meta.get("name", "?")
        cluster = kind.startswith("cluster")

        # ---- Roles / ClusterRoles: examine the granted rules ----
        if kind in ("role", "clusterrole"):
            obj = f"{doc.get('kind')}/{name}"
            for r in doc.get("rules") or []:
                if not isinstance(r, dict):
                    continue
                verbs = _norm(r.get("verbs"))
                resources = _norm(r.get("resources"))
                groups = _norm(r.get("apiGroups"))

                if "*" in verbs and "*" in resources:
                    out.append(_f(VulnClass.AUTHZ,
                        Severity.CRITICAL if cluster else Severity.HIGH,
                        f"Wildcard RBAC {'ClusterRole' if cluster else 'Role'}: {name}",
                        f"{obj} grants verbs '*' on resources '*'"
                        + (" (apiGroups '*')" if "*" in groups else "")
                        + (" cluster-wide — this is effectively cluster-admin." if cluster
                           else " in its namespace — full namespace control."),
                        source, obj, "rbac-wildcard"))
                esc = verbs & _ESCALATION_VERBS
                if esc:
                    out.append(_f(VulnClass.AUTHZ, Severity.HIGH,
                        f"RBAC privilege-escalation verb ({', '.join(sorted(esc))}): {name}",
                        f"{obj} grants '{', '.join(sorted(esc))}' — a subject with this can grant "
                        "itself (or others) higher privileges, defeating RBAC boundaries.",
                        source, obj, "rbac-escalation-verb"))
                if "secrets" in resources and (verbs & _READ_VERBS or "*" in verbs):
                    out.append(_f(VulnClass.AUTHZ,
                        Severity.HIGH if cluster else Severity.MEDIUM,
                        f"RBAC allows reading secrets: {name}",
                        f"{obj} can read Secrets"
                        + (" cluster-wide — exposes every namespace's credentials." if cluster
                           else " in its namespace.") + " Scope to specific resourceNames.",
                        source, obj, "rbac-secret-read", cwe="CWE-522"))
                if "pods/exec" in resources or ("pods" in resources and ({"create", "*"} & verbs)):
                    out.append(_f(VulnClass.AUTHZ, Severity.HIGH,
                        f"RBAC allows pod create/exec: {name}",
                        f"{obj} can create pods or exec into them — arbitrary code execution on the "
                        "cluster (and a path to steal any mounted service-account token/node creds).",
                        source, obj, "rbac-pod-exec", cwe="CWE-250"))

        # ---- Bindings: dangerous roleRef or subjects ----
        if kind in ("rolebinding", "clusterrolebinding"):
            obj = f"{doc.get('kind')}/{name}"
            role_ref = (doc.get("roleRef") or {}).get("name", "")
            subjects = doc.get("subjects") or []
            subj_names = {str(s.get("name", "")).lower() for s in subjects if isinstance(s, dict)}

            exposed = subj_names & (_ANON_SUBJECTS | _ALL_AUTH)
            if exposed:
                anon = subj_names & _ANON_SUBJECTS
                out.append(_f(VulnClass.AUTHZ, Severity.CRITICAL if anon else Severity.HIGH,
                    f"RBAC binding grants a role to {'anonymous' if anon else 'all authenticated'} users: {name}",
                    f"{obj} binds role '{role_ref}' to {sorted(exposed)} — "
                    + ("ANY unauthenticated request gets these permissions." if anon
                       else "any authenticated identity (a very wide group) gets these permissions."),
                    source, obj, "rbac-broad-subject", cwe="CWE-284",
                    extra={"role": role_ref, "subjects": sorted(exposed)}))
            if role_ref.lower() in ("cluster-admin", "admin") and not exposed:
                out.append(_f(VulnClass.AUTHZ, Severity.HIGH,
                    f"RBAC binding to '{role_ref}': {name}",
                    f"{obj} grants the built-in '{role_ref}' role to {sorted(subj_names)[:3]} — "
                    "full control; confirm every subject truly needs cluster-admin.",
                    source, obj, "rbac-admin-binding",
                    extra={"role": role_ref, "subjects": sorted(subj_names)[:10]}))
    return out


RBAC_KINDS = {"role", "clusterrole", "rolebinding", "clusterrolebinding"}
