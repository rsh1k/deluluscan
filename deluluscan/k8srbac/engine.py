"""K8sRbacScan — load Kubernetes manifests and analyze their RBAC objects."""
from __future__ import annotations

import os

from .analyzer import analyze_rbac, RBAC_KINDS


class K8sRbacScan:
    def scan_text(self, text: str, source: str = "manifest") -> list:
        try:
            import yaml
            docs = [d for d in yaml.safe_load_all(text)
                    if isinstance(d, dict) and (d.get("kind") or "").lower() in RBAC_KINDS]
        except Exception:
            return []
        return analyze_rbac(docs, source)

    def scan_path(self, path: str) -> list:
        if os.path.isfile(path):
            try:
                return self.scan_text(open(path, encoding="utf-8", errors="replace").read(),
                                      os.path.basename(path))
            except Exception:
                return []
        out = []
        for dirpath, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
            for n in names:
                if n.lower().endswith((".yaml", ".yml")):
                    fp = os.path.join(dirpath, n)
                    try:
                        out.extend(self.scan_text(open(fp, encoding="utf-8", errors="replace").read(),
                                                  os.path.relpath(fp, path)))
                    except Exception:
                        continue
        return out
