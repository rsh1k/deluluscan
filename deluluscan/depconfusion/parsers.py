"""Parse dependency manifests + private-registry config. Best-effort and
dependency-free (no toml/yaml libs required) — regex/JSON only."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Dependency:
    ecosystem: str          # npm | pip | composer | rubygems
    name: str
    manifest: str           # file it came from
    scoped: bool = False    # npm @scope/name


# ---- manifest parsers (filename -> parser) ---------------------------------
def _parse_package_json(text: str, path: str) -> list:
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name in (data.get(key) or {}):
            if not isinstance(name, str) or not name:
                continue
            out.append(Dependency("npm", name, path, scoped=name.startswith("@")))
    return out


_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~;\[].*)?$")


def _parse_requirements(text: str, path: str) -> list:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://", ".")):
            continue
        m = _REQ_RE.match(line)
        if m:
            out.append(Dependency("pip", m.group(1), path))
    return out


def _parse_pyproject(text: str, path: str) -> list:
    # dependency-free: pull quoted names out of [project].dependencies / poetry deps
    out, seen = [], set()
    for m in re.finditer(r'["\']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~\[].*?)?["\']', text):
        nm = m.group(1)
        # crude filter: skip obvious non-package tokens
        if nm.lower() in ("python", "name", "version", "description", "readme") or nm in seen:
            continue
        seen.add(nm)
    # only trust names that appear in a dependencies-ish context
    if re.search(r'dependencies\s*=|\[tool\.poetry\.dependencies\]', text):
        for nm in seen:
            out.append(Dependency("pip", nm, path))
    return out


def _parse_composer(text: str, path: str) -> list:
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for key in ("require", "require-dev"):
        for name in (data.get(key) or {}):
            if isinstance(name, str) and "/" in name and not name.startswith("php") and "ext-" not in name:
                out.append(Dependency("composer", name, path))
    return out


def _parse_gemfile(text: str, path: str) -> list:
    return [Dependency("rubygems", m.group(1), path)
            for m in re.finditer(r'^\s*gem\s+["\']([A-Za-z0-9._-]+)["\']', text, re.M)]


_MANIFESTS = {
    "package.json": _parse_package_json,
    "requirements.txt": _parse_requirements,
    "pyproject.toml": _parse_pyproject,
    "composer.json": _parse_composer,
    "Gemfile": _parse_gemfile,
}

# ---- private-registry config detection -------------------------------------
_PRIVATE_CFG = {
    ".npmrc": r"(?im)^\s*(?:@[\w-]+:)?registry\s*=\s*https?://(?!registry\.npmjs\.org)",
    "pip.conf": r"(?im)index-url\s*=\s*https?://(?!(?:pypi\.org|files\.pythonhosted\.org))",
    ".yarnrc.yml": r"(?im)npmRegistryServer:\s*[\"']?https?://(?!registry\.npmjs\.org)",
    "pyproject.toml": r"(?im)\[\[tool\.(?:poetry|uv)\.(?:source|index)\]\]",
}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "vendor"}


def scan_tree(root: str):
    """Return (deps: list[Dependency], private_registries: list[str])."""
    deps, private = [], []
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for n in names:
            fp = os.path.join(dirpath, n)
            rel = os.path.relpath(fp, root)
            if n in _MANIFESTS or n in _PRIVATE_CFG:
                try:
                    text = open(fp, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                if n in _MANIFESTS:
                    deps += _MANIFESTS[n](text, rel)
                if n in _PRIVATE_CFG and re.search(_PRIVATE_CFG[n], text):
                    private.append(rel)
    # de-dup deps
    seen, uniq = set(), []
    for d in deps:
        k = (d.ecosystem, d.name)
        if k not in seen:
            seen.add(k); uniq.append(d)
    return uniq, private
