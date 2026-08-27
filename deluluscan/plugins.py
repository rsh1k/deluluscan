"""deluluscan.plugins — load out-of-tree scanners from a directory.

A YAML template (`deluluscan.templates`) covers "request these paths, match these
markers". Anything needing real logic — a multi-step chain, a differential
across identities, correlation with telemetry — needs Python. Until now that
meant editing `deluluscan/scanners/__init__.py`, which makes a site-specific or
experimental check a fork of the tool.

A plugin is a `.py` file under the plugin directory that defines one or more
`Scanner` subclasses. It is discovered, validated and registered at startup:

    # plugins/my_check.py
    from deluluscan.scanners.base import Scanner
    from deluluscan.models import Finding, Severity, VulnClass

    class MyCheckScanner(Scanner):
        name = "my_check"
        vuln_classes = ["misconfig"]

        def run(self, endpoint):
            ...
            yield Finding(...)

Deliberate constraints, and why:

* **A plugin is code, and loading it executes it.** There is no sandbox here and
  this module does not pretend otherwise — the boundary is the filesystem. The
  loader therefore defaults to OFF, must be pointed at a directory explicitly,
  and refuses a world-writable one, because "anyone on the box can drop a file
  that Deluluscan will execute as you" is a privilege-escalation primitive rather
  than an extensibility feature.
* **A broken plugin never breaks the scan.** Import errors, bad subclasses and
  name collisions are collected and reported; the scan proceeds with what
  loaded. A half-working plugin directory must not cost you the other 40
  scanners.
* **A plugin cannot silently shadow a built-in.** Overriding a core scanner name
  requires `allow_override=True`, so a stray file cannot quietly replace the
  SQLi scanner with something weaker.
"""
from __future__ import annotations

import importlib.util
import inspect
import os
import stat
import sys
from dataclasses import dataclass, field

from .scanners import SCANNER_REGISTRY
from .scanners.base import Scanner


@dataclass
class LoadedPlugin:
    name: str
    cls: type
    source_path: str
    vuln_classes: list[str] = field(default_factory=list)


@dataclass
class PluginLoadResult:
    plugins: list[LoadedPlugin] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def registry(self) -> dict[str, type]:
        return {p.name: p.cls for p in self.plugins}

    def summary(self) -> str:
        parts = [f"{len(self.plugins)} plugin(s) loaded"]
        if self.skipped:
            parts.append(f"{len(self.skipped)} skipped")
        if self.errors:
            parts.append(f"{len(self.errors)} error(s)")
        return ", ".join(parts)


def _is_world_writable(path: str) -> bool:
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return bool(mode & stat.S_IWOTH)


def discover(directory: str) -> list[str]:
    """Python files in `directory` that are candidate plugins."""
    if not os.path.isdir(directory):
        return []
    out = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".py") or name.startswith(("_", ".")):
            continue
        out.append(os.path.join(directory, name))
    return out


def _load_module(path: str):
    mod_name = f"deluluscan_plugin_{os.path.splitext(os.path.basename(path))[0]}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot build a module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    # Registered before exec so a plugin that imports itself resolves, and
    # removed again on failure so a broken import leaves nothing behind.
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(mod_name, None)
        raise
    return module


def scanner_classes(module) -> list[type]:
    """Scanner subclasses defined IN this module (not imported into it)."""
    out = []
    for _name, obj in inspect.getmembers(module, inspect.isclass):
        if not issubclass(obj, Scanner) or obj is Scanner:
            continue
        # Only classes the plugin itself defines: `from ... import SqliScanner`
        # should not re-register the built-in under a plugin's banner.
        if getattr(obj, "__module__", None) != module.__name__:
            continue
        out.append(obj)
    return out


def load(directory: str | None, *, allow_override: bool = False,
         allow_world_writable: bool = False) -> PluginLoadResult:
    """Load plugins from `directory`. Never raises; collects problems instead."""
    result = PluginLoadResult()
    if not directory:
        return result
    directory = os.path.abspath(os.path.expanduser(directory))

    if not os.path.isdir(directory):
        result.errors.append(f"plugin directory not found: {directory}")
        return result

    if _is_world_writable(directory) and not allow_world_writable:
        result.errors.append(
            f"refusing to load plugins from world-writable directory {directory}. "
            "Loading a plugin executes it, so a directory any user can write to "
            "is a code-execution path into this process. Fix the permissions "
            "(chmod o-w) or pass allow_world_writable=True if this is deliberate.")
        return result

    for path in discover(directory):
        if _is_world_writable(path) and not allow_world_writable:
            result.errors.append(f"refusing world-writable plugin file: {path}")
            continue
        try:
            module = _load_module(path)
        except Exception as exc:
            # A plugin that fails to import must not take the scan with it.
            result.errors.append(f"{os.path.basename(path)}: {type(exc).__name__}: {exc}")
            continue

        found = scanner_classes(module)
        if not found:
            result.skipped.append(f"{os.path.basename(path)}: defines no Scanner subclass")
            continue

        for cls in found:
            name = getattr(cls, "name", "") or ""
            if not name or name == "base":
                result.errors.append(
                    f"{os.path.basename(path)}: {cls.__name__} needs a unique "
                    f"class attribute `name`")
                continue
            if not callable(getattr(cls, "run", None)) or cls.run is Scanner.run:
                result.errors.append(
                    f"{os.path.basename(path)}: {cls.__name__} does not implement run()")
                continue
            if name in SCANNER_REGISTRY and not allow_override:
                result.errors.append(
                    f"{os.path.basename(path)}: {cls.__name__} uses the name "
                    f"'{name}', which is a built-in scanner. Rename it, or pass "
                    f"allow_override=True to replace the built-in deliberately.")
                continue
            if any(p.name == name for p in result.plugins):
                result.errors.append(
                    f"{os.path.basename(path)}: duplicate plugin name '{name}'")
                continue
            result.plugins.append(LoadedPlugin(
                name=name, cls=cls, source_path=path,
                vuln_classes=list(getattr(cls, "vuln_classes", []) or [])))
    return result


def merged_registry(directory: str | None, **kwargs) -> tuple[dict[str, type], PluginLoadResult]:
    """The built-in registry with plugins layered on top.

    Returns (registry, load_result) so a caller can surface load errors rather
    than discovering later that a plugin silently did not run.
    """
    result = load(directory, **kwargs)
    registry = dict(SCANNER_REGISTRY)
    registry.update(result.registry)
    return registry, result


def describe(directory: str | None = None) -> str:
    result = load(directory, allow_world_writable=True)
    lines = [f"Deluluscan plugins ({directory or 'no directory configured'})", "=" * 60,
             result.summary(), ""]
    for p in result.plugins:
        lines.append(f"  {p.name:24} {p.cls.__name__:28} "
                     f"[{', '.join(p.vuln_classes) or 'no class declared'}]")
        lines.append(f"  {'':24} {p.source_path}")
    for s in result.skipped:
        lines.append(f"  - skipped: {s}")
    for e in result.errors:
        lines.append(f"  ! {e}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(describe(sys.argv[1] if len(sys.argv) > 1 else None))
