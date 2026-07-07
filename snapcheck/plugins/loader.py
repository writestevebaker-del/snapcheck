"""Discover and load SnapCheck plugins from disk."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from snapcheck.plugins.base import SnapCheckPlugin

PLUGINS_DIRNAME = ".snapcheck/plugins"


def _load_module_from_file(path: Path):
    spec = importlib.util.spec_from_file_location(f"snapcheck_plugin_{path.stem}", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _extract_plugin(module) -> SnapCheckPlugin | None:
    if hasattr(module, "plugin") and isinstance(module.plugin, SnapCheckPlugin):
        return module.plugin
    if hasattr(module, "get_plugin"):
        obj = module.get_plugin()
        if isinstance(obj, SnapCheckPlugin):
            return obj
    for attr in dir(module):
        if attr.startswith("_"):
            continue
        obj = getattr(module, attr)
        if (
            isinstance(obj, type)
            and issubclass(obj, SnapCheckPlugin)
            and obj is not SnapCheckPlugin
        ):
            return obj()
    return None


def load_plugin_file(path: Path) -> SnapCheckPlugin | None:
    path = path.resolve()
    if not path.is_file() or path.suffix != ".py":
        return None
    try:
        module = _load_module_from_file(path)
    except Exception:
        return None
    if module is None:
        return None
    return _extract_plugin(module)


def discover_plugin_paths(root: Path, extra_files: list[Path] | None = None) -> list[Path]:
    paths: list[Path] = []
    plugins_dir = root / PLUGINS_DIRNAME
    if plugins_dir.is_dir():
        paths.extend(sorted(plugins_dir.glob("*.py")))
    if extra_files:
        paths.extend(extra_files)
    seen: set[Path] = set()
    unique: list[Path] = []
    for p in paths:
        if p.name.startswith("_"):
            continue
        resolved = p.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return unique


def load_plugins(
    root: Path,
    *,
    extra_files: list[Path] | None = None,
) -> list[SnapCheckPlugin]:
    plugins: list[SnapCheckPlugin] = []
    for path in discover_plugin_paths(root, extra_files):
        plugin = load_plugin_file(path)
        if plugin is not None:
            plugins.append(plugin)
    return plugins