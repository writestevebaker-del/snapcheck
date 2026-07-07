"""Load .snapcheckignore and decide which paths to skip."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

IGNORE_FILENAME = ".snapcheckignore"

DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".snapcheck",
        ".pytest_cache",
    }
)

# Secrets scanner also skips tests by default (noisy fixtures).
SECRETS_EXTRA_SKIP_DIRS = frozenset({"tests"})


@dataclass
class IgnoreRules:
    """Merged ignore rules for a scan root."""

    dir_names: set[str] = field(default_factory=set)
    path_globs: list[str] = field(default_factory=list)
    path_prefixes: list[str] = field(default_factory=list)

    def with_extra_dirs(self, names: set[str]) -> IgnoreRules:
        return IgnoreRules(
            dir_names=self.dir_names | names,
            path_globs=list(self.path_globs),
            path_prefixes=list(self.path_prefixes),
        )

    def should_skip_path(self, rel_path: Path) -> bool:
        parts = rel_path.parts
        for name in self.dir_names:
            if name in parts:
                return True
        rel_str = rel_path.as_posix()
        for prefix in self.path_prefixes:
            if rel_str == prefix or rel_str.startswith(prefix + "/"):
                return True
        name = rel_path.name
        for pattern in self.path_globs:
            if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(name, pattern):
                return True
        return False


def _parse_ignore_lines(lines: list[str]) -> IgnoreRules:
    dir_names: set[str] = set()
    path_globs: list[str] = []
    path_prefixes: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("/"):
            base = line.rstrip("/")
            if "/" in base:
                path_prefixes.append(base)
            else:
                dir_names.add(base)
            continue
        if "*" in line or "/" in line:
            path_globs.append(line)
        else:
            dir_names.add(line)
    return IgnoreRules(
        dir_names=dir_names,
        path_globs=path_globs,
        path_prefixes=path_prefixes,
    )


def load_ignore_file(root: Path) -> IgnoreRules:
    """Read ``.snapcheckignore`` from *root* if present."""
    path = root / IGNORE_FILENAME
    if not path.is_file():
        return IgnoreRules()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return IgnoreRules()
    return _parse_ignore_lines(text.splitlines())


def build_ignore_rules(
    root: Path,
    *,
    extra_skip_dirs: set[str] | None = None,
    include_secrets_defaults: bool = False,
) -> IgnoreRules:
    """Default skips + file + CLI ``--exclude``."""
    base_dirs = set(DEFAULT_SKIP_DIRS)
    if include_secrets_defaults:
        base_dirs |= set(SECRETS_EXTRA_SKIP_DIRS)
    file_rules = load_ignore_file(root)
    merged = IgnoreRules(
        dir_names=base_dirs | file_rules.dir_names,
        path_globs=list(file_rules.path_globs),
        path_prefixes=list(file_rules.path_prefixes),
    )
    if extra_skip_dirs:
        merged = merged.with_extra_dirs(extra_skip_dirs)
    return merged