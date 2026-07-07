"""Summarize disk usage by top-level directories."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from snapcheck.ignore import IgnoreRules, build_ignore_rules


@dataclass(frozen=True)
class DirUsage:
    path: Path
    size_bytes: int


def _dir_size(path: Path, root: Path, rules: IgnoreRules) -> int:
    total = 0
    try:
        for child in path.rglob("*"):
            if not child.is_file():
                continue
            rel = child.relative_to(root)
            if rules.should_skip_path(rel):
                continue
            try:
                total += child.stat().st_size
            except OSError:
                pass
    except OSError:
        return 0
    return total


def scan_disk_usage(
    root: Path,
    *,
    top_n: int = 10,
    ignore: IgnoreRules | None = None,
) -> list[DirUsage]:
    root = root.resolve()
    rules = ignore if ignore is not None else build_ignore_rules(root)
    usages: list[DirUsage] = []

    try:
        children = sorted(root.iterdir())
    except OSError:
        return []

    for child in children:
        if not child.is_dir():
            continue
        if rules.should_skip_path(child.relative_to(root)):
            continue
        size = _dir_size(child, root, rules)
        if size > 0:
            usages.append(DirUsage(path=child.relative_to(root), size_bytes=size))

    usages.sort(key=lambda item: item.size_bytes, reverse=True)
    return usages[:top_n]