"""Unified file tree walker with depth/file limits."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from snapcheck.ignore import IgnoreRules

SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".woff", ".woff2", ".ttf", ".exe", ".dll", ".so", ".pyc", ".pyo",
    ".mp4", ".mp3", ".avi", ".mov", ".sqlite", ".db", ".bin", ".dat",
})


@dataclass
class WalkConfig:
    max_depth: int | None = None
    max_files: int | None = None
    progress: bool = False
    skip_extensions: frozenset[str] = SKIP_EXTENSIONS


def walk_files(
    root: Path,
    ignore: IgnoreRules,
    *,
    config: WalkConfig | None = None,
) -> Iterator[tuple[Path, Path]]:
    """Yield (absolute_path, relative_path) for each file under *root*."""
    cfg = config or WalkConfig()
    root = root.resolve()
    count = 0
    stack: list[tuple[Path, int]] = [(root, 0)]

    while stack:
        current, depth = stack.pop()
        if cfg.max_depth is not None and depth > cfg.max_depth:
            continue
        try:
            with os.scandir(current) as entries:
                dirs: list[Path] = []
                files: list[Path] = []
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        dirs.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        files.append(Path(entry.path))
        except OSError:
            continue

        for file_path in sorted(files):
            rel = file_path.relative_to(root)
            if ignore.should_skip_path(rel):
                continue
            if file_path.suffix.lower() in cfg.skip_extensions:
                continue
            yield file_path, rel
            count += 1
            if cfg.progress and count % 500 == 0:
                print(f"\r  … {count} files", end="", file=sys.stderr, flush=True)
            if cfg.max_files is not None and count >= cfg.max_files:
                if cfg.progress:
                    print(file=sys.stderr)
                return

        for dir_path in sorted(dirs, reverse=True):
            rel = dir_path.relative_to(root)
            if ignore.should_skip_path(rel):
                continue
            if cfg.max_depth is not None and depth + 1 > cfg.max_depth:
                continue
            stack.append((dir_path, depth + 1))

    if cfg.progress and count:
        print(f"\r  … {count} files", file=sys.stderr, flush=True)