"""Find duplicate files by content hash."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from snapcheck.ignore import IgnoreRules, build_ignore_rules


@dataclass(frozen=True)
class DuplicateGroup:
    hash: str
    paths: list[Path]
    size_bytes: int


def _file_hash(path: Path, chunk_size: int = 65536) -> str | None:
    digest = hashlib.md5()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def scan_duplicates(
    root: Path,
    *,
    min_size_bytes: int = 1024,
    max_files: int = 5000,
    ignore: IgnoreRules | None = None,
) -> list[DuplicateGroup]:
    root = root.resolve()
    rules = ignore if ignore is not None else build_ignore_rules(root)
    by_size: dict[int, list[Path]] = defaultdict(list)
    scanned = 0

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(root)
        if rules.should_skip_path(rel):
            continue
        try:
            size = file_path.stat().st_size
        except OSError:
            continue
        if size < min_size_bytes:
            continue
        by_size[size].append(file_path)
        scanned += 1
        if scanned >= max_files:
            break

    by_hash: dict[str, list[Path]] = {}
    for size, paths in by_size.items():
        if len(paths) < 2:
            continue
        for file_path in paths:
            file_hash = _file_hash(file_path)
            if file_hash is None:
                continue
            rel = file_path.relative_to(root)
            by_hash.setdefault(file_hash, []).append(rel)

    groups: list[DuplicateGroup] = []
    for file_hash, paths in by_hash.items():
        if len(paths) < 2:
            continue
        try:
            size = (root / paths[0]).stat().st_size
        except OSError:
            size = 0
        groups.append(
            DuplicateGroup(hash=file_hash, paths=sorted(paths), size_bytes=size)
        )

    groups.sort(key=lambda g: g.size_bytes * len(g.paths), reverse=True)
    return groups