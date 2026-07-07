"""Find files larger than a threshold."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from snapcheck.ignore import IgnoreRules, build_ignore_rules


@dataclass(frozen=True)
class LargeFile:
    path: Path
    size_bytes: int


def scan_large_files(
    root: Path,
    *,
    min_size_bytes: int = 10 * 1024 * 1024,
    ignore: IgnoreRules | None = None,
) -> list[LargeFile]:
    results: list[LargeFile] = []
    root = root.resolve()
    rules = ignore if ignore is not None else build_ignore_rules(root)

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        if rules.should_skip_path(file_path.relative_to(root)):
            continue
        try:
            size = file_path.stat().st_size
        except OSError:
            continue
        if size >= min_size_bytes:
            results.append(LargeFile(path=file_path.relative_to(root), size_bytes=size))

    results.sort(key=lambda item: item.size_bytes, reverse=True)
    return results