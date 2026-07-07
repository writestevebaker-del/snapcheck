"""Baseline allowlist — ignore known accepted findings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

BASELINE_FILENAME = ".snapcheck-baseline.json"


@dataclass(frozen=True)
class BaselineEntry:
    path: str
    line: int
    kind: str


def load_baseline(root: Path) -> set[BaselineEntry]:
    path = root / BASELINE_FILENAME
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    entries: set[BaselineEntry] = set()
    for item in data.get("accepted", []):
        entries.add(
            BaselineEntry(
                path=item.get("path", ""),
                line=int(item.get("line", 0)),
                kind=item.get("kind", ""),
            )
        )
    return entries


def save_baseline(root: Path, entries: set[BaselineEntry]) -> Path:
    path = root / BASELINE_FILENAME
    data = {
        "version": 1,
        "accepted": [
            {"path": e.path, "line": e.line, "kind": e.kind}
            for e in sorted(entries, key=lambda x: (x.path, x.line))
        ],
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def filter_by_baseline(findings, baseline: set[BaselineEntry]):
    """Filter SecretFinding list against baseline."""
    if not baseline:
        return findings
    kept = []
    for f in findings:
        key = BaselineEntry(path=str(f.path).replace("\\", "/"), line=f.line, kind=f.kind)
        if key not in baseline:
            kept.append(f)
    return kept