"""Persist scan history for trend comparison."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from snapcheck.i18n import t

HISTORY_FILENAME = ".snapcheck-history.json"
MAX_ENTRIES = 20


@dataclass
class HistoryEntry:
    timestamp: str
    score: int
    critical: int
    secrets: int
    large_files: int


def load_history(root: Path) -> list[HistoryEntry]:
    path = root / HISTORY_FILENAME
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    entries = []
    for item in data.get("scans", []):
        entries.append(
            HistoryEntry(
                timestamp=item.get("timestamp", ""),
                score=int(item.get("score", 0)),
                critical=int(item.get("critical", 0)),
                secrets=int(item.get("secrets", 0)),
                large_files=int(item.get("large_files", 0)),
            )
        )
    return entries


def append_history(root: Path, *, score: int, critical: int, secrets: int, large_files: int) -> None:
    entries = load_history(root)
    entries.append(
        HistoryEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            score=score,
            critical=critical,
            secrets=secrets,
            large_files=large_files,
        )
    )
    entries = entries[-MAX_ENTRIES:]
    path = root / HISTORY_FILENAME
    data = {
        "version": 1,
        "scans": [
            {
                "timestamp": e.timestamp,
                "score": e.score,
                "critical": e.critical,
                "secrets": e.secrets,
                "large_files": e.large_files,
            }
            for e in entries
        ],
    }
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def format_trend(root: Path, current_score: int) -> str | None:
    history = load_history(root)
    if not history:
        return None
    prev = history[-1]
    delta = current_score - prev.score
    arrow = "↑" if delta > 0 else "↓" if delta < 0 else "→"
    return t(
        "cli.trend",
        prev=prev.score,
        current=current_score,
        arrow=arrow,
        delta=abs(delta),
    )