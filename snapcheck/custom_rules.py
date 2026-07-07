"""Load user-defined secret patterns from .snapcheck-rules.json."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

RULES_FILENAME = ".snapcheck-rules.json"


@dataclass(frozen=True)
class CustomPattern:
    name: str
    pattern: re.Pattern[str]
    severity: str = "review"


def load_custom_patterns(root: Path) -> list[CustomPattern]:
    path = root / RULES_FILENAME
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    patterns: list[CustomPattern] = []
    for item in data.get("patterns", []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "Custom Rule"))
        regex = item.get("regex") or item.get("pattern")
        if not regex:
            continue
        try:
            compiled = re.compile(regex)
        except re.error:
            continue
        severity = str(item.get("severity", "review"))
        patterns.append(CustomPattern(name=name, pattern=compiled, severity=severity))
    return patterns


def list_builtin_patterns() -> list[tuple[str, str]]:
    from snapcheck.scanners.secrets import PATTERNS

    return [(name, pattern.pattern) for name, pattern in PATTERNS]