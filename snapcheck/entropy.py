"""Detect high-entropy strings that may be secrets."""

from __future__ import annotations

import math
import re

_ASSIGNMENT = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|auth)\s*[=:]\s*['\"]?([A-Za-z0-9_\-/+=]{20,})['\"]?"
)
_BASE64ISH = re.compile(r"^[A-Za-z0-9_\-/+=]+$")


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def find_high_entropy_assignments(line: str, *, min_entropy: float = 4.2) -> list[str]:
    """Return suspicious assignment values from a line."""
    hits: list[str] = []
    for match in _ASSIGNMENT.finditer(line):
        value = match.group(1)
        if len(value) < 20:
            continue
        if not _BASE64ISH.match(value):
            continue
        if value.isupper() and "_" in value:
            continue  # ENV_VAR_NAME
        if shannon_entropy(value) >= min_entropy:
            hits.append(match.group(0)[:60])
    return hits