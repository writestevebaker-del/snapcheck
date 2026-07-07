"""Redact sensitive values in output."""

from __future__ import annotations

import re

_REDACT_PATTERNS = [
    (re.compile(r"(sk-[A-Za-z0-9_\-]{8})[A-Za-z0-9_\-]+"), r"\1••••••••"),
    (re.compile(r"(ghp_[A-Za-z0-9]{6})[A-Za-z0-9]+"), r"\1••••••"),
    (re.compile(r"(AKIA[0-9A-Z]{4})[0-9A-Z]+"), r"\1••••••••"),
    (re.compile(r"(xox[baprs]-[0-9A-Za-z\-]{4})[0-9A-Za-z\-]+"), r"\1••••"),
    (re.compile(r"(sk_live_[0-9a-zA-Z]{6})[0-9a-zA-Z]+"), r"\1••••••"),
    (re.compile(r"(\d{8,10}:)[A-Za-z0-9_-]{6}[A-Za-z0-9_-]+"), r"\1••••••••"),
    (re.compile(r"(?i)(api[_-]?key\s*[=:]\s*['\"]?)([A-Za-z0-9_\-]{8})[A-Za-z0-9_\-]+"), r"\1\2••••"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{6}[A-Za-z0-9_\-\.]+"), r"Bearer ••••••••"),
]


def redact_snippet(text: str) -> str:
    result = text
    for pattern, repl in _REDACT_PATTERNS:
        result = pattern.sub(repl, result)
    if len(result) > 64:
        result = result[:61] + "..."
    return result