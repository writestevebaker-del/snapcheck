"""Detect potential secrets in text files."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from snapcheck.custom_rules import CustomPattern, load_custom_patterns
from snapcheck.entropy import find_high_entropy_assignments
from snapcheck.ignore import IgnoreRules, build_ignore_rules

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".woff", ".woff2", ".ttf", ".exe", ".dll", ".so", ".pyc", ".pyo",
    ".mp4", ".mp3", ".avi", ".mov", ".sqlite", ".db", ".bin", ".dat",
}

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(r"ghp_[A-Za-z0-9]{36,}")),
    ("GitHub Fine-grained", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Anthropic API Key", re.compile(r"sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{20,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("Telegram Bot Token", re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")),
    ("Discord Bot Token", re.compile(r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("NPM Token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("PyPI Token", re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}")),
    ("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}")),
    ("Bearer Token", re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}")),
    (
        "Generic API Key",
        re.compile(
            r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})"
        ),
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

_BINARY_SNIFF = re.compile(r"[\x00-\x08\x0e-\x1f]")


@dataclass(frozen=True)
class SecretFinding:
    path: Path
    line: int
    kind: str
    snippet: str


def _skip_extension(path: Path) -> bool:
    return path.suffix.lower() in SKIP_EXTENSIONS


def _looks_binary(text: str) -> bool:
    sample = text[:4096]
    if not sample:
        return False
    if _BINARY_SNIFF.search(sample):
        return True
    non_printable = sum(1 for c in sample if ord(c) < 32 and c not in "\n\r\t")
    return non_printable / len(sample) > 0.05


def _add_finding(
    findings: list[SecretFinding],
    *,
    rel: Path,
    line_no: int,
    kind: str,
    snippet: str,
) -> None:
    if len(snippet) > 60:
        snippet = snippet[:57] + "..."
    findings.append(
        SecretFinding(path=rel, line=line_no, kind=kind, snippet=snippet)
    )


def scan_secrets(
    root: Path,
    *,
    max_file_size: int = 512_000,
    ignore: IgnoreRules | None = None,
    enable_entropy: bool = True,
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    root = root.resolve()
    rules = (
        ignore
        if ignore is not None
        else build_ignore_rules(root, include_secrets_defaults=True)
    )
    custom = load_custom_patterns(root)
    all_patterns: list[tuple[str, re.Pattern[str]]] = list(PATTERNS)
    for cp in custom:
        all_patterns.append((cp.name, cp.pattern))

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(root)
        if rules.should_skip_path(rel):
            continue
        if _skip_extension(file_path):
            continue
        try:
            size = file_path.stat().st_size
            if size > max_file_size or size == 0:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _looks_binary(text):
            continue

        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            matched = False
            for kind, pattern in all_patterns:
                match = pattern.search(line)
                if match:
                    _add_finding(
                        findings,
                        rel=rel,
                        line_no=line_no,
                        kind=kind,
                        snippet=match.group(0),
                    )
                    matched = True
                    break
            if not matched and enable_entropy:
                for snippet in find_high_entropy_assignments(line):
                    _add_finding(
                        findings,
                        rel=rel,
                        line_no=line_no,
                        kind="High Entropy Secret",
                        snippet=snippet,
                    )
                    break

    return findings