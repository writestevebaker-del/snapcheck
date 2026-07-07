"""Detect plain-text passwords in JSON/YAML/TOML configs."""

from __future__ import annotations

import re
from pathlib import Path

from snapcheck.ignore import IgnoreRules, build_ignore_rules
from snapcheck.scanners._walk import WalkConfig, walk_files
from snapcheck.scanners.secrets import SecretFinding, _add_finding, _looks_binary

_JSON_KV = re.compile(
    r'(?i)"(?:password|passwd|pwd|secret|token|api_key|apikey|auth)"\s*:\s*"([^"]{8,})"'
)
_YAML_KV = re.compile(
    r"(?i)^\s*(?:password|passwd|secret|token|api_key|apikey|auth)\s*:\s*['\"]?([^'\"#\s]{8,})"
)
_BARE_JSON_VALUE = re.compile(r'"([^"]{12,})"\s*[,}]')
_CREDENTIAL_FILENAMES = re.compile(
    r"(?i)(passwords|credentials|secrets)",
)
_PLACEHOLDER = re.compile(r"x{3,}|your[_-]|placeholder|example|changeme", re.I)


def _is_credential_filename(path: Path) -> bool:
    return bool(_CREDENTIAL_FILENAMES.search(path.name))


def _scan_json_content(
    findings: list[SecretFinding],
    *,
    rel: Path,
    text: str,
) -> None:
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in _JSON_KV.finditer(line):
            value = match.group(1)
            if _PLACEHOLDER.search(value):
                continue
            _add_finding(
                findings,
                rel=rel,
                line_no=line_no,
                kind="Config Password",
                snippet=match.group(0),
            )
            return

    if not _is_credential_filename(rel):
        return

    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped in {"{", "}", "[", "]"}:
            continue
        for match in _BARE_JSON_VALUE.finditer(line):
            value = match.group(1)
            if not re.fullmatch(r"[A-Za-z0-9_\-]{12,}", value):
                continue
            if _PLACEHOLDER.search(value):
                continue
            if ":" in value and value.count(":") == 1 and value[0].isdigit():
                continue
            _add_finding(
                findings,
                rel=rel,
                line_no=line_no,
                kind="Config Password",
                snippet=f'"{value[:20]}..."',
            )


def _scan_yaml_content(
    findings: list[SecretFinding],
    *,
    rel: Path,
    text: str,
) -> None:
    for line_no, line in enumerate(text.splitlines(), start=1):
        match = _YAML_KV.search(line)
        if not match:
            continue
        value = match.group(1)
        if _PLACEHOLDER.search(value):
            continue
        _add_finding(
            findings,
            rel=rel,
            line_no=line_no,
            kind="Config Password",
            snippet=line.strip()[:60],
        )


def scan_config_secrets(
    root: Path,
    *,
    ignore: IgnoreRules | None = None,
    walk_config: WalkConfig | None = None,
    max_file_size: int = 512_000,
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    root = root.resolve()
    rules = ignore if ignore is not None else build_ignore_rules(root, include_secrets_defaults=True)

    for file_path, rel in walk_files(root, rules, config=walk_config):
        suffix = file_path.suffix.lower()
        if suffix not in {".json", ".yaml", ".yml", ".toml"} and not _is_credential_filename(rel):
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

        if suffix in {".json"} or _is_credential_filename(rel):
            _scan_json_content(findings, rel=rel, text=text)
        if suffix in {".yaml", ".yml", ".toml"}:
            _scan_yaml_content(findings, rel=rel, text=text)

    return findings