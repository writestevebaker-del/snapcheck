"""Generate .snapcheckignore from scan results."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from snapcheck.i18n import t
from snapcheck.ignore import IGNORE_FILENAME, load_ignore_file
from snapcheck.init_cmd import DEFAULT_IGNORE_TEMPLATE
from snapcheck.recommendations import SecretRisk, classify_secrets
from snapcheck.scanners.secrets import scan_secrets


def suggest_ignore_lines(root: Path) -> list[str]:
    """Analyze false positives and noisy paths; return extra ignore lines."""
    findings = scan_secrets(root)
    classified = classify_secrets(findings)
    lines: list[str] = []

    false_pos = [c for c in classified if c.risk == SecretRisk.FALSE_POSITIVE]
    if len(false_pos) >= 3:
        backup_dirs: Counter[str] = Counter()
        for item in false_pos:
            path = str(item.finding.path).replace("\\", "/")
            if "backup" in path.lower():
                lines.append("*_backup_*")
                lines.append("*backup*")
                break
            parts = Path(path).parts
            if len(parts) > 1:
                backup_dirs[parts[0]] += 1
        for name, count in backup_dirs.most_common(3):
            if count >= 2 and name not in {"bot", "src", "lib"}:
                lines.append(f"{name}/")

    log_hits = sum(
        1
        for c in classified
        if str(c.finding.path).startswith("logs/") or "/logs/" in str(c.finding.path)
    )
    if log_hits >= 2 and "logs/" not in lines:
        lines.append("logs/")
        lines.append("*.log")

    # Heavy log files from path patterns
    for item in false_pos:
        path = str(item.finding.path)
        if path.endswith(".md") and "logs/" in path:
            if "logs/" not in lines:
                lines.append("logs/")

    seen: set[str] = set()
    unique: list[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique.append(line)
    return unique


def run_smart_init(target: Path, *, force: bool = False) -> int:
    target = target.resolve()
    if not target.is_dir():
        print(t("cli.err_not_dir", path=target), file=sys.stderr)
        return 2

    ignore_path = target / IGNORE_FILENAME
    if ignore_path.exists() and not force:
        suggestions = suggest_ignore_lines(target)
        if suggestions:
            print(t("init.suggested"))
            for line in suggestions:
                print(f"  {line}")
        else:
            print(t("init.no_suggestions", path=ignore_path))
        return 0

    suggestions = suggest_ignore_lines(target)
    content = DEFAULT_IGNORE_TEMPLATE
    if suggestions:
        content += "\n# Auto-detected from project scan\n"
        content += "\n".join(suggestions) + "\n"

    ignore_path.write_text(content, encoding="utf-8")
    print(t("init.created", path=ignore_path))
    if suggestions:
        print(t("init.auto_added"))
        for line in suggestions:
            print(f"  + {line}")
    return 0