"""Interactive fix wizard for safe remediations."""

from __future__ import annotations

import sys
from pathlib import Path

from snapcheck.i18n import t
from snapcheck.ignore import IGNORE_FILENAME
from snapcheck.recommendations import Severity, build_recommendations
from snapcheck.report import ScanReport


def _append_unique_line(path: Path, line: str) -> bool:
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="ignore")
        if line in text.splitlines():
            return False
        with path.open("a", encoding="utf-8") as fh:
            if text and not text.endswith("\n"):
                fh.write("\n")
            fh.write(line + "\n")
    else:
        path.write_text(line + "\n", encoding="utf-8")
    return True


def apply_safe_fixes(report: ScanReport, *, yes: bool = False) -> int:
    applied = 0
    gitignore = report.root / ".gitignore"
    snapignore = report.root / IGNORE_FILENAME

    for rec in report.recommendations:
        if rec.severity not in {Severity.CRITICAL, Severity.WARNING}:
            continue
        for cmd in rec.commands:
            if cmd.startswith("#"):
                continue
            if "git rm" in cmd:
                if yes:
                    print(t("fix.skip_git", cmd=cmd))
                continue
            if cmd.startswith("echo "):
                parts = cmd.split(">>", 1)
                if len(parts) != 2:
                    continue
                target_name = parts[1].strip()
                line = parts[0].replace("echo ", "").strip().strip("'\"")
                target = gitignore if "gitignore" in target_name else snapignore
                if not yes:
                    answer = input(t("fix.confirm", cmd=cmd)).strip().lower()
                    if answer not in {"y", "yes", "д", "да"}:
                        continue
                if _append_unique_line(target, line):
                    print(t("fix.applied", path=target, line=line))
                    applied += 1

    print(t("fix.done", count=applied))
    return 0 if applied >= 0 else 1