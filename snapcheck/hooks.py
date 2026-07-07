"""Install git pre-commit hook for SnapCheck."""

from __future__ import annotations

import stat
import sys
from pathlib import Path

from snapcheck.i18n import t

HOOK_SCRIPT = """#!/bin/sh
# SnapCheck pre-commit hook — auto-installed
exec snapcheck scan . --fail-on-critical --no-duplicates --quiet
"""


def install_pre_commit(root: Path) -> int:
    root = root.resolve()
    git_dir = root / ".git"
    if not git_dir.is_dir():
        print(t("cli.err_not_git"), file=sys.stderr)
        return 2

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8", errors="ignore")
        if "SnapCheck pre-commit" in existing:
            print(t("hooks.already", path=hook_path))
            return 0

    hook_path.write_text(HOOK_SCRIPT, encoding="utf-8")
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(t("hooks.installed", path=hook_path))
    return 0