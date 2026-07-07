"""Initialize SnapCheck config in a project."""

from __future__ import annotations

from pathlib import Path

from snapcheck.i18n import t
from snapcheck.ignore import IGNORE_FILENAME

DEFAULT_IGNORE_TEMPLATE = """# SnapCheck — paths to skip during scan
# https://github.com/midnight-bot/snapcheck

# Logs (often contain env var names, not real secrets)
logs/
*.log

# Backup copies of source files
*_backup_*
*backup*

# Dependencies & caches
node_modules/
vendor/
.venv/
venv/

# Build artifacts
dist/
build/
*.egg-info/

# Test fixtures with fake tokens
tests/fixtures/
"""


def run_init(target: Path, *, force: bool = False) -> int:
    target = target.resolve()
    if not target.is_dir():
        print(t("cli.err_not_dir", path=target), file=sys.stderr)
        return 2

    ignore_path = target / IGNORE_FILENAME
    if ignore_path.exists() and not force:
        print(t("init.exists", path=ignore_path))
        print(t("init.force_hint"))
        return 1

    ignore_path.write_text(DEFAULT_IGNORE_TEMPLATE, encoding="utf-8")
    print(t("init.created", path=ignore_path))
    print(t("init.hint"))
    return 0