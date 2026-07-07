"""Validate SnapCheck configuration files."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from snapcheck.config import CONFIG_FILENAME, load_config
from snapcheck.custom_rules import RULES_FILENAME, load_custom_patterns
from snapcheck.ignore import IGNORE_FILENAME, load_ignore_file
from snapcheck.i18n import t


def validate_project(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []

    cfg_path = root / CONFIG_FILENAME
    if cfg_path.is_file():
        try:
            load_config(root)
        except Exception as exc:
            errors.append(f"{CONFIG_FILENAME}: {exc}")

    rules_path = root / RULES_FILENAME
    if rules_path.is_file():
        try:
            data = json.loads(rules_path.read_text(encoding="utf-8"))
            for idx, item in enumerate(data.get("patterns", [])):
                regex = item.get("regex") or item.get("pattern")
                if not regex:
                    errors.append(f"{RULES_FILENAME}[{idx}]: missing regex")
                    continue
                try:
                    re.compile(regex)
                except re.error as exc:
                    errors.append(f"{RULES_FILENAME}[{idx}]: {exc}")
        except json.JSONDecodeError as exc:
            errors.append(f"{RULES_FILENAME}: invalid JSON — {exc}")

    ignore_path = root / IGNORE_FILENAME
    if ignore_path.is_file():
        load_ignore_file(root)

    return errors


def run_validate(target: Path) -> int:
    if not target.is_dir():
        print(t("cli.err_not_dir", path=target), file=sys.stderr)
        return 2
    errors = validate_project(target)
    if errors:
        for err in errors:
            print(f"  ✗ {err}", file=sys.stderr)
        return 1
    print(f"  ✓ {target} — config OK")
    return 0