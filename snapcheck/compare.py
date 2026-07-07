"""Compare two scan JSON reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from snapcheck.i18n import t


@dataclass(frozen=True)
class ScanDiff:
    score_delta: int
    new_secrets: list[str]
    fixed_secrets: list[str]
    new_large_files: list[str]


def _secret_keys(data: dict) -> set[str]:
    keys: set[str] = set()
    for item in data.get("secrets", []):
        keys.add(f"{item.get('path')}:{item.get('line')}:{item.get('kind')}")
    return keys


def compare_reports(old: dict, new: dict) -> ScanDiff:
    old_score = old.get("health", {}).get("score", 0)
    new_score = new.get("health", {}).get("score", 0)
    old_s = _secret_keys(old)
    new_s = _secret_keys(new)
    old_large = {f["path"] for f in old.get("large_files", [])}
    new_large = {f["path"] for f in new.get("large_files", [])}

    return ScanDiff(
        score_delta=new_score - old_score,
        new_secrets=sorted(new_s - old_s),
        fixed_secrets=sorted(old_s - new_s),
        new_large_files=sorted(new_large - old_large),
    )


def load_report_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def format_diff(diff: ScanDiff) -> str:
    arrow = "+" if diff.score_delta > 0 else ""
    lines = [
        f"Score: {arrow}{diff.score_delta}",
        f"New secrets: {len(diff.new_secrets)}",
        f"Fixed secrets: {len(diff.fixed_secrets)}",
        f"New large files: {len(diff.new_large_files)}",
    ]
    for key in diff.new_secrets[:10]:
        lines.append(f"  + {key}")
    for key in diff.fixed_secrets[:10]:
        lines.append(f"  - {key}")
    return "\n".join(lines)