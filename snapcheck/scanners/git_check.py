"""Check if sensitive files are tracked by git."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

SENSITIVE_GLOBS = (".env", ".env.local", ".env.production", "credentials.json", "secrets.json")


@dataclass(frozen=True)
class GitTrackedSecret:
    path: str
    sensitive_name: str


def _run_git(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def scan_git_tracked(root: Path) -> list[GitTrackedSecret]:
    """Return sensitive paths that appear to be tracked by git."""
    if _run_git(root, "rev-parse", "--is-inside-work-tree") != "true":
        return []

    findings: list[GitTrackedSecret] = []
    tracked = _run_git(root, "ls-files")
    if not tracked:
        return []

    tracked_files = set(tracked.splitlines())
    for name in SENSITIVE_GLOBS:
        for path in tracked_files:
            if path == name or path.endswith(f"/{name}"):
                findings.append(GitTrackedSecret(path=path, sensitive_name=name))

    return findings