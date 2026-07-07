"""Scan profiles — git-repo, server, ci."""

from __future__ import annotations

from dataclasses import dataclass

VALID_PROFILES = frozenset({"git-repo", "server", "ci"})


@dataclass(frozen=True)
class ProfileRules:
    name: str
    extra_exclude_dirs: frozenset[str]
    extra_exclude_globs: tuple[str, ...]
    default_hide_noise: bool = False
    default_fail_on_critical: bool = False
    skip_duplicates: bool = False
    skip_disk_usage: bool = False
    ci_output: bool = False


_SERVER_EXCLUDES = frozenset({".ssh", "letsencrypt"})
_SERVER_GLOBS = (
    "etc/letsencrypt/**",
    "**/privkey.pem",
    "**/fullchain.pem",
    "**/*.pem",
)


def get_profile_rules(profile: str) -> ProfileRules:
    if profile not in VALID_PROFILES:
        profile = "git-repo"

    if profile == "server":
        return ProfileRules(
            name="server",
            extra_exclude_dirs=_SERVER_EXCLUDES,
            extra_exclude_globs=_SERVER_GLOBS,
        )

    if profile == "ci":
        return ProfileRules(
            name="ci",
            extra_exclude_dirs=frozenset(),
            extra_exclude_globs=(),
            default_hide_noise=True,
            default_fail_on_critical=True,
            skip_duplicates=True,
            skip_disk_usage=True,
            ci_output=True,
        )

    return ProfileRules(
        name="git-repo",
        extra_exclude_dirs=frozenset(),
        extra_exclude_globs=(),
    )


def is_server_expected_path(path_str: str, kind: str) -> bool:
    """Private keys in typical server locations are expected, not critical."""
    if kind != "Private Key Block":
        return False
    markers = (".ssh/", ".ssh\\", "letsencrypt/", "/live/", "privkey.pem", "fullchain.pem")
    normalized = path_str.replace("\\", "/")
    if normalized.startswith(".ssh/") or "/.ssh/" in normalized:
        return True
    return any(m in normalized for m in markers)


def is_system_scan_path(path: str) -> bool:
    normalized = path.rstrip("/") or "/"
    return normalized in {"/", "/home", "/root"}