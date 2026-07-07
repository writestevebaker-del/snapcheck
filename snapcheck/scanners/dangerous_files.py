"""Detect dangerous files by path/extension."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from snapcheck.ignore import IgnoreRules, build_ignore_rules
from snapcheck.profiles import get_profile_rules
from snapcheck.scanners._walk import WalkConfig, walk_files

_WEBROOT_PARTS = frozenset({"www", "public", "html", "static", "webroot"})
_SSH_KEY_NAMES = frozenset({"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"})
_CRYPTO_EXTENSIONS = frozenset({".pem", ".key", ".p12", ".pfx"})
_SENSITIVE_NAMES = frozenset({
    "credentials.json",
    "secrets.json",
    "service-account.json",
    ".env",
    ".env.local",
    ".env.production",
})


@dataclass(frozen=True)
class DangerousFile:
    path: Path
    kind: str
    severity: str
    reason: str


def _in_webroot(rel: Path) -> bool:
    return bool(_WEBROOT_PARTS & set(rel.parts))


def _classify_file(rel: Path, *, profile: str) -> DangerousFile | None:
    path_str = rel.as_posix()
    name = rel.name.lower()

    if name in _SENSITIVE_NAMES or rel.name in _SENSITIVE_NAMES:
        return DangerousFile(
            path=rel,
            kind="Sensitive env file",
            severity="critical",
            reason="Environment file may contain secrets",
        )

    if name in _SSH_KEY_NAMES and not name.endswith(".pub"):
        if profile == "server":
            return DangerousFile(
                path=rel,
                kind="SSH private key",
                severity="info",
                reason="Expected on server",
            )
        return DangerousFile(
            path=rel,
            kind="SSH private key",
            severity="critical",
            reason="Private SSH key in project tree",
        )

    if rel.suffix.lower() == ".ovpn":
        if _in_webroot(rel):
            return DangerousFile(
                path=rel,
                kind="OpenVPN config",
                severity="critical",
                reason="VPN config with keys in public web directory",
            )
        if profile == "server" and any(p in path_str for p in ("openvpn", "etc/openvpn")):
            return DangerousFile(
                path=rel,
                kind="OpenVPN config",
                severity="info",
                reason="Expected VPN config location on server",
            )
        return DangerousFile(
            path=rel,
            kind="OpenVPN config",
            severity="review",
            reason="VPN config may contain embedded private key",
        )

    if rel.suffix.lower() in _CRYPTO_EXTENSIONS:
        if profile == "server" and any(m in path_str for m in ("letsencrypt", "live/", ".ssh/")):
            return None
        return DangerousFile(
            path=rel,
            kind="Crypto material",
            severity="review",
            reason="Cryptographic key or certificate file",
        )

    if name in {"credentials.json", "secrets.json", "service-account.json"}:
        return DangerousFile(
            path=rel,
            kind="Cloud credentials file",
            severity="critical",
            reason="Filename indicates stored credentials",
        )

    return None


def scan_dangerous_files(
    root: Path,
    *,
    profile: str = "git-repo",
    ignore: IgnoreRules | None = None,
    walk_config: WalkConfig | None = None,
) -> list[DangerousFile]:
    root = root.resolve()
    rules = ignore if ignore is not None else build_ignore_rules(root)
    profile_rules = get_profile_rules(profile)
    if profile_rules.extra_exclude_dirs:
        rules = rules.with_extra_dirs(set(profile_rules.extra_exclude_dirs))

    findings: list[DangerousFile] = []
    seen: set[str] = set()

    for _abs, rel in walk_files(root, rules, config=walk_config):
        hit = _classify_file(rel, profile=profile)
        if hit is None:
            continue
        key = f"{hit.path}:{hit.kind}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(hit)

    return findings