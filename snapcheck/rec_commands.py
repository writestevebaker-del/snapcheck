"""Map findings to actionable shell commands."""

from __future__ import annotations

from pathlib import Path

from snapcheck.profiles import is_server_expected_path
from snapcheck.scanners.dangerous_files import DangerousFile
from snapcheck.scanners.git_check import GitTrackedSecret
from snapcheck.scanners.large_files import LargeFile
from snapcheck.scanners.secrets import SecretFinding


def commands_for_secret(finding: SecretFinding, risk: str, *, profile: str) -> tuple[str, ...]:
    f = finding
    path_str = str(f.path).replace("\\", "/")

    if risk == "expected":
        return ()

    if f.kind == "Private Key Block" and is_server_expected_path(path_str, f.kind):
        return ()

    if path_str.endswith(".env") or f.path.name == ".env":
        return (
            "git rm --cached .env 2>/dev/null || true",
            "echo '.env' >> .gitignore",
        )

    if f.kind == "Config Password":
        return (
            "# Move to .env (do not commit):",
            "echo 'SECRET=...' >> .env",
            "echo '.env' >> .gitignore",
            f"git rm --cached {path_str} 2>/dev/null || true",
        )

    if f.kind == "Private Key Block":
        return (
            f"git rm --cached {path_str}",
            "echo '*.pem' >> .gitignore",
            "echo 'privkey.pem' >> .gitignore",
        )

    if risk == "critical":
        return (
            f"# Remove secret from {path_str}",
            "git rm --cached <file> 2>/dev/null || true",
            "echo '<file>' >> .gitignore",
        )

    return ()


def commands_for_dangerous(item: DangerousFile) -> tuple[str, ...]:
    path_str = str(item.path).replace("\\", "/")

    if item.severity == "info":
        return ()

    if item.kind == "OpenVPN config" and item.severity == "critical":
        return (
            f"mv {path_str} /etc/openvpn/clients/",
            f"chmod 600 /etc/openvpn/clients/{item.path.name}",
        )

    if item.kind == "Sensitive env file":
        return (
            f"git rm --cached {path_str} 2>/dev/null || true",
            "echo '.env' >> .gitignore",
        )

    if item.kind == "SSH private key":
        return (
            f"git rm --cached {path_str}",
            "echo 'id_rsa' >> .gitignore",
            "echo 'id_ed25519' >> .gitignore",
        )

    if item.kind == "Cloud credentials file":
        return (
            f"git rm --cached {path_str}",
            f"echo '{item.path.name}' >> .gitignore",
        )

    return ()


def commands_for_git_tracked(item: GitTrackedSecret) -> tuple[str, ...]:
    return (
        f"git rm --cached {item.path}",
        f"echo '{item.path}' >> .gitignore",
    )


def commands_for_large_file(item: LargeFile) -> tuple[str, ...]:
    path_str = str(item.path).replace("\\", "/")
    return (
        f"git rm --cached {path_str} 2>/dev/null || true",
        f"echo '{item.path.name}' >> .gitignore",
    )


def docs_for_finding(kind: str) -> str | None:
    mapping = {
        "Config Password": "config-password",
        "Private Key Block": "private-key",
        "OpenVPN config": "ovpn-webroot",
    }
    topic = mapping.get(kind)
    return f"snapcheck teach {topic}" if topic else None