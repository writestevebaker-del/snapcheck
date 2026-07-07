"""Tests for SnapCheck agent skill workflow (.grok/skills/snapcheck)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from snapcheck.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _scan_json(path: Path, *, profile: str = "git-repo") -> dict:
    code = main(["scan", str(path), "--profile", profile, "--json"])
    assert code == 0 or profile == "git-repo"
    # Re-run via subprocess to capture stdout cleanly
    out = subprocess.check_output(
        ["snapcheck", "scan", str(path), "--profile", profile, "--json"],
        text=True,
    )
    return json.loads(out)


def test_skill_clean_fixture_passes_gate() -> None:
    data = _scan_json(FIXTURES / "clean")
    assert data["health"]["critical"] == 0
    assert data["health"]["score"] >= 90
    assert data.get("profile") == "git-repo"


def test_skill_git_repo_has_critical_blocker() -> None:
    data = _scan_json(FIXTURES / "git-repo")
    assert data["health"]["critical"] > 0
    assert data["health"]["score"] < 70
    recs = data["recommendations"]
    assert any(r.get("commands") for r in recs)


def test_skill_json_secrets_detected() -> None:
    data = _scan_json(FIXTURES / "json-secrets")
    assert data["health"]["critical"] > 0
    kinds = {s["kind"] for s in data["secrets"]}
    assert "Config Password" in kinds


def test_skill_server_profile_no_critical() -> None:
    data = _scan_json(FIXTURES / "server-profile", profile="server")
    assert data["health"]["critical"] == 0
    assert data["health"]["score"] >= 90


def test_skill_webroot_ovpn_critical() -> None:
    data = _scan_json(FIXTURES / "webroot")
    assert data["health"]["critical"] > 0
    assert data["dangerous_files"]
    assert any(d["kind"] == "OpenVPN config" for d in data["dangerous_files"])


def test_skill_fail_on_critical_exit_codes() -> None:
    assert main(["scan", str(FIXTURES / "git-repo"), "--fail-on-critical"]) == 1
    assert main(["scan", str(FIXTURES / "clean"), "--fail-on-critical"]) == 0


def test_skill_json_has_agent_fields() -> None:
    data = _scan_json(FIXTURES / "git-repo")
    assert "score_breakdown" in data
    assert "dangerous_files" in data
    assert "recommendations" in data
    for rec in data["recommendations"]:
        assert "commands" in rec


def test_skill_explain_and_teach(capsys) -> None:
    assert main(["explain", "--finding", "Config Password"]) == 0
    captured = capsys.readouterr()
    assert "password" in captured.out.lower() or "пароль" in captured.out.lower()

    assert main(["teach", "ci"]) == 0
    captured = capsys.readouterr()
    assert "SnapCheck" in captured.out


def test_skill_ci_profile_output(capsys) -> None:
    main(["scan", str(FIXTURES / "clean"), "--profile", "ci"])
    captured = capsys.readouterr()
    assert "score=" in captured.out
    assert "SnapCheck Health Report" not in captured.out