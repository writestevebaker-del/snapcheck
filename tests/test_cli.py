import json
from pathlib import Path

from snapcheck.cli import main


def test_scan_clean_project(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text('print("ok")\n')
    code = main(["scan", str(tmp_path)])
    captured = capsys.readouterr()
    assert code == 0
    assert "SnapCheck Health Report" in captured.out
    assert "health score" in captured.out.lower()


def test_scan_json_output(tmp_path: Path, capsys) -> None:
    (tmp_path / "readme.md").write_text("# Hello\n")
    code = main(["scan", str(tmp_path), "--json"])
    captured = capsys.readouterr()
    assert code == 0
    data = json.loads(captured.out)
    assert data["summary"]["secrets"] == 0
    assert "large_files" in data


def test_fail_on_secrets(tmp_path: Path) -> None:
    (tmp_path / "leak.txt").write_text(
        "key=ghp_abcdefghijklmnopqrstuvwxyz1234567890AB\n"
    )
    code = main(["scan", str(tmp_path), "--fail-on-secrets"])
    assert code == 1


def test_fail_on_critical_ignores_false_positive(tmp_path: Path) -> None:
    (tmp_path / "bot.py").write_text("api_key=ANTHROPIC_API_KEY\n")
    code = main(["scan", str(tmp_path), "--fail-on-critical"])
    assert code == 0


def test_fail_on_critical_catches_env(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("API_KEY=sk-ant-api03-realkey1234567890abcd\n")
    code = main(["scan", str(tmp_path), "--fail-on-critical"])
    assert code == 1


def test_invalid_directory() -> None:
    code = main(["scan", "/nonexistent-path-xyz"])
    assert code == 2


def test_scan_respects_snapcheckignore(tmp_path: Path) -> None:
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "leak.txt").write_text(
        "key=ghp_abcdefghijklmnopqrstuvwxyz1234567890AB\n"
    )
    (tmp_path / ".snapcheckignore").write_text("vendor\n")
    code = main(["scan", str(tmp_path), "--fail-on-secrets"])
    assert code == 0