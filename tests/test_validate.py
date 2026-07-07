from pathlib import Path

from snapcheck.cli import main


def test_validate_ok(tmp_path: Path) -> None:
    (tmp_path / "snapcheck.toml").write_text("[scan]\nmin_health_score = 80\n")
    assert main(["validate", str(tmp_path)]) == 0


def test_validate_bad_regex(tmp_path: Path) -> None:
    (tmp_path / ".snapcheck-rules.json").write_text(
        '{"patterns":[{"name":"bad","regex":"[invalid"}]}'
    )
    assert main(["validate", str(tmp_path)]) == 1