from pathlib import Path

from snapcheck.cli import main
from snapcheck.config import load_config


def test_load_config_defaults(tmp_path: Path) -> None:
    cfg = load_config(tmp_path)
    assert cfg.large_threshold_mb == 10
    assert cfg.min_health_score == 0


def test_load_config_from_file(tmp_path: Path) -> None:
    (tmp_path / "snapcheck.toml").write_text(
        "[scan]\nlarge_threshold_mb = 5\nmin_health_score = 80\nfail_on_critical = true\n"
    )
    cfg = load_config(tmp_path)
    assert cfg.large_threshold_mb == 5
    assert cfg.min_health_score == 80
    assert cfg.fail_on_critical is True


def test_min_score_exit_code(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("API_KEY=sk-ant-api03-abcdefghijklmnop1234\n")
    (tmp_path / "snapcheck.toml").write_text("[scan]\nmin_health_score = 100\n")
    code = main(["scan", str(tmp_path), "--quiet"])
    assert code == 1