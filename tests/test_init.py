from pathlib import Path

from snapcheck.cli import main
from snapcheck.ignore import IGNORE_FILENAME


def test_init_creates_ignore_file(tmp_path: Path) -> None:
    code = main(["init", str(tmp_path)])
    assert code == 0
    path = tmp_path / IGNORE_FILENAME
    assert path.is_file()
    text = path.read_text()
    assert "logs/" in text
    assert "*_backup_*" in text


def test_init_refuses_overwrite(tmp_path: Path) -> None:
    path = tmp_path / IGNORE_FILENAME
    path.write_text("existing\n")
    code = main(["init", str(tmp_path)])
    assert code == 1
    assert path.read_text() == "existing\n"


def test_init_force_overwrites(tmp_path: Path) -> None:
    path = tmp_path / IGNORE_FILENAME
    path.write_text("old\n")
    code = main(["init", str(tmp_path), "--force"])
    assert code == 0
    assert "logs/" in path.read_text()