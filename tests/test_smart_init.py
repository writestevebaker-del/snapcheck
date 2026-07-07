from pathlib import Path

from snapcheck.cli import main
from snapcheck.ignore import IGNORE_FILENAME


def test_init_smart_creates_ignore(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "note.md").write_text("api_key=ANTHROPIC_API_KEY\n")
    (tmp_path / "bot_backup.py").write_text("api_key=ANTHROPIC_API_KEY\n")

    code = main(["init", str(tmp_path), "--smart"])
    assert code == 0
    text = (tmp_path / IGNORE_FILENAME).read_text()
    assert "logs/" in text