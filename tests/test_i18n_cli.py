from pathlib import Path

from snapcheck.cli import main
from snapcheck.i18n import set_locale


def test_scan_russian_output(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text("x=1\n")
    code = main(["scan", str(tmp_path), "--lang", "ru", "-q"])
    captured = capsys.readouterr()
    assert code == 0
    assert "Оценка" in captured.out


def test_scan_english_explicit(tmp_path: Path, capsys) -> None:
    set_locale("ru")
    (tmp_path / "app.py").write_text("x=1\n")
    code = main(["scan", str(tmp_path), "--lang", "en", "-q"])
    captured = capsys.readouterr()
    assert code == 0
    assert "Score:" in captured.out