from pathlib import Path

from snapcheck.cli import main


def test_markdown_export(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print(1)\n")
    out = tmp_path / "r.md"
    code = main(["scan", str(tmp_path), "--markdown", str(out), "-q"])
    assert code == 0
    text = out.read_text()
    assert "#" in text
    assert "SnapCheck" in text