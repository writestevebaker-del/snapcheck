from pathlib import Path

from snapcheck.scanners.duplicates import scan_duplicates


def test_finds_duplicate_files(tmp_path: Path) -> None:
    content = b"duplicate content here" * 100
    (tmp_path / "a.txt").write_bytes(content)
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "b.txt").write_bytes(content)

    groups = scan_duplicates(tmp_path, min_size_bytes=1)
    assert len(groups) == 1
    assert len(groups[0].paths) == 2