from pathlib import Path

from snapcheck.scanners.disk_usage import scan_disk_usage


def test_ranks_directories_by_size(tmp_path: Path) -> None:
    (tmp_path / "small").mkdir()
    (tmp_path / "small" / "a.txt").write_text("x")
    (tmp_path / "big").mkdir()
    (tmp_path / "big" / "b.bin").write_bytes(b"x" * 5000)

    usage = scan_disk_usage(tmp_path, top_n=5)
    assert len(usage) == 2
    assert usage[0].path == Path("big")
    assert usage[0].size_bytes > usage[1].size_bytes