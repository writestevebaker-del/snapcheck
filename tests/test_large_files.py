from pathlib import Path

from snapcheck.scanners.large_files import scan_large_files


def test_finds_large_file(tmp_path: Path) -> None:
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * (2 * 1024 * 1024))
    small = tmp_path / "small.txt"
    small.write_text("tiny")

    results = scan_large_files(tmp_path, min_size_bytes=1024 * 1024)
    assert len(results) == 1
    assert results[0].path == Path("big.bin")
    assert results[0].size_bytes == 2 * 1024 * 1024