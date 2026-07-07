from pathlib import Path

from snapcheck.ignore import IGNORE_FILENAME, build_ignore_rules, load_ignore_file
from snapcheck.scanners.secrets import scan_secrets


def test_load_ignore_file_parses_dirs_and_globs(tmp_path: Path) -> None:
    (tmp_path / IGNORE_FILENAME).write_text(
        "# vendor\nvendor\n*.pem\nfixtures/\n"
    )
    rules = load_ignore_file(tmp_path)
    assert "vendor" in rules.dir_names
    assert "fixtures" in rules.dir_names
    assert "*.pem" in rules.path_globs


def test_snapcheckignore_skips_custom_dir(tmp_path: Path) -> None:
    ignored = tmp_path / "vendor" / "leak.txt"
    ignored.parent.mkdir(parents=True)
    ignored.write_text("ghp_abcdefghijklmnopqrstuvwxyz1234567890AB\n")
    (tmp_path / IGNORE_FILENAME).write_text("vendor\n")
    findings = scan_secrets(tmp_path)
    assert findings == []


def test_cli_exclude_merged_with_ignore_file(tmp_path: Path) -> None:
    (tmp_path / "custom").mkdir()
    (tmp_path / "custom" / "x.txt").write_text(
        "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB\n"
    )
    rules = build_ignore_rules(tmp_path, extra_skip_dirs={"custom"})
    findings = scan_secrets(tmp_path, ignore=rules)
    assert findings == []