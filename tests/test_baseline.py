from pathlib import Path

from snapcheck.baseline import BaselineEntry, load_baseline, save_baseline
from snapcheck.cli import main
from snapcheck.scanners.secrets import SecretFinding, scan_secrets
from snapcheck.baseline import filter_by_baseline


def test_baseline_filters_findings(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('k="ghp_abcdefghijklmnopqrstuvwxyz1234567890AB"\n')
    findings = scan_secrets(tmp_path)
    assert len(findings) == 1

    save_baseline(
        tmp_path,
        {BaselineEntry(path="a.py", line=1, kind=findings[0].kind)},
    )
    filtered = filter_by_baseline(findings, load_baseline(tmp_path))
    assert filtered == []


def test_baseline_update_command(tmp_path: Path) -> None:
    (tmp_path / "bot.py").write_text("api_key=ANTHROPIC_API_KEY\n")
    code = main(["baseline", "update", str(tmp_path)])
    assert code == 0
    assert load_baseline(tmp_path)