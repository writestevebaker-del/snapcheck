from pathlib import Path

from snapcheck.report import ScanReport
from snapcheck.scanners.secrets import SecretFinding


def test_breakdown_matches_score() -> None:
    finding = SecretFinding(
        path=Path(".env"),
        line=1,
        kind="Anthropic API Key",
        snippet="sk-ant-api03-abc",
    )
    report = ScanReport(
        root=Path("."),
        secrets=[finding],
        large_files=[],
        disk_usage=[],
        duplicates=[],
    )
    health = report.health
    assert health.score_breakdown is not None
    assert health.score_breakdown.total == health.score
    assert health.score_breakdown.base == 100