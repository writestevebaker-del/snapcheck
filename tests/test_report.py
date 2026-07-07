from pathlib import Path

from snapcheck.formatting import human_size
from snapcheck.report import ScanReport
from snapcheck.scanners.secrets import SecretFinding


def test_human_size() -> None:
    assert human_size(500) == "500 B"
    assert human_size(2048) == "2.0 KB"
    assert human_size(10 * 1024 * 1024) == "10.0 MB"


def test_report_has_health_score() -> None:
    finding = SecretFinding(
        path=Path(".env"), line=1, kind="Test", snippet="API_KEY=sk-real-1234567890"
    )
    report = ScanReport(
        root=Path("."),
        secrets=[finding],
        large_files=[],
        disk_usage=[],
        duplicates=[],
    )
    text = report.to_text()
    assert "Health Score" in text
    assert "Recommendations" in text
    assert "CRITICAL" in text


def test_report_json_includes_recommendations() -> None:
    report = ScanReport(root=Path("."), secrets=[], large_files=[], disk_usage=[], duplicates=[])
    data = report.to_dict()
    assert "health" in data
    assert "recommendations" in data
    assert data["health"]["score"] >= 90