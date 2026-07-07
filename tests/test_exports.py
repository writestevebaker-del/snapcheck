import json
from pathlib import Path

from snapcheck.cli import build_report, main
from snapcheck.html_report import to_html
from snapcheck.report import ScanReport
from snapcheck.sarif import to_sarif
import argparse


def _args(**kwargs):
    defaults = dict(
        large_threshold_mb=10,
        no_duplicates=True,
        exclude=[],
        use_baseline=False,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_html_report_escapes_content(tmp_path: Path) -> None:
    from snapcheck.scanners.secrets import SecretFinding

    finding = SecretFinding(
        path=Path("<bad>.py"),
        line=1,
        kind="Test",
        snippet='<script>alert("x")</script>',
    )
    report = ScanReport(root=tmp_path, secrets=[finding], large_files=[], disk_usage=[], duplicates=[])
    html = to_html(report)
    assert "<script>" not in html
    assert "&lt;bad&gt;.py" in html


def test_sarif_valid_json(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("API_KEY=sk-ant-api03-abcdefghijklmnop1234\n")
    report = build_report(tmp_path, _args())
    data = json.loads(to_sarif(report))
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) >= 1


def test_scan_writes_html(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print(1)\n")
    out = tmp_path / "report.html"
    code = main(["scan", str(tmp_path), "--html", str(out), "--quiet"])
    assert code == 0
    assert out.is_file()
    assert "SnapCheck" in out.read_text()