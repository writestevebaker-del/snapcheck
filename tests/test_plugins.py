"""Tests for SnapCheck Plugin API."""

from __future__ import annotations

import json
from pathlib import Path

from snapcheck.cli import main
from snapcheck.plugins import PluginFinding, ScanContext, SnapCheckPlugin, load_plugin_file, run_plugins
from snapcheck.report import ScanReport


TEST_PLUGIN = '''"""Test plugin."""

from pathlib import Path

from snapcheck.plugins import PluginFinding, ScanContext, SnapCheckPlugin


class MarkerPlugin(SnapCheckPlugin):
    name = "test-marker"
    version = "0.1.0"
    description = "Finds MARKER tokens"

    def scan_file(self, ctx: ScanContext, path: Path, content: str) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            if "MARKER_SECRET" in line:
                findings.append(
                    PluginFinding(
                        path=path,
                        line=line_no,
                        message="Marker token found",
                        plugin_name=self.name,
                        severity="critical",
                        snippet=line.strip()[:40],
                    )
                )
        return findings


plugin = MarkerPlugin()
'''


def _write_test_plugin(tmp_path: Path) -> Path:
    plugins_dir = tmp_path / ".snapcheck" / "plugins"
    plugins_dir.mkdir(parents=True)
    plugin_path = plugins_dir / "test_plugin.py"
    plugin_path.write_text(TEST_PLUGIN, encoding="utf-8")
    return plugin_path


def test_load_plugin_file(tmp_path: Path) -> None:
    plugin_path = _write_test_plugin(tmp_path)
    loaded = load_plugin_file(plugin_path)
    assert loaded is not None
    assert loaded.name == "test-marker"


def test_run_plugins_finds_marker(tmp_path: Path) -> None:
    plugin_path = _write_test_plugin(tmp_path)
    loaded = load_plugin_file(plugin_path)
    assert loaded is not None
    (tmp_path / "code.py").write_text("token = MARKER_SECRET_abc\n")
    findings = run_plugins(tmp_path, [loaded])
    assert len(findings) == 1
    assert findings[0].plugin_name == "test-marker"
    assert findings[0].severity == "critical"


def test_scan_with_plugin_integration(tmp_path: Path, capsys) -> None:
    _write_test_plugin(tmp_path)
    (tmp_path / "app.py").write_text("x = MARKER_SECRET_xyz\n")
    code = main(["scan", str(tmp_path)])
    captured = capsys.readouterr()
    assert code == 0
    assert "Plugin findings" in captured.out
    assert "test-marker" in captured.out


def test_scan_json_includes_plugin_findings(tmp_path: Path, capsys) -> None:
    _write_test_plugin(tmp_path)
    (tmp_path / "app.py").write_text("x = MARKER_SECRET_xyz\n")
    code = main(["scan", str(tmp_path), "--json"])
    captured = capsys.readouterr()
    assert code == 0
    data = json.loads(captured.out)
    assert data["summary"]["plugin_findings"] == 1
    assert data["plugin_findings"][0]["plugin_name"] == "test-marker"


def test_fail_on_critical_with_plugin(tmp_path: Path) -> None:
    _write_test_plugin(tmp_path)
    (tmp_path / "app.py").write_text("x = MARKER_SECRET_xyz\n")
    code = main(["scan", str(tmp_path), "--fail-on-critical"])
    assert code == 1


def test_no_plugins_flag_skips_plugins(tmp_path: Path, capsys) -> None:
    _write_test_plugin(tmp_path)
    (tmp_path / "app.py").write_text("x = MARKER_SECRET_xyz\n")
    code = main(["scan", str(tmp_path), "--no-plugins", "--json"])
    captured = capsys.readouterr()
    assert code == 0
    data = json.loads(captured.out)
    assert data["summary"]["plugin_findings"] == 0
    assert data["plugin_findings"] == []


def test_plugins_init_command(tmp_path: Path, capsys) -> None:
    code = main(["plugins", "init", str(tmp_path)])
    captured = capsys.readouterr()
    assert code == 0
    example = tmp_path / ".snapcheck" / "plugins" / "example.py"
    assert example.is_file()
    assert "example plugin" in captured.out.lower()


def test_plugins_list_command(tmp_path: Path, capsys) -> None:
    _write_test_plugin(tmp_path)
    code = main(["plugins", "list", str(tmp_path)])
    captured = capsys.readouterr()
    assert code == 0
    assert "test-marker" in captured.out


def test_report_plugin_section(tmp_path: Path) -> None:
    finding = PluginFinding(
        path=Path("app.py"),
        line=1,
        message="test issue",
        plugin_name="demo",
        severity="review",
        snippet="demo snippet",
    )
    report = ScanReport(
        root=tmp_path,
        secrets=[],
        large_files=[],
        disk_usage=[],
        duplicates=[],
        plugin_findings=[finding],
    )
    text = report.to_text()
    assert "Plugin findings" in text
    assert "demo" in text