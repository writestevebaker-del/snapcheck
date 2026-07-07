from pathlib import Path

from snapcheck.cli import main
from snapcheck.scanners.config_secrets import scan_config_secrets


def test_naive_passwords_json() -> None:
    root = Path(__file__).parent / "fixtures" / "json-secrets"
    hits = scan_config_secrets(root)
    assert any(h.kind == "Config Password" for h in hits)


def test_placeholder_not_critical(tmp_path: Path) -> None:
    cfg = tmp_path / "config.json"
    cfg.write_text('{"api_key": "YOUR_KEY_HERE"}')
    hits = scan_config_secrets(tmp_path)
    assert hits == []


def test_scan_fixture_critical(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "json-secrets"
    code = main(["scan", str(fixture), "--fail-on-critical"])
    assert code == 1