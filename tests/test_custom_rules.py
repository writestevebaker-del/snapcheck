import json
from pathlib import Path

from snapcheck.custom_rules import load_custom_patterns
from snapcheck.scanners.secrets import scan_secrets


def test_custom_rule_matches(tmp_path: Path) -> None:
    rules = {
        "patterns": [
            {"name": "Acme Token", "regex": "ACME_[A-Z0-9]{16}", "severity": "critical"}
        ]
    }
    (tmp_path / ".snapcheck-rules.json").write_text(json.dumps(rules))
    (tmp_path / "app.py").write_text('TOKEN="ACME_ABCDEF0123456789"\n')
    findings = scan_secrets(tmp_path)
    assert any(f.kind == "Acme Token" for f in findings)