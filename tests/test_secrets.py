from pathlib import Path

from snapcheck.scanners.secrets import scan_secrets


def test_finds_github_token(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB"\n'
    )
    findings = scan_secrets(tmp_path)
    assert len(findings) == 1
    assert findings[0].kind == "GitHub Token"
    assert findings[0].line == 1


def test_finds_aws_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
    findings = scan_secrets(tmp_path)
    assert any(f.kind == "AWS Access Key" for f in findings)


def test_skips_node_modules(tmp_path: Path) -> None:
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text(
        'const k = "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB";\n'
    )
    findings = scan_secrets(tmp_path)
    assert findings == []


def test_clean_project_no_findings(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text('print("hello world")\n')
    findings = scan_secrets(tmp_path)
    assert findings == []