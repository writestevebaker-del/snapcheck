from pathlib import Path

from snapcheck.scanners.secrets import scan_secrets


def test_postgres_uri_detected(tmp_path: Path) -> None:
    (tmp_path / "db.py").write_text('url = "postgres://user:secretpass@localhost/mydb"\n')
    hits = scan_secrets(tmp_path)
    assert any(h.kind == "PostgreSQL URI" for h in hits)


def test_postgres_no_password_skipped(tmp_path: Path) -> None:
    (tmp_path / "db.py").write_text('url = "postgres://user@localhost/mydb"\n')
    hits = scan_secrets(tmp_path)
    assert not any(h.kind == "PostgreSQL URI" for h in hits)