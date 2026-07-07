from pathlib import Path

from snapcheck.cli import main
from snapcheck.profiles import get_profile_rules


def test_server_profile_rules() -> None:
    rules = get_profile_rules("server")
    assert ".ssh" in rules.extra_exclude_dirs


def test_server_profile_high_score_on_ssh_keys(tmp_path: Path) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    key = ssh / "id_ed25519"
    key.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    code = main(["scan", str(tmp_path), "--profile", "server", "--json"])
    assert code == 0


def test_ci_profile_minimal_output(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text("x = 1\n")
    main(["scan", str(tmp_path), "--profile", "ci"])
    captured = capsys.readouterr()
    assert "score=" in captured.out
    assert "SnapCheck Health Report" not in captured.out