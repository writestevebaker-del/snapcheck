from pathlib import Path

from snapcheck.cli import main
from snapcheck.scanners.dangerous_files import scan_dangerous_files


def test_ovpn_in_webroot_critical() -> None:
    root = Path(__file__).parent / "fixtures" / "webroot"
    hits = scan_dangerous_files(root, profile="git-repo")
    assert any(h.severity == "critical" and h.path.name == "client.ovpn" for h in hits)


def test_server_openvpn_info() -> None:
    root = Path(__file__).parent / "fixtures" / "webroot"
    hits = scan_dangerous_files(root, profile="server")
    assert hits


def test_fixture_git_repo_fails(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "git-repo"
    code = main(["scan", str(fixture), "--fail-on-critical"])
    assert code == 1