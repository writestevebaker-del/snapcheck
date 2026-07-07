from pathlib import Path

from snapcheck.entropy import find_high_entropy_assignments, shannon_entropy
from snapcheck.scanners.secrets import scan_secrets


def test_entropy_detects_random_assignment() -> None:
    line = 'api_key = "k8Jd9sL2mN4pQ7rT1vX0wY3zA6bC5eD8fG"'
    assert find_high_entropy_assignments(line)


def test_entropy_ignores_env_var_name() -> None:
    line = "api_key=ANTHROPIC_API_KEY"
    assert not find_high_entropy_assignments(line)


def test_scan_finds_high_entropy(tmp_path: Path) -> None:
    (tmp_path / "cfg.py").write_text(
        'SECRET = "k8Jd9sL2mN4pQ7rT1vX0wY3zA6bC5eD8fG9hJ"\n'
    )
    findings = scan_secrets(tmp_path)
    assert any(f.kind == "High Entropy Secret" for f in findings)


def test_shannon_entropy_range() -> None:
    assert shannon_entropy("aaaa") < shannon_entropy("aZb9_kL2mN4pQ7rT1vX")