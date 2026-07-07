from pathlib import Path

from snapcheck.recommendations import (
    SecretRisk,
    Severity,
    build_health_summary,
    build_recommendations,
    classify_secret,
)
from snapcheck.scanners.secrets import SecretFinding


def test_classify_env_file_as_critical() -> None:
    finding = SecretFinding(
        path=Path(".env"),
        line=1,
        kind="Generic API Key",
        snippet="API_KEY=sk-ant-api03-realkeyhere123456789",
    )
    assert classify_secret(finding) == SecretRisk.CRITICAL


def test_classify_env_var_reference_as_false_positive() -> None:
    finding = SecretFinding(
        path=Path("bot/chatbot.py"),
        line=100,
        kind="Generic API Key",
        snippet="api_key=ANTHROPIC_API_KEY",
    )
    assert classify_secret(finding) == SecretRisk.FALSE_POSITIVE


def test_classify_placeholder_in_example() -> None:
    finding = SecretFinding(
        path=Path(".env.example"),
        line=1,
        kind="Generic API Key",
        snippet="API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxx",
    )
    assert classify_secret(finding) == SecretRisk.PLACEHOLDER


def test_health_score_drops_on_critical() -> None:
    secrets = [
        SecretFinding(Path(".env"), 1, "Generic API Key", "API_KEY=sk-real-key-1234567890"),
    ]
    summary = build_health_summary(secrets, [], [], [])
    assert summary.score < 90
    assert summary.critical_count == 1


def test_recommendations_include_env_warning(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("API_KEY=sk-ant-api03-abcdefghijklmnop\n")
    secrets = [
        SecretFinding(Path(".env"), 1, "Generic API Key", "API_KEY=sk-ant-api03-abc"),
    ]
    recs = build_recommendations(tmp_path, secrets, [], [], [])
    assert any(r.severity == Severity.CRITICAL for r in recs)
    assert any(".env" in r.title for r in recs)


def test_recommendations_for_large_log() -> None:
    from snapcheck.scanners.disk_usage import DirUsage
    from snapcheck.scanners.large_files import LargeFile

    large = [LargeFile(path=Path("logs/bot.log"), size_bytes=20 * 1024 * 1024)]
    disk = [DirUsage(path=Path("logs"), size_bytes=20 * 1024 * 1024)]
    recs = build_recommendations(Path("."), [], large, [], disk)
    assert any("лог" in r.action.lower() or "log" in r.title.lower() for r in recs)