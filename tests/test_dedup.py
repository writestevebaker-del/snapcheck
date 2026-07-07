from pathlib import Path

from snapcheck.recommendations import SecretRisk, classify_secrets
from snapcheck.scanners.secrets import SecretFinding


def test_dedup_same_line_multiple_patterns() -> None:
    finding_a = SecretFinding(
        Path(".env"), 10, "Generic API Key", "API_KEY=sk-ant-api03-abc"
    )
    finding_b = SecretFinding(
        Path(".env"), 10, "Anthropic API Key", "API_KEY=sk-ant-api03-abc"
    )
    result = classify_secrets([finding_a, finding_b])
    assert len(result) == 1
    assert result[0].risk == SecretRisk.CRITICAL