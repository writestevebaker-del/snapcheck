from pathlib import Path

from snapcheck.scanners.secrets import scan_secrets


def test_finds_slack_token(tmp_path: Path) -> None:
    fake_token = "xoxb-" + "1234567890-" + "abcdefghijklmnop"
    (tmp_path / "config.txt").write_text(f"SLACK={fake_token}\n")
    findings = scan_secrets(tmp_path)
    assert any(f.kind == "Slack Token" for f in findings)


def test_finds_stripe_live_key(tmp_path: Path) -> None:
    fake_key = "sk_live_" + "1234567890abcdefghijklmnop"
    (tmp_path / "pay.py").write_text(f"STRIPE={fake_key}\n")
    findings = scan_secrets(tmp_path)
    assert any(f.kind == "Stripe Secret Key" for f in findings)