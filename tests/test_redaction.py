from snapcheck.redaction import redact_snippet


def test_redacts_openai_key() -> None:
    raw = "API_KEY=sk-ant-api03-t9qyNe1kNPCmTKTXMR0l3Rpzd_P9s8w0z0Tg"
    result = redact_snippet(raw)
    assert "t9qyNe1kNPCmTKTXMR0l3Rpzd" not in result
    assert "sk-ant" in result


def test_redacts_telegram_token() -> None:
    raw = "8491618670:AAHepxlfGO-Lyk-zj6ljILs_vpyhxHcNcAk"
    result = redact_snippet(raw)
    assert "AAHepxlfGO" not in result
    assert "8491618670:" in result