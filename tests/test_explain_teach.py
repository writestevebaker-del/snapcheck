from snapcheck.cli import main
from snapcheck.explain import explain_by_kind
from snapcheck.teach import teach_topic


def test_explain_by_kind() -> None:
    text = explain_by_kind("Config Password")
    assert "password" in text.lower() or "пароль" in text.lower()


def test_teach_secrets() -> None:
    text = teach_topic("secrets")
    assert len(text) > 20


def test_teach_cli(capsys) -> None:
    code = main(["teach", "ci"])
    captured = capsys.readouterr()
    assert code == 0
    assert "SnapCheck" in captured.out