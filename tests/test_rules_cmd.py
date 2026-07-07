from snapcheck.cli import main


def test_rules_list(capsys) -> None:
    code = main(["rules", "list"])
    captured = capsys.readouterr()
    assert code == 0
    assert "GitHub Token" in captured.out
    assert "AWS Access Key" in captured.out