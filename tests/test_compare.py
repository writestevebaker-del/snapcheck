from snapcheck.compare import compare_reports


def test_compare_detects_new_secrets() -> None:
    old = {
        "health": {"score": 80},
        "secrets": [{"path": "a.py", "line": 1, "kind": "Test"}],
        "large_files": [],
    }
    new = {
        "health": {"score": 60},
        "secrets": [
            {"path": "a.py", "line": 1, "kind": "Test"},
            {"path": "b.py", "line": 2, "kind": "Test"},
        ],
        "large_files": [{"path": "big.log"}],
    }
    diff = compare_reports(old, new)
    assert diff.score_delta == -20
    assert len(diff.new_secrets) == 1
    assert "big.log" in diff.new_large_files[0]