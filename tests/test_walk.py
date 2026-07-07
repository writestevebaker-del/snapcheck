from pathlib import Path

from snapcheck.ignore import build_ignore_rules
from snapcheck.scanners._walk import WalkConfig, walk_files


def test_max_depth_limits(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "leaf.txt").write_text("x")
    rules = build_ignore_rules(tmp_path)
    files = list(walk_files(tmp_path, rules, config=WalkConfig(max_depth=1)))
    rels = [rel.as_posix() for _, rel in files]
    assert "a/b/c/leaf.txt" not in rels