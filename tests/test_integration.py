"""End-to-end workflow tests."""

import json
from pathlib import Path

from snapcheck.cli import main


def test_full_workflow_init_scan_compare(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "bot.py").write_text("api_key=ANTHROPIC_API_KEY\n")
    (project / "logs").mkdir()
    (project / "logs" / "app.log").write_text("api_key=ANTHROPIC_API_KEY\n" * 50)

    assert main(["init", str(project), "--smart"]) == 0
    assert (project / ".snapcheckignore").is_file()

    report1 = project / "scan1.json"
    assert main(["scan", str(project), "--save-json", str(report1), "--hide-noise", "-q"]) == 0
    data1 = json.loads(report1.read_text())
    assert "health" in data1
    score1 = data1["health"]["score"]

    report2 = project / "scan2.json"
    assert main(["scan", str(project), "--save-json", str(report2), "--hide-noise", "-q"]) == 0
    data2 = json.loads(report2.read_text())
    assert data2["health"]["score"] == score1

    assert main(["compare", str(report1), str(report2)]) == 0
    assert main(["baseline", "update", str(project)]) == 0
    assert main(["baseline", "show", str(project)]) == 0