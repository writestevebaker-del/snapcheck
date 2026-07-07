"""Scaffold plugin directory and example plugin."""

from __future__ import annotations

import shutil
from pathlib import Path

from snapcheck.i18n import t
from snapcheck.plugins.loader import PLUGINS_DIRNAME

EXAMPLE_PLUGIN = '''"""Custom SnapCheck plugin — edit me."""

from __future__ import annotations

import re
from pathlib import Path

from snapcheck.plugins import PluginFinding, ScanContext, SnapCheckPlugin

# Match your company's internal token format
_PATTERN = re.compile(r"MYCOMPANY_[A-Z0-9]{24}")


class MyCompanyPlugin(SnapCheckPlugin):
    name = "my-company"
    version = "1.0.0"
    description = "Detect internal MYCOMPANY_* tokens"

    def scan_file(self, ctx: ScanContext, path: Path, content: str) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            match = _PATTERN.search(line)
            if match:
                findings.append(
                    PluginFinding(
                        path=path,
                        line=line_no,
                        message="Internal company token",
                        plugin_name=self.name,
                        severity="critical",
                        snippet=match.group(0)[:40],
                    )
                )
        return findings


plugin = MyCompanyPlugin()
'''


def run_init_plugins(target: Path, *, force: bool = False) -> int:
    target = target.resolve()
    plugins_dir = target / PLUGINS_DIRNAME
    example = plugins_dir / "example.py"

    plugins_dir.mkdir(parents=True, exist_ok=True)
    if example.exists() and not force:
        print(t("init.exists", path=example))
        print(t("init.force_hint"))
        return 1

    example.write_text(EXAMPLE_PLUGIN, encoding="utf-8")
    print(t("plugins.init_created", path=example))
    return 0