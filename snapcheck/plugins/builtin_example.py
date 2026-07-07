"""Example built-in plugin — detects TODO/FIXME with SECRET marker."""

from __future__ import annotations

import re
from pathlib import Path

from snapcheck.plugins.base import PluginFinding, ScanContext, SnapCheckPlugin

_MARKER = re.compile(r"(?i)(TODO|FIXME|HACK).{0,40}(secret|password|key|token)")


class TodoSecretMarkerPlugin(SnapCheckPlugin):
    name = "todo-secret-marker"
    version = "1.0.0"
    description = "Flags TODO/FIXME comments mentioning secrets"

    def scan_file(
        self,
        ctx: ScanContext,
        path: Path,
        content: str,
    ) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            if _MARKER.search(line):
                findings.append(
                    PluginFinding(
                        path=path,
                        line=line_no,
                        message="TODO/FIXME references sensitive data",
                        plugin_name=self.name,
                        severity="review",
                        snippet=line.strip()[:60],
                    )
                )
        return findings


plugin = TodoSecretMarkerPlugin()