"""Plugin API — extend SnapCheck with custom scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Severity = Literal["critical", "review", "info"]


@dataclass(frozen=True)
class ScanContext:
    """Context passed to plugins during a scan."""

    root: Path
    locale: str = "en"


@dataclass(frozen=True)
class PluginFinding:
    """A single finding reported by a plugin."""

    path: Path
    line: int
    message: str
    plugin_name: str
    severity: Severity = "review"
    snippet: str = ""


class SnapCheckPlugin(ABC):
    """Base class for SnapCheck plugins.

    Subclass and implement ``scan_file`` and/or ``scan_project``.
    Export instance as module-level ``plugin`` or implement ``get_plugin()``.
    """

    name: str = "unnamed"
    version: str = "1.0.0"
    description: str = ""

    def scan_file(
        self,
        ctx: ScanContext,
        path: Path,
        content: str,
    ) -> list[PluginFinding]:
        """Scan a single text file. Override in subclass."""
        return []

    def scan_project(self, ctx: ScanContext) -> list[PluginFinding]:
        """Project-level checks (docker-compose, CI configs, etc.)."""
        return []

    def findings_with_plugin(self, items: list[PluginFinding]) -> list[PluginFinding]:
        """Attach plugin name to findings that lack it."""
        return [
            PluginFinding(
                path=f.path,
                line=f.line,
                message=f.message,
                plugin_name=self.name,
                severity=f.severity,
                snippet=f.snippet,
            )
            for f in items
        ]