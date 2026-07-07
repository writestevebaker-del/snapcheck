"""Execute loaded plugins against a project tree."""

from __future__ import annotations

from pathlib import Path

from snapcheck.ignore import IgnoreRules, build_ignore_rules
from snapcheck.i18n import get_locale
from snapcheck.plugins.base import PluginFinding, ScanContext, SnapCheckPlugin
from snapcheck.scanners.secrets import SKIP_EXTENSIONS, _looks_binary

_MAX_FILE = 512_000


def run_plugins(
    root: Path,
    plugins: list[SnapCheckPlugin],
    *,
    ignore: IgnoreRules | None = None,
) -> list[PluginFinding]:
    if not plugins:
        return []

    root = root.resolve()
    rules = ignore if ignore is not None else build_ignore_rules(root)
    ctx = ScanContext(root=root, locale=get_locale())
    all_findings: list[PluginFinding] = []

    for plugin in plugins:
        project_hits = plugin.findings_with_plugin(plugin.scan_project(ctx))
        all_findings.extend(project_hits)

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(root)
        if rules.should_skip_path(rel):
            continue
        if file_path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        try:
            if file_path.stat().st_size > _MAX_FILE:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _looks_binary(text):
            continue

        for plugin in plugins:
            hits = plugin.scan_file(ctx, rel, text)
            all_findings.extend(plugin.findings_with_plugin(hits))

    return all_findings