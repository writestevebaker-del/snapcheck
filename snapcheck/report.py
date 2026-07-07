"""Format scan results for terminal and JSON output."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from snapcheck import __version__
from snapcheck.formatting import human_size
from snapcheck.i18n import get_locale, t
from snapcheck.redaction import redact_snippet
from snapcheck.recommendations import (
    Recommendation,
    SecretRisk,
    Severity,
    build_health_summary,
    build_recommendations,
)
from snapcheck.scanners.duplicates import DuplicateGroup
from snapcheck.scanners.disk_usage import DirUsage
from snapcheck.scanners.large_files import LargeFile
from snapcheck.scanners.git_check import GitTrackedSecret
from snapcheck.plugins.base import PluginFinding
from snapcheck.scanners.dangerous_files import DangerousFile
from snapcheck.scanners.secrets import SecretFinding

_BOX_W = 62

_SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.WARNING: "🟠",
    Severity.INFO: "🔵",
    Severity.OK: "🟢",
}

_RISK_KEYS = {
    SecretRisk.CRITICAL: "risk.critical",
    SecretRisk.REVIEW: "risk.review",
    SecretRisk.PLACEHOLDER: "risk.placeholder",
    SecretRisk.FALSE_POSITIVE: "risk.false_positive",
    SecretRisk.EXPECTED: "risk.expected",
}


def _bar(value: int, maximum: int, width: int = 20) -> str:
    if maximum <= 0:
        return "░" * width
    filled = round((value / maximum) * width)
    filled = max(0, min(width, filled))
    return "█" * filled + "░" * (width - filled)


def _section(title: str) -> str:
    line = f"─ {title} "
    return line + "─" * max(0, _BOX_W - len(line))


@dataclass
class ScanReport:
    root: Path
    secrets: list[SecretFinding]
    large_files: list[LargeFile]
    disk_usage: list[DirUsage]
    duplicates: list[DuplicateGroup]
    git_tracked: list[GitTrackedSecret] | None = None
    hide_noise: bool = False
    scan_duration_seconds: float | None = None
    plugin_findings: list[PluginFinding] | None = None
    dangerous_files: list[DangerousFile] | None = None
    profile: str = "git-repo"

    @property
    def has_secrets(self) -> bool:
        return len(self.secrets) > 0

    @property
    def _visible_secrets(self) -> list[SecretFinding]:
        if not self.hide_noise:
            return self.secrets
        classified = build_health_summary(
            self.secrets,
            self.large_files,
            self.duplicates,
            self.disk_usage,
            self.git_tracked,
            profile=self.profile,
        ).classified_secrets
        return [
            c.finding
            for c in classified
            if c.risk not in {SecretRisk.FALSE_POSITIVE, SecretRisk.EXPECTED}
        ]

    @property
    def health(self):
        return build_health_summary(
            self._visible_secrets,
            self.large_files,
            self.duplicates,
            self.disk_usage,
            self.git_tracked,
            self.plugin_findings,
            self.dangerous_files,
            profile=self.profile,
        )

    @property
    def recommendations(self) -> list[Recommendation]:
        return build_recommendations(
            self.root,
            self._visible_secrets,
            self.large_files,
            self.duplicates,
            self.disk_usage,
            self.git_tracked,
            self.plugin_findings,
            self.dangerous_files,
            profile=self.profile,
        )

    def to_dict(self) -> dict:
        health = self.health
        return {
            "root": str(self.root),
            "version": __version__,
            "locale": get_locale(),
            "scan_duration_seconds": self.scan_duration_seconds,
            "profile": self.profile,
            "health": {
                "score": health.score,
                "grade": health.grade,
                "critical": health.critical_count,
                "warning": health.warning_count,
                "info": health.info_count,
            },
            "score_breakdown": (
                {
                    "base": health.score_breakdown.base,
                    "total": health.score_breakdown.total,
                    "lines": [
                        {"label": line.label, "delta": line.delta}
                        for line in health.score_breakdown.lines
                    ],
                }
                if health.score_breakdown
                else None
            ),
            "summary": {
                "secrets": len(self._visible_secrets),
                "large_files": len(self.large_files),
                "duplicate_groups": len(self.duplicates),
                "plugin_findings": len(self.plugin_findings or []),
                "has_secrets": self.has_secrets,
            },
            "plugin_findings": [
                {
                    "path": str(f.path),
                    "line": f.line,
                    "message": f.message,
                    "plugin_name": f.plugin_name,
                    "severity": f.severity,
                    "snippet": f.snippet,
                }
                for f in self.plugin_findings or []
            ],
            "recommendations": [
                {**asdict(r), "commands": list(r.commands)} for r in self.recommendations
            ],
            "dangerous_files": [
                {
                    "path": str(d.path),
                    "kind": d.kind,
                    "severity": d.severity,
                    "reason": d.reason,
                }
                for d in self.dangerous_files or []
            ],
            "secrets": [
                {
                    **asdict(c.finding),
                    "path": str(c.finding.path),
                    "risk": c.risk.value,
                }
                for c in health.classified_secrets
            ],
            "large_files": [
                {"path": str(f.path), "size_bytes": f.size_bytes} for f in self.large_files
            ],
            "disk_usage": [
                {"path": str(d.path), "size_bytes": d.size_bytes} for d in self.disk_usage
            ],
            "duplicates": [
                {
                    "hash": g.hash,
                    "size_bytes": g.size_bytes,
                    "paths": [str(p) for p in g.paths],
                }
                for g in self.duplicates
            ],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def _format_recommendations(self) -> list[str]:
        lines: list[str] = []
        lines.append("")
        lines.append(_section(f"💡 {t('report.recommendations')}"))
        for idx, rec in enumerate(self.recommendations, start=1):
            icon = _SEVERITY_ICON[rec.severity]
            lines.append(f"  {idx}. {icon} {rec.title}")
            lines.append(f"     → {rec.action}")
            lines.append(f"     ℹ {rec.reason}")
            if rec.commands:
                lines.append(f"     {t('report.commands')}")
                for cmd in rec.commands:
                    lines.append(f"       $ {cmd}")
            if rec.docs_url:
                lines.append(f"     {t('report.learn_more')}: {rec.docs_url}")
        return lines

    def _format_secrets_detail(self) -> list[str]:
        lines: list[str] = []
        health = self.health
        by_risk: dict[SecretRisk, list] = {r: [] for r in SecretRisk}
        for item in health.classified_secrets:
            by_risk[item.risk].append(item)

        lines.append("")
        visible = self._visible_secrets
        lines.append(_section(f"🔐 {t('report.secrets')} ({len(visible)})"))

        if not visible:
            lines.append(f"  ✓ {t('report.no_secrets')}")
            return lines

        for risk in (
            SecretRisk.CRITICAL,
            SecretRisk.REVIEW,
            SecretRisk.PLACEHOLDER,
            SecretRisk.FALSE_POSITIVE,
            SecretRisk.EXPECTED,
        ):
            items = by_risk[risk]
            if not items:
                continue
            label = t(_RISK_KEYS[risk])
            lines.append(f"  [{label}] — {len(items)}")
            show = items if risk == SecretRisk.CRITICAL else items[:5]
            for item in show:
                f = item.finding
                lines.append(f"    • {f.path}:{f.line}  {f.kind}")
                lines.append(f"      {redact_snippet(f.snippet)}")
            if len(items) > len(show):
                lines.append(f"    … {t('report.more')} {len(items) - len(show)}")

        return lines

    def _format_dangerous_detail(self) -> list[str]:
        lines: list[str] = []
        items = self.dangerous_files or []
        lines.append("")
        lines.append(_section(f"⚠️  {t('report.dangerous_files')} ({len(items)})"))
        if not items:
            lines.append(f"  ✓ {t('report.no_dangerous')}")
            return lines
        for item in items[:10]:
            lines.append(f"  [{item.severity.upper()}] {item.path} — {item.kind}")
            lines.append(f"      {item.reason}")
        if len(items) > 10:
            lines.append(f"    … {t('report.more')} {len(items) - 10}")
        return lines

    def _format_plugins_detail(self) -> list[str]:
        lines: list[str] = []
        findings = self.plugin_findings or []
        lines.append("")
        lines.append(_section(f"🔌 {t('report.plugins')} ({len(findings)})"))
        if not findings:
            lines.append(f"  ✓ {t('report.no_plugins')}")
            return lines

        by_severity: dict[str, list[PluginFinding]] = {"critical": [], "review": [], "info": []}
        for f in findings:
            by_severity.setdefault(f.severity, []).append(f)

        labels = {
            "critical": t("risk.critical"),
            "review": t("risk.review"),
            "info": "INFO",
        }
        for sev in ("critical", "review", "info"):
            items = by_severity.get(sev, [])
            if not items:
                continue
            lines.append(f"  [{labels[sev]}] — {len(items)}")
            show = items if sev == "critical" else items[:5]
            for item in show:
                lines.append(f"    • [{item.plugin_name}] {item.path}:{item.line}  {item.message}")
                if item.snippet:
                    lines.append(f"      {redact_snippet(item.snippet)}")
            if len(items) > len(show):
                lines.append(f"    … {t('report.more')} {len(items) - len(show)}")
        return lines

    def to_text(self) -> str:
        health = self.health
        lines: list[str] = []
        title = t("report.title")

        lines.append("╔" + "═" * _BOX_W + "╗")
        pad = max(0, _BOX_W - len(title) - 2)
        lines.append(f"║  {title}{' ' * pad}║")
        lines.append(f"║  {str(self.root)[:_BOX_W - 5]:<{_BOX_W - 5}} ║")
        lines.append("╚" + "═" * _BOX_W + "╝")

        lines.append("")
        lines.append(
            f"  {health.grade_icon} {t('report.health_score')}: {health.score}/100  "
            f"({health.grade})"
        )
        lines.append(
            f"     {_bar(health.score, 100)}  "
            f"critical={health.critical_count}  "
            f"review={health.warning_count}  "
            f"noise={health.info_count}"
        )
        if health.score_breakdown and health.score_breakdown.lines:
            lines.append("")
            lines.append(_section(f"📉 {t('report.score_breakdown')}"))
            lines.append(f"  {t('report.score_base')}: {health.score_breakdown.base}")
            for item in health.score_breakdown.lines:
                lines.append(f"  {item.label}: {item.delta:+d}")
            lines.append(f"  {'─' * 28}")
            lines.append(f"  {t('report.score_total')}: {health.score_breakdown.total}")

        lines.append("")
        lines.append(_section(f"📊 {t('report.summary')}"))
        visible_count = len(self._visible_secrets)
        plugin_count = len(self.plugin_findings or [])
        max_count = max(
            visible_count,
            len(self.large_files),
            len(self.duplicates),
            len(self.disk_usage),
            plugin_count,
            1,
        )
        lines.append(
            f"  🔐 {t('report.secrets'):<14} {_bar(visible_count, max_count, 12)}  {visible_count}"
        )
        lines.append(
            f"  📦 {t('report.large_files'):<14} {_bar(len(self.large_files), max_count, 12)}  {len(self.large_files)}"
        )
        lines.append(
            f"  📋 {t('report.duplicates'):<14} {_bar(len(self.duplicates), max_count, 12)}  {len(self.duplicates)}"
        )
        if self.disk_usage:
            top = self.disk_usage[0]
            lines.append(
                f"  💾 {t('report.heaviest_dir'):<14} {human_size(top.size_bytes):>8}  {top.path}/"
            )

        lines.extend(self._format_secrets_detail())
        if self.dangerous_files:
            lines.extend(self._format_dangerous_detail())
        if self.plugin_findings is not None:
            lines.extend(self._format_plugins_detail())

        if self.git_tracked:
            lines.append("")
            lines.append(_section(f"🚨 {t('report.git_tracked')} ({len(self.git_tracked)})"))
            for item in self.git_tracked:
                reason = t("git.sensitive_tracked", name=item.sensitive_name)
                lines.append(f"  ! {item.path} — {reason}")

        lines.append("")
        lines.append(_section(f"📦 {t('report.large_files')} ({len(self.large_files)})"))
        if not self.large_files:
            lines.append(f"  ✓ {t('report.no_large_files')}")
        else:
            for item in self.large_files[:10]:
                lines.append(f"  {human_size(item.size_bytes):>10}  {item.path}")

        lines.append("")
        lines.append(_section(f"💾 {t('report.top_folders')} ({len(self.disk_usage)})"))
        if not self.disk_usage:
            lines.append(f"  ✓ {t('report.no_subdirs')}")
        else:
            total = sum(d.size_bytes for d in self.disk_usage) or 1
            for item in self.disk_usage[:8]:
                pct = item.size_bytes / total * 100
                lines.append(
                    f"  {human_size(item.size_bytes):>10}  ({pct:4.0f}%)  {item.path}/"
                )

        lines.append("")
        lines.append(_section(f"📋 {t('report.duplicates')} ({len(self.duplicates)})"))
        if not self.duplicates:
            lines.append(f"  ✓ {t('report.no_duplicates')}")
        else:
            total_waste = 0
            for group in self.duplicates[:8]:
                wasted = group.size_bytes * (len(group.paths) - 1)
                total_waste += wasted
                lines.append(
                    f"  {human_size(group.size_bytes)} × {len(group.paths)} {t('report.copies')} "
                    f"({t('report.waste')} ~{human_size(wasted)})"
                )
                for path in group.paths:
                    lines.append(f"    - {path}")
            lines.append(f"  {t('report.total_recoverable')}: ~{human_size(total_waste)}")

        lines.extend(self._format_recommendations())

        lines.append("")
        if health.critical_count > 0:
            lines.append(f"  🔴 {t('report.action_required')}")
        elif health.score >= 90:
            lines.append(f"  🟢 {t('report.healthy')}")
        else:
            lines.append(f"  🟡 {t('report.review')}")

        return "\n".join(lines)