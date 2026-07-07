"""Export scan report as Markdown."""

from __future__ import annotations

from snapcheck.formatting import human_size
from snapcheck.i18n import t
from snapcheck.redaction import redact_snippet
from snapcheck.recommendations import SecretRisk
from snapcheck.report import ScanReport


def to_markdown(report: ScanReport) -> str:
    health = report.health
    lines: list[str] = [
        f"# {t('report.title')}",
        "",
        f"**Path:** `{report.root}`",
        f"**{t('report.health_score')}:** {health.score}/100 ({health.grade})",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| critical | {health.critical_count} |",
        f"| review | {health.warning_count} |",
        f"| noise | {health.info_count} |",
        "",
        f"## {t('report.recommendations')}",
        "",
    ]

    if not report.recommendations:
        lines.append(f"- {t('rec.healthy.reason')}")
    else:
        for rec in report.recommendations:
            lines.append(f"### {rec.title}")
            lines.append(f"- **Action:** {rec.action}")
            lines.append(f"- **Why:** {rec.reason}")
            lines.append("")

    lines.extend([f"## {t('report.secrets')}", ""])
    visible = report._visible_secrets
    if not visible:
        lines.append(f"_{t('report.no_secrets')}_")
    else:
        lines.append("| Risk | Location | Kind |")
        lines.append("|------|----------|------|")
        for item in health.classified_secrets:
            if item.risk == SecretRisk.FALSE_POSITIVE and report.hide_noise:
                continue
            f = item.finding
            lines.append(
                f"| {item.risk.value} | `{f.path}:{f.line}` | {f.kind} |"
            )

    if report.large_files:
        lines.extend(["", f"## {t('report.large_files')}", ""])
        for lf in report.large_files[:15]:
            lines.append(f"- `{lf.path}` — {human_size(lf.size_bytes)}")

    return "\n".join(lines) + "\n"