"""Generate actionable recommendations from scan results."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from snapcheck.formatting import human_size
from snapcheck.i18n import t, translate_grade
from snapcheck.scanners.duplicates import DuplicateGroup
from snapcheck.scanners.disk_usage import DirUsage
from snapcheck.scanners.large_files import LargeFile
from snapcheck.scanners.git_check import GitTrackedSecret
from snapcheck.plugins.base import PluginFinding
from snapcheck.scanners.secrets import SecretFinding

_ENV_VAR_REF = re.compile(
    r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*=\s*([A-Z][A-Z0-9_]*)$"
)
_PLACEHOLDER = re.compile(r"x{3,}|your[_-]|placeholder|example|changeme", re.I)


class SecretRisk(str, Enum):
    CRITICAL = "critical"
    REVIEW = "review"
    PLACEHOLDER = "placeholder"
    FALSE_POSITIVE = "false_positive"


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"


@dataclass(frozen=True)
class ClassifiedSecret:
    finding: SecretFinding
    risk: SecretRisk


@dataclass(frozen=True)
class Recommendation:
    severity: Severity
    title: str
    action: str
    reason: str


@dataclass(frozen=True)
class HealthSummary:
    score: int
    grade: str
    grade_icon: str
    critical_count: int
    warning_count: int
    info_count: int
    classified_secrets: list[ClassifiedSecret]


def classify_secret(finding: SecretFinding) -> SecretRisk:
    path_str = str(finding.path).replace("\\", "/")
    snippet = finding.snippet.strip()

    if _ENV_VAR_REF.match(snippet):
        return SecretRisk.FALSE_POSITIVE

    if path_str.endswith(".env.example") or "example" in path_str.lower():
        if _PLACEHOLDER.search(snippet):
            return SecretRisk.PLACEHOLDER

    if "backup" in path_str.lower():
        return SecretRisk.FALSE_POSITIVE

    if path_str.startswith("logs/") or "/logs/" in path_str:
        return SecretRisk.REVIEW

    if path_str.endswith(".env"):
        return SecretRisk.CRITICAL

    if _PLACEHOLDER.search(snippet):
        return SecretRisk.PLACEHOLDER

    if finding.kind in {
        "AWS Access Key",
        "GitHub Token",
        "GitHub Fine-grained",
        "OpenAI API Key",
        "Anthropic API Key",
        "Slack Token",
        "Stripe Secret Key",
        "Telegram Bot Token",
        "Discord Bot Token",
        "Google API Key",
        "Private Key Block",
        "Bearer Token",
        "NPM Token",
        "PyPI Token",
        "SendGrid API Key",
        "High Entropy Secret",
    }:
        return SecretRisk.CRITICAL

    if finding.kind == "JWT Token":
        return SecretRisk.CRITICAL

    return SecretRisk.REVIEW


_RISK_PRIORITY = {
    SecretRisk.CRITICAL: 4,
    SecretRisk.REVIEW: 3,
    SecretRisk.PLACEHOLDER: 2,
    SecretRisk.FALSE_POSITIVE: 1,
}


def classify_secrets(findings: list[SecretFinding]) -> list[ClassifiedSecret]:
    classified = [ClassifiedSecret(finding=f, risk=classify_secret(f)) for f in findings]
    best: dict[tuple[str, int], ClassifiedSecret] = {}
    for item in classified:
        key = (str(item.finding.path).replace("\\", "/"), item.finding.line)
        prev = best.get(key)
        if prev is None or _RISK_PRIORITY[item.risk] > _RISK_PRIORITY[prev.risk]:
            best[key] = item
    return list(best.values())


def compute_health_score(
    classified: list[ClassifiedSecret],
    large_files: list[LargeFile],
    duplicates: list[DuplicateGroup],
    disk_usage: list[DirUsage],
    git_tracked: list[GitTrackedSecret] | None = None,
    plugin_findings: list[PluginFinding] | None = None,
) -> int:
    score = 100

    critical = sum(1 for c in classified if c.risk == SecretRisk.CRITICAL)
    review = sum(1 for c in classified if c.risk == SecretRisk.REVIEW)
    plugin_critical = sum(1 for f in plugin_findings or [] if f.severity == "critical")
    plugin_review = sum(1 for f in plugin_findings or [] if f.severity == "review")

    score -= min(critical * 15, 45)
    score -= min(len(git_tracked or []) * 20, 40)
    score -= min(review * 3, 15)
    score -= min(plugin_critical * 10, 30)
    score -= min(plugin_review * 2, 10)
    score -= min(len(large_files) * 5, 15)

    wasted = sum(g.size_bytes * (len(g.paths) - 1) for g in duplicates)
    if wasted > 1024 * 1024:
        score -= 5

    for usage in disk_usage[:3]:
        if usage.path.name in {"logs", "log", "tmp", "cache", ".cache"}:
            if usage.size_bytes > 5 * 1024 * 1024:
                score -= 5
                break

    return max(0, min(100, score))


def grade_for_score(score: int) -> tuple[str, str]:
    if score >= 90:
        return "excellent", "🟢"
    if score >= 70:
        return "good", "🟡"
    if score >= 50:
        return "needs_work", "🟠"
    return "critical", "🔴"


def build_health_summary(
    secrets: list[SecretFinding],
    large_files: list[LargeFile],
    duplicates: list[DuplicateGroup],
    disk_usage: list[DirUsage],
    git_tracked: list[GitTrackedSecret] | None = None,
    plugin_findings: list[PluginFinding] | None = None,
) -> HealthSummary:
    classified = classify_secrets(secrets)
    score = compute_health_score(
        classified,
        large_files,
        duplicates,
        disk_usage,
        git_tracked,
        plugin_findings,
    )
    grade_key, icon = grade_for_score(score)
    grade = translate_grade(grade_key)

    critical = sum(1 for c in classified if c.risk == SecretRisk.CRITICAL)
    warning = sum(1 for c in classified if c.risk == SecretRisk.REVIEW)
    info = sum(
        1
        for c in classified
        if c.risk in {SecretRisk.PLACEHOLDER, SecretRisk.FALSE_POSITIVE}
    )
    if plugin_findings:
        critical += sum(1 for f in plugin_findings if f.severity == "critical")
        warning += sum(1 for f in plugin_findings if f.severity == "review")
        info += sum(1 for f in plugin_findings if f.severity == "info")

    return HealthSummary(
        score=score,
        grade=grade,
        grade_icon=icon,
        critical_count=critical,
        warning_count=warning,
        info_count=info,
        classified_secrets=classified,
    )


def build_recommendations(
    root: Path,
    secrets: list[SecretFinding],
    large_files: list[LargeFile],
    duplicates: list[DuplicateGroup],
    disk_usage: list[DirUsage],
    git_tracked: list[GitTrackedSecret] | None = None,
    plugin_findings: list[PluginFinding] | None = None,
) -> list[Recommendation]:
    recs: list[Recommendation] = []
    classified = classify_secrets(secrets)

    critical = [c for c in classified if c.risk == SecretRisk.CRITICAL]
    if critical:
        env_hits = [c for c in critical if str(c.finding.path).endswith(".env")]
        if env_hits:
            recs.append(
                Recommendation(
                    severity=Severity.CRITICAL,
                    title=t("rec.env_keys.title"),
                    action=t("rec.env_keys.action"),
                    reason=t("rec.env_keys.reason", count=len(env_hits)),
                )
            )
        other = [c for c in critical if c not in env_hits]
        if other:
            recs.append(
                Recommendation(
                    severity=Severity.CRITICAL,
                    title=t("rec.code_secrets.title"),
                    action=t("rec.code_secrets.action"),
                    reason=t("rec.code_secrets.reason", count=len(other)),
                )
            )

    false_pos = [c for c in classified if c.risk == SecretRisk.FALSE_POSITIVE]
    if len(false_pos) >= 5:
        recs.append(
            Recommendation(
                severity=Severity.INFO,
                title=t("rec.false_pos.title"),
                action=t("rec.false_pos.action"),
                reason=t("rec.false_pos.reason", count=len(false_pos)),
            )
        )

    for item in large_files[:3]:
        if item.size_bytes >= 10 * 1024 * 1024:
            recs.append(
                Recommendation(
                    severity=Severity.WARNING,
                    title=t("rec.large_file.title", path=item.path),
                    action=t("rec.large_file.action"),
                    reason=t("rec.large_file.reason", size=human_size(item.size_bytes)),
                )
            )

    for usage in disk_usage[:5]:
        if usage.path.name in {"logs", "log", "tmp", "cache", "node_modules", ".cache"}:
            if usage.size_bytes > 1024 * 1024:
                recs.append(
                    Recommendation(
                        severity=Severity.WARNING,
                        title=t("rec.heavy_dir.title", path=usage.path),
                        action=t("rec.heavy_dir.action"),
                        reason=t("rec.heavy_dir.reason", size=human_size(usage.size_bytes)),
                    )
                )

    for group in duplicates[:3]:
        wasted = group.size_bytes * (len(group.paths) - 1)
        if wasted >= 1024:
            recs.append(
                Recommendation(
                    severity=Severity.INFO,
                    title=t("rec.duplicates.title"),
                    action=t(
                        "rec.duplicates.action",
                        paths=", ".join(str(p) for p in group.paths[1:]),
                    ),
                    reason=t("rec.duplicates.reason", size=human_size(wasted)),
                )
            )

    if git_tracked:
        for item in git_tracked:
            recs.append(
                Recommendation(
                    severity=Severity.CRITICAL,
                    title=t("rec.git_tracked.title", path=item.path),
                    action=t("rec.git_tracked.action"),
                    reason=t("git.sensitive_tracked", name=item.sensitive_name),
                )
            )

    gitignore = root / ".gitignore"
    if critical and gitignore.is_file():
        text = gitignore.read_text(encoding="utf-8", errors="ignore")
        if ".env" not in text:
            recs.append(
                Recommendation(
                    severity=Severity.CRITICAL,
                    title=t("rec.no_gitignore.title"),
                    action=t("rec.no_gitignore.action"),
                    reason=t("rec.no_gitignore.reason"),
                )
            )

    if plugin_findings:
        by_plugin: dict[str, dict[str, int]] = {}
        for f in plugin_findings:
            bucket = by_plugin.setdefault(f.plugin_name, {"critical": 0, "review": 0, "info": 0})
            bucket[f.severity] = bucket.get(f.severity, 0) + 1
        for pname, counts in by_plugin.items():
            total = sum(counts.values())
            severity = (
                Severity.CRITICAL
                if counts.get("critical", 0)
                else Severity.WARNING
                if counts.get("review", 0)
                else Severity.INFO
            )
            recs.append(
                Recommendation(
                    severity=severity,
                    title=t("rec.plugin.title", name=pname),
                    action=t("rec.plugin.action"),
                    reason=t("rec.plugin.reason", count=total, name=pname),
                )
            )

    if not recs and not secrets and not large_files and not plugin_findings:
        recs.append(
            Recommendation(
                severity=Severity.OK,
                title=t("rec.healthy.title"),
                action=t("rec.healthy.action"),
                reason=t("rec.healthy.reason"),
            )
        )

    return recs