"""Generate standalone HTML health report."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from snapcheck import __version__
from snapcheck.i18n import get_locale, t, translate_grade
from snapcheck.formatting import human_size
from snapcheck.redaction import redact_snippet
from snapcheck.recommendations import SecretRisk, Severity
from snapcheck.report import ScanReport

_SEV_COLOR = {
    Severity.CRITICAL: "#dc2626",
    Severity.WARNING: "#ea580c",
    Severity.INFO: "#2563eb",
    Severity.OK: "#16a34a",
}

_RISK_COLOR = {
    SecretRisk.CRITICAL: "#dc2626",
    SecretRisk.REVIEW: "#ea580c",
    SecretRisk.PLACEHOLDER: "#6b7280",
    SecretRisk.FALSE_POSITIVE: "#9ca3af",
}


def to_html(report: ScanReport) -> str:
    health = report.health
    score = health.score
    bar_color = "#16a34a" if score >= 90 else "#eab308" if score >= 70 else "#ea580c" if score >= 50 else "#dc2626"

    rec_rows = ""
    for rec in report.recommendations:
        color = _SEV_COLOR[rec.severity]
        rec_rows += f"""
        <div class="rec" style="border-left:4px solid {color}">
          <strong>{html.escape(rec.title)}</strong>
          <p>{html.escape(rec.action)}</p>
          <small>{html.escape(rec.reason)}</small>
        </div>"""

    secret_rows = ""
    for item in health.classified_secrets:
        if item.risk == SecretRisk.FALSE_POSITIVE:
            continue
        f = item.finding
        color = _RISK_COLOR[item.risk]
        secret_rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{item.risk.value}</span></td>
          <td>{html.escape(str(f.path))}:{f.line}</td>
          <td>{html.escape(f.kind)}</td>
          <td><code>{html.escape(redact_snippet(f.snippet))}</code></td>
        </tr>"""

    large_rows = "".join(
        f"<tr><td>{html.escape(str(f.path))}</td><td>{human_size(f.size_bytes)}</td></tr>"
        for f in report.large_files[:20]
    )

    locale = get_locale()
    title = t("report.title")
    return f"""<!DOCTYPE html>
<html lang="{locale}">
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)} — {html.escape(str(report.root))}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0f172a; color: #e2e8f0; }}
    h1 {{ margin: 0; }}
    .card {{ background: #1e293b; border-radius: 12px; padding: 1.5rem; margin: 1rem 0; }}
    .score {{ font-size: 2.5rem; font-weight: bold; color: {bar_color}; }}
    .bar {{ height: 12px; background: #334155; border-radius: 6px; overflow: hidden; }}
    .bar-fill {{ height: 100%; width: {score}%; background: {bar_color}; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 0.5rem; border-bottom: 1px solid #334155; }}
    .badge {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }}
    .rec {{ background: #0f172a; padding: 1rem; margin: 0.5rem 0; border-radius: 8px; }}
    code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; }}
    .meta {{ color: #94a3b8; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <p class="meta">{html.escape(str(report.root))} · v{__version__} · {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</p>

  <div class="card">
    <div class="score">{score}/100 {health.grade_icon} {html.escape(health.grade)}</div>
    <div class="bar"><div class="bar-fill"></div></div>
    <p>critical={health.critical_count} · review={health.warning_count} · noise={health.info_count}</p>
  </div>

  <div class="card">
    <h2>{html.escape(t("html.recommendations"))}</h2>
    {rec_rows or f"<p>{html.escape(t('html.healthy'))}</p>"}
  </div>

  <div class="card">
    <h2>{html.escape(t("html.secrets"))} ({len(report.secrets)})</h2>
    <table>
      <tr><th>Risk</th><th>Location</th><th>Kind</th><th>Snippet</th></tr>
      {secret_rows or f"<tr><td colspan=4>{html.escape(t('html.none'))}</td></tr>"}
    </table>
  </div>

  <div class="card">
    <h2>{html.escape(t("html.large_files"))} ({len(report.large_files)})</h2>
    <table>
      <tr><th>Path</th><th>Size</th></tr>
      {large_rows or f"<tr><td colspan=2>{html.escape(t('html.none'))}</td></tr>"}
    </table>
  </div>
</body>
</html>"""