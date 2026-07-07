"""Explain individual findings without AI."""

from __future__ import annotations

from snapcheck.i18n import t
from snapcheck.recommendations import classify_secrets
from snapcheck.scanners.secrets import SecretFinding

_EXPLAIN: dict[str, dict[str, str]] = {
    "Config Password": {
        "what": "explain.config.what",
        "why": "explain.config.why",
        "action": "explain.config.action",
    },
    "Private Key Block": {
        "what": "explain.privkey.what",
        "why": "explain.privkey.why",
        "action": "explain.privkey.action",
    },
    "OpenVPN config": {
        "what": "explain.ovpn.what",
        "why": "explain.ovpn.why",
        "action": "explain.ovpn.action",
    },
}


def explain_finding(
    finding: SecretFinding,
    *,
    profile: str = "git-repo",
) -> str:
    classified = classify_secrets([finding], profile=profile)[0]
    kind = finding.kind
    info = _EXPLAIN.get(kind, _EXPLAIN.get("Config Password"))

    lines = [
        t("explain.header", path=f"{finding.path}:{finding.line}", kind=kind),
        t("explain.severity", severity=classified.risk.value.upper()),
        "",
        t("explain.what"),
        f"  {t(info['what'])}",
        "",
        t("explain.why"),
        f"  {t(info['why'])}",
        "",
        t("explain.do"),
        f"  {t(info['action'])}",
    ]
    return "\n".join(lines)


def explain_by_kind(kind: str) -> str:
    info = _EXPLAIN.get(kind)
    if not info:
        return t("explain.unknown", kind=kind)

    lines = [
        t("explain.kind_header", kind=kind),
        "",
        t("explain.what"),
        f"  {t(info['what'])}",
        "",
        t("explain.why"),
        f"  {t(info['why'])}",
        "",
        t("explain.do"),
        f"  {t(info['action'])}",
    ]
    return "\n".join(lines)