"""Load optional snapcheck.toml configuration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

CONFIG_FILENAME = "snapcheck.toml"


@dataclass
class ScanConfig:
    large_threshold_mb: int = 10
    min_health_score: int = 0
    fail_on_critical: bool = False
    skip_duplicates: bool = False
    extra_exclude: list[str] | None = None
    language: str | None = None
    plugins_enabled: bool = True
    profile: str = "git-repo"


def _parse_toml_simple(text: str) -> dict:
    """Minimal TOML parser for flat [scan] section — no external deps."""
    section = None
    data: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            data.setdefault(section, {})
            continue
        if "=" in line and section:
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if val.lower() in {"true", "false"}:
                parsed: object = val.lower() == "true"
            elif val.isdigit():
                parsed = int(val)
            else:
                parsed = val
            data[section][key] = parsed
    return data


def load_config(root: Path) -> ScanConfig:
    path = root / CONFIG_FILENAME
    if not path.is_file():
        return ScanConfig()
    try:
        text = path.read_text(encoding="utf-8")
        data = _parse_toml_simple(text)
    except OSError:
        return ScanConfig()

    scan = data.get("scan", {})
    exclude = scan.get("exclude")
    if isinstance(exclude, str):
        exclude_list = [exclude]
    elif isinstance(exclude, list):
        exclude_list = exclude
    else:
        exclude_list = None

    locale = data.get("locale", {})
    lang = locale.get("language") if isinstance(locale, dict) else None
    if isinstance(lang, str):
        lang_val: str | None = lang
    else:
        lang_val = None

    plugins = data.get("plugins", {})
    plugins_enabled = True
    if isinstance(plugins, dict) and "enabled" in plugins:
        plugins_enabled = bool(plugins.get("enabled", True))

    profile = str(scan.get("profile", "git-repo"))

    return ScanConfig(
        large_threshold_mb=int(scan.get("large_threshold_mb", 10)),
        min_health_score=int(scan.get("min_health_score", 0)),
        fail_on_critical=bool(scan.get("fail_on_critical", False)),
        skip_duplicates=bool(scan.get("skip_duplicates", False)),
        extra_exclude=exclude_list,
        language=lang_val,
        plugins_enabled=plugins_enabled,
        profile=profile,
    )