from snapcheck.i18n import (
    detect_system_locale,
    resolve_locale,
    set_locale,
    t,
    translate_grade,
)


def test_english_strings() -> None:
    set_locale("en")
    assert t("report.title") == "SnapCheck Health Report"
    assert translate_grade("excellent") == "EXCELLENT"


def test_russian_strings() -> None:
    set_locale("ru")
    assert "отчёт" in t("report.title").lower()
    assert translate_grade("excellent") == "ОТЛИЧНО"
    assert t("rec.env_keys.title") == "Реальные ключи в .env"


def test_resolve_locale_cli_overrides(monkeypatch) -> None:
    monkeypatch.delenv("SNAPCHECK_LANG", raising=False)
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    assert resolve_locale(cli_lang="ru") == "ru"


def test_resolve_locale_from_config(monkeypatch) -> None:
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    assert resolve_locale(config_lang="ru") == "ru"


def test_detect_russian_lang(monkeypatch) -> None:
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("SNAPCHECK_LANG", raising=False)
    monkeypatch.setenv("LANG", "ru_RU.UTF-8")
    assert detect_system_locale() == "ru"