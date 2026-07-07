import pytest

from snapcheck.i18n import set_locale


@pytest.fixture(autouse=True)
def english_locale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    monkeypatch.setenv("LC_ALL", "en_US.UTF-8")
    monkeypatch.delenv("SNAPCHECK_LANG", raising=False)
    set_locale("en")