"""Package version consistency."""

from importlib.metadata import version

from snapcheck import __version__


def test_cli_version_matches_package() -> None:
    assert version("snapcheck") == __version__


def test_version_is_semver() -> None:
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


def test_mvp_version() -> None:
    assert __version__ == "0.9.0"