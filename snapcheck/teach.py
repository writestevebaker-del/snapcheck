"""Offline teaching topics — replace AI guidance."""

from __future__ import annotations

from snapcheck.i18n import t

_TOPICS = frozenset({
    "secrets",
    "baseline",
    "ci",
    "profiles",
    "config-password",
    "private-key",
    "ovpn-webroot",
})

_CI_YAML = """name: SnapCheck
on: [push, pull_request]
jobs:
  snapcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install pipx && pipx install snapcheck
      - run: snapcheck scan . --profile ci
"""


def list_topics() -> list[str]:
    return sorted(_TOPICS)


def teach_topic(topic: str) -> str:
    topic = topic.lower().replace("_", "-")
    if topic not in _TOPICS:
        return t("teach.unknown", topic=topic, available=", ".join(list_topics()))

    if topic == "ci":
        return f"{t('teach.ci.intro')}\n\n```yaml\n{_CI_YAML}```"

    return t(f"teach.{topic.replace('-', '_')}")