# SnapCheck v0.5.1

CLI-сканер здоровья проекта с Health Score, рекомендациями и CI-интеграцией.

Создан автономно **Midnight Bot**.

## Установка

```bash
cd ~/midnight-bot
source venv/bin/activate
pip install -e src/app
```

## Быстрый старт

```bash
snapcheck scan .                    # полный отчёт
snapcheck scan . --hide-noise         # без false positives
snapcheck scan . --quiet              # score + рекомендации
snapcheck doctor .                    # smart init + scan
snapcheck init . --smart              # .snapcheckignore с авто-правилами
```

## Экспорт

```bash
snapcheck scan . --html report.html
snapcheck scan . --sarif results.sarif   # GitHub Code Scanning
snapcheck scan . --json
snapcheck scan . --save-report out.txt
```

## CI / Git

```bash
snapcheck scan . --fail-on-critical     # exit 1 только на реальные секреты
snapcheck scan . --min-score 80           # exit 1 если score < 80
snapcheck baseline update .             # зафиксировать известные находки
snapcheck hooks install .               # pre-commit hook
```

## Конфиг `snapcheck.toml`

```toml
[scan]
large_threshold_mb = 10
min_health_score = 70
fail_on_critical = true
skip_duplicates = false
exclude = ["vendor"]
```

## Что ищет

| Категория | Паттерны |
|-----------|----------|
| Secrets | AWS, GitHub, OpenAI, Anthropic, Slack, Stripe, Telegram, Discord, Google API, JWT, Bearer, private keys |
| Large files | > 10 MB (настраивается) |
| Disk usage | Топ папок по размеру |
| Duplicates | MD5 |
| Git | `.env` в git index |

## Файлы проекта

| Файл | Назначение |
|------|------------|
| `.snapcheckignore` | Исключения |
| `.snapcheck-baseline.json` | Allowlist |
| `.snapcheck-history.json` | История score |
| `snapcheck.toml` | Конфиг |

## Тесты

```bash
cd src/app && pytest -v   # 43+ tests
```