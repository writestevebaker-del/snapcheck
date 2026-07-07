# SnapCheck v0.9.0

**Одна команда — и ты знаешь, всё ли в порядке с твоим проектом.**

SnapCheck проверяет папку с кодом и находит то, что обычно всплывает
в самый неудобный момент:

- 🔑 **Забытые пароли и ключи** в коде (AWS, GitHub, Stripe, Telegram и другие)
- 📄 **Пароли в JSON/YAML** конфигах (naive-passwords.json и подобные)
- 📦 **Огромные файлы** и **дубликаты**
- ⚠️ **Опасные файлы** по пути (`.ovpn` в webroot, `id_rsa`, `.env`)
- 💾 Что именно «ест» место на диске

В конце — Health Score, разбор оценки, рекомендации с **готовыми командами**.

## Установка

```bash
pip install git+https://github.com/writestevebaker-del/snapcheck.git
```

Или через pipx:

```bash
pipx install git+https://github.com/writestevebaker-del/snapcheck.git
```

Локальная разработка:

```bash
git clone https://github.com/writestevebaker-del/snapcheck.git
cd snapcheck
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

## Быстрый старт

```bash
snapcheck scan .                         # полный отчёт
snapcheck scan . --hide-noise            # без false positives
snapcheck scan . --profile server        # VPS: SSH/Let's Encrypt = OK
snapcheck scan . --profile ci            # CI: быстро, fail on critical
snapcheck doctor .                       # smart init + scan + советы
snapcheck explain --finding "Config Password"
snapcheck teach ci                       # GitHub Actions snippet
snapcheck fix .                          # безопасные авто-фиксы (.gitignore)
```

## Профили

| Профиль | Когда использовать |
|---------|-------------------|
| `git-repo` | Репозиторий перед push (default) |
| `server` | VPS: `.ssh/`, `letsencrypt/` не штрафуют score |
| `ci` | GitHub Actions: `--hide-noise`, `--fail-on-critical`, без дубликатов |

```toml
# snapcheck.toml
[scan]
profile = "git-repo"
```

## Экспорт

```bash
snapcheck scan . --html report.html
snapcheck scan . --sarif results.sarif
snapcheck scan . --json
snapcheck scan . --save-report out.txt
```

## CI / GitHub Actions

```yaml
name: SnapCheck
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
```

## Плагины

```bash
snapcheck plugins init .
snapcheck plugins list .
snapcheck scan . --plugin ./my_plugin.py
```

## Сравнение с конкурентами

| Feature | gitleaks | trufflehog | SnapCheck |
|---------|----------|------------|-----------|
| Secrets | ✅ | ✅ | ✅ |
| JSON/YAML passwords | ❌ | ❌ | ✅ |
| Large files | ❌ | ❌ | ✅ |
| Duplicates | ❌ | ❌ | ✅ |
| Health score + breakdown | ❌ | ❌ | ✅ |
| Actionable commands | ❌ | ❌ | ✅ |
| Русский UI | ❌ | ❌ | ✅ |
| Zero deps | ❌ | ❌ | ✅ |

## Тесты

```bash
pytest -v
```

## Файлы проекта

| Файл | Назначение |
|------|------------|
| `.snapcheckignore` | Исключения |
| `.snapcheck-baseline.json` | Allowlist |
| `snapcheck.toml` | Конфиг + профиль |
| `.snapcheck/plugins/` | Кастомные плагины |