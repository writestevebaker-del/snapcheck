"""Internationalization — auto-detect locale from env or config."""

from __future__ import annotations

import os
from typing import Any

SUPPORTED = frozenset({"en", "ru"})

_MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        "grade.excellent": "EXCELLENT",
        "grade.good": "GOOD",
        "grade.needs_work": "NEEDS WORK",
        "grade.critical": "CRITICAL",
        "report.title": "SnapCheck Health Report",
        "report.health_score": "Health Score",
        "report.summary": "Summary",
        "report.secrets": "Secrets",
        "report.large_files": "Large files",
        "report.duplicates": "Duplicates",
        "report.top_folders": "Top folders",
        "report.heaviest_dir": "Heaviest dir",
        "report.recommendations": "Recommendations",
        "report.git_tracked": "Git tracked sensitive",
        "report.no_secrets": "No potential secrets found",
        "report.no_large_files": "No large files above threshold",
        "report.no_subdirs": "No subdirectories",
        "report.no_duplicates": "No duplicates found",
        "report.copies": "copies",
        "report.waste": "waste",
        "report.total_recoverable": "Total recoverable",
        "report.more": "more",
        "report.action_required": "ACTION REQUIRED — fix critical items before commit",
        "report.healthy": "Project looks healthy — keep snapcheck in CI",
        "report.review": "Review recommendations above",
        "risk.critical": "CRITICAL",
        "risk.review": "REVIEW",
        "risk.placeholder": "PLACEHOLDER",
        "risk.false_positive": "FALSE+",
        "rec.env_keys.title": "Real API keys in .env",
        "rec.env_keys.action": "Ensure .env is in .gitignore; rotate compromised keys",
        "rec.env_keys.reason": "Found {count} keys in .env",
        "rec.code_secrets.title": "Critical secrets in source code",
        "rec.code_secrets.action": "Remove keys from source; use environment variables",
        "rec.code_secrets.reason": "Found {count} critical matches",
        "rec.false_pos.title": "Many false positives",
        "rec.false_pos.action": "Add .snapcheckignore: backups, logs/, test fixtures",
        "rec.false_pos.reason": "{count} matches are env var references, not real keys",
        "rec.large_file.title": "Large file: {path}",
        "rec.large_file.action": "Rotate or delete log; add to .gitignore / logrotate",
        "rec.large_file.reason": "Size {size} — bloats the project",
        "rec.heavy_dir.title": "Heavy folder: {path}/",
        "rec.heavy_dir.action": "Clean up or exclude from repo; set up rotation",
        "rec.heavy_dir.reason": "Uses {size}",
        "rec.duplicates.title": "Duplicate files",
        "rec.duplicates.action": "Keep one copy, delete: {paths}",
        "rec.duplicates.reason": "Can free ~{size}",
        "rec.git_tracked.title": "Git tracks: {path}",
        "rec.git_tracked.action": "git rm --cached; add to .gitignore; rotate keys",
        "rec.git_tracked.reason": "{reason}",
        "rec.no_gitignore.title": ".env not in .gitignore",
        "rec.no_gitignore.action": "Add `.env` to .gitignore immediately",
        "rec.no_gitignore.reason": "Risk of leaking keys to git",
        "rec.healthy.title": "Project in good shape",
        "rec.healthy.action": "Run snapcheck in CI: snapcheck scan . --fail-on-secrets",
        "rec.healthy.reason": "No serious issues found",
        "rec.plugin.title": "Plugin [{name}] findings",
        "rec.plugin.action": "Review plugin output and fix reported issues",
        "rec.plugin.reason": "{name}: {count} finding(s)",
        "report.plugins": "Plugin findings",
        "report.no_plugins": "No plugin findings",
        "plugins.list_header": "Loaded plugins",
        "plugins.none": "No plugins loaded",
        "plugins.init_created": "Created example plugin: {path}",
        "plugins.dir_created": "Created plugins directory: {path}",
        "git.sensitive_tracked": "Sensitive file tracked in git: {name}",
        "cli.err_not_dir": "Error: not a directory: {path}",
        "cli.err_not_git": "Error: not a git repository",
        "cli.html_written": "HTML report: {path}",
        "cli.sarif_written": "SARIF report: {path}",
        "cli.text_written": "Text report: {path}",
        "cli.markdown_written": "Markdown report: {path}",
        "cli.json_written": "JSON report: {path}",
        "cli.score_line": "Score: {score}/100 ({grade}) critical={critical}",
        "cli.scan_done": "Scan completed in {seconds:.2f}s",
        "cli.trend": "Trend: {prev} → {current} ({arrow}{delta})",
        "cli.no_baseline": "No baseline ({file})",
        "cli.baseline_updated": "Baseline updated: {path} ({count} entries)",
        "cli.doctor_init": "→ Creating smart .snapcheckignore...",
        "cli.html_path": "HTML: {path}",
        "init.exists": "Already exists: {path}",
        "init.force_hint": "Use --force to overwrite.",
        "init.created": "Created {path}",
        "init.hint": "Edit the file for your project, then run: snapcheck scan .",
        "init.suggested": "Suggested additions for .snapcheckignore:",
        "init.no_suggestions": "Already exists: {path} — no new suggestions.",
        "init.auto_added": "Auto-added:",
        "hooks.installed": "Installed pre-commit hook: {path}",
        "hooks.already": "Already installed: {path}",
        "html.recommendations": "Recommendations",
        "html.secrets": "Secrets",
        "html.large_files": "Large files",
        "html.none": "None found",
        "html.healthy": "No issues — project looks healthy.",
        "risk.expected": "EXPECTED",
        "report.score_breakdown": "Score breakdown",
        "report.score_base": "Base",
        "report.score_total": "Total",
        "report.commands": "Commands:",
        "report.learn_more": "Learn more",
        "report.dangerous_files": "Dangerous files",
        "report.no_dangerous": "No dangerous file paths",
        "rec.config_password.title": "Plain-text password in {path}",
        "rec.config_password.action": "Move to .env or secrets manager; rotate password",
        "rec.config_password.reason": "Password stored in config file",
        "rec.dangerous.title": "{kind}: {path}",
        "rec.dangerous.action": "Review and secure {path}",
        "score.critical_secrets": "critical secrets ({count}×)",
        "score.git_tracked": "git tracked ({count}×)",
        "score.review_secrets": "review secrets ({count}×)",
        "score.dangerous_files": "dangerous files ({count}×)",
        "score.plugin_critical": "plugin critical ({count}×)",
        "score.plugin_review": "plugin review ({count}×)",
        "score.large_files": "large files ({count}×)",
        "score.duplicates": "duplicate waste",
        "score.heavy_logs": "heavy logs: {path}",
        "cli.ci_line": "score={score} critical={critical}",
        "cli.system_path_warn": "Looks like a system directory. Try: snapcheck scan . --profile server",
        "explain.header": "Finding: {path} — {kind}",
        "explain.severity": "Severity: {severity}",
        "explain.what": "What is this:",
        "explain.why": "Why it matters:",
        "explain.do": "What to do:",
        "explain.kind_header": "Finding type: {kind}",
        "explain.unknown": "No explanation for: {kind}",
        "explain.need_scan": "Run snapcheck scan first, or use --finding KIND",
        "explain.config.what": "A password stored in plain text inside a config file.",
        "explain.config.why": "Anyone with repo access sees it; git history keeps it forever.",
        "explain.config.action": "Move to .env, add .gitignore, rotate the password.",
        "explain.privkey.what": "A private cryptographic key embedded in a file.",
        "explain.privkey.why": "Key compromise grants full access to linked services.",
        "explain.privkey.action": "Remove from repo, use secret storage, rotate key.",
        "explain.ovpn.what": "OpenVPN config that may include certificates and keys.",
        "explain.ovpn.why": "In a web directory it can be downloaded by anyone.",
        "explain.ovpn.action": "Move out of webroot and chmod 600.",
        "teach.list_header": "Available topics:",
        "teach.unknown": "Unknown topic: {topic}. Available: {available}",
        "teach.secrets": "Secrets are API keys, passwords, tokens. Env var references (API_KEY=FOO) are noise.",
        "teach.baseline": "Baseline marks accepted findings. Use when legacy issues cannot be fixed immediately.",
        "teach.profiles": "Profiles: git-repo (default), server (VPS keys OK), ci (fast fail).",
        "teach.config_password": "Config passwords in JSON/YAML are critical. Use env vars or vault.",
        "teach.private_key": "Private keys in git are critical. On servers use --profile server.",
        "teach.ovpn_webroot": "Never serve .ovpn from public web directories.",
        "teach.ci.intro": "GitHub Actions snippet:",
        "fix.confirm": "Apply '{cmd}'? [y/N] ",
        "fix.applied": "Updated {path}: {line}",
        "fix.skip_git": "Skipped (needs confirm): {cmd}",
        "fix.done": "Applied {count} safe fix(es).",
    },
    "ru": {
        "grade.excellent": "ОТЛИЧНО",
        "grade.good": "ХОРОШО",
        "grade.needs_work": "НУЖНА РАБОТА",
        "grade.critical": "КРИТИЧНО",
        "report.title": "SnapCheck — отчёт о здоровье проекта",
        "report.health_score": "Оценка здоровья",
        "report.summary": "Сводка",
        "report.secrets": "Секреты",
        "report.large_files": "Большие файлы",
        "report.duplicates": "Дубликаты",
        "report.top_folders": "Топ папок",
        "report.heaviest_dir": "Самая тяжёлая",
        "report.recommendations": "Рекомендации",
        "report.git_tracked": "Чувствительные файлы в git",
        "report.no_secrets": "Потенциальных секретов не найдено",
        "report.no_large_files": "Больших файлов выше порога нет",
        "report.no_subdirs": "Подкаталогов нет",
        "report.no_duplicates": "Дубликатов не найдено",
        "report.copies": "копий",
        "report.waste": "лишнего",
        "report.total_recoverable": "Можно освободить",
        "report.more": "ещё",
        "report.action_required": "ТРЕБУЮТСЯ ДЕЙСТВИЯ — исправь критичное перед коммитом",
        "report.healthy": "Проект здоров — держи snapcheck в CI",
        "report.review": "Просмотри рекомендации выше",
        "risk.critical": "КРИТИЧНО",
        "risk.review": "ПРОВЕРИТЬ",
        "risk.placeholder": "ПЛЕЙСХОЛДЕР",
        "risk.false_positive": "ШУМ",
        "rec.env_keys.title": "Реальные ключи в .env",
        "rec.env_keys.action": "Проверь, что .env в .gitignore; ротируй скомпрометированные ключи",
        "rec.env_keys.reason": "Найдено {count} ключей в .env",
        "rec.code_secrets.title": "Критичные секреты в коде",
        "rec.code_secrets.action": "Удали ключи из исходников, используй переменные окружения",
        "rec.code_secrets.reason": "Найдено {count} критичных совпадений",
        "rec.false_pos.title": "Много ложных срабатываний",
        "rec.false_pos.action": "Добавь .snapcheckignore: backup-файлы, logs/, тестовые фикстуры",
        "rec.false_pos.reason": "{count} совпадений — ссылки на env-переменные, не ключи",
        "rec.large_file.title": "Большой файл: {path}",
        "rec.large_file.action": "Ротируй или удали лог; добавь в .gitignore / logrotate",
        "rec.large_file.reason": "Размер {size} — раздувает проект",
        "rec.heavy_dir.title": "Тяжёлая папка: {path}/",
        "rec.heavy_dir.action": "Очисти или исключи из репозитория; настрой ротацию",
        "rec.heavy_dir.reason": "Занимает {size}",
        "rec.duplicates.title": "Дубликаты файлов",
        "rec.duplicates.action": "Оставь одну копию, удали: {paths}",
        "rec.duplicates.reason": "Можно освободить ~{size}",
        "rec.git_tracked.title": "Git отслеживает: {path}",
        "rec.git_tracked.action": "git rm --cached; добавь в .gitignore; ротируй ключи",
        "rec.git_tracked.reason": "{reason}",
        "rec.no_gitignore.title": ".env не в .gitignore",
        "rec.no_gitignore.action": "Добавь строку `.env` в .gitignore немедленно",
        "rec.no_gitignore.reason": "Риск утечки ключей в git",
        "rec.healthy.title": "Проект в хорошем состоянии",
        "rec.healthy.action": "Запускай snapcheck в CI: snapcheck scan . --fail-on-secrets",
        "rec.healthy.reason": "Серьёзных проблем не обнаружено",
        "rec.plugin.title": "Плагин [{name}] — находки",
        "rec.plugin.action": "Проверь вывод плагина и исправь проблемы",
        "rec.plugin.reason": "{name}: {count} находок",
        "report.plugins": "Находки плагинов",
        "report.no_plugins": "Плагины ничего не нашли",
        "plugins.list_header": "Загруженные плагины",
        "plugins.none": "Плагины не загружены",
        "plugins.init_created": "Создан пример плагина: {path}",
        "plugins.dir_created": "Создана папка плагинов: {path}",
        "git.sensitive_tracked": "Чувствительный файл в git: {name}",
        "cli.err_not_dir": "Ошибка: не каталог: {path}",
        "cli.err_not_git": "Ошибка: не git-репозиторий",
        "cli.html_written": "HTML-отчёт: {path}",
        "cli.sarif_written": "SARIF-отчёт: {path}",
        "cli.text_written": "Текстовый отчёт: {path}",
        "cli.markdown_written": "Markdown-отчёт: {path}",
        "cli.json_written": "JSON-отчёт: {path}",
        "cli.score_line": "Оценка: {score}/100 ({grade}) критичных={critical}",
        "cli.scan_done": "Скан завершён за {seconds:.2f}с",
        "cli.trend": "Динамика: {prev} → {current} ({arrow}{delta})",
        "cli.no_baseline": "Нет baseline ({file})",
        "cli.baseline_updated": "Baseline обновлён: {path} ({count} записей)",
        "cli.doctor_init": "→ Создаю smart .snapcheckignore...",
        "cli.html_path": "HTML: {path}",
        "init.exists": "Уже существует: {path}",
        "init.force_hint": "Используй --force для перезаписи.",
        "init.created": "Создан {path}",
        "init.hint": "Отредактируй файл под проект, затем: snapcheck scan .",
        "init.suggested": "Предлагаемые дополнения для .snapcheckignore:",
        "init.no_suggestions": "Уже существует: {path} — новых предложений нет.",
        "init.auto_added": "Авто-добавлено:",
        "hooks.installed": "Pre-commit hook установлен: {path}",
        "hooks.already": "Уже установлен: {path}",
        "html.recommendations": "Рекомендации",
        "html.secrets": "Секреты",
        "html.large_files": "Большие файлы",
        "html.none": "Не найдено",
        "html.healthy": "Проблем нет — проект в порядке.",
        "risk.expected": "ОЖИДАЕМО",
        "report.score_breakdown": "Разбор оценки",
        "report.score_base": "База",
        "report.score_total": "Итого",
        "report.commands": "Команды:",
        "report.learn_more": "Подробнее",
        "report.dangerous_files": "Опасные файлы",
        "report.no_dangerous": "Опасных путей не найдено",
        "rec.config_password.title": "Пароль в открытом виде: {path}",
        "rec.config_password.action": "Перенеси в .env или secrets manager; ротируй пароль",
        "rec.config_password.reason": "Пароль хранится в конфиге",
        "rec.dangerous.title": "{kind}: {path}",
        "rec.dangerous.action": "Проверь и защити {path}",
        "score.critical_secrets": "критичные секреты ({count}×)",
        "score.git_tracked": "в git ({count}×)",
        "score.review_secrets": "на проверку ({count}×)",
        "score.dangerous_files": "опасные файлы ({count}×)",
        "score.plugin_critical": "плагин critical ({count}×)",
        "score.plugin_review": "плагин review ({count}×)",
        "score.large_files": "большие файлы ({count}×)",
        "score.duplicates": "дубликаты",
        "score.heavy_logs": "тяжёлые логи: {path}",
        "cli.ci_line": "score={score} critical={critical}",
        "cli.system_path_warn": "Похоже на системную папку. Попробуй: snapcheck scan . --profile server",
        "explain.header": "Находка: {path} — {kind}",
        "explain.severity": "Серьёзность: {severity}",
        "explain.what": "Что это:",
        "explain.why": "Почему важно:",
        "explain.do": "Что делать:",
        "explain.kind_header": "Тип находки: {kind}",
        "explain.unknown": "Нет объяснения для: {kind}",
        "explain.need_scan": "Сначала snapcheck scan, или --finding KIND",
        "explain.config.what": "Пароль в открытом виде в конфигурационном файле.",
        "explain.config.why": "Любой с доступом к репо увидит его; git history сохранит навсегда.",
        "explain.config.action": "Перенеси в .env, добавь в .gitignore, ротируй пароль.",
        "explain.privkey.what": "Приватный криптографический ключ в файле.",
        "explain.privkey.why": "Компрометация ключа = полный доступ к сервисам.",
        "explain.privkey.action": "Убери из репо, используй secret storage, ротируй ключ.",
        "explain.ovpn.what": "Конфиг OpenVPN с сертификатами и ключами.",
        "explain.ovpn.why": "В web-папке файл могут скачать все.",
        "explain.ovpn.action": "Убери из webroot, chmod 600.",
        "teach.list_header": "Доступные темы:",
        "teach.unknown": "Неизвестная тема: {topic}. Доступно: {available}",
        "teach.secrets": "Секреты — ключи, пароли, токены. Ссылки на env (API_KEY=FOO) — шум.",
        "teach.baseline": "Baseline фиксирует принятые находки. Когда legacy нельзя быстро исправить.",
        "teach.profiles": "Профили: git-repo (default), server (ключи VPS OK), ci (быстрый fail).",
        "teach.config_password": "Пароли в JSON/YAML — critical. Используй env или vault.",
        "teach.private_key": "Приватные ключи в git — critical. На серверах --profile server.",
        "teach.ovpn_webroot": "Никогда не отдавай .ovpn из публичного web-каталога.",
        "teach.ci.intro": "Сниппет GitHub Actions:",
        "fix.confirm": "Применить '{cmd}'? [y/N] ",
        "fix.applied": "Обновлён {path}: {line}",
        "fix.skip_git": "Пропущено (нужно подтверждение): {cmd}",
        "fix.done": "Применено безопасных исправлений: {count}.",
    },
}

_GRADE_KEYS = {
    "EXCELLENT": "excellent",
    "GOOD": "good",
    "NEEDS WORK": "needs_work",
    "CRITICAL": "critical",
}

_current_locale: str = "en"


def _normalize_lang(value: str | None) -> str | None:
    if not value:
        return None
    val = value.strip().lower()
    if val in {"auto", "default", ""}:
        return None
    if val.startswith("ru"):
        return "ru"
    if val.startswith("en"):
        return "en"
    if val in SUPPORTED:
        return val
    return None


def detect_system_locale() -> str:
    for var in ("SNAPCHECK_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        raw = os.environ.get(var)
        lang = _normalize_lang(raw)
        if lang:
            return lang
    return "en"


def resolve_locale(*, cli_lang: str | None = None, config_lang: str | None = None) -> str:
    for source in (cli_lang, config_lang):
        lang = _normalize_lang(source)
        if lang:
            return lang
    return detect_system_locale()


def set_locale(lang: str) -> str:
    global _current_locale
    resolved = _normalize_lang(lang) or detect_system_locale()
    _current_locale = resolved if resolved in SUPPORTED else "en"
    return _current_locale


def get_locale() -> str:
    return _current_locale


def t(key: str, **kwargs: Any) -> str:
    table = _MESSAGES.get(_current_locale) or _MESSAGES["en"]
    template = table.get(key) or _MESSAGES["en"].get(key) or key
    if kwargs:
        try:
            return template.format(**kwargs)
        except (KeyError, ValueError):
            return template
    return template


def translate_grade(grade_key: str) -> str:
    """Translate internal grade key (excellent, good, ...) to localized label."""
    return t(f"grade.{grade_key}")