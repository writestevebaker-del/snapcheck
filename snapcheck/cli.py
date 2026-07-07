"""SnapCheck CLI entry point."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from snapcheck import __version__
from snapcheck.config import load_config
from snapcheck.baseline import (
    BASELINE_FILENAME,
    BaselineEntry,
    filter_by_baseline,
    load_baseline,
    save_baseline,
)
from snapcheck.compare import compare_reports, format_diff, load_report_json
from snapcheck.custom_rules import RULES_FILENAME, list_builtin_patterns, load_custom_patterns
from snapcheck.html_report import to_html
from snapcheck.markdown_report import to_markdown
from snapcheck.i18n import resolve_locale, set_locale, t
from snapcheck.ignore import build_ignore_rules
from snapcheck.init_cmd import run_init
from snapcheck.report import ScanReport
from snapcheck.sarif import to_sarif
from snapcheck.scanners.git_check import scan_git_tracked
from snapcheck.scanners.duplicates import scan_duplicates
from snapcheck.scanners.disk_usage import scan_disk_usage
from snapcheck.scanners.large_files import scan_large_files
from snapcheck.scanners.secrets import scan_secrets
from snapcheck.history import append_history, format_trend
from snapcheck.hooks import install_pre_commit
from snapcheck.smart_init import run_smart_init
from snapcheck.validate import run_validate
from snapcheck.plugins import load_plugins, run_plugins
from snapcheck.plugin_init import run_init_plugins


def _common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument(
        "--lang",
        choices=["auto", "en", "ru"],
        default="auto",
        help="UI language (auto = detect from LANG / snapcheck.toml)",
    )
    return p


def setup_locale(args: argparse.Namespace, root: Path | None = None) -> str:
    config_lang = load_config(root).language if root else None
    cli_lang = None if args.lang == "auto" else args.lang
    lang = resolve_locale(cli_lang=cli_lang, config_lang=config_lang)
    return set_locale(lang)


def build_report(root: Path, args: argparse.Namespace) -> ScanReport:
    cfg = load_config(root)
    threshold_mb = getattr(args, "large_threshold_mb", None) or cfg.large_threshold_mb
    min_large = threshold_mb * 1024 * 1024
    cli_exclude = set(args.exclude) if getattr(args, "exclude", None) else set()
    extra_skip = cli_exclude | set(cfg.extra_exclude or [])
    no_dupes = getattr(args, "no_duplicates", False) or cfg.skip_duplicates
    ignore_general = build_ignore_rules(root, extra_skip_dirs=extra_skip)
    ignore_secrets = build_ignore_rules(
        root,
        extra_skip_dirs=extra_skip,
        include_secrets_defaults=True,
    )

    enable_entropy = not getattr(args, "no_entropy", False)
    secrets = scan_secrets(root, ignore=ignore_secrets, enable_entropy=enable_entropy)
    if getattr(args, "use_baseline", True):
        secrets = filter_by_baseline(secrets, load_baseline(root))

    plugin_findings = None
    no_plugins = getattr(args, "no_plugins", False)
    if not no_plugins and cfg.plugins_enabled:
        extra = [Path(p).resolve() for p in getattr(args, "plugin", []) or []]
        plugins = load_plugins(root, extra_files=extra or None)
        if plugins:
            plugin_findings = run_plugins(root, plugins, ignore=ignore_general)

    return ScanReport(
        root=root,
        secrets=secrets,
        hide_noise=getattr(args, "hide_noise", False),
        large_files=scan_large_files(root, min_size_bytes=min_large, ignore=ignore_general),
        disk_usage=scan_disk_usage(root, ignore=ignore_general),
        duplicates=[] if no_dupes else scan_duplicates(root, ignore=ignore_general),
        git_tracked=scan_git_tracked(root),
        plugin_findings=plugin_findings,
    )


def _write_outputs(report: ScanReport, args: argparse.Namespace) -> None:
    if args.html:
        path = Path(args.html)
        path.write_text(to_html(report), encoding="utf-8")
        print(t("cli.html_written", path=path), file=sys.stderr)
    if args.sarif:
        path = Path(args.sarif)
        path.write_text(to_sarif(report), encoding="utf-8")
        print(t("cli.sarif_written", path=path), file=sys.stderr)
    if getattr(args, "save_report", None):
        path = Path(args.save_report)
        path.write_text(report.to_text(), encoding="utf-8")
        print(t("cli.text_written", path=path), file=sys.stderr)
    if getattr(args, "markdown", None):
        path = Path(args.markdown)
        path.write_text(to_markdown(report), encoding="utf-8")
        print(t("cli.markdown_written", path=path), file=sys.stderr)
    if getattr(args, "save_json", None):
        path = Path(args.save_json)
        path.write_text(report.to_json(), encoding="utf-8")
        print(t("cli.json_written", path=path), file=sys.stderr)


def _print_report(report: ScanReport, args: argparse.Namespace) -> None:
    if args.quiet:
        h = report.health
        print(t("cli.score_line", score=h.score, grade=h.grade, critical=h.critical_count))
        for rec in report.recommendations[:5]:
            print(f"  [{rec.severity.value}] {rec.title}: {rec.action}")
        return
    if args.json:
        print(report.to_json())
    elif not args.quiet:
        print(report.to_text())


def build_parser() -> argparse.ArgumentParser:
    common = _common_parser()
    parser = argparse.ArgumentParser(
        prog="snapcheck",
        description="Scan a project folder for secrets, large files, duplicates, and disk usage.",
    )
    parser.add_argument("--version", action="version", version=f"snapcheck {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", parents=[common], help="Run full health scan")
    scan.add_argument("path", type=Path, nargs="?", default=Path("."), help="Directory to scan")
    scan.add_argument("--json", action="store_true", help="Output JSON report")
    scan.add_argument("--save-json", metavar="FILE", help="Write JSON report to FILE")
    scan.add_argument("--quiet", "-q", action="store_true", help="Summary + top recommendations only")
    scan.add_argument("--hide-noise", action="store_true", help="Hide false positives from report")
    scan.add_argument("--html", metavar="FILE", help="Write HTML report to FILE")
    scan.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 report to FILE")
    scan.add_argument("--markdown", metavar="FILE", help="Write Markdown report to FILE")
    scan.add_argument("--save-report", metavar="FILE", help="Write text report to FILE")
    scan.add_argument("--no-entropy", action="store_true", help="Disable entropy-based detection")
    scan.add_argument("--large-threshold-mb", type=int, default=10)
    scan.add_argument("--no-duplicates", action="store_true")
    scan.add_argument("--fail-on-secrets", action="store_true")
    scan.add_argument("--fail-on-critical", action="store_true")
    scan.add_argument("--min-score", type=int, default=None, metavar="N", help="Exit 1 if health score < N")
    scan.add_argument("--no-baseline", action="store_true", help="Ignore .snapcheck-baseline.json")
    scan.add_argument("--exclude", action="append", default=[], metavar="DIR")
    scan.add_argument(
        "--plugin",
        action="append",
        default=[],
        metavar="FILE",
        help="Load extra plugin from FILE (can repeat)",
    )
    scan.add_argument("--no-plugins", action="store_true", help="Disable custom plugins")

    init = sub.add_parser("init", parents=[common], help="Create .snapcheckignore in a project")
    init.add_argument("path", type=Path, nargs="?", default=Path("."))
    init.add_argument("--force", action="store_true")
    init.add_argument("--smart", action="store_true", help="Auto-detect ignore rules from scan")

    baseline = sub.add_parser("baseline", parents=[common], help="Manage accepted findings baseline")
    baseline_sub = baseline.add_subparsers(dest="baseline_cmd", required=True)
    b_update = baseline_sub.add_parser("update", parents=[common], help="Snapshot current findings as accepted")
    b_update.add_argument("path", type=Path, nargs="?", default=Path("."))
    b_show = baseline_sub.add_parser("show", parents=[common], help="Show baseline entries")
    b_show.add_argument("path", type=Path, nargs="?", default=Path("."))

    hooks = sub.add_parser("hooks", parents=[common], help="Install git hooks")
    hooks_sub = hooks.add_subparsers(dest="hooks_cmd", required=True)
    h_install = hooks_sub.add_parser("install", parents=[common], help="Install pre-commit hook")
    h_install.add_argument("path", type=Path, nargs="?", default=Path("."))

    doctor = sub.add_parser("doctor", parents=[common], help="Scan + smart init + report (fix workflow)")
    doctor.add_argument("path", type=Path, nargs="?", default=Path("."))
    doctor.add_argument("--html", metavar="FILE", default=None)

    rules = sub.add_parser("rules", parents=[common], help="List detection rules")
    rules_sub = rules.add_subparsers(dest="rules_cmd", required=True)
    rules_sub.add_parser("list", parents=[common], help="Show built-in patterns")

    compare = sub.add_parser("compare", parents=[common], help="Diff two JSON scan reports")
    compare.add_argument("old_report", type=Path)
    compare.add_argument("new_report", type=Path)

    validate = sub.add_parser("validate", parents=[common], help="Validate snapcheck config files")
    validate.add_argument("path", type=Path, nargs="?", default=Path("."))

    plugins = sub.add_parser("plugins", parents=[common], help="Manage custom scan plugins")
    plugins_sub = plugins.add_subparsers(dest="plugins_cmd", required=True)
    p_list = plugins_sub.add_parser("list", parents=[common], help="List loaded plugins")
    p_list.add_argument("path", type=Path, nargs="?", default=Path("."))
    p_init = plugins_sub.add_parser("init", parents=[common], help="Scaffold example plugin")
    p_init.add_argument("path", type=Path, nargs="?", default=Path("."))
    p_init.add_argument("--force", action="store_true")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    root = args.path.resolve()
    if not root.is_dir():
        print(t("cli.err_not_dir", path=root), file=sys.stderr)
        return 2

    setup_locale(args, root)
    args.use_baseline = not args.no_baseline
    t0 = time.perf_counter()
    report = build_report(root, args)
    elapsed = time.perf_counter() - t0
    report.scan_duration_seconds = round(elapsed, 3)
    _print_report(report, args)
    if not args.json and not args.quiet:
        history = format_trend(root, report.health.score)
        append_history(
            root,
            score=report.health.score,
            critical=report.health.critical_count,
            secrets=len(report._visible_secrets),
            large_files=len(report.large_files),
        )
        print(f"\n  ⏱  {t('cli.scan_done', seconds=elapsed)}")
        if history:
            print(f"  📈  {history}")
    _write_outputs(report, args)

    cfg = load_config(root)
    if args.fail_on_critical or cfg.fail_on_critical:
        if report.health.critical_count > 0:
            return 1
    if args.fail_on_secrets and report.has_secrets:
        return 1
    min_score = args.min_score if args.min_score is not None else cfg.min_health_score
    if min_score and report.health.score < min_score:
        return 1
    return 0


def run_baseline(args: argparse.Namespace) -> int:
    root = args.path.resolve()
    if not root.is_dir():
        print(t("cli.err_not_dir", path=root), file=sys.stderr)
        return 2

    setup_locale(args, root)

    if args.baseline_cmd == "show":
        entries = load_baseline(root)
        if not entries:
            print(t("cli.no_baseline", file=BASELINE_FILENAME))
            return 0
        for e in sorted(entries, key=lambda x: (x.path, x.line)):
            print(f"  {e.path}:{e.line} [{e.kind}]")
        return 0

    if args.baseline_cmd == "update":
        scan_args = argparse.Namespace(
            large_threshold_mb=10,
            no_duplicates=True,
            exclude=[],
            use_baseline=False,
            hide_noise=False,
        )
        report = build_report(root, scan_args)
        entries = {
            BaselineEntry(
                path=str(c.finding.path).replace("\\", "/"),
                line=c.finding.line,
                kind=c.finding.kind,
            )
            for c in report.health.classified_secrets
        }
        path = save_baseline(root, entries)
        print(t("cli.baseline_updated", path=path, count=len(entries)))
        return 0

    return 2


def run_doctor(args: argparse.Namespace) -> int:
    root = args.path.resolve()
    if not root.is_dir():
        print(t("cli.err_not_dir", path=root), file=sys.stderr)
        return 2

    setup_locale(args, root)

    ignore = root / ".snapcheckignore"
    if not ignore.exists():
        print(t("cli.doctor_init"))
        run_smart_init(root, force=False)

    scan_args = argparse.Namespace(
        path=root,
        json=False,
        quiet=False,
        hide_noise=True,
        html=args.html,
        sarif=None,
        save_report=None,
        large_threshold_mb=10,
        no_duplicates=False,
        fail_on_secrets=False,
        fail_on_critical=False,
        no_baseline=False,
        exclude=[],
        use_baseline=True,
    )
    report = build_report(root, scan_args)
    print(report.to_text())
    if args.html:
        Path(args.html).write_text(to_html(report), encoding="utf-8")
        print(f"\n{t('cli.html_path', path=args.html)}", file=sys.stderr)

    return 1 if report.health.critical_count > 0 else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)
    if args.command == "init":
        root = args.path.resolve()
        setup_locale(args, root if root.is_dir() else None)
        if args.smart:
            return run_smart_init(args.path, force=args.force)
        return run_init(args.path, force=args.force)
    if args.command == "baseline":
        return run_baseline(args)
    if args.command == "doctor":
        return run_doctor(args)
    if args.command == "hooks":
        root = args.path.resolve()
        setup_locale(args, root if root.is_dir() else None)
        if args.hooks_cmd == "install":
            return install_pre_commit(args.path)
    if args.command == "rules":
        setup_locale(args, None)
        if args.rules_cmd == "list":
            for name, pattern in list_builtin_patterns():
                print(f"  {name:24} {pattern}")
            custom = load_custom_patterns(Path("."))
            if custom:
                print(f"\n  Custom ({RULES_FILENAME}):")
                for cp in custom:
                    print(f"  {cp.name:24} {cp.pattern.pattern}")
            return 0
    if args.command == "compare":
        setup_locale(args, None)
        old = load_report_json(args.old_report.resolve())
        new = load_report_json(args.new_report.resolve())
        print(format_diff(compare_reports(old, new)))
        return 0
    if args.command == "validate":
        setup_locale(args, args.path.resolve())
        return run_validate(args.path.resolve())
    if args.command == "plugins":
        root = args.path.resolve()
        setup_locale(args, root if root.is_dir() else None)
        if args.plugins_cmd == "init":
            return run_init_plugins(args.path, force=args.force)
        if args.plugins_cmd == "list":
            if not root.is_dir():
                print(t("cli.err_not_dir", path=root), file=sys.stderr)
                return 2
            loaded = load_plugins(root)
            if not loaded:
                print(t("plugins.none"))
                return 0
            print(t("plugins.list_header"))
            for plugin in loaded:
                desc = f" — {plugin.description}" if plugin.description else ""
                print(f"  {plugin.name} v{plugin.version}{desc}")
            return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())