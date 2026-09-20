"""Command-line entry for DeepOpen."""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from deepopen.baseline import save_baseline
from deepopen.catalog import all_rule_records, explain_rule
from deepopen.checklist import CHECKLIST
from deepopen.config import PROFILES, load_config
from deepopen.fixers import apply_fixes
from deepopen.hook import install_hook, uninstall_hook
from deepopen.projectinit import init_project
from deepopen.report import (
    exit_code,
    render_json,
    render_markdown,
    render_sarif,
    render_text,
    write_report,
)
from deepopen.scanner import scan_path
from deepopen.version import __version__

COMMANDS = {"scan", "serve", "init", "rules", "hook", "checklist", "fix", "explain", "baseline"}


def normalize_argv(argv: list[str] | None) -> list[str]:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return ["scan", "."]
    head = args[0]
    if head in COMMANDS or head in {"-h", "--help", "--version", "-V"}:
        return args
    return ["scan", *args]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deepopen",
        description="检查本地源码中的常见缺陷和不安全写法，并给出加固建议。",
    )
    parser.add_argument("-V", "--version", action="version", version=f"DeepOpen {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="扫描目录或文件")
    scan.add_argument("path", nargs="?", default=".", help="要扫描的文件或目录")
    scan.add_argument("-f", "--format", choices=("text", "json", "sarif", "md"), default="text")
    scan.add_argument("-o", "--output", type=Path, help="写入报告（.json / .html / .sarif / .md / .txt）")
    scan.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info", "never"), default=None)
    scan.add_argument("--staged", action="store_true", help="只扫描 Git 暂存文件")
    scan.add_argument("--config", type=Path, help="指定 deepopen.toml / deepopen.json")
    scan.add_argument("--show-baseline", action="store_true", help="显示已被基线接受的命中")
    scan.add_argument("--save-baseline", action="store_true", help="把本次命中写入基线文件")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument("--checklist", action="store_true", help="扫描前打印加固清单")
    scan.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        default=None,
        help="扫描配置档：all / security / bug / secret",
    )

    serve = sub.add_parser("serve", help="打开本地 Web 控制台（仅 127.0.0.1）")
    serve.add_argument("path", nargs="?", default=".", help="控制台默认扫描目录")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--no-open", action="store_true", help="不自动打开浏览器")

    init = sub.add_parser("init", help="生成 deepopen.toml 和忽略文件")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--with-ci", action="store_true", help="同时生成 GitHub Actions 工作流")

    rules = sub.add_parser("rules", help="列出全部规则")
    rules.add_argument("--json", action="store_true")

    hook = sub.add_parser("hook", help="安装或移除 Git pre-commit 钩子")
    hook.add_argument("action", choices=("install", "uninstall"))

    explain = sub.add_parser("explain", help="查看一条规则的说明")
    explain.add_argument("rule_id")

    fix = sub.add_parser("fix", help="对可自动修复的质量问题做行级改写")
    fix.add_argument("path", nargs="?", default=".")
    fix.add_argument("--apply", action="store_true", help="真正写回文件（默认只预览）")

    baseline = sub.add_parser("baseline", help="管理已接受的命中")
    baseline.add_argument("action", choices=("save", "show"))
    baseline.add_argument("path", nargs="?", default=".")

    sub.add_parser("checklist", help="打印开发加固清单")
    return parser


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.checklist:
        print(CHECKLIST)
        print()
    target = Path(args.path)
    if not target.exists():
        print(f"路径不存在: {target}", file=sys.stderr)
        return 2
    cfg = load_config(target, explicit=args.config)
    if args.profile:
        cfg.profile = args.profile
    fail_on = args.fail_on or cfg.fail_on
    result = scan_path(
        target,
        config=cfg,
        staged=args.staged,
        hide_baseline=not args.show_baseline,
    )
    if args.save_baseline:
        path = save_baseline(target, result.findings)
        print(f"基线已写入: {path}（{len(result.findings)} 条）")
    if args.format == "json":
        print(render_json(result))
    elif args.format == "sarif":
        print(render_sarif(result))
    elif args.format == "md":
        print(render_markdown(result))
    else:
        color = not args.no_color and sys.stdout.isatty()
        print(render_text(result, color=color))
    if args.output:
        write_report(result, args.output)
        print(f"报告已写入: {args.output}")
    return exit_code(result, fail_on)


def _cmd_serve(args: argparse.Namespace) -> int:
    from deepopen.server import serve

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print("Web 控制台只允许绑定本机回环地址。", file=sys.stderr)
        return 2
    httpd = serve(args.host, args.port, args.path)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"DeepOpen 控制台: {url}", flush=True)
    print("仅监听本机。按 Ctrl+C 结束。", flush=True)
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:
            print("未能自动打开浏览器，请手动访问上面的地址。")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        httpd.server_close()
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    written = init_project(Path(args.path), with_ci=args.with_ci)
    if not written:
        print("配置文件已存在，未覆盖。")
    else:
        for path in written:
            print(f"已创建: {path}")
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    records = all_rule_records(load_config(Path.cwd()))
    if args.json:
        print(json.dumps(records, ensure_ascii=False, indent=2))
        return 0
    print(f"共 {len(records)} 条规则\n")
    for item in records:
        cwe = f"  {item['cwe']}" if item.get("cwe") else ""
        print(f"{item['rule_id']:8} {item['severity']:8} {item['title']}{cwe}")
    return 0


def _cmd_hook(args: argparse.Namespace) -> int:
    cwd = Path.cwd()
    try:
        if args.action == "install":
            path = install_hook(cwd)
            print(f"已安装 pre-commit 钩子: {path}")
        else:
            if uninstall_hook(cwd):
                print("已移除 DeepOpen pre-commit 钩子")
            else:
                print("未找到由 DeepOpen 安装的钩子")
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    item = explain_rule(args.rule_id, load_config(Path.cwd()))
    if item is None:
        print(f"未找到规则: {args.rule_id}", file=sys.stderr)
        return 2
    print(f"{item['rule_id']}  [{item['severity']}]  {item['title']}")
    if item.get("cwe"):
        print(f"CWE: {item['cwe']}")
    if item.get("category"):
        print(f"类别: {item['category']}")
    if item.get("message"):
        print(f"说明: {item['message']}")
    if item.get("remediation"):
        print(f"加固: {item['remediation']}")
    return 0


def _cmd_fix(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"路径不存在: {target}", file=sys.stderr)
        return 2
    result = scan_path(target, hide_baseline=True)
    changes = apply_fixes(target, result.findings, dry_run=not args.apply)
    if not changes:
        print("没有可自动修复的命中（仅支持 is/is not None 改写，以及把裸 except 改成 except Exception）。")
        return 0
    mode = "已写回" if args.apply else "预览"
    print(f"{mode} {len(changes)} 处：")
    for item in changes:
        print(f"  {item['path']}:{item['line']} {item['rule_id']}")
        print(f"    - {item['before']}")
        print(f"    + {item['after']}")
    if not args.apply:
        print("\n确认后加上 --apply 才会改文件。安全类命中不会自动改写。")
    return 0


def _cmd_baseline(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"路径不存在: {target}", file=sys.stderr)
        return 2
    if args.action == "save":
        result = scan_path(target, hide_baseline=False)
        path = save_baseline(target, [item for item in result.findings if not item.baselined])
        print(f"基线已写入: {path}")
        return 0
    from deepopen.baseline import baseline_path, load_fingerprints

    path = baseline_path(target)
    fps = load_fingerprints(target)
    print(f"{path}  （{len(fps)} 条指纹）")
    return 0


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(normalize_argv(argv))
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "rules":
        return _cmd_rules(args)
    if args.command == "hook":
        return _cmd_hook(args)
    if args.command == "checklist":
        print(CHECKLIST)
        return 0
    if args.command == "explain":
        return _cmd_explain(args)
    if args.command == "fix":
        return _cmd_fix(args)
    if args.command == "baseline":
        return _cmd_baseline(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
