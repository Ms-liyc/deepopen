"""Terminal, JSON, HTML, Markdown and SARIF reports."""

from __future__ import annotations

import html
import json
from pathlib import Path

from deepopen.version import __version__
from deepopen.models import Finding, Severity
from deepopen.scanner import ScanResult

SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[95m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_text(result: ScanResult, color: bool = True) -> str:
    lines: list[str] = []
    lines.append(f"扫描目录: {result.root}")
    lines.append(f"已检查文件: {result.files_scanned}/{result.files_total or result.files_scanned}  耗时: {result.duration_ms}ms")
    if result.baselined_count:
        lines.append(f"基线已忽略: {result.baselined_count}")
    if result.languages:
        lines.append(
            "语言分布: "
            + ", ".join(f"{name}={count}" for name, count in sorted(result.languages.items()))
        )
    lines.append(
        "问题统计: "
        + ", ".join(f"{name}={count}" for name, count in result.counts_by_severity.items())
    )
    if result.counts_by_category:
        lines.append(
            "问题分类: "
            + ", ".join(f"{name}={count}" for name, count in result.counts_by_category.items())
        )
    if result.errors:
        lines.append("注意:")
        lines.extend(f"  - {item}" for item in result.errors)
    lines.append("")
    if not result.findings:
        lines.append("未发现规则命中。这不代表没有缺陷，只说明当前规则没有匹配。")
        return "\n".join(lines)

    for finding in result.findings:
        sev = finding.severity.value.upper()
        head = f"[{sev}] {finding.rule_id} {finding.title}"
        if color:
            head = f"{SEVERITY_COLOR[finding.severity]}{BOLD}{head}{RESET}"
        lines.append(head)
        lines.append(f"  位置: {finding.path}:{finding.line}")
        lines.append(f"  类别: {finding.category.value}" + (f"  {finding.cwe}" if finding.cwe else ""))
        lines.append(f"  代码: {finding.snippet}")
        lines.append(f"  说明: {finding.message}")
        lines.append(f"  加固: {finding.remediation}")
        lines.append("")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload = {
        **result.to_summary(),
        "findings": [item.to_dict() for item in result.findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_markdown(result: ScanResult) -> str:
    from deepopen.fixers import is_fixable
    from deepopen.models import infer_language

    counts = result.counts_by_severity
    lines = [
        "# DeepOpen 缺陷修改方案",
        "",
        f"由 DeepOpen {__version__} 生成。这是防守检查说明，不是渗透测试步骤。",
        "",
        f"- 扫描目录: `{result.root}`",
        f"- 检查文件: {result.files_scanned}",
        f"- 命中项: {len(result.findings)}",
        f"- 耗时: {result.duration_ms}ms",
    ]
    if result.baselined_count:
        lines.append(f"- 基线已忽略: {result.baselined_count}")
    if result.profile:
        lines.append(f"- 配置档: `{result.profile}`")
    lines.extend(
        [
            "",
            "## 总览",
            "",
            "| 级别 | 数量 |",
            "| --- | ---: |",
        ]
    )
    for name, count in counts.items():
        lines.append(f"| {name} | {count} |")
    if result.counts_by_category:
        lines.extend(["", "| 类别 | 数量 |", "| --- | ---: |"])
        for name, count in result.counts_by_category.items():
            lines.append(f"| {name} | {count} |")
    if result.errors:
        lines.extend(["", "## 扫描注意", ""])
        lines.extend(f"- {item}" for item in result.errors)
    lines.extend(["", "## 修改清单", ""])
    if not result.findings:
        lines.append("未发现规则命中。这不代表没有缺陷，只说明当前规则没有匹配。")
        return "\n".join(lines) + "\n"

    grouped: dict[str, list] = {}
    for finding in result.findings:
        grouped.setdefault(finding.path, []).append(finding)

    index = 1
    for path, items in grouped.items():
        lines.append(f"### `{path}`")
        lines.append("")
        lines.append(f"本文件共 **{len(items)}** 处需要处理。")
        lines.append("")
        for finding in items:
            auto = "是，可用 `deepopen fix --apply`" if is_fixable(finding.rule_id) else "否，请按下方方案手工修改"
            lang = infer_language(finding.path)
            fence = _md_fence(finding.snippet, lang)
            extra = f" · {finding.cwe}" if finding.cwe else ""
            lines.extend(
                [
                    f"#### {index}. [{finding.severity.value.upper()}] {finding.rule_id} {finding.title}",
                    "",
                    f"- 位置: 第 {finding.line} 行",
                    f"- 类别: {finding.category.value}{extra}",
                    f"- 问题: {finding.message}",
                    f"- 可自动修复: {auto}",
                    "",
                    "**当前代码**",
                    "",
                    fence,
                    "",
                    "**修改方案**",
                    "",
                    finding.remediation,
                    "",
                ]
            )
            index += 1
    return "\n".join(lines) + "\n"


def _md_fence(text: str, lang: str = "") -> str:
    body = str(text or "").replace("\r\n", "\n").rstrip()
    ticks = "```"
    while ticks in body:
        ticks += "`"
    label = lang if lang and lang != "other" else ""
    return f"{ticks}{label}\n{body}\n{ticks}"


def render_sarif(result: ScanResult) -> str:
    rules: dict[str, dict[str, object]] = {}
    results = []
    for finding in result.findings:
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.message},
                "help": {"text": finding.remediation},
                "properties": {"cwe": finding.cwe, "category": finding.category.value},
                "defaultConfiguration": {"level": SARIF_LEVEL[finding.severity]},
            }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": f"{finding.message} 加固：{finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path.replace("\\", "/")},
                            "region": {"startLine": max(finding.line, 1), "snippet": {"text": finding.snippet}},
                        }
                    }
                ],
            }
        )
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DeepOpen",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_html(result: ScanResult) -> str:
    rows = "".join(_html_row(item) for item in result.findings)
    counts = result.counts_by_severity
    cards = "".join(
        f'<div class="card {name}"><div class="n">{count}</div><div class="l">{name}</div></div>'
        for name, count in counts.items()
    )
    empty = ""
    if not result.findings:
        empty = "<p class='empty'>未发现规则命中。请把本工具当作辅助检查，而不是安全证明。</p>"
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>DeepOpen 检查报告</title>
  <style>
    :root {{ font-family: "Segoe UI", sans-serif; background: #0b1220; color: #e7ecf3; }}
    body {{ margin: 0; padding: 32px; }}
    h1 {{ margin: 0 0 8px; font-size: 28px; }}
    .meta {{ color: #9aa7b8; margin-bottom: 24px; }}
    .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
    .card {{ background: #121b2b; border-radius: 12px; padding: 16px 20px; min-width: 110px; border: 1px solid #223049; }}
    .card .n {{ font-size: 28px; font-weight: 700; }}
    .card .l {{ color: #9aa7b8; text-transform: uppercase; font-size: 12px; }}
    .critical .n {{ color: #e879f9; }}
    .high .n {{ color: #fb7185; }}
    .medium .n {{ color: #fbbf24; }}
    .low .n {{ color: #38bdf8; }}
    table {{ width: 100%; border-collapse: collapse; background: #121b2b; border-radius: 12px; overflow: hidden; }}
    th, td {{ text-align: left; padding: 12px 14px; vertical-align: top; border-bottom: 1px solid #223049; }}
    th {{ color: #9aa7b8; font-size: 12px; letter-spacing: .04em; }}
    code {{ background: #0b1220; padding: 2px 6px; border-radius: 6px; }}
    .sev {{ font-weight: 700; text-transform: uppercase; font-size: 12px; }}
    .empty {{ color: #9aa7b8; }}
  </style>
</head>
<body>
  <h1>DeepOpen 代码检查报告</h1>
  <p class="meta">DeepOpen {__version__} · 目录 {html.escape(str(result.root))} · 文件 {result.files_scanned} · 命中 {len(result.findings)} · {result.duration_ms}ms</p>
  <div class="cards">{cards}</div>
  {empty}
  <table>
    <thead>
      <tr><th>级别</th><th>规则</th><th>位置</th><th>说明与加固</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
"""


def _html_row(finding: Finding) -> str:
    loc = html.escape(f"{finding.path}:{finding.line}")
    return (
        "<tr>"
        f"<td class='sev {html.escape(finding.severity.value)}'>{html.escape(finding.severity.value)}</td>"
        f"<td>{html.escape(finding.rule_id)}<br>{html.escape(finding.title)}</td>"
        f"<td>{loc}<br><code>{html.escape(finding.snippet)}</code></td>"
        f"<td>{html.escape(finding.message)}<br><strong>加固：</strong>{html.escape(finding.remediation)}</td>"
        "</tr>"
    )


def write_report(result: ScanResult, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    suffix = output.suffix.lower()
    if suffix == ".json":
        body = render_json(result)
    elif suffix == ".sarif":
        body = render_sarif(result)
    elif suffix in {".html", ".htm"}:
        body = render_html(result)
    elif suffix in {".md", ".markdown"}:
        body = render_markdown(result)
    else:
        body = render_text(result, color=False)
    output.write_text(body, encoding="utf-8")


def exit_code(result: ScanResult, fail_on: str) -> int:
    threshold = {
        "critical": {Severity.CRITICAL},
        "high": {Severity.CRITICAL, Severity.HIGH},
        "medium": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM},
        "low": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW},
        "info": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO},
        "never": set(),
    }[fail_on]
    return 1 if any(item.severity in threshold for item in result.findings) else 0
