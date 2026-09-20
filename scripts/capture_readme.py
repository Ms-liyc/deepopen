"""Generate README screenshots from a real DeepOpen scan of examples/."""

from __future__ import annotations

import html
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
EDGE_CANDIDATES = [
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft/Edge/Application/msedge.exe",
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Google/Chrome/Application/chrome.exe",
]


def _esc(value: object) -> str:
    return html.escape(str(value or ""))


def _find_browser() -> Path:
    for path in EDGE_CANDIDATES:
        if path.is_file():
            return path
    raise FileNotFoundError("未找到 Edge / Chrome，无法截屏")


def _screenshot(browser: Path, page: Path, dest: Path, width: int, height: int) -> None:
    profile = OUT / ".edge-profile"
    profile.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(browser),
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--no-first-run",
        "--no-default-browser-check",
        f"--user-data-dir={profile}",
        f"--window-size={width},{height}",
        f"--screenshot={dest}",
        page.resolve().as_uri(),
    ]
    subprocess.run(cmd, check=True, cwd=OUT)
    if not dest.is_file():
        fallback = Path.cwd() / "screenshot.png"
        if fallback.is_file():
            fallback.replace(dest)


def _write_cli(text: str) -> Path:
    lines = []
    for raw in text.splitlines()[:28]:
        escaped = _esc(raw)
        css = ""
        if raw.startswith("[HIGH]"):
            css = "high"
        elif raw.startswith("[MEDIUM]"):
            css = "med"
        elif raw.startswith("[LOW]"):
            css = "low"
        elif raw.startswith("扫描") or raw.startswith("已检查") or raw.startswith("问题"):
            css = "meta"
        lines.append(f'<div class="ln {css}">{escaped if escaped else "&nbsp;"}</div>')
    page = OUT / "_cli.html"
    page.write_text(
        f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><style>
html,body {{ margin:0; background:#071018; }}
.win {{ margin:24px; border:1px solid #2a3b55; border-radius:14px; overflow:hidden;
  box-shadow: 0 18px 50px rgba(0,0,0,.45); }}
.bar {{ background:#122033; padding:10px 14px; display:flex; align-items:center; gap:8px; }}
.dot {{ width:10px; height:10px; border-radius:50%; }}
.r {{ background:#ff6b7a; }} .y {{ background:#f3c15a; }} .g {{ background:#3ee0b2; }}
.title {{ color:#8ea0b8; font:12px/1.4 Segoe UI,sans-serif; margin-left:8px; }}
pre {{ margin:0; padding:16px 18px 20px; background:#08111d; color:#d7e7ff;
  font:13px/1.55 Consolas, Cascadia Code, monospace; }}
.ln {{ white-space:pre; }}
.high {{ color:#ff6b7a; font-weight:700; }}
.med {{ color:#f3c15a; font-weight:700; }}
.low {{ color:#5ec8ff; }}
.meta {{ color:#8ea0b8; }}
</style></head><body>
<div class="win">
  <div class="bar"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
    <span class="title">powershell · python -m deepopen scan examples</span></div>
  <pre>{''.join(lines)}
<div class="ln meta">… 其余命中已省略</div></pre>
</div>
</body></html>""",
        encoding="utf-8",
    )
    return page


def _write_console(result: dict, version: str, rule_count: int) -> Path:
    findings = result["findings"][:8]
    counts = result["counts"]
    selected = next((item for item in findings if item["rule_id"] == "AST001"), findings[0])
    cards = "".join(
        f'<div class="stat {name}"><b>{counts.get(name, 0)}</b><span>{name}</span></div>'
        for name in ("critical", "high", "medium", "low", "info")
    )
    rows = []
    for item in findings:
        klass = " selected" if item is selected else ""
        rows.append(
            "<tr class='"
            + klass
            + "'><td class='sev "
            + _esc(item["severity"])
            + "'>"
            + _esc(item["severity"])
            + "</td><td>"
            + _esc(item["rule_id"])
            + "<br>"
            + _esc(item["title"])
            + "</td><td>"
            + _esc(item["path"])
            + ":"
            + str(item["line"])
            + "<br><code>"
            + _esc(item["snippet"])
            + "</code></td></tr>"
        )
    page = OUT / "_console.html"
    page.write_text(
        f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><style>
:root {{ --bg:#08111d; --panel:#0f1a2a; --line:#24344c; --text:#e8eef7; --muted:#8ea0b8;
  --mint:#3ee0b2; --gold:#f3c15a; --coral:#ff6b7a; --violet:#c084fc; --sky:#5ec8ff; }}
html,body {{ margin:0; height:100%; background:var(--bg); color:var(--text);
  font-family:"Segoe UI","Microsoft YaHei",sans-serif; }}
.app {{ display:grid; grid-template-columns:280px 1fr; min-height:100%; }}
aside {{ border-right:1px solid var(--line); background:rgba(15,26,42,.92); padding:22px 18px; }}
.brand {{ display:flex; gap:12px; align-items:center; margin-bottom:18px; }}
.mark {{ width:36px; height:36px; border-radius:10px; background:linear-gradient(135deg,var(--mint),#1a8f8a);
  color:#062019; display:grid; place-items:center; font-weight:800; }}
h1 {{ font-size:16px; margin:0; }} .sub {{ color:var(--muted); font-size:12px; margin-top:2px; }}
label {{ font-size:12px; color:var(--muted); display:block; margin:12px 0 6px; }}
.box {{ background:var(--bg); border:1px solid var(--line); border-radius:10px; padding:10px 12px; font-size:13px; }}
button {{ border:0; border-radius:10px; padding:10px 12px; font-weight:700; background:var(--mint); color:#062019; width:100%; margin-top:12px; }}
.ghost {{ background:transparent; color:var(--text); border:1px solid var(--line); margin-top:8px; }}
.hint {{ color:var(--muted); font-size:12px; margin-top:14px; line-height:1.5; }}
main {{ padding:22px 26px; }}
.stats {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin-bottom:16px; }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:14px; }}
.stat b {{ display:block; font-size:26px; }} .stat span {{ color:var(--muted); font-size:12px; text-transform:uppercase; }}
.stat.high b {{ color:var(--coral); }} .stat.medium b {{ color:var(--gold); }}
.stat.low b {{ color:var(--sky); }} .stat.info b {{ color:var(--muted); }} .stat.critical b {{ color:var(--violet); }}
.layout {{ display:grid; grid-template-columns:1.15fr .85fr; gap:16px; }}
.list,.detail {{ background:var(--panel); border:1px solid var(--line); border-radius:16px; overflow:hidden; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ text-align:left; color:var(--muted); font-size:11px; padding:10px 12px; }}
td {{ padding:10px 12px; border-top:1px solid var(--line); vertical-align:top; }}
tr.selected td {{ background:#173047; }}
.sev {{ font-family:Consolas,monospace; font-size:11px; font-weight:700; text-transform:uppercase; }}
.sev.high {{ color:var(--coral); }} .sev.medium {{ color:var(--gold); }} .sev.low {{ color:var(--sky); }}
code {{ font-family:Consolas,monospace; font-size:12px; color:#d7e7ff; }}
.detail {{ padding:18px; }}
.detail h2 {{ margin:8px 0; font-size:18px; }}
.detail p {{ color:#c9d6e8; line-height:1.55; }}
.badge {{ display:inline-block; border:1px solid var(--line); border-radius:999px; padding:2px 8px; font-size:11px; color:var(--muted); }}
</style></head><body>
<div class="app">
  <aside>
    <div class="brand"><div class="mark">DO</div><div><h1>DeepOpen</h1>
      <div class="sub">v{_esc(version)} · {rule_count} 条规则</div></div></div>
    <label>扫描路径</label><div class="box">examples</div>
    <label>配置档</label><div class="box">all · 全部规则</div>
    <button>开始检查</button>
    <button class="ghost">导出 HTML</button>
    <p class="hint">文件 {result["files_scanned"]} · 命中 {result["finding_count"]} · {result["duration_ms"]}ms<br>只监听本机 127.0.0.1</p>
  </aside>
  <main>
    <div class="stats">{cards}</div>
    <div class="layout">
      <div class="list"><table><thead><tr><th>级别</th><th>规则</th><th>位置</th></tr></thead>
      <tbody>{''.join(rows)}</tbody></table></div>
      <div class="detail">
        <div class="sev {_esc(selected['severity'])}">{_esc(selected['severity'])} · {_esc(selected['category'])}</div>
        <h2>{_esc(selected['rule_id'])} {_esc(selected['title'])}</h2>
        <p><span class="badge">{_esc(selected.get('language') or 'python')}</span>
           {_esc(selected['cwe']) if selected.get('cwe') else ''}</p>
        <p><code>{_esc(selected['path'])}:{selected['line']}</code></p>
        <p><code>{_esc(selected['snippet'])}</code></p>
        <p>{_esc(selected['message'])}</p>
        <p><strong>加固建议</strong><br>{_esc(selected['remediation'])}</p>
      </div>
    </div>
  </main>
</div>
</body></html>""",
        encoding="utf-8",
    )
    return page


def _write_guide(sections: list[dict], version: str, rule_count: int) -> Path:
    blocks = []
    for section in sections[:4]:
        items = "".join(f"<li>{_esc(item)}</li>" for item in section["items"])
        blocks.append(
            f'<div class="panel"><h3>{_esc(section["title"])}</h3><ul>{items}</ul></div>'
        )
    page = OUT / "_guide.html"
    page.write_text(
        f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><style>
html,body {{ margin:0; background:#08111d; color:#e8eef7; font-family:"Segoe UI","Microsoft YaHei",sans-serif; }}
.app {{ display:grid; grid-template-columns:280px 1fr; min-height:100%; }}
aside {{ border-right:1px solid #24344c; padding:22px 18px; background:#0f1a2a; }}
.brand {{ display:flex; gap:12px; align-items:center; }}
.mark {{ width:36px; height:36px; border-radius:10px; background:linear-gradient(135deg,#3ee0b2,#1a8f8a);
  color:#062019; display:grid; place-items:center; font-weight:800; }}
.tabs {{ display:flex; gap:6px; margin:18px 0; }}
.tab {{ flex:1; text-align:center; border:1px solid #3ee0b2; color:#3ee0b2; border-radius:10px; padding:8px; font-size:12px; }}
.idle {{ border-color:#24344c; color:#e8eef7; }}
main {{ padding:22px 26px; }}
.panel {{ background:#0f1a2a; border:1px solid #24344c; border-radius:16px; padding:16px 18px; margin-bottom:12px; }}
h3 {{ margin:0 0 8px; font-size:15px; }} ul {{ margin:0; padding-left:18px; color:#c9d6e8; line-height:1.6; }}
h1 {{ font-size:16px; margin:0; }} .sub {{ color:#8ea0b8; font-size:12px; }}
</style></head><body>
<div class="app">
  <aside>
    <div class="brand"><div class="mark">DO</div><div><h1>DeepOpen</h1>
      <div class="sub">v{_esc(version)} · {rule_count} 条规则</div></div></div>
    <div class="tabs"><div class="tab idle">扫描</div><div class="tab idle">规则</div><div class="tab">清单</div></div>
  </aside>
  <main>{''.join(blocks)}</main>
</div>
</body></html>""",
        encoding="utf-8",
    )
    return page


def main() -> int:
    sys.path.insert(0, str(ROOT))
    from deepopen.catalog import all_rule_records
    from deepopen.checklist import CHECKLIST_SECTIONS
    from deepopen.report import render_html, render_json, render_text
    from deepopen.scanner import scan_path
    from deepopen.version import __version__

    OUT.mkdir(parents=True, exist_ok=True)
    result = scan_path(ROOT / "examples")
    payload = json.loads(render_json(result))
    rule_count = len(all_rule_records())
    cli_text = render_text(result, color=False)
    (OUT / "report.html").write_text(render_html(result), encoding="utf-8")

    browser = _find_browser()
    cli_page = _write_cli(cli_text)
    console_page = _write_console(payload, __version__, rule_count)
    guide_page = _write_guide(CHECKLIST_SECTIONS, __version__, rule_count)
    _screenshot(browser, cli_page, OUT / "cli.png", 1100, 720)
    _screenshot(browser, console_page, OUT / "console.png", 1440, 860)
    _screenshot(browser, OUT / "report.html", OUT / "report.png", 1400, 900)
    _screenshot(browser, guide_page, OUT / "checklist.png", 1440, 860)
    print("wrote", OUT)
    for name in ("cli.png", "console.png", "report.png", "checklist.png"):
        path = OUT / name
        print(f"  {name}: {path.stat().st_size if path.is_file() else 'MISSING'} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
