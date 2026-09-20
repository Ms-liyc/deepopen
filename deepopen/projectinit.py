"""Create config files and optional CI workflow."""

from __future__ import annotations

from pathlib import Path

TOML_TEMPLATE = """# DeepOpen 配置
fail_on = "high"
min_severity = "info"
profile = "all"
exclude = ["node_modules", "dist", "build", "vendor"]
disable_rules = []
hide_baseline = true

# 自定义规则（id 必须以 CUSTOM / TEAM / ORG / LOCAL 开头）
# [[rules]]
# id = "TEAM001"
# title = "禁止提交调试 print"
# pattern = "\\\\bprint\\\\s*\\\\("
# severity = "low"
# category = "quality"
# suffixes = [".py"]
# message = "使用日志库代替 print"
# remediation = "改用 logging"
"""

IGNORE_TEMPLATE = """# 每行一个 gitignore 风格路径
reports/
.pytest_cache/
"""

WORKFLOW_TEMPLATE = """name: DeepOpen
on:
  push:
  pull_request:
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install DeepOpen
        run: pip install .
      - name: Scan
        run: python -m deepopen scan . --fail-on high -o deepopen.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: deepopen.sarif
          wait-for-processing: false
"""


def init_project(root: Path, with_ci: bool = False) -> list[Path]:
    root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    toml_path = root / "deepopen.toml"
    if not toml_path.exists():
        toml_path.write_text(TOML_TEMPLATE, encoding="utf-8")
        written.append(toml_path)
    ignore_path = root / ".deepopenignore"
    if not ignore_path.exists():
        ignore_path.write_text(IGNORE_TEMPLATE, encoding="utf-8")
        written.append(ignore_path)
    if with_ci:
        workflow = root / ".github" / "workflows" / "deepopen.yml"
        if not workflow.exists():
            workflow.parent.mkdir(parents=True, exist_ok=True)
            workflow.write_text(WORKFLOW_TEMPLATE, encoding="utf-8")
            written.append(workflow)
    return written
