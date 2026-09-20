from pathlib import Path

from deepopen.cli import main
from deepopen.config import Config
from deepopen.report import render_sarif, write_report
from deepopen.scanner import scan_path, scan_text

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def test_javascript_bundle() -> None:
    result = scan_path(EXAMPLES / "web" / "insecure.js")
    ids = {item.rule_id for item in result.findings}
    assert "JS001" in ids
    assert "JS002" in ids
    assert "JS005" in ids
    assert "JS007" in ids
    assert "JS009" in ids


def test_safe_javascript() -> None:
    result = scan_path(EXAMPLES / "web" / "safe.js")
    assert result.findings == []


def test_dockerfile_and_java_go() -> None:
    docker = scan_path(EXAMPLES / "infra" / "Dockerfile")
    docker_ids = {item.rule_id for item in docker.findings}
    assert "DK001" in docker_ids or "DK004" in docker_ids
    assert "DK003" in docker_ids

    java_ids = {item.rule_id for item in scan_path(EXAMPLES / "java" / "Demo.java").findings}
    assert "JV001" in java_ids
    assert "JV005" in java_ids

    go_ids = {item.rule_id for item in scan_path(EXAMPLES / "go" / "main.go").findings}
    assert "GO001" in go_ids
    assert "GO002" in go_ids
    assert "GO003" in go_ids


def test_placeholder_secret_ignored() -> None:
    findings = scan_text(Path("app.py"), 'PASSWORD = "CHANGE_ME"\n')
    assert findings == []


def test_inline_ignore() -> None:
    findings = scan_text(Path("app.py"), "eval(user_input)  # deepopen: ignore\n")
    assert findings == []


def test_disable_rules() -> None:
    cfg = Config(disable_rules=["AST001", "PY001"])
    findings = scan_text(Path("app.py"), "eval(user_input)\n", config=cfg)
    assert all(item.rule_id not in {"AST001", "PY001"} for item in findings)


def test_sarif_and_html_report(tmp_path: Path) -> None:
    result = scan_path(EXAMPLES / "insecure_patterns.py")
    sarif = render_sarif(result)
    assert '"version": "2.1.0"' in sarif
    assert "DeepOpen" in sarif
    html_path = tmp_path / "out" / "report.html"
    write_report(result, html_path)
    assert html_path.exists()
    assert "DeepOpen" in html_path.read_text(encoding="utf-8")


def test_cli_scan_subcommand(tmp_path: Path) -> None:
    target = tmp_path / "ok.py"
    target.write_text("value = 1\n", encoding="utf-8")
    assert main(["scan", str(target), "--fail-on", "high", "--no-color"]) == 0


def test_rules_command(capsys) -> None:
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "AST001" in out
    assert "SEC001" in out
