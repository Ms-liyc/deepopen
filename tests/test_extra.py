from pathlib import Path

from deepopen.cli import main
from deepopen.config import Config
from deepopen.report import render_markdown, render_sarif, write_report
from deepopen.scanner import scan_path, scan_text


def test_javascript_bundle() -> None:
    source = """
function render(userInput) {
  document.getElementById("x").innerHTML = userInput;
  eval("mark(" + userInput + ")");
  window.open("javascript:void(0)");
  localStorage.setItem("authToken", userInput);
  otherWindow.postMessage(userInput, "*");
}
"""
    ids = {item.rule_id for item in scan_text(Path("insecure.js"), source)}
    assert "JS001" in ids
    assert "JS002" in ids
    assert "JS005" in ids
    assert "JS007" in ids
    assert "JS009" in ids


def test_safe_javascript() -> None:
    source = """
function render(userInput) {
  document.getElementById("x").textContent = userInput;
}
"""
    assert scan_text(Path("safe.js"), source) == []


def test_dockerfile_and_java_go() -> None:
    docker_ids = {
        item.rule_id
        for item in scan_text(
            Path("Dockerfile"),
            "FROM python:3.12\nADD http://example.com/payload.tar.gz /tmp/app.tar.gz\nUSER root\nRUN chmod 777 /tmp\n",
        )
    }
    assert "DK001" in docker_ids or "DK004" in docker_ids
    assert "DK003" in docker_ids

    java_ids = {
        item.rule_id
        for item in scan_text(
            Path("Demo.java"),
            "class Demo {\n    void run(String name) {\n"
            '        Runtime.getRuntime().exec("cmd /c echo " + name);\n'
            "        java.util.Random random = new java.util.Random();\n"
            "        java.io.ObjectInputStream in = new java.io.ObjectInputStream(System.in);\n"
            "    }\n}\n",
        )
    }
    assert "JV001" in java_ids
    assert "JV005" in java_ids

    go_ids = {
        item.rule_id
        for item in scan_text(
            Path("main.go"),
            'package main\nimport ("crypto/tls"; "fmt"; "os/exec")\n'
            "func main() {\n"
            '        exec.Command("sh", "-c", "echo hi")\n'
            "        _ = tls.Config{InsecureSkipVerify: true}\n"
            '        query := fmt.Sprintf("SELECT * FROM users WHERE name = \'%s\'", "x")\n'
            "        fmt.Println(query)\n}\n",
        )
    }
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


def test_markdown_fix_plan(tmp_path: Path) -> None:
    sample = tmp_path / "bad.py"
    sample.write_text("eval(user_input)\nPASSWORD = \"supersecret-demo-key\"\n", encoding="utf-8")
    result = scan_path(sample)
    body = render_markdown(result)
    assert "缺陷修改方案" in body
    assert "**修改方案**" in body
    assert "问题:" in body
    assert "eval" in body.lower() or "AST001" in body or "PY001" in body
    md_path = tmp_path / "out" / "plan.md"
    write_report(result, md_path)
    assert "修改清单" in md_path.read_text(encoding="utf-8")


def test_sarif_and_html_report(tmp_path: Path) -> None:
    sample = tmp_path / "bad.py"
    sample.write_text("eval(user_input)\nPASSWORD = \"supersecret-demo-key\"\n", encoding="utf-8")
    result = scan_path(sample)
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
