from pathlib import Path

from deepopen.cli import main
from deepopen.scanner import scan_path, scan_text

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def test_flags_insecure_python_patterns() -> None:
    result = scan_path(EXAMPLES / "insecure_patterns.py")
    rule_ids = {item.rule_id for item in result.findings}
    assert result.files_scanned == 1
    assert any(rid in rule_ids for rid in ("SEC004",))
    assert any(rid in {"AST001", "PY001"} for rid in rule_ids)
    assert any(rid in {"AST002", "PY002"} for rid in rule_ids)
    assert any(rid in {"AST003", "PY003"} for rid in rule_ids)
    assert any(rid in {"AST008", "PY008"} for rid in rule_ids)
    assert any(rid in {"AST010", "BUG001"} for rid in rule_ids)
    assert any(rid in {"AST013", "BUG002"} for rid in rule_ids)


def test_clean_python_file_has_no_findings() -> None:
    result = scan_path(EXAMPLES / "safe_patterns.py")
    assert result.findings == []


def test_javascript_innerhtml() -> None:
    findings = scan_text(Path("app.js"), "document.getElementById('x').innerHTML = userInput;")
    assert any(item.rule_id == "JS001" for item in findings)


def test_php_eval_pattern() -> None:
    findings = scan_text(Path("app.php"), "eval($code);\n")
    assert any(item.rule_id == "PHP001" for item in findings)


def test_cli_json_and_clean_exit(tmp_path: Path, capsys) -> None:
    target = tmp_path / "ok.py"
    target.write_text("x = 1\n", encoding="utf-8")
    code = main([str(target), "--format", "json", "--fail-on", "high"])
    captured = capsys.readouterr()
    assert code == 0
    assert '"findings": []' in captured.out


def test_cli_fails_on_high(tmp_path: Path) -> None:
    target = tmp_path / "bad.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    code = main([str(target), "--no-color", "--fail-on", "high"])
    assert code == 1
