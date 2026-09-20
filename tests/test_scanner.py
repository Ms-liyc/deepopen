from pathlib import Path

from deepopen.cli import main
from deepopen.scanner import scan_path, scan_text

INSECURE_PY = '''
import os
import pickle
import sqlite3

PASSWORD = "supersecret-demo-key"
API_KEY = "abcdefghijklmnopqrstuvwxyz"

def load_user(raw):
    return pickle.loads(raw)

def run_query(name):
    conn = sqlite3.connect(":memory:")
    conn.execute(f"SELECT * FROM users WHERE name = '{name}'")

def run_cmd(arg):
    os.system("echo " + arg)

def parse_number(text):
    return eval(text)

def add_item(items=[]):
    items.append(1)
    return items

def silent():
    try:
        parse_number("1")
    except:
        pass

def is_none(value):
    return value == None
'''

SAFE_PY = '''
from __future__ import annotations
import json
import sqlite3
from pathlib import Path

def load_config(raw: str) -> dict:
    return json.loads(raw)

def run_query(conn: sqlite3.Connection, name: str) -> list[tuple]:
    cur = conn.execute("SELECT id, name FROM users WHERE name = ?", (name,))
    return list(cur.fetchall())

def add_item(items: list[int] | None = None) -> list[int]:
    if items is None:
        items = []
    items.append(1)
    return items

def maybe_value(value: object) -> bool:
    return value is None

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"cannot read {path}") from exc
'''


def test_flags_insecure_python_patterns(tmp_path: Path) -> None:
    target = tmp_path / "insecure_patterns.py"
    target.write_text(INSECURE_PY, encoding="utf-8")
    result = scan_path(target)
    rule_ids = {item.rule_id for item in result.findings}
    assert result.files_scanned == 1
    assert any(rid in rule_ids for rid in ("SEC004",))
    assert any(rid in {"AST001", "PY001"} for rid in rule_ids)
    assert any(rid in {"AST002", "PY002"} for rid in rule_ids)
    assert any(rid in {"AST003", "PY003"} for rid in rule_ids)
    assert any(rid in {"AST008", "PY008"} for rid in rule_ids)
    assert any(rid in {"AST010", "BUG001"} for rid in rule_ids)
    assert any(rid in {"AST013", "BUG002"} for rid in rule_ids)


def test_clean_python_file_has_no_findings(tmp_path: Path) -> None:
    target = tmp_path / "safe_patterns.py"
    target.write_text(SAFE_PY, encoding="utf-8")
    result = scan_path(target)
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
