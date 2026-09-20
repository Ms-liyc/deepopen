from pathlib import Path

from deepopen.checklist import CHECKLIST, CHECKLIST_SECTIONS
from deepopen.scanner import scan_text


def test_python_bug_details() -> None:
    source = """
from os import *
import pdb

class Box:
    items = []

def demo(flag):
    pdb.set_trace()
    if type(flag) == int:
        return flag == True
    try:
        open("x.txt")
    except Exception as err:
        raise err
    if 0.1 + 0.2 == 0.3:
        return {"a": 1, "a": 2}
"""
    ids = {item.rule_id for item in scan_text(Path("bugs.py"), source)}
    assert "BUG008" in ids or "AST040" in ids
    assert "BUG009" in ids
    assert "AST033" in ids
    assert "AST035" in ids or "BUG010" in ids
    assert "AST036" in ids
    assert "AST037" in ids
    assert "AST038" in ids or "BUG005" in ids
    assert "AST039" in ids
    assert "AST043" in ids or "BUG011" in ids


def test_python_bug_details_extended() -> None:
    source = """
a = b = []
list = []

def worker(items):
    for item in items:
        try:
            item / 0
        except Exception:
            continue
        if not items == []:
            return None
            dead = 1
        if flag is True:
            return flag

class Point:
    def __eq__(self, other):
        return True
    def __eq__(self, other):
        return False

class Lock:
    def __enter__(self):
        return self

async def fetch():
    import time
    time.sleep(1)

def boom(n):
    return n / 0
"""
    ids = {item.rule_id for item in scan_text(Path("more_bugs.py"), source)}
    assert "AST044" in ids
    assert "AST046" in ids or "BUG019" in ids
    assert "AST047" in ids
    assert "AST048" in ids
    assert "AST049" in ids
    assert "AST050" in ids or "BUG028" in ids
    assert "AST052" in ids
    assert "AST053" in ids
    assert "AST054" in ids
    assert "AST055" in ids
    assert "AST056" in ids
    assert "AST057" in ids


def test_js_eqeq_and_var() -> None:
    ids = {item.rule_id for item in scan_text(Path("app.js"), "var x = 1;\nif (x == 2) { console.log(x); }\n")}
    assert "BUG012" in ids
    assert "BUG013" in ids
    assert "BUG014" in ids


def test_js_nan_parseint_debugger() -> None:
    ids = {item.rule_id for item in scan_text(Path("app.js"), "debugger;\nparseInt(x);\nif (x == NaN) {}\n")}
    assert "BUG020" in ids
    assert "BUG021" in ids
    assert "BUG022" in ids


def test_java_string_eq() -> None:
    ids = {item.rule_id for item in scan_text(Path("A.java"), 'if (name == "root") { e.printStackTrace(); }\n')}
    assert "BUG016" in ids
    assert "BUG015" in ids


def test_go_empty_err() -> None:
    ids = {item.rule_id for item in scan_text(Path("main.go"), "if err != nil {}\n_ = err\n")}
    assert "BUG017" in ids
    assert "BUG023" in ids


def test_sql_dml_without_where() -> None:
    ids = {item.rule_id for item in scan_text(Path("a.sql"), "DELETE FROM users;\nUPDATE users SET name = 'x';\nINSERT INTO users VALUES (1);\n")}
    assert "SQL003" in ids
    assert "SQL004" in ids
    assert "SQL005" in ids


def test_c_assignment_in_if() -> None:
    ids = {item.rule_id for item in scan_text(Path("app.c"), "if (x = 1) { }\n")}
    assert "C004" in ids


def test_http_and_subprocess_timeout() -> None:
    ids = {item.rule_id for item in scan_text(Path("net.py"), "import requests\nrequests.get('https://example.com')\n")}
    assert "AST058" in ids


def test_checklist_covers_detailed_bugs() -> None:
    text = CHECKLIST
    assert "timeout" in text.lower() or "超时" in text
    assert "WHERE" in text
    assert len(CHECKLIST_SECTIONS) >= 9
    titles = " ".join(section["title"] for section in CHECKLIST_SECTIONS)
    assert "Python" in titles
    assert "空值" in titles
    assert any("isinstance" in item or "type()" in item for section in CHECKLIST_SECTIONS for item in section["items"])
