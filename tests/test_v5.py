from pathlib import Path

from deepopen.catalog import all_rule_records, explain_rule
from deepopen.scanner import scan_text


def test_new_python_ast_rules() -> None:
    source = """
import argparse
import ctypes
import ftplib
import http.client
import os
import socket
import tarfile
import zipfile
import xmlrpc.client

tarfile.open('a.tar').extractall('out')
zipfile.ZipFile('a.zip').extract('x')
argparse.ArgumentParser().add_argument('--x', type=eval)
os.umask(0)
ctypes.CDLL('lib' + name)
ftplib.FTP('example.com')
xmlrpc.client.ServerProxy('http://127.0.0.1:8000')
socket.create_connection(('127.0.0.1', 80))
http.client.HTTPConnection('example.com')
"""
    ids = {item.rule_id for item in scan_text(Path("extra.py"), source)}
    assert "AST060" in ids
    assert "AST061" in ids
    assert "AST062" in ids
    assert "AST063" in ids
    assert "AST064" in ids
    assert "AST065" in ids
    assert "AST066" in ids
    assert "AST067" in ids
    assert "AST068" in ids


def test_new_language_pattern_rules() -> None:
    js = scan_text(Path("app.js"), "setTimeout('go()', 1);\nel.insertAdjacentHTML('beforeend', x);\nbox.innerHTML += y;\n$('#a').html(x);\ndebugger;\n")
    js_ids = {item.rule_id for item in js}
    assert "JS014" in js_ids
    assert "JS015" in js_ids
    assert "JS016" in js_ids
    assert "JS017" in js_ids
    assert "BUG030" in js_ids

    go_ids = {item.rule_id for item in scan_text(Path("main.go"), 'http.ListenAndServe(":80", nil)\ntemplate.HTML(x)\nos.Chmod("f", 0777)\n')}
    assert "GO006" in go_ids
    assert "GO007" in go_ids
    assert "GO008" in go_ids

    java_ids = {item.rule_id for item in scan_text(Path("A.java"), 'engine.eval("x");\nresponse.addHeader("Access-Control-Allow-Origin", "*");\ne.printStackTrace();\n')}
    assert "JV007" in java_ids
    assert "JV008" in java_ids
    assert "JV009" in java_ids

    php_ids = {item.rule_id for item in scan_text(Path("a.php"), 'header("Location: " . $_GET["n"]);\necho $_GET["q"];\npreg_replace("/x/e", $y, $z);\n')}
    assert "PHP007" in php_ids
    assert "PHP008" in php_ids
    assert "PHP009" in php_ids

    rb_ids = {item.rule_id for item in scan_text(Path("a.rb"), "html_safe(x)\nredirect_to params[:url]\n")}
    assert "RB004" in rb_ids
    assert "RB005" in rb_ids

    cs_ids = {item.rule_id for item in scan_text(Path("A.cs"), "MD5.Create();\nhandler.ServerCertificateCustomValidationCallback = cb;\n")}
    assert "CS005" in cs_ids
    assert "CS006" in cs_ids

    c_ids = {item.rule_id for item in scan_text(Path("a.c"), 'printf(buf);\nscanf("%s", buf);\nalloca(n);\n')}
    assert "C005" in c_ids
    assert "C006" in c_ids
    assert "C007" in c_ids

    rs_ids = {item.rule_id for item in scan_text(Path("a.rs"), "unsafe { x }\nfs::Permissions::from_mode(0o777)\n")}
    assert "RS004" in rs_ids
    assert "RS005" in rs_ids

    sql_ids = {item.rule_id for item in scan_text(Path("a.sql"), "DROP TABLE users;\n")}
    assert "SQL006" in sql_ids


def test_new_infra_web_secret_rules() -> None:
    sh_ids = {item.rule_id for item in scan_text(Path("a.sh"), 'eval "$cmd"\n')}
    assert "SH004" in sh_ids
    tf_ids = {item.rule_id for item in scan_text(Path("a.tf"), 'cidr_blocks = ["0.0.0.0/0"]\n')}
    assert "TF002" in tf_ids
    k8s_ids = {item.rule_id for item in scan_text(Path("pod.yaml"), "capabilities:\n  add: [SYS_ADMIN]\n")}
    assert "K8S005" in k8s_ids
    py_ids = {item.rule_id for item in scan_text(Path("settings.py"), "SESSION_COOKIE_HTTPONLY = False\nX_FRAME_OPTIONS = 'OFF'\nprint(password)\nfor x in items: pass\n")}
    assert "PY021" in py_ids
    assert "PY022" in py_ids
    assert "BUG029" in py_ids
    assert "BUG031" in py_ids
    html_ids = {item.rule_id for item in scan_text(Path("a.html"), '<input type="password" autocomplete="on">\n')}
    assert "WEB005" in html_ids
    sec_ids = {item.rule_id for item in scan_text(Path("a.env"), "GLPAT=glpat-" + ("a" * 22) + "\nHF=hf_" + ("b" * 22) + "\nANT=sk-ant-" + ("c" * 22) + "\n")}
    assert "SEC014" in sec_ids
    assert "SEC015" in sec_ids
    assert "SEC016" in sec_ids


def test_new_rules_are_catalogued() -> None:
    ids = {str(item["rule_id"]) for item in all_rule_records()}
    for rule_id in ("AST060", "JS014", "GO006", "JV007", "PHP007", "C005", "SEC014", "WEB005", "K8S005"):
        assert rule_id in ids
        assert explain_rule(rule_id) is not None
