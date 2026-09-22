from pathlib import Path

from deepopen.catalog import all_rule_records, explain_rule
from deepopen.scanner import scan_text


def test_new_python_ast_batch() -> None:
    source = """
import hashlib
import importlib
import pickle
import random
import shutil
import smtplib
import ssl
import subprocess
import urllib3
import xml.etree.ElementTree as ET

ET.fromstring(blob)
redirect(request.args.get("next"))
shutil.rmtree(base + "/tmp")
pickle.Unpickler(raw)
importlib.import_module(name)
random.seed(1)
subprocess.Popen(["echo", "hi"])
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
pandas.read_pickle("model.pkl")
numpy.load("a.npy", allow_pickle=True)
smtplib.SMTP("mail.example.com")
set_missing_host_key_policy(paramiko.AutoAddPolicy())
urllib3.disable_warnings()
hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 1000)
jinja2.Environment(autoescape=False)
"""
    ids = {item.rule_id for item in scan_text(Path("batch.py"), source)}
    for rule_id in (
        "AST070",
        "AST071",
        "AST072",
        "AST073",
        "AST074",
        "AST075",
        "AST076",
        "AST077",
        "AST078",
        "AST079",
        "AST080",
        "AST081",
        "AST082",
        "AST083",
    ):
        assert rule_id in ids, rule_id


def test_new_language_rules() -> None:
    py_ids = {
        item.rule_id
        for item in scan_text(
            Path("cfg.py"),
            "kind = yaml.UnsafeLoader\n"
            "password = input('pw')\n"
            "opts = dict(allow_pickle=True)\n"
            "if len(items) == 0:\n    pass\n"
            "dsn = 'sslmode=disable'\n",
        )
    }
    assert "PY023" in py_ids
    assert "PY026" in py_ids
    assert "PY027" in py_ids
    assert "BUG032" in py_ids
    assert "CFG008" in py_ids

    js_ids = {
        item.rule_id
        for item in scan_text(
            Path("app.js"),
            "vm.runInNewContext(code);\n"
            "crypto.createCipher('aes192', key);\n"
            "res.redirect(req.query.next);\n"
            "buf = new Buffer(8);\n"
            "cors({ origin: '*' });\n"
            "try { go(); } catch (e) {}\n",
        )
    }
    assert "JS018" in js_ids
    assert "JS019" in js_ids
    assert "JS020" in js_ids
    assert "JS021" in js_ids
    assert "JS022" in js_ids
    assert "BUG033" in js_ids

    go_ids = {item.rule_id for item in scan_text(Path("main.go"), 'http.Get(url)\nio.ReadAll(resp.Body)\n')}
    assert "GO009" in go_ids
    assert "GO010" in go_ids

    java_ids = {
        item.rule_id
        for item in scan_text(
            Path("A.java"),
            'new XMLDecoder(in);\nnew IvParameterSpec(new byte[16]);\ncookie.setSecure(false);\n',
        )
    }
    assert "JV010" in java_ids
    assert "JV011" in java_ids
    assert "JV012" in java_ids

    php_ids = {
        item.rule_id
        for item in scan_text(Path("a.php"), 'md5($_POST["password"]);\ncreate_function("", $c);\nfile_get_contents($_GET["u"]);\n')
    }
    assert "PHP010" in php_ids
    assert "PHP011" in php_ids
    assert "PHP012" in php_ids

    assert any(item.rule_id == "CS007" for item in scan_text(Path("A.cs"), "TypeNameHandling.Auto\n"))
    assert any(item.rule_id == "RB006" for item in scan_text(Path("a.rb"), "name.constantize\n"))
    assert any(
        item.rule_id == "RS006"
        for item in scan_text(Path("a.rs"), "danger_accept_invalid_certs(true)\n")
    )
    sql = scan_text(Path("a.sql"), "LOAD DATA INFILE '/tmp/a.csv' INTO TABLE t;\nEXEC xp_cmdshell 'dir';\nSELECT 1 INTO OUTFILE '/tmp/a';\n")
    sql_ids = {item.rule_id for item in sql}
    assert "SQL007" in sql_ids
    assert "SQL008" in sql_ids
    assert "SQL009" in sql_ids
    assert any(item.rule_id == "C008" for item in scan_text(Path("a.c"), "tmpnam(buf);\n"))
    assert any(item.rule_id == "DK006" for item in scan_text(Path("Dockerfile"), "RUN curl https://example.com/i.sh | sh\n"))
    assert any(item.rule_id == "K8S006" for item in scan_text(Path("pod.yaml"), "readOnlyRootFilesystem: false\n"))
    assert any(item.rule_id == "TF003" for item in scan_text(Path("a.tf"), "publicly_accessible = true\n"))
    assert any(item.rule_id == "SEC017" for item in scan_text(Path("k.env"), "OPENAI=sk-proj-" + ("a" * 24) + "\n"))
    assert any(item.rule_id == "SEC018" for item in scan_text(Path("k.env"), "PYPI=pypi-" + ("b" * 24) + "\n"))
    html_ids = {item.rule_id for item in scan_text(Path("a.html"), '<iframe src="https://example.com/embed"></iframe>\n')}
    assert "WEB006" in html_ids


def test_v7_rules_are_catalogued() -> None:
    ids = {str(item["rule_id"]) for item in all_rule_records()}
    for rule_id in ("AST070", "AST083", "PY023", "JS018", "GO009", "SQL008", "SEC017", "WEB006"):
        assert rule_id in ids
        assert explain_rule(rule_id) is not None
