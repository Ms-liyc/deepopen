from pathlib import Path

from deepopen.baseline import apply_baseline, save_baseline
from deepopen.catalog import explain_rule
from deepopen.cli import main
from deepopen.fixers import apply_fixes, fix_line
from deepopen.scanner import scan_path, scan_text


def test_c_and_rust_rules() -> None:
    c_ids = {item.rule_id for item in scan_text(Path("app.c"), "gets(buf);\nstrcpy(a, b);\n")}
    assert "C001" in c_ids
    assert "C002" in c_ids
    rust_ids = {item.rule_id for item in scan_text(Path("app.rs"), 'Command::new("sh")\n')}
    assert "RS001" in rust_ids


def test_django_allowed_hosts() -> None:
    ids = {item.rule_id for item in scan_text(Path("settings.py"), "ALLOWED_HOSTS = ['*']\n")}
    assert "PY016" in ids


def test_fix_none_comparison() -> None:
    assert "is None" in (fix_line("AST009", "    if value == None:\n") or "")
    assert fix_line("AST010", "except:\n") == "except Exception:\n"


def test_apply_fix_writes(tmp_path: Path) -> None:
    target = tmp_path / "sample.py"
    target.write_text("def ok(value):\n    return value == None\n", encoding="utf-8")
    result = scan_path(target)
    changes = apply_fixes(tmp_path, result.findings, dry_run=False)
    assert changes
    assert "is None" in target.read_text(encoding="utf-8")


def test_baseline_hides_findings(tmp_path: Path) -> None:
    target = tmp_path / "bad.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    first = scan_path(target)
    assert first.findings
    save_baseline(tmp_path, first.findings)
    hidden = scan_path(target, hide_baseline=True)
    shown = scan_path(target, hide_baseline=False)
    assert hidden.findings == []
    assert hidden.baselined_count >= 1
    marked = apply_baseline(first.findings, tmp_path, hide=False)
    assert marked[1] >= 1
    assert all(item.baselined for item in marked[0])


def test_explain_and_fix_cli(capsys, tmp_path: Path) -> None:
    assert main(["explain", "AST001"]) == 0
    assert "eval" in capsys.readouterr().out.lower()
    sample = tmp_path / "x.py"
    sample.write_text("x == None\n", encoding="utf-8")
    assert main(["fix", str(sample)]) == 0
