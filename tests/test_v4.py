from pathlib import Path

from deepopen.catalog import explain_rule
from deepopen.cli import main
from deepopen.config import Config, load_config
from deepopen.scanner import scan_path, scan_text


def test_profile_secret_skips_eval() -> None:
    cfg = Config(profile="secret")
    ids = {item.rule_id for item in scan_text(Path("app.py"), "eval(user_input)\n", config=cfg)}
    assert "AST001" not in ids
    assert "PY001" not in ids


def test_profile_security_keeps_eval() -> None:
    cfg = Config(profile="security")
    ids = {item.rule_id for item in scan_text(Path("app.py"), "eval(user_input)\n", config=cfg)}
    assert "AST001" in ids or "PY001" in ids


def test_custom_rule_from_toml(tmp_path: Path) -> None:
    (tmp_path / "deepopen.toml").write_text(
        """
fail_on = "high"
[[rules]]
id = "TEAM001"
title = "禁止 zzdebug"
pattern = "zzdebug\\\\s*\\\\("
severity = "low"
category = "quality"
suffixes = [".py"]
message = "调试函数不应提交"
remediation = "删除该调用"
""",
        encoding="utf-8",
    )
    sample = tmp_path / "app.py"
    sample.write_text("zzdebug(1)\n", encoding="utf-8")
    cfg = load_config(tmp_path)
    assert cfg.custom_rules
    ids = {item.rule_id for item in scan_path(sample, config=cfg).findings}
    assert "TEAM001" in ids
    explained = explain_rule("TEAM001", cfg)
    assert explained is not None
    assert explained["title"] == "禁止 zzdebug"


def test_custom_rule_rejects_bad_id(tmp_path: Path) -> None:
    (tmp_path / "deepopen.toml").write_text(
        """
[[rules]]
id = "BUG001"
title = "nope"
pattern = "foo"
suffixes = [".py"]
""",
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert cfg.custom_rules == ()
    assert cfg.config_errors


def test_pyproject_and_gomod_and_cargo() -> None:
    py_ids = {
        item.rule_id
        for item in scan_text(
            Path("pyproject.toml"),
            '[project]\ndependencies = [\n    "requests",\n    "flask==2.0.0",\n]\n',
        )
    }
    assert "DEP002" in py_ids
    go_ids = {item.rule_id for item in scan_text(Path("go.mod"), "module x\nrequire github.com/foo/bar latest\n")}
    assert "DEP004" in go_ids
    cargo_ids = {
        item.rule_id
        for item in scan_text(Path("Cargo.toml"), '[dependencies]\nserde = "*"\n')
    }
    assert "DEP005" in cargo_ids


def test_env_and_github_permissions() -> None:
    env_ids = {item.rule_id for item in scan_text(Path(".env"), "SECRET=1\n")}
    assert "ENV001" in env_ids
    example_ids = {item.rule_id for item in scan_text(Path(".env.example"), "SECRET=1\n")}
    assert "ENV001" not in example_ids
    gh_ids = {
        item.rule_id
        for item in scan_text(Path(".github") / "workflows" / "ci.yml", "permissions: write-all\n")
    }
    assert "GH002" in gh_ids


def test_cli_profile_json(tmp_path: Path, capsys) -> None:
    sample = tmp_path / "x.py"
    sample.write_text("eval(user_input)\n", encoding="utf-8")
    assert main(["scan", str(sample), "--profile", "secret", "--format", "json", "--fail-on", "high"]) == 0
    out = capsys.readouterr().out
    assert '"findings": []' in out or '"finding_count": 0' in out
