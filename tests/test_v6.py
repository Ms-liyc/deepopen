from pathlib import Path
from urllib.error import URLError

from deepopen.catalog import all_rule_records, explain_rule
from deepopen.config import Config
from deepopen.scanner import scan_path, scan_text


def test_auth_and_business_patterns() -> None:
    py = """
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def checkout(request):
    Order.objects.create(**request.data)
    item = Order.objects.get(id=request.GET["id"])
    price = request.POST.get("price")
    is_admin = request.data["is_admin"]
    return item
"""
    ids = {item.rule_id for item in scan_text(Path("shop.py"), py)}
    assert "AUTH001" in ids
    assert "AUTH003" in ids
    assert "AUTH004" in ids
    assert "AUTH005" in ids
    assert "AUTH006" in ids

    java_ids = {
        item.rule_id
        for item in scan_text(Path("Sec.java"), "http.csrf().disable();\nhttp.authorizeHttpRequests().anyRequest().permitAll();\n")
    }
    assert "AUTH001" in java_ids
    assert "AUTH007" in java_ids

    js_ids = {item.rule_id for item in scan_text(Path("pay.js"), "price = req.body.price;\nisAdmin = req.body.isAdmin;\n")}
    assert "AUTH014" in js_ids


def test_route_without_auth_ast() -> None:
    source = """
@app.route("/orders")
def orders():
    return "ok"

@app.route("/health")
def health():
    return "ok"

@app.route("/me")
@login_required
def me():
    return "ok"

@app.get("/who")
def who(user=Depends(get_user)):
    return user
"""
    hits = [item for item in scan_text(Path("views.py"), source) if item.rule_id == "AST069"]
    assert any(item.snippet.startswith("def orders") or "orders" in item.snippet for item in hits)
    assert not any("health" in item.snippet or "def me" in item.snippet or "def who" in item.snippet for item in hits)


def test_runtime_config_and_django_settings() -> None:
    redis_ids = {
        item.rule_id
        for item in scan_text(Path("redis.conf"), "port 6379\nprotected-mode no\n")
    }
    assert "CFG001" in redis_ids
    assert "CFG007" in redis_ids

    yaml_ids = {item.rule_id for item in scan_text(Path("app.yaml"), "tls: false\n")}
    assert "CFG005" in yaml_ids

    prop_ids = {
        item.rule_id
        for item in scan_text(Path("application.properties"), "spring.datasource.password=s3cret-value\n")
    }
    assert "CFG006" in prop_ids

    settings = """
INSTALLED_APPS = ["django.contrib.admin"]
MIDDLEWARE = ["django.middleware.security.SecurityMiddleware"]
"""
    settings_ids = {item.rule_id for item in scan_text(Path("settings.py"), settings)}
    assert "AUTH010" in settings_ids
    assert "AUTH011" in settings_ids


def test_review_missing_tests_and_empty_assert(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    missing = {item.rule_id for item in scan_path(tmp_path).findings}
    assert "REV001" in missing

    (tmp_path / "test_empty.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    empty = {item.rule_id for item in scan_path(tmp_path).findings}
    assert "REV001" not in empty
    assert "REV002" in empty


def test_known_malicious_package(tmp_path: Path) -> None:
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"event-stream":"3.3.6"}}',
        encoding="utf-8",
    )
    ids = {item.rule_id for item in scan_path(tmp_path).findings}
    assert "ADV002" in ids


def test_osv_advisories_opt_in(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("jinja2==2.4.1\n", encoding="utf-8")

    class FakeResp:
        def read(self) -> bytes:
            return b'{"results":[{"vulns":[{"id":"GHSA-demo"}]}]}'

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def fake_urlopen(req: object, timeout: int = 0) -> FakeResp:
        _ = req, timeout
        return FakeResp()

    monkeypatch.setattr("deepopen.advisories.urllib.request.urlopen", fake_urlopen)
    cfg = Config(advisories=True)
    ids = {item.rule_id for item in scan_path(tmp_path, config=cfg).findings}
    assert "ADV001" in ids


def test_osv_network_error_is_silent(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("jinja2==2.4.1\n", encoding="utf-8")

    def boom(req: object, timeout: int = 0) -> None:
        _ = req, timeout
        raise URLError("offline")

    monkeypatch.setattr("deepopen.advisories.urllib.request.urlopen", boom)
    result = scan_path(tmp_path, config=Config(advisories=True))
    assert "ADV001" not in {item.rule_id for item in result.findings}


def test_new_v6_rules_are_catalogued() -> None:
    ids = {str(item["rule_id"]) for item in all_rule_records()}
    for rule_id in (
        "AUTH001",
        "AUTH005",
        "AUTH010",
        "AST069",
        "CFG001",
        "CFG006",
        "CFG007",
        "REV001",
        "ADV001",
        "ADV002",
    ):
        assert rule_id in ids
        assert explain_rule(rule_id) is not None
