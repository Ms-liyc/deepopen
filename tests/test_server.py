import json
import threading
from pathlib import Path

from deepopen.projectinit import init_project
from deepopen.server import serve


def test_init_writes_config(tmp_path: Path) -> None:
    written = init_project(tmp_path)
    names = {path.name for path in written}
    assert "deepopen.toml" in names
    assert ".deepopenignore" in names


def test_server_scan_roundtrip(tmp_path: Path) -> None:
    sample = tmp_path / "ok.py"
    sample.write_text("value = 1\n", encoding="utf-8")
    httpd = serve("127.0.0.1", 0, str(tmp_path))
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        import urllib.request

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/meta", timeout=5) as resp:
            meta = json.loads(resp.read().decode("utf-8"))
        assert meta["version"]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
            home = resp.read().decode("utf-8")
        assert "DeepOpen" in home
        assert "导出修改方案" in home
        assert "progress-wrap" in home
        assert "/static/logo.jpg" in home
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/static/logo.jpg", timeout=5) as resp:
            assert resp.headers.get_content_type() == "image/jpeg"
            assert resp.read()[:3] == b"\xff\xd8\xff"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/scan",
            data=json.dumps({"path": str(sample)}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert payload["files_scanned"] == 1
        assert payload["findings"] == []
        stream_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/scan/stream",
            data=json.dumps({"path": str(sample)}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(stream_req, timeout=10) as resp:
            rows = [json.loads(line) for line in resp.read().decode("utf-8").splitlines() if line.strip()]
        assert rows[0]["event"] == "progress"
        assert rows[-1]["event"] == "done"
        assert rows[-1]["result"]["files_scanned"] == 1
        assert any(row.get("event") == "progress" and "scanned" in row and "findings" in row for row in rows)
        md_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/scan",
            data=json.dumps({"path": str(sample), "format": "md"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(md_req, timeout=10) as resp:
            markdown = resp.read().decode("utf-8")
            disposition = resp.headers.get("Content-Disposition") or ""
        assert "deepopen-fix-plan.md" in disposition
        assert "缺陷修改方案" in markdown
        assert "未发现规则命中" in markdown
    finally:
        httpd.shutdown()
        httpd.server_close()
