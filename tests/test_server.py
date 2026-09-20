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
    finally:
        httpd.shutdown()
        httpd.server_close()
