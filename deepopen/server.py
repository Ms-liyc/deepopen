"""Local web console. Binds to 127.0.0.1 only."""

from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from deepopen.baseline import save_baseline
from deepopen.catalog import all_rule_records, explain_rule
from deepopen.checklist import CHECKLIST, CHECKLIST_SECTIONS
from deepopen.config import PROFILES, load_config
from deepopen.fixers import apply_fixes
from deepopen.report import render_html, render_json, render_markdown, render_sarif
from deepopen.scanner import scan_path
from deepopen.version import __version__

WEB_DIR = Path(__file__).resolve().parent / "web"


class DeepOpenHandler(BaseHTTPRequestHandler):
    server_version = f"DeepOpen/{__version__}"
    default_path: str = "."
    last_scan_root: str = ""

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _read_json(self) -> tuple[dict[str, object] | None, str | None]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > 1_000_000:
            return None, "请求过大"
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return None, "JSON 无效"
        if not isinstance(payload, dict):
            return None, "JSON 必须是对象"
        return payload, None

    def _resolve_scan_path(self, target: str) -> Path | None:
        path = Path(str(target or self.default_path)).expanduser()
        if not path.is_absolute():
            base = Path(self.default_path)
            path = (base / path).resolve() if base.is_dir() else path.resolve()
        else:
            path = path.resolve()
        return path if path.exists() else None

    def _safe_read(self, rel: str) -> Path | None:
        roots: list[Path] = [Path(self.default_path).resolve()]
        if self.last_scan_root:
            roots.append(Path(self.last_scan_root).resolve())
        raw = Path(rel)
        candidates = [raw.resolve()] if raw.is_absolute() else [root / rel for root in roots]
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            for root in roots:
                base = root if root.is_dir() else root.parent
                try:
                    resolved.relative_to(base)
                except ValueError:
                    continue
                if resolved.is_file():
                    return resolved
        return None

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        route = parsed.path
        if route == "/":
            index = WEB_DIR / "index.html"
            self._send(200, index.read_bytes(), "text/html; charset=utf-8")
            return
        if route == "/api/meta":
            self._send_json(
                200,
                {
                    "version": __version__,
                    "default_path": self.default_path,
                    "rule_count": len(all_rule_records(load_config(Path(self.default_path)))),
                    "profiles": list(PROFILES),
                },
            )
            return
        if route == "/api/rules":
            self._send_json(200, {"rules": all_rule_records(load_config(Path(self.default_path)))})
            return
        if route == "/api/checklist":
            self._send_json(200, {"text": CHECKLIST, "sections": CHECKLIST_SECTIONS})
            return
        if route == "/api/explain":
            qs = parse_qs(parsed.query)
            rule_id = (qs.get("id") or [""])[0]
            item = explain_rule(rule_id, load_config(Path(self.default_path)))
            if item is None:
                self._send_json(404, {"error": f"未找到规则: {rule_id}"})
                return
            self._send_json(200, item)
            return
        if route == "/api/snippet":
            qs = parse_qs(parsed.query)
            rel = (qs.get("path") or [""])[0]
            try:
                line = int((qs.get("line") or ["1"])[0])
            except ValueError:
                line = 1
            path = self._safe_read(rel)
            if path is None:
                self._send_json(400, {"error": "无法读取该文件"})
                return
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(1, line - 4)
            end = min(len(lines), line + 4)
            snippet = [
                {"n": index, "text": lines[index - 1], "hit": index == line}
                for index in range(start, end + 1)
            ]
            self._send_json(200, {"path": str(path), "line": line, "lines": snippet})
            return
        if route.startswith("/static/"):
            name = Path(route).name
            path = WEB_DIR / name
            if path.is_file() and path.resolve().parent == WEB_DIR:
                mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
                self._send(200, path.read_bytes(), mime)
                return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        payload, err = self._read_json()
        if err:
            self._send_json(400 if err != "请求过大" else 413, {"error": err})
            return
        assert payload is not None
        if parsed.path == "/api/scan":
            self._handle_scan(payload)
            return
        if parsed.path == "/api/baseline":
            path = self._resolve_scan_path(str(payload.get("path") or self.default_path))
            if path is None:
                self._send_json(400, {"error": "路径不存在"})
                return
            result = scan_path(path, config=load_config(path), hide_baseline=False)
            saved = save_baseline(path, result.findings)
            self._send_json(200, {"path": str(saved), "count": len(result.findings)})
            return
        if parsed.path == "/api/fix":
            path = self._resolve_scan_path(str(payload.get("path") or self.default_path))
            if path is None:
                self._send_json(400, {"error": "路径不存在"})
                return
            apply = bool(payload.get("apply"))
            result = scan_path(path, config=load_config(path), hide_baseline=True)
            changes = apply_fixes(path, result.findings, dry_run=not apply)
            self._send_json(200, {"applied": apply, "changes": changes})
            return
        self._send_json(404, {"error": "not found"})

    def _handle_scan(self, payload: dict[str, object]) -> None:
        target = str(payload.get("path") or self.default_path)
        staged = bool(payload.get("staged"))
        fmt = str(payload.get("format") or "json")
        show_baseline = bool(payload.get("show_baseline"))
        path = self._resolve_scan_path(target)
        if path is None:
            self._send_json(400, {"error": f"路径不存在: {target}"})
            return
        DeepOpenHandler.last_scan_root = str(path)
        cfg = load_config(path)
        profile = str(payload.get("profile") or "").strip().lower()
        if profile in PROFILES:
            cfg.profile = profile
        result = scan_path(
            path,
            config=cfg,
            staged=staged,
            hide_baseline=not show_baseline,
        )
        if fmt == "html":
            self._send(200, render_html(result).encode("utf-8"), "text/html; charset=utf-8")
            return
        if fmt == "sarif":
            self._send(200, render_sarif(result).encode("utf-8"), "application/json; charset=utf-8")
            return
        if fmt == "md":
            self._send(200, render_markdown(result).encode("utf-8"), "text/markdown; charset=utf-8")
            return
        self._send(200, render_json(result).encode("utf-8"), "application/json; charset=utf-8")


def serve(host: str, port: int, default_path: str) -> ThreadingHTTPServer:
    DeepOpenHandler.default_path = str(Path(default_path).resolve())
    DeepOpenHandler.last_scan_root = DeepOpenHandler.default_path
    httpd = ThreadingHTTPServer((host, port), DeepOpenHandler)
    return httpd
