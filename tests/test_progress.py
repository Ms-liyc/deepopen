from pathlib import Path

from deepopen.scanner import format_progress_line, scan_path


def test_scan_reports_progress(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("eval(user_input)\n", encoding="utf-8")
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    seen = []
    result = scan_path(tmp_path, on_progress=seen.append)
    assert seen
    assert seen[0].phase == "listing"
    assert seen[-1].phase == "done"
    assert seen[-1].total == result.files_total == 3
    assert seen[-1].scanned == 3
    assert seen[-1].findings == len(result.findings)
    assert any(item.phase == "scan" and item.scanned > 0 for item in seen)
    assert any(item.findings >= 1 for item in seen)
    assert result.files_scanned == 3


def test_progress_line_contains_counts() -> None:
    from deepopen.scanner import ScanProgress

    line = format_progress_line(ScanProgress(total=40, scanned=12, findings=3, path="app.py", phase="scan"))
    assert "12/40" in line
    assert "已发现 3" in line
    assert "30%" in line
