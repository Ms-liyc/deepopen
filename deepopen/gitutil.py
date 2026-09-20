"""Git helpers for staged-file scans."""

from __future__ import annotations

import subprocess
from pathlib import Path


def git_root(start: Path) -> Path | None:
    current = start if start.is_dir() else start.parent
    for _ in range(12):
        if (current / ".git").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    return None


def staged_paths(start: Path) -> tuple[list[Path], str | None]:
    root = git_root(start)
    if root is None:
        return [], "当前目录不是 Git 仓库，无法使用 --staged"
    try:
        proc = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "-z"],
            cwd=root,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return [], "git diff --cached 超时"
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        return [], err or "git diff --cached 失败"
    raw = proc.stdout.split(b"\0")
    files: list[Path] = []
    for item in raw:
        if not item:
            continue
        rel = item.decode("utf-8", errors="replace")
        path = root / rel
        if path.is_file():
            files.append(path)
    return files, None
