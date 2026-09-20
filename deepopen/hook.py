"""Install a Git pre-commit hook that runs DeepOpen on staged files."""

from __future__ import annotations

from pathlib import Path

from deepopen.gitutil import git_root

HOOK_BODY = """#!/bin/sh
# DeepOpen pre-commit
if command -v python >/dev/null 2>&1; then
  PY=python
elif command -v python3 >/dev/null 2>&1; then
  PY=python3
else
  echo "DeepOpen hook: python 未找到" >&2
  exit 1
fi
cd "$(git rev-parse --show-toplevel)" || exit 1
$PY -m deepopen scan --staged --fail-on high --no-color
"""


def hook_path(start: Path) -> Path | None:
    root = git_root(start)
    if root is None:
        return None
    return root / ".git" / "hooks" / "pre-commit"


def install_hook(start: Path) -> Path:
    path = hook_path(start)
    if path is None:
        raise FileNotFoundError("未找到 .git 目录，无法安装 hook")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_text(encoding="utf-8", errors="replace")
        if "deepopen scan --staged" not in existing:
            backup = path.with_suffix(path.suffix + ".bak")
            backup.write_text(existing, encoding="utf-8")
    path.write_text(HOOK_BODY, encoding="utf-8")
    try:
        path.chmod(0o755)
    except OSError:
        return path
    return path


def uninstall_hook(start: Path) -> bool:
    path = hook_path(start)
    if path is None or not path.exists():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    if "DeepOpen pre-commit" not in text:
        return False
    bak = path.with_suffix(path.suffix + ".bak")
    if bak.exists():
        path.write_text(bak.read_text(encoding="utf-8"), encoding="utf-8")
        bak.unlink()
    else:
        path.unlink()
    return True
