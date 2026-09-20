"""Path ignore: directory names, gitignore-style patterns, inline comments."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from deepopen.models import Finding

SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".tox",
    ".idea",
    ".vscode",
    "site-packages",
    ".deepopen-cache",
}

SKIP_FILE_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".woff",
    ".woff2",
    ".ttf",
    ".exe",
    ".dll",
    ".so",
    ".pyc",
    ".pyo",
    ".class",
    ".o",
}

TEXT_SUFFIXES = {
    ".py",
    ".pyw",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".java",
    ".go",
    ".php",
    ".rb",
    ".rs",
    ".cs",
    ".kt",
    ".swift",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".sql",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".env",
    ".xml",
    ".html",
    ".htm",
    ".vue",
    ".md",
    ".txt",
    ".tf",
    ".tfvars",
    ".gradle",
}

SPECIAL_NAMES = {
    "dockerfile",
    "containerfile",
    "makefile",
    "jenkinsfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    ".env",
    "gemfile",
}

INLINE_IGNORE = re.compile(
    r"deepopen\s*:\s*ignore(?:\s+([A-Za-z0-9_,\-\s]+))?",
    re.IGNORECASE,
)

PLACEHOLDER_VALUES = {
    "changeme",
    "change_me",
    "changeme!",
    "yourpassword",
    "your_password",
    "password",
    "secret",
    "apikey",
    "api_key",
    "xxxxxxxx",
    "placeholder",
    "example",
    "dummy",
    "todo",
    "testtest",
    "notasecret",
    "replace_me",
}


def should_skip_dir(name: str) -> bool:
    return name in SKIP_DIR_NAMES or name.endswith(".egg-info")


def is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in SKIP_FILE_SUFFIXES:
        return False
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    if path.name.lower() in SPECIAL_NAMES or path.name.startswith(".env"):
        return True
    return path.suffix == ""


def path_is_excluded(relative: Path, patterns: list[str]) -> bool:
    posix = relative.as_posix()
    parts = relative.parts
    for pattern in patterns:
        text = pattern.strip().replace("\\", "/").rstrip("/")
        if not text:
            continue
        if posix == text or posix.startswith(text + "/"):
            return True
        if fnmatch.fnmatch(posix, text) or fnmatch.fnmatch(relative.name, text):
            return True
        if any(fnmatch.fnmatch(part, text) for part in parts):
            return True
    return False


def iter_files(root: Path, exclude: list[str] | None = None, max_files: int = 20_000) -> tuple[list[Path], str | None]:
    exclude = exclude or []
    files: list[Path] = []
    if root.is_file():
        return [root], None
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(should_skip_dir(part) for part in relative.parts[:-1]):
            continue
        if path_is_excluded(relative, exclude):
            continue
        if not is_probably_text(path):
            continue
        files.append(path)
        if len(files) >= max_files:
            return sorted(files), f"已达到文件上限 {max_files}，其余文件未扫描"
    return sorted(files), None


def line_is_comment(line: str, suffix: str) -> bool:
    stripped = line.lstrip()
    if suffix in {".py", ".pyw", ".rb", ".sh", ".bash", ".yml", ".yaml", ".toml"}:
        return stripped.startswith("#")
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".c", ".cpp", ".h", ".rs", ".cs", ".php"}:
        return stripped.startswith("//") or stripped.startswith("/*")
    return False


def ignored_rule_ids(lines: list[str], lineno: int) -> set[str] | None:
    """Return None to ignore all rules on this line, a set of ids, or empty set."""
    candidates: list[str] = []
    if 1 <= lineno <= len(lines):
        candidates.append(lines[lineno - 1])
    if lineno > 1:
        candidates.append(lines[lineno - 2])
    collected: set[str] = set()
    ignore_all = False
    found = False
    for text in candidates:
        match = INLINE_IGNORE.search(text)
        if not match:
            continue
        found = True
        raw = match.group(1)
        if not raw or not raw.strip():
            ignore_all = True
            continue
        collected.update(item.strip().upper() for item in raw.split(",") if item.strip())
    if not found:
        return set()
    if ignore_all:
        return None
    return collected


def is_placeholder_secret(snippet: str) -> bool:
    match = re.search(r"""['\"]([^'\"]{8,})['\"]""", snippet)
    if not match:
        return False
    value = match.group(1).strip().lower()
    if value in PLACEHOLDER_VALUES:
        return True
    if re.fullmatch(r"[x*]{8,}", value):
        return True
    if value.startswith("your_") or value.endswith("_here"):
        return True
    return False


def filter_inline_ignores(source: str, findings: list[Finding]) -> list[Finding]:
    lines = source.splitlines()
    kept: list[Finding] = []
    for finding in findings:
        ignored = ignored_rule_ids(lines, finding.line)
        if ignored is None:
            continue
        if finding.rule_id.upper() in ignored:
            continue
        kept.append(finding)
    return kept
