"""Project-level checks for missing tests and empty test files."""

from __future__ import annotations

from pathlib import Path

from deepopen.config import Config
from deepopen.models import Category, Finding, Severity
from deepopen.paths import SKIP_DIR_NAMES


def analyze_project(root: Path, config: Config | None = None) -> list[Finding]:
    _ = config
    if not root.is_dir():
        return []
    test_files = list(_iter_test_files(root))
    source_files = list(_iter_source_files(root))
    findings: list[Finding] = []
    if source_files and not test_files:
        findings.append(
            _hit(
                root / "tests",
                1,
                "missing tests",
                "REV001",
                "仓库缺少测试文件",
                Severity.MEDIUM,
                Category.QUALITY,
                "没有发现 test_*.py / *_test.go / *Test.java 等测试文件。",
                "为关键路径补回归测试，尤其是错误分支、空输入和权限相关逻辑。",
            )
        )
        return findings
    for path in test_files:
        if not _is_named_test(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _has_assertion(text):
            findings.append(
                _hit(
                    path,
                    1,
                    path.name,
                    "REV002",
                    "测试文件没有断言",
                    Severity.LOW,
                    Category.QUALITY,
                    "测试里看不到 assert / expect / self.assert，可能没有真正校验结果。",
                    "补上对返回值、状态码或异常的断言。",
                )
            )
    return findings


def _iter_test_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if _is_test_file(path) or _is_named_test(path):
            files.append(path)
    return files


def _iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".py", ".js", ".ts", ".go", ".java"}:
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if _is_test_file(path):
            continue
        files.append(path)
    return files


def _is_named_test(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith("test_") and name.endswith(".py"):
        return True
    if name.endswith("_test.py") or name.endswith("_test.go") or name.endswith("_spec.rb"):
        return True
    if name.endswith("test.java") or name.endswith("tests.java"):
        return True
    return name.endswith(".test.js") or name.endswith(".spec.ts") or name.endswith(".test.ts")


def _is_test_file(path: Path) -> bool:
    if _is_named_test(path):
        return True
    if "tests" in path.parts or "test" in path.parts:
        return path.suffix.lower() in {".py", ".js", ".ts", ".go", ".java"}
    return False


def _has_assertion(text: str) -> bool:
    markers = ("assert ", "assert(", "self.assert", "expect(", "pytest.raises", "require(", "t.error")
    lowered = text
    return any(marker in lowered for marker in markers)


def _hit(
    path: Path,
    line: int,
    snippet: str,
    rule_id: str,
    title: str,
    severity: Severity,
    category: Category,
    message: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        path=str(path),
        line=line,
        snippet=snippet[:240],
        message=message,
        remediation=remediation,
    )
