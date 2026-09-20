"""Finding data model for DeepOpen static checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECURITY = "security"
    SECRET = "secret"
    BUG = "bug"
    QUALITY = "quality"
    CONFIG = "config"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".swift": "swift",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".ini": "ini",
    ".xml": "xml",
    ".html": "html",
    ".htm": "html",
    ".vue": "vue",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".md": "markdown",
    ".txt": "text",
}

LANGUAGE_BY_NAME = {
    "dockerfile": "docker",
    "containerfile": "docker",
    "jenkinsfile": "groovy",
    "makefile": "make",
    ".env": "dotenv",
}


def infer_language(path: str) -> str:
    p = Path(path)
    name = p.name.lower()
    if name in LANGUAGE_BY_NAME:
        return LANGUAGE_BY_NAME[name]
    if name.startswith(".env"):
        return "dotenv"
    if name.startswith("docker-compose") or name == "compose.yaml" or name == "compose.yml":
        return "docker"
    return LANGUAGE_BY_SUFFIX.get(p.suffix.lower(), "other")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    path: str
    line: int
    snippet: str
    message: str
    remediation: str
    cwe: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    baselined: bool = False

    def fingerprint(self) -> str:
        import hashlib

        path = self.path.replace("\\", "/")
        raw = f"{self.rule_id}|{path}|{self.snippet.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        from deepopen.fixers import is_fixable

        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "message": self.message,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "language": infer_language(self.path),
            "fingerprint": self.fingerprint(),
            "baselined": self.baselined,
            "fixable": is_fixable(self.rule_id),
        }
