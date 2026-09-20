"""Pattern rule definition shared by all language packs."""

from __future__ import annotations

import re
from dataclasses import dataclass

from deepopen.models import Category, Severity


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    pattern: re.Pattern[str]
    message: str
    remediation: str
    cwe: str | None = None
    suffixes: frozenset[str] | None = None
    names: frozenset[str] | None = None
    skip_comments: bool = True

    def applies_to(self, path_name: str, suffix: str) -> bool:
        if self.suffixes is None and self.names is None:
            return True
        if self.suffixes is not None and suffix in self.suffixes:
            return True
        if self.names is not None and path_name in self.names:
            return True
        if self.names is not None and path_name.startswith(".env"):
            return ".env" in self.names
        return False

    def meta(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "cwe": self.cwe,
            "message": self.message,
            "remediation": self.remediation,
            "suffixes": sorted(self.suffixes) if self.suffixes else None,
            "names": sorted(self.names) if self.names else None,
        }


def compile_re(source: str, flags: int = re.IGNORECASE | re.MULTILINE) -> re.Pattern[str]:
    return re.compile(source, flags)
