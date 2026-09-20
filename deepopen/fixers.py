"""Safe, line-local auto-fixes for quality/bug findings.

Only rewrites a single source line when the transformation is unambiguous.
Security findings are never auto-rewritten.
"""

from __future__ import annotations

import re
from pathlib import Path

from deepopen.models import Finding

FIXABLE_RULES = frozenset({"AST009", "BUG003", "AST010", "BUG001"})


def is_fixable(rule_id: str) -> bool:
    return rule_id.upper() in FIXABLE_RULES


def fix_line(rule_id: str, line: str) -> str | None:
    newline = ""
    body = line
    if body.endswith("\r\n"):
        newline, body = "\r\n", body[:-2]
    elif body.endswith("\n"):
        newline, body = "\n", body[:-1]
    indent_len = len(body) - len(body.lstrip(" \t"))
    indent, text = body[:indent_len], body[indent_len:]
    updated = _rewrite(rule_id.upper(), text)
    if updated is None or updated == text:
        return None
    return indent + updated + newline


def _rewrite(rule_id: str, text: str) -> str | None:
    if rule_id in {"AST009", "BUG003"}:
        next_text = text
        next_text = re.sub(r"!=\s*None\b", "is not None", next_text)
        next_text = re.sub(r"==\s*None\b", "is None", next_text)
        next_text = re.sub(r"\bNone\s*!=", "None is not", next_text)
        next_text = re.sub(r"\bNone\s*==", "None is", next_text)
        return next_text
    if rule_id in {"AST010", "BUG001"}:
        if re.fullmatch(r"except\s*:", text):
            return "except Exception:"
    return None


def apply_fixes(root: Path, findings: list[Finding], dry_run: bool = True) -> list[dict[str, str]]:
    grouped: dict[str, list[Finding]] = {}
    for item in findings:
        if not is_fixable(item.rule_id) or item.baselined:
            continue
        grouped.setdefault(item.path, []).append(item)

    changes: list[dict[str, str]] = []
    for rel, items in grouped.items():
        path = Path(rel)
        if not path.is_file():
            candidate = root / rel if root.is_dir() else root.parent / rel
            if candidate.is_file():
                path = candidate
            else:
                continue
        original = path.read_text(encoding="utf-8")
        lines = original.splitlines(keepends=True)
        items = sorted(items, key=lambda item: item.line, reverse=True)
        file_changes: list[dict[str, str]] = []
        for item in items:
            index = item.line - 1
            if index < 0 or index >= len(lines):
                continue
            updated = fix_line(item.rule_id, lines[index])
            if updated is None:
                continue
            file_changes.append(
                {
                    "path": str(path),
                    "line": str(item.line),
                    "rule_id": item.rule_id,
                    "before": lines[index].rstrip("\n"),
                    "after": updated.rstrip("\n"),
                }
            )
            lines[index] = updated
        if file_changes and not dry_run:
            path.write_text("".join(lines), encoding="utf-8")
        changes.extend(file_changes)
    return changes
