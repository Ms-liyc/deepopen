"""Scan source files with pattern rules, Python AST and manifest checks."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from deepopen.advisories import analyze_dependencies
from deepopen.analyzers import analyze_manifest
from deepopen.baseline import apply_baseline
from deepopen.config import Config, load_config, load_ignore_patterns
from deepopen.fixers import is_fixable
from deepopen.gitutil import staged_paths
from deepopen.models import Finding, SEVERITY_ORDER, Severity, infer_language
from deepopen.review import analyze_project
from deepopen.paths import (
    filter_inline_ignores,
    is_placeholder_secret,
    iter_files,
    line_is_comment,
)
from deepopen.patterns import ALL_PATTERN_RULES, PatternRule
from deepopen.python_ast import analyze_python


def _skip_placeholder_secret(rule_id: str, snippet: str) -> bool:
    if not (rule_id.startswith("SEC") or rule_id == "CFG006"):
        return False
    lowered = snippet.lower()
    if "${" in snippet or "{{" in snippet or "change_me" in lowered:
        return True
    return is_placeholder_secret(snippet)


def _severity_included(severity: Severity, minimum: str) -> bool:
    try:
        floor = Severity(minimum)
    except ValueError:
        floor = Severity.INFO
    return SEVERITY_ORDER[severity] <= SEVERITY_ORDER[floor]


def scan_text(
    path: Path,
    source: str,
    rules: tuple[PatternRule, ...] | None = None,
    config: Config | None = None,
) -> list[Finding]:
    cfg = config or Config()
    suffix = path.suffix.lower()
    findings: list[Finding] = []
    lines = source.splitlines()
    if rules is None:
        rules = ALL_PATTERN_RULES + cfg.custom_rules
    for rule in rules:
        if not cfg.allows(rule.rule_id, rule.category):
            continue
        if not rule.applies_to(path.name, suffix):
            if not (path.name.startswith(".env") and rule.category.value == "secret"):
                continue
        for match in rule.pattern.finditer(source):
            lineno = source.count("\n", 0, match.start()) + 1
            snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else match.group(0)
            if rule.skip_comments and line_is_comment(snippet, suffix):
                continue
            if _skip_placeholder_secret(rule.rule_id, snippet):
                continue
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    category=rule.category,
                    path=str(path),
                    line=lineno,
                    snippet=snippet[:240],
                    message=rule.message,
                    remediation=rule.remediation,
                    cwe=rule.cwe,
                )
            )
    if suffix in {".py", ".pyw"}:
        for item in analyze_python(path, source):
            if cfg.allows(item.rule_id, item.category):
                findings.append(item)
    findings.extend(
        item for item in analyze_manifest(path, source) if cfg.allows(item.rule_id, item.category)
    )
    findings = _dedupe(findings)
    findings = filter_inline_ignores(source, findings)
    return [item for item in findings if _severity_included(item.severity, cfg.min_severity)]


def _dedupe(findings: list[Finding]) -> list[Finding]:
    preferred: dict[tuple[str, int, str], Finding] = {}
    for finding in findings:
        family = finding.cwe or finding.title
        key = (finding.path, finding.line, family)
        existing = preferred.get(key)
        if existing is None:
            preferred[key] = finding
            continue
        if finding.rule_id.startswith("AST") and not existing.rule_id.startswith("AST"):
            preferred[key] = finding
    return list(preferred.values())


@dataclass
class ScanResult:
    root: Path
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    truncated: bool = False
    baselined_count: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    profile: str = "all"

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {name: 0 for name in ("critical", "high", "medium", "low", "info")}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def counts_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            key = finding.category.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_summary(self) -> dict[str, object]:
        return {
            "root": str(self.root),
            "files_scanned": self.files_scanned,
            "finding_count": len(self.findings),
            "counts": self.counts_by_severity,
            "categories": self.counts_by_category,
            "errors": self.errors,
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
            "baselined_count": self.baselined_count,
            "languages": self.languages,
            "fixable_count": sum(1 for item in self.findings if is_fixable(item.rule_id) and not item.baselined),
            "profile": self.profile,
        }


def scan_path(
    root: Path,
    config: Config | None = None,
    staged: bool = False,
    hide_baseline: bool | None = None,
) -> ScanResult:
    root = root.resolve()
    cfg = config or load_config(root)
    started = time.perf_counter()
    result = ScanResult(root=root, profile=cfg.profile)
    exclude = load_ignore_patterns(root, cfg.exclude)
    result.errors.extend(cfg.config_errors)

    if staged:
        files, err = staged_paths(root)
        if err:
            result.errors.append(err)
            result.duration_ms = int((time.perf_counter() - started) * 1000)
            return result
    else:
        files, truncated_msg = iter_files(root, exclude=exclude, max_files=cfg.max_files)
        if truncated_msg:
            result.truncated = True
            result.errors.append(truncated_msg)

    for file_path in files:
        try:
            data = file_path.read_bytes()
        except OSError as exc:
            result.errors.append(f"{file_path}: {exc}")
            continue
        if len(data) > cfg.max_file_bytes or b"\x00" in data[:4096]:
            continue
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                source = data.decode("gbk")
            except UnicodeDecodeError:
                continue
        result.files_scanned += 1
        lang = infer_language(str(file_path))
        result.languages[lang] = result.languages.get(lang, 0) + 1
        try:
            display = file_path.relative_to(root if root.is_dir() else root.parent)
        except ValueError:
            display = file_path
        result.findings.extend(scan_text(display, source, config=cfg))

    if root.is_dir():
        result.findings.extend(
            item for item in analyze_project(root, cfg) if cfg.allows(item.rule_id, item.category)
        )
        result.findings.extend(
            item for item in analyze_dependencies(root, cfg) if cfg.allows(item.rule_id, item.category)
        )

    result.findings.sort(
        key=lambda item: (SEVERITY_ORDER[item.severity], item.path, item.line, item.rule_id)
    )
    hide = cfg.hide_baseline if hide_baseline is None else hide_baseline
    result.findings, result.baselined_count = apply_baseline(result.findings, root, hide=hide)
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    return result
