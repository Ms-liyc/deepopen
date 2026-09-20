"""Project config: deepopen.toml / deepopen.json."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from deepopen.models import Category, Severity
from deepopen.patterns.base import PatternRule, compile_re as _compile_re

CONFIG_FILENAMES = ("deepopen.toml", "deepopen.json", ".deepopen.toml")
IGNORE_FILENAME = ".deepopenignore"

PROFILES: dict[str, frozenset[str] | None] = {
    "all": None,
    "security": frozenset({"security", "secret", "config"}),
    "bug": frozenset({"bug", "quality"}),
    "secret": frozenset({"secret"}),
}

_ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*(?:#.*)?$")
_CUSTOM_ID = re.compile(r"^(?:CUSTOM|TEAM|ORG|LOCAL)[A-Z0-9_]{0,24}$", re.IGNORECASE)


@dataclass
class Config:
    fail_on: str = "high"
    exclude: list[str] = field(default_factory=list)
    disable_rules: list[str] = field(default_factory=list)
    min_severity: str = "info"
    max_file_bytes: int = 1_500_000
    max_files: int = 20_000
    hide_baseline: bool = True
    profile: str = "all"
    custom_rules: tuple[PatternRule, ...] = ()
    config_errors: list[str] = field(default_factory=list)
    source: Path | None = None

    def is_rule_enabled(self, rule_id: str) -> bool:
        disabled = {item.strip().upper() for item in self.disable_rules}
        return rule_id.upper() not in disabled

    def allows(self, rule_id: str, category: Category | str | None = None) -> bool:
        if not self.is_rule_enabled(rule_id):
            return False
        allowed = PROFILES.get(self.profile.lower(), None)
        if allowed is None:
            return True
        if category is None:
            return True
        name = category.value if isinstance(category, Category) else str(category)
        return name.lower() in allowed


def find_config_dir(start: Path) -> Path | None:
    current = start if start.is_dir() else start.parent
    for _ in range(8):
        for name in CONFIG_FILENAMES + (IGNORE_FILENAME,):
            if (current / name).is_file():
                return current
        if (current / ".git").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    return None


def load_config(start: Path, explicit: Path | None = None) -> Config:
    if explicit:
        return _read_config_file(explicit)
    root = find_config_dir(start)
    if root is None:
        return Config()
    for name in CONFIG_FILENAMES:
        candidate = root / name
        if candidate.is_file():
            return _read_config_file(candidate)
    return Config(source=root)


def load_ignore_patterns(start: Path, extra: list[str] | None = None) -> list[str]:
    patterns = list(extra or [])
    root = find_config_dir(start)
    if root is None:
        return patterns
    path = root / IGNORE_FILENAME
    if not path.is_file():
        return patterns
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        patterns.append(text)
    return patterns


def _read_config_file(path: Path) -> Config:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        loaded = json.loads(text)
        if not isinstance(loaded, dict):
            raise ValueError(f"配置必须是对象: {path}")
        data: dict[str, object] = loaded
    else:
        data = _parse_simple_toml(text)
    cfg = Config(source=path)
    if isinstance(data.get("fail_on"), str):
        cfg.fail_on = str(data["fail_on"])
    if isinstance(data.get("min_severity"), str):
        cfg.min_severity = str(data["min_severity"])
    if isinstance(data.get("max_file_bytes"), int):
        cfg.max_file_bytes = int(data["max_file_bytes"])
    if isinstance(data.get("max_files"), int):
        cfg.max_files = int(data["max_files"])
    if isinstance(data.get("hide_baseline"), bool):
        cfg.hide_baseline = bool(data["hide_baseline"])
    if isinstance(data.get("profile"), str):
        profile = str(data["profile"]).strip().lower()
        if profile in PROFILES:
            cfg.profile = profile
        else:
            cfg.config_errors.append(f"未知 profile: {data['profile']}，已回退为 all")
    exclude = data.get("exclude")
    if isinstance(exclude, list):
        cfg.exclude = [str(item) for item in exclude]
    disable = data.get("disable_rules")
    if isinstance(disable, list):
        cfg.disable_rules = [str(item) for item in disable]
    cfg.custom_rules, custom_errors = _compile_custom_rules(data.get("rules"))
    cfg.config_errors.extend(custom_errors)
    return cfg


def _compile_custom_rules(raw: object) -> tuple[tuple[PatternRule, ...], list[str]]:
    from deepopen.patterns import RULE_BY_ID

    if raw is None:
        return (), []
    rows: list[dict[str, object]] = []
    if isinstance(raw, list):
        rows = [item for item in raw if isinstance(item, dict)]
    elif isinstance(raw, dict):
        rows = [item for item in raw.values() if isinstance(item, dict)]
    else:
        return (), ["rules 必须是表数组 [[rules]] 或 JSON 数组"]

    compiled: list[PatternRule] = []
    errors: list[str] = []
    seen: set[str] = set()
    for item in rows:
        rule_id = str(item.get("id") or item.get("rule_id") or "").strip().upper()
        pattern_text = str(item.get("pattern") or "")
        title = str(item.get("title") or rule_id or "自定义规则").strip()
        if not rule_id:
            errors.append("自定义规则缺少 id")
            continue
        if not _CUSTOM_ID.match(rule_id):
            errors.append(f"自定义规则 {rule_id} 必须以 CUSTOM/TEAM/ORG/LOCAL 开头")
            continue
        if rule_id in RULE_BY_ID or rule_id in seen:
            errors.append(f"自定义规则 {rule_id} 与已有规则冲突")
            continue
        if not pattern_text or len(pattern_text) > 500:
            errors.append(f"自定义规则 {rule_id} 的 pattern 为空或过长")
            continue
        suffixes = _as_suffixes(item.get("suffixes"))
        names = _as_names(item.get("names"))
        if suffixes is None and names is None:
            errors.append(f"自定义规则 {rule_id} 必须指定 suffixes 或 names")
            continue
        try:
            pattern = _compile_re(pattern_text)
        except re.error as exc:
            errors.append(f"自定义规则 {rule_id} 正则无效: {exc}")
            continue
        try:
            severity = Severity(str(item.get("severity") or "medium").lower())
        except ValueError:
            severity = Severity.MEDIUM
        try:
            category = Category(str(item.get("category") or "quality").lower())
        except ValueError:
            category = Category.QUALITY
        skip_comments = item.get("skip_comments")
        compiled.append(
            PatternRule(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category=category,
                pattern=pattern,
                message=str(item.get("message") or title),
                remediation=str(item.get("remediation") or "按团队规范修改。"),
                cwe=str(item["cwe"]) if item.get("cwe") else None,
                suffixes=suffixes,
                names=names,
                skip_comments=True if skip_comments is None else bool(skip_comments),
            )
        )
        seen.add(rule_id)
    return tuple(compiled), errors


def _as_suffixes(raw: object) -> frozenset[str] | None:
    if not isinstance(raw, list) or not raw:
        return None
    items: list[str] = []
    for item in raw:
        text = str(item).strip().lower()
        if not text:
            continue
        if not text.startswith("."):
            text = "." + text
        items.append(text)
    return frozenset(items) or None


def _as_names(raw: object) -> frozenset[str] | None:
    if not isinstance(raw, list) or not raw:
        return None
    items = [str(item).strip() for item in raw if str(item).strip()]
    return frozenset(items) or None


def _parse_simple_toml(text: str) -> dict[str, object]:
    result: dict[str, object] = {}
    current: dict[str, object] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[[") and line.endswith("]]"):
            name = line[2:-2].strip()
            bucket = result.setdefault(name, [])
            if not isinstance(bucket, list):
                bucket = []
                result[name] = bucket
            current = {}
            bucket.append(current)
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            current = {}
            result[name] = current
            continue
        match = _ASSIGN.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        target = current if current is not None else result
        target[key] = _parse_toml_value(value)
    return result


def _parse_toml_value(value: str) -> object:
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_toml_value(part.strip()) for part in _split_toml_list(inner)]
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return _unquote(value)
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def _split_toml_list(inner: str) -> list[str]:
    items: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    for char in inner:
        if quote:
            buf.append(char)
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
            buf.append(char)
            continue
        if char == ",":
            part = "".join(buf).strip()
            if part:
                items.append(part)
            buf = []
            continue
        buf.append(char)
    part = "".join(buf).strip()
    if part:
        items.append(part)
    return items


def _unquote(value: str) -> str:
    inner = value[1:-1]
    if value.startswith("'"):
        return inner
    return (
        inner.replace("\\\\", "\0")
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace('\\"', '"')
        .replace("\0", "\\")
    )
