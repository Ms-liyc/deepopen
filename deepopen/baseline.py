"""Accepted-finding baseline so known issues don't fail CI."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from deepopen.config import find_config_dir
from deepopen.models import Finding

BASELINE_NAME = ".deepopen-baseline.json"


def baseline_path(start: Path, explicit: Path | None = None) -> Path:
    if explicit:
        return explicit
    root = start if start.is_dir() else start.parent
    return root / BASELINE_NAME


def load_fingerprints(start: Path, explicit: Path | None = None) -> set[str]:
    fingerprints: set[str] = set()
    paths = [baseline_path(start, explicit)]
    if explicit is None:
        cfg_dir = find_config_dir(start)
        if cfg_dir is not None:
            paths.append(cfg_dir / BASELINE_NAME)
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        fingerprints.update(_read_fingerprints(path))
    return fingerprints


def _read_fingerprints(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    items = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return set()
    fingerprints: set[str] = set()
    for item in items:
        if isinstance(item, dict) and item.get("fingerprint"):
            fingerprints.add(str(item["fingerprint"]))
    return fingerprints


def apply_baseline(
    findings: list[Finding],
    start: Path,
    hide: bool,
    explicit: Path | None = None,
) -> tuple[list[Finding], int]:
    known = load_fingerprints(start, explicit)
    if not known:
        return findings, 0
    kept: list[Finding] = []
    hidden = 0
    for item in findings:
        if item.fingerprint() not in known:
            kept.append(item)
            continue
        hidden += 1
        if not hide:
            kept.append(replace(item, baselined=True))
    return kept, hidden


def save_baseline(start: Path, findings: list[Finding], explicit: Path | None = None) -> Path:
    path = baseline_path(start, explicit)
    records: dict[str, dict[str, object]] = {}
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for item in data.get("findings") or []:
                if isinstance(item, dict) and item.get("fingerprint"):
                    records[str(item["fingerprint"])] = item
        except (OSError, json.JSONDecodeError, AttributeError):
            records = {}
    for item in findings:
        records[item.fingerprint()] = {
            "fingerprint": item.fingerprint(),
            "rule_id": item.rule_id,
            "path": item.path,
            "line": item.line,
            "title": item.title,
        }
    payload = {
        "version": 1,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": list(records.values()),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path
