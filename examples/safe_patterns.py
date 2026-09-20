"""Clean control file: scanner should not flag this module."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def load_config(raw: str) -> dict:
    return json.loads(raw)


def run_query(conn: sqlite3.Connection, name: str) -> list[tuple]:
    cur = conn.execute("SELECT id, name FROM users WHERE name = ?", (name,))
    return list(cur.fetchall())


def add_item(items: list[int] | None = None) -> list[int]:
    if items is None:
        items = []
    items.append(1)
    return items


def maybe_value(value: object) -> bool:
    return value is None


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"cannot read {path}") from exc
