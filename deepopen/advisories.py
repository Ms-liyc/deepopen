"""Dependency advisories: offline known-bad names, optional OSV lookup."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from deepopen.config import Config
from deepopen.models import Category, Finding, Severity

OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT = 8
OSV_LIMIT = 20

# 历史上被投毒或大规模滥用的包名。不是完整 CVE 库。
MALICIOUS_PACKAGES = {
    ("npm", "event-stream"),
    ("npm", "flatmap-stream"),
    ("PyPI", "ctx"),
}

_REQ_LINE = re.compile(
    r"""^\s*(?:-e\s+)?(?:[A-Za-z0-9._-]+@)?(?:git\+\S+\s+)?([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:==|===)\s*([A-Za-z0-9_.+-]+)"""
)
_REQ_NAME = re.compile(r"""^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:==|>=|<=|~=|===|>|<)?""")
_GO_LINE = re.compile(r"^([A-Za-z0-9./_-]+)\s+v?([0-9][^\s]+)\s*(?://.*)?$")


def analyze_dependencies(root: Path, config: Config | None = None) -> list[Finding]:
    cfg = config or Config()
    deps = _collect_deps(root)
    findings: list[Finding] = []
    for dep in deps:
        key = (dep["ecosystem"], dep["name"].lower())
        if key in MALICIOUS_PACKAGES:
            findings.append(
                _hit(
                    Path(dep["path"]),
                    int(dep["line"]),
                    dep["snippet"],
                    "ADV002",
                    "依赖名属于已知被投毒/滥用包",
                    Severity.HIGH,
                    Category.SECURITY,
                    f"{dep['name']} 曾出现过供应链投毒或恶意版本，不要继续使用。",
                    "移除该依赖，改用维护中的替代库，并检查 lock 文件是否被改写。",
                    "CWE-1357",
                )
            )
    if cfg.advisories:
        findings.extend(_query_osv(deps))
    return findings


def _collect_deps(root: Path) -> list[dict[str, str]]:
    if root.is_file():
        root = root.parent
    deps: list[dict[str, str]] = []
    mapping = (
        ("requirements.txt", _from_requirements, "PyPI"),
        ("pyproject.toml", _from_pyproject, "PyPI"),
        ("package.json", _from_package_json, "npm"),
        ("go.mod", _from_go_mod, "Go"),
    )
    for name, parser, eco in mapping:
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        deps.extend(parser(path, text, eco))
    return deps


def _from_requirements(path: Path, text: str, eco: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        pinned = _REQ_LINE.match(line)
        if pinned:
            rows.append(_dep(path, index, line, eco, pinned.group(1), pinned.group(2)))
            continue
        named = _REQ_NAME.match(line)
        if named:
            rows.append(_dep(path, index, line, eco, named.group(1), ""))
    return rows


def _from_pyproject(path: Path, text: str, eco: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    in_deps = False
    for index, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_deps = "dependencies" in stripped.lower()
            continue
        if re.match(r"^(?:dependencies|dev-dependencies)\s*=", stripped, re.I):
            in_deps = True
        if not in_deps:
            continue
        for match in re.finditer(
            r"""["']([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?(?:\s*==\s*([A-Za-z0-9_.+-]+))?["']""",
            raw,
        ):
            rows.append(_dep(path, index, stripped, eco, match.group(1), match.group(2) or ""))
    return rows


def _from_package_json(path: Path, text: str, eco: str) -> list[dict[str, str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows: list[dict[str, str]] = []
    for field in ("dependencies", "devDependencies"):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            version = str(spec).lstrip("^~>=< ")
            rows.append(_dep(path, 1, f"{name}: {spec}", eco, str(name), version))
    return rows


def _from_go_mod(path: Path, text: str, eco: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    in_block = False
    for index, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        line = stripped[8:].strip() if stripped.startswith("require ") and not stripped.startswith("require (") else stripped
        if not (in_block or stripped.startswith("require ")):
            continue
        match = _GO_LINE.match(line)
        if match:
            rows.append(_dep(path, index, stripped, eco, match.group(1), match.group(2)))
    return rows


def _dep(path: Path, line: int, snippet: str, eco: str, name: str, version: str) -> dict[str, str]:
    return {
        "path": str(path),
        "line": str(line),
        "snippet": snippet[:240],
        "ecosystem": "npm" if eco == "npm" else ("Go" if eco == "Go" else "PyPI"),
        "name": name,
        "version": version,
    }


def _query_osv(deps: list[dict[str, str]]) -> list[Finding]:
    queries = []
    used: list[dict[str, str]] = []
    for dep in deps:
        if not dep["version"] or not dep["version"][:1].isdigit() or len(queries) >= OSV_LIMIT:
            continue
        queries.append(
            {
                "package": {"name": dep["name"], "ecosystem": dep["ecosystem"]},
                "version": dep["version"].lstrip("v"),
            }
        )
        used.append(dep)
    if not queries:
        return []
    payload = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        OSV_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "DeepOpen-defensive-scanner"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return []
    results = body.get("results") if isinstance(body, dict) else None
    if not isinstance(results, list):
        return []
    findings: list[Finding] = []
    for dep, item in zip(used, results):
        if not isinstance(item, dict):
            continue
        vulns = item.get("vulns")
        if not isinstance(vulns, list) or not vulns:
            continue
        first = vulns[0] if isinstance(vulns[0], dict) else {}
        ident = str(first.get("id") or "OSV")
        findings.append(
            _hit(
                Path(dep["path"]),
                int(dep["line"]),
                dep["snippet"],
                "ADV001",
                "依赖版本存在公开安全公告",
                Severity.HIGH,
                Category.SECURITY,
                f"{dep['name']}=={dep['version']} 命中公开公告 {ident}（共 {len(vulns)} 条）。",
                "升级到公告中的已修复版本，并重新锁定依赖。完整持续审计仍建议搭配 pip-audit / npm audit。",
                "CWE-1395",
            )
        )
    return findings


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
    cwe: str | None = None,
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
        cwe=cwe,
    )
