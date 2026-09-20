"""Whole-file analyzers for manifests and Dockerfiles."""

from __future__ import annotations

import json
import re
from pathlib import Path

from deepopen.models import Category, Finding, Severity

_PY_BARE_DEP = re.compile(
    r"""^[\s,]*["']([A-Za-z0-9_.-]+)(\[[^\]]+\])?["']\s*,?\s*(?:#.*)?$"""
)
_PY_PINNED_DEP = re.compile(
    r"""["'][A-Za-z0-9_.-]+(?:\[[^\]]+\])?\s*(==|>=|<=|~=|!=|>|<|@)"""
)
_GO_REQUIRE = re.compile(r"^require\s+(\S+)(?:\s+(\S+))?\s*(?://.*)?$")
_GO_MOD_LINE = re.compile(r"^(\S+)\s+(\S+)\s*(?://.*)?$")
_GO_MOD_ONLY = re.compile(r"^(\S+)\s*(?://.*)?$")
_CARGO_STAR = re.compile(
    r"""^\s*[A-Za-z0-9_-]+\s*=\s*['\"](?:\*|latest)['\"]|version\s*=\s*['\"](?:\*|latest)['\"]""",
    re.IGNORECASE,
)
_WRITE_ALL = re.compile(r"(?i)permissions\s*:\s*write-all")
_ENV_SKIP = ("example", "sample", "template", "dummy", "dist")


def analyze_manifest(path: Path, source: str) -> list[Finding]:
    name = path.name.lower()
    if name == "dockerfile" or name == "containerfile":
        return _dockerfile(path, source)
    if name == "requirements.txt":
        return _requirements(path, source)
    if name == "package.json":
        return _package_json(path, source)
    if name == "pyproject.toml":
        return _pyproject(path, source)
    if name == "go.mod":
        return _go_mod(path, source)
    if name == "cargo.toml":
        return _cargo_toml(path, source)
    if name == "redis.conf":
        return _redis_conf(path, source)
    if name == "settings.py" or name.endswith("settings.py"):
        return _django_settings(path, source)
    if _is_dotenv_name(name):
        return [_env_committed(path, source)]
    if _is_github_workflow(path) and name.endswith((".yml", ".yaml")):
        return _github_workflow(path, source)
    return []


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


def _dockerfile(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    has_user = False
    for index, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if stripped.upper().startswith("USER ") and stripped.split(None, 1)[-1] not in {"root", "0"}:
            has_user = True
        if re.match(r"(?i)^FROM\s+\S+:latest\b", stripped) or re.match(r"(?i)^FROM\s+[^\s:]+\s*$", stripped):
            findings.append(
                _hit(
                    path, index, stripped, "DK005", "基础镜像未钉标签",
                    Severity.LOW, Category.CONFIG,
                    "使用 latest 或未写标签时，构建不可复现。",
                    "把 FROM 钉到明确版本或摘要。",
                    "CWE-494",
                )
            )
        if re.match(r"(?i)^ADD\s+https?://", stripped):
            findings.append(
                _hit(
                    path, index, stripped, "DK003", "Dockerfile ADD 远程 URL",
                    Severity.MEDIUM, Category.CONFIG,
                    "ADD 远程 URL 缺少完整性校验。",
                    "先下载并校验校验和，再用 COPY 放入镜像。",
                    "CWE-494",
                )
            )
    if not has_user:
        findings.append(
            _hit(
                path, 1, lines[0].strip() if lines else "FROM", "DK004",
                "Dockerfile 未切换非 root 用户",
                Severity.LOW, Category.CONFIG,
                "未发现非 root 的 USER 指令。",
                "创建普通用户并在最后用 USER 切换。",
                "CWE-250",
            )
        )
    return findings


def _requirements(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for index, raw in enumerate(source.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if re.fullmatch(r"[A-Za-z0-9_.-]+", line):
            findings.append(_unpinned_python(path, index, line))
    return findings


def _unpinned_python(path: Path, line: int, snippet: str) -> Finding:
    return _hit(
        path, line, snippet, "DEP002", "Python 依赖未钉版本",
        Severity.INFO, Category.CONFIG,
        "未固定版本的依赖在安装时可能被换成含缺陷的版本。",
        "使用 == 钉版本，或改用锁定文件（pip-tools / uv.lock / poetry.lock）。",
    )


def _package_json(path: Path, source: str) -> list[Finding]:
    try:
        data = json.loads(source)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    for field in ("dependencies", "devDependencies"):
        deps = data.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if spec in {"*", "latest"}:
                findings.append(
                    _hit(
                        path, 1, f"{name}: {spec}", "DEP003", "npm 依赖使用 * / latest",
                        Severity.MEDIUM, Category.CONFIG,
                        "浮动到 latest 会使构建不可复现，也可能装上含缺陷版本。",
                        "钉到明确版本，并提交 lock 文件。",
                    )
                )
    return findings


def _pyproject(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    in_optional = False
    in_array = False
    for index, raw in enumerate(source.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            key = stripped[1:-1].lower()
            in_optional = "optional-dependencies" in key or key in {"dependencies", "dev-dependencies"}
            in_array = False
            continue
        if re.search(r"(?i)\b(?:optional-)?dependencies\s*=\s*\[", stripped):
            in_array = "]" not in stripped.split("[", 1)[-1]
            for snippet in _quoted_packages(stripped):
                if not _PY_PINNED_DEP.search(f'"{snippet}"') and "==" not in snippet and ">=" not in snippet:
                    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", snippet):
                        findings.append(_unpinned_python(path, index, stripped))
            continue
        if in_optional and re.search(r"^\w+\s*=\s*\[", stripped):
            in_array = "]" not in stripped.split("[", 1)[-1]
            for snippet in _quoted_packages(stripped):
                if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", snippet):
                    findings.append(_unpinned_python(path, index, stripped))
            continue
        if in_array:
            if stripped.startswith("]"):
                in_array = False
                continue
            match = _PY_BARE_DEP.match(stripped)
            if match and not _PY_PINNED_DEP.search(stripped):
                findings.append(_unpinned_python(path, index, stripped))
            if stripped.endswith("]") and not stripped.startswith("["):
                in_array = False
    return findings


def _redis_conf(path: Path, source: str) -> list[Finding]:
    if re.search(r"(?im)^requirepass\s+\S+", source):
        return []
    first = source.splitlines()[0].strip() if source.strip() else path.name
    return [
        _hit(
            path, 1, first or path.name, "CFG007", "Redis 未设置 requirepass",
            Severity.HIGH, Category.CONFIG,
            "redis.conf 里没有有效的 requirepass，未授权客户端可能读写数据。",
            "设置 requirepass，绑定内网地址，并保持 protected-mode yes。",
            "CWE-306",
        )
    ]


def _django_settings(path: Path, source: str) -> list[Finding]:
    if "INSTALLED_APPS" not in source or "MIDDLEWARE" not in source:
        return []
    line = 1
    for index, raw in enumerate(source.splitlines(), start=1):
        if "MIDDLEWARE" in raw:
            line = index
            break
    snippet = source.splitlines()[line - 1].strip() if source.splitlines() else path.name
    findings: list[Finding] = []
    if "CsrfViewMiddleware" not in source:
        findings.append(
            _hit(
                path, line, snippet, "AUTH010", "Django 中间件缺少 CSRF 保护",
                Severity.HIGH, Category.SECURITY,
                "settings 里有 MIDDLEWARE，但没有 CsrfViewMiddleware。",
                "把 django.middleware.csrf.CsrfViewMiddleware 加回中间件列表。",
                "CWE-352",
            )
        )
    if "AuthenticationMiddleware" not in source:
        findings.append(
            _hit(
                path, line, snippet, "AUTH011", "Django 中间件缺少认证",
                Severity.HIGH, Category.SECURITY,
                "settings 里有 MIDDLEWARE，但没有 AuthenticationMiddleware。",
                "把 django.contrib.auth.middleware.AuthenticationMiddleware 加回中间件列表。",
                "CWE-306",
            )
        )
    return findings


def _quoted_packages(line: str) -> list[str]:
    return re.findall(r"""["']([A-Za-z0-9][A-Za-z0-9_.-]*)["']""", line)


def _go_mod(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    in_block = False
    for index, raw in enumerate(source.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("require ") and not stripped.startswith("require ("):
            match = _GO_REQUIRE.match(stripped)
            if match and (match.group(2) is None or match.group(2).lower() == "latest"):
                findings.append(_go_unpinned(path, index, stripped))
            continue
        if in_block:
            if stripped.lower().endswith(" latest") or _GO_MOD_ONLY.match(stripped) and not _GO_MOD_LINE.match(stripped):
                findings.append(_go_unpinned(path, index, stripped))
            elif _GO_MOD_LINE.match(stripped) and stripped.split()[-1].lower() == "latest":
                findings.append(_go_unpinned(path, index, stripped))
    return findings


def _go_unpinned(path: Path, line: int, snippet: str) -> Finding:
    return _hit(
        path, line, snippet, "DEP004", "Go 模块未钉版本",
        Severity.MEDIUM, Category.CONFIG,
        "go.mod 中的依赖缺少版本或使用了 latest。",
        "写成 module vX.Y.Z，并提交 go.sum。",
    )


def _cargo_toml(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    in_deps = False
    for index, raw in enumerate(source.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1].lower()
            in_deps = name in {"dependencies", "dev-dependencies", "build-dependencies"} or name.endswith(".dependencies")
            continue
        if in_deps and _CARGO_STAR.search(stripped):
            findings.append(
                _hit(
                    path, index, stripped, "DEP005", "Cargo 依赖使用 * / latest",
                    Severity.MEDIUM, Category.CONFIG,
                    "未钉版本会使构建不可复现。",
                    "写成明确 semver，例如 \"1.0\"，并提交 Cargo.lock。",
                )
            )
    return findings


def _is_dotenv_name(name: str) -> bool:
    if not name.startswith(".env"):
        return False
    return not any(marker in name for marker in _ENV_SKIP)


def _env_committed(path: Path, source: str) -> Finding:
    first = source.splitlines()[0].strip() if source.strip() else path.name
    return _hit(
        path, 1, first or path.name, "ENV001", "仓库中出现环境文件",
        Severity.MEDIUM, Category.SECRET,
        "真实 .env 容易把口令和主机名一并提交进版本库。",
        "加入 .gitignore；只提交 .env.example，真实值放密钥托管。",
        "CWE-260",
    )


def _is_github_workflow(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    return ".github" in parts and "workflows" in parts


def _github_workflow(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for index, raw in enumerate(source.splitlines(), start=1):
        if _WRITE_ALL.search(raw):
            findings.append(
                _hit(
                    path, index, raw.strip(), "GH002", "GitHub Actions 权限 write-all",
                    Severity.HIGH, Category.CONFIG,
                    "write-all 让工作流拿到仓库几乎全部写权限。",
                    "按需授予最小权限，例如 contents: read。",
                    "CWE-250",
                )
            )
    return findings
