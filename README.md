<div align="center">

# DeepOpen

**本地静态检查工具**

扫描**你自己的源码**，找出常见缺陷、密钥泄露和不安全写法，并给出加固建议。

### ✨ 当前版本 0.4.1

Python 3.10+ · 仅标准库 · 约 239 条规则

#### 🌟 项目亮点

🎨 **多语言规则** — Python、JS/TS、Java、Go、PHP、C/C++、Rust 等  
🔒 **防守检查** — 只给加固建议，不生成攻击步骤、PoC 或利用代码  
🖥️ **本机控制台** — 只监听 `127.0.0.1`，可导出 Markdown 修改方案  
📋 **工程接入** — 基线、钩子、GitHub Actions、自定义规则

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.4.1-3ee0b2)](https://github.com/Ms-liyc/deepopen)
[![Stdlib](https://img.shields.io/badge/deps-stdlib%20only-success)](https://github.com/Ms-liyc/deepopen)
[![Rules](https://img.shields.io/badge/rules-239-orange)](https://github.com/Ms-liyc/deepopen)
[![Stars](https://img.shields.io/github/stars/Ms-liyc/deepopen?style=flat)](https://github.com/Ms-liyc/deepopen/stargazers)
[![Issues](https://img.shields.io/github/issues/Ms-liyc/deepopen)](https://github.com/Ms-liyc/deepopen/issues)

它做的是防守检查，不是渗透测试。请在自己的仓库上运行。

#### ⚠️ 使用注意

❌ 不能发现鉴权设计、业务逻辑、运行时配置问题  
❌ 不能替代依赖 CVE 扫描（请另外使用 pip-audit / npm audit 等）  
❌ 不能替代代码评审和测试

> 扫描结果也不能证明「没有漏洞」。

</div>

## 它能做什么

- 🌐 **多语言规则**：Python（AST + 正则）、JavaScript/TypeScript、Java/Kotlin、Go、PHP、Ruby、C#、C/C++、Rust、SQL、HTML、Docker/K8s、Terraform、Shell
- 🔑 **密钥检测**：私钥、云厂商密钥、常见令牌形态、连接串口令、误提交的 `.env`
- 🐛 **缺陷检测**：裸 except、可变默认参数、资源泄漏、死代码、超时缺失等
- 📦 **清单分析**：`pyproject.toml` / `go.mod` / `Cargo.toml` 未钉版本，GitHub Actions `write-all`
- 🖥️ **本地控制台**：只监听 `127.0.0.1`，可筛选、看源码上下文、预览修复，并导出 Markdown 修改方案
- 📄 **报告**：终端 / JSON / HTML / Markdown / SARIF
- 🛠️ **基线与修复**：忽略已接受命中；`deepopen fix` 只改 `== None`、裸 `except` 这类质量问题
- ⚙️ **工程接入**：`deepopen.toml`、行内忽略、自定义规则、Git pre-commit、GitHub Actions

## 它不能代替什么

- ❌ 不能证明「没有漏洞」
- ❌ 不能发现鉴权设计、业务逻辑、运行时配置问题
- ❌ 不能替代依赖 CVE 扫描（请另外使用 pip-audit / npm audit 等）
- ❌ 不能替代代码评审和测试

## 安装

克隆后在项目目录执行：

```bash
pip install -e .
deepopen -V
```

开发（含 pytest）：

```bash
pip install -e ".[dev]"
python -m pytest
```

不安装也可以直接跑：

```bash
python -m deepopen scan .
```

## 30 秒上手

```bash
# 1. 检查当前仓库，high 及以上失败（适合 CI）
python -m deepopen scan . --fail-on high

# 2. 打开本机控制台
python -m deepopen serve .
```

浏览器访问 http://127.0.0.1:8765/ ，路径填要扫描的目录，点「开始检查」。检查完成后可点「导出修改方案」，下载一份说明有哪些问题、该怎么改的 Markdown 文件。控制台只绑定回环地址，不会对外网开放。

演示链接也可以带参数自动开扫：

```
http://127.0.0.1:8765/?path=.&autoscan=1
```

## 命令一览

| 命令 | 作用 |
| --- | --- |
| `deepopen scan [路径]` | 扫描目录或文件 |
| `deepopen serve [路径]` | 打开本机 Web 控制台 |
| `deepopen rules` | 列出全部规则 |
| `deepopen explain AST001` | 查看一条规则的说明和加固建议 |
| `deepopen checklist` | 打印开发加固清单 |
| `deepopen init [--with-ci]` | 生成 `deepopen.toml`、忽略文件，可选 GitHub Actions |
| `deepopen hook install` | 安装 Git pre-commit 钩子 |
| `deepopen fix [--apply]` | 预览 / 写回安全的质量修复 |
| `deepopen baseline save` | 把当前命中记入基线 |

常用扫描参数：

```bash
python -m deepopen scan . --fail-on high
python -m deepopen scan . --profile security
python -m deepopen scan . --staged
python -m deepopen scan . -o reports/report.html
python -m deepopen scan . -o reports/report.sarif --format text
python -m deepopen scan . --format json
python -m deepopen scan . --checklist
```

- `--fail-on`：`critical` / `high`（默认） / `medium` / `low` / `info` / `never`
- `--profile`：`all`（默认） / `security` / `bug` / `secret`
- `--staged`：只检查 Git 已暂存文件
- 默认出现 `high` 或 `critical` 时退出码为 1，方便接 CI；`--fail-on never` 只出报告不失败

## 扫描配置档

| 档位 | 包含 | 适用 |
| --- | --- | --- |
| `all` | 全部规则 | 本地完整检查 |
| `security` | 安全 / 密钥 / 配置 | CI 拦高风险写法 |
| `bug` | 缺陷 / 质量 | 提测前查正确性 |
| `secret` | 仅密钥 | 快速查口令、Token |

```bash
python -m deepopen scan . --profile security --fail-on high
```

控制台侧栏也可以切换配置档。

## 配置文件

仓库根目录放 `deepopen.toml`（`deepopen init` 会生成）：

```toml
fail_on = "high"
min_severity = "info"
profile = "all"
exclude = ["node_modules", "vendor"]
disable_rules = ["WEB001"]
hide_baseline = true

# [[rules]]
# id = "TEAM001"
# title = "禁止调试 print"
# pattern = "\\bprint\\s*\\("
# severity = "low"
# category = "quality"
# suffixes = [".py"]
```

也支持 `deepopen.json`。扫描时 `--profile` 会覆盖文件里的 `profile`。

### 自定义规则

- `id` 必须以 `CUSTOM`、`TEAM`、`ORG` 或 `LOCAL` 开头
- 必须指定 `suffixes` 或 `names`
- `pattern` 是正则；双引号字符串里反斜杠要写成 `\\`
- 与内置规则 ID 冲突、正则无效时会写入扫描错误，不会中断扫描

### 忽略与占位符

`.deepopenignore` 语法类似 gitignore。

某一行确定是误报：

```python
value = example()  # deepopen: ignore
value = example()  # deepopen: ignore AST001,PY001
```

占位符口令（如 `CHANGE_ME`）不会当成真实密钥。

## 基线与自动修复

把当前命中记入基线（下次扫描默认隐藏这些指纹）：

```bash
python -m deepopen baseline save .
python -m deepopen baseline show .
```

质量问题可自动改写（**安全类命中不会改文件**）：

```bash
python -m deepopen fix .          # 只预览
python -m deepopen fix . --apply  # 写回
```

目前支持：`== None` → `is None`，裸 `except:` → `except Exception:`。

## 报告格式

| 方式 | 命令 |
| --- | --- |
| 终端 | 默认 |
| HTML | `-o reports/report.html` |
| JSON | `--format json` 或 `-o out.json` |
| Markdown | `--format md` 或 `-o out.md`；控制台「导出修改方案」也会下载这份文件 |
| SARIF | `-o out.sarif`（可上传 GitHub Code Scanning） |

## 接入 CI 与 Git 钩子

```bash
python -m deepopen init --with-ci
python -m deepopen hook install
```

GitHub Actions 示例会跑 pytest，并以 `--fail-on high` 扫描仓库。工作流里也可以改成 `--profile security`。

Pre-commit 钩子对暂存文件做同样检查。

## 规则从哪来

| 位置 | 内容 |
| --- | --- |
| `deepopen/patterns/` | 各语言正则规则 |
| `deepopen/python_ast.py` | Python AST 检查 |
| `deepopen/analyzers.py` | Dockerfile、依赖清单、`.env`、Actions 权限 |
| `deepopen.toml` 的 `[[rules]]` | 仓库自己的规则 |

查看规则：

```bash
python -m deepopen rules
python -m deepopen explain AST001
```

新增规则时请补测试，说明里只写「如何改安全」，不要写攻击步骤。

## 开发

```bash
pip install -e ".[dev]"
python -m pytest
python -m deepopen scan . --fail-on high
```

本仓库自检（`scan .`）应保持干净。规则命中请用 `tests/` 里的片段验证。
