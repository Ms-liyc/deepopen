"""C/C++、Rust、SQL 等额外语言规则。"""

from __future__ import annotations

from deepopen.models import Category, Severity
from deepopen.patterns.base import PatternRule, compile_re as _re

C_FAM = frozenset({".c", ".cc", ".cpp", ".h", ".hpp"})
RUST = frozenset({".rs"})
SQL = frozenset({".sql"})
KT = frozenset({".kt"})

C_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="C001",
        title="使用 gets",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\bgets\s*\("),
        message="gets 无法限制长度，缓冲区可能被写穿。",
        remediation="改用 fgets，并传入缓冲区大小。",
        cwe="CWE-120",
        suffixes=C_FAM,
    ),
    PatternRule(
        rule_id="C002",
        title="strcpy / sprintf 无界拷贝",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\b(?:strcpy|strcat|sprintf|scanf)\s*\("),
        message="这些函数不检查目标缓冲区长度。",
        remediation="改用带长度参数的 API（strncpy_s / snprintf / scanf 宽度限制）。",
        cwe="CWE-120",
        suffixes=C_FAM,
    ),
    PatternRule(
        rule_id="C003",
        title="C 库 system() 执行命令",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\bsystem\s*\("),
        message="system() 把字符串交给 shell。",
        remediation="用 execve 一类按参数数组启动进程，并对参数做白名单。",
        cwe="CWE-78",
        suffixes=C_FAM,
    ),
    PatternRule(
        rule_id="C004",
        title="if 条件里赋值",
        severity=Severity.MEDIUM,
        category=Category.BUG,
        pattern=_re(r"\bif\s*\(\s*\w+\s*=\s*[^=]"),
        message="条件里的 = 是赋值，常常是把 == 写成了 =。",
        remediation="比较用 ==；若确实要赋值，写成独立语句再判断。",
        suffixes=C_FAM,
    ),
)

RUST_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="RS001",
        title="通过 shell 启动进程",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"""Command::new\s*\(\s*['\"](?:/?bin/)?(?:ba)?sh['\"]"""),
        message="先启动 shell 再执行字符串，命令结构可能被改写。",
        remediation="Command::new(程序).args(参数列表)，不要经过 sh -c。",
        cwe="CWE-78",
        suffixes=RUST,
    ),
    PatternRule(
        rule_id="RS002",
        title="mem::transmute",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        pattern=_re(r"mem::transmute"),
        message="transmute 绕过类型系统，容易造成内存安全问题。",
        remediation="优先用安全抽象或 bytemuck 一类受约束转换。",
        cwe="CWE-704",
        suffixes=RUST,
    ),
    PatternRule(
        rule_id="RS003",
        title="unwrap / expect 丢掉错误上下文",
        severity=Severity.LOW,
        category=Category.BUG,
        pattern=_re(r"\.(?:unwrap|expect)\s*\("),
        message="unwrap 在 Err 时会 panic，调用方无法恢复。",
        remediation="用 ? 向上传递，或 match 后返回明确错误。",
        suffixes=RUST,
    ),
)

SQL_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="SQL001",
        title="GRANT ALL 过宽授权",
        severity=Severity.MEDIUM,
        category=Category.CONFIG,
        pattern=_re(r"\bGRANT\s+ALL\b"),
        message="把全部权限授出会扩大账号失陷后的影响。",
        remediation="按对象授予最小权限。",
        cwe="CWE-250",
        suffixes=SQL,
    ),
    PatternRule(
        rule_id="SQL002",
        title="SQL 脚本含明文口令",
        severity=Severity.HIGH,
        category=Category.SECRET,
        pattern=_re(r"IDENTIFIED\s+BY\s+'[^']+'"),
        message="脚本里写了数据库口令。",
        remediation="改用密钥托管或启动时注入，不要把真实口令提交进仓库。",
        cwe="CWE-798",
        suffixes=SQL,
    ),
    PatternRule(
        rule_id="SQL003",
        title="DELETE 缺少 WHERE",
        severity=Severity.HIGH,
        category=Category.BUG,
        pattern=_re(r"\bDELETE\s+FROM\s+\S+\s*;"),
        message="没有 WHERE 的 DELETE 会清掉整张表。",
        remediation="加上精确的 WHERE，或改用显式的 TRUNCATE 并经审批。",
        suffixes=SQL,
    ),
    PatternRule(
        rule_id="SQL004",
        title="UPDATE 缺少 WHERE",
        severity=Severity.HIGH,
        category=Category.BUG,
        pattern=_re(r"\bUPDATE\s+\S+\s+SET\b(?![^;]*\bWHERE\b)"),
        message="没有 WHERE 的 UPDATE 会改写全部行。",
        remediation="加上精确的 WHERE，先 SELECT 确认范围。",
        suffixes=SQL,
    ),
    PatternRule(
        rule_id="SQL005",
        title="INSERT 未写列名",
        severity=Severity.LOW,
        category=Category.QUALITY,
        pattern=_re(r"\bINSERT\s+INTO\s+\S+\s+VALUES\b"),
        message="不写列名时，表结构一变插入就会错位。",
        remediation="写成 INSERT INTO t (col1, col2) VALUES (...)。",
        suffixes=SQL,
    ),
)

KOTLIN_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="KT001",
        title="Kotlin 拼接 SQL",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"""(?:execSQL|rawQuery)\s*\(\s*\"[^\"]*\$"""),
        message="把变量插进 SQL 字符串会破坏查询结构。",
        remediation="使用占位符 ? 绑定参数。",
        cwe="CWE-89",
        suffixes=KT,
    ),
)
