"""PHP / Ruby / C# 常见不安全写法。"""

from __future__ import annotations

from deepopen.models import Category, Severity
from deepopen.patterns.base import PatternRule, compile_re as _re

PHP = frozenset({".php"})
RUBY = frozenset({".rb"})
CS = frozenset({".cs"})

PHP_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="PHP001",
        title="eval / assert 执行字符串",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\b(?:eval|assert)\s*\("),
        message="把字符串当 PHP 代码执行。",
        remediation="用明确分支或安全解析；不要对请求参数 eval。",
        cwe="CWE-95",
        suffixes=PHP,
    ),
    PatternRule(
        rule_id="PHP002",
        title="unserialize 不可信数据",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\bunserialize\s*\("),
        message="PHP 反序列化可触发对象魔术方法。",
        remediation="对外数据用 json_decode；必须序列化时校验来源并限制允许的类。",
        cwe="CWE-502",
        suffixes=PHP,
    ),
    PatternRule(
        rule_id="PHP003",
        title="include/require 使用请求参数",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\b(?:include|require|include_once|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)"),
        message="把请求参数当文件路径包含，会加载非预期文件。",
        remediation="用白名单映射到固定文件，不要直接拿用户输入当路径。",
        cwe="CWE-98",
        suffixes=PHP,
    ),
    PatternRule(
        rule_id="PHP004",
        title="命令执行函数",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\b(?:system|shell_exec|passthru|popen|proc_open|exec)\s*\("),
        message="这些函数会把字符串交给系统命令执行。",
        remediation="避免调用系统命令；必须调用时使用参数数组/转义 API，并做白名单。",
        cwe="CWE-78",
        suffixes=PHP,
    ),
    PatternRule(
        rule_id="PHP005",
        title="SQL 拼接请求参数",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"""(?:mysql_query|mysqli_query|->query)\s*\([^;]*\$_(?:GET|POST|REQUEST)"""),
        message="把请求参数拼进 SQL。",
        remediation="使用预处理语句绑定参数。",
        cwe="CWE-89",
        suffixes=PHP,
    ),
    PatternRule(
        rule_id="PHP006",
        title="extract 导入请求数组",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"),
        message="extract 会把请求字段变成变量，覆盖现有状态。",
        remediation="不要 extract 超全局数组；显式读取需要的字段并校验。",
        cwe="CWE-621",
        suffixes=PHP,
    ),
)

RUBY_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="RB001",
        title="Ruby eval / send 动态代码",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\beval\s*\(|\binstance_eval\s*(?:\{|\()|\bclass_eval\s*"),
        message="动态执行或改类可能把不可信输入变成代码。",
        remediation="用白名单方法和明确分支替代。",
        cwe="CWE-95",
        suffixes=RUBY,
    ),
    PatternRule(
        rule_id="RB002",
        title="YAML.load / Marshal.load",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\b(?:YAML|Psych)\.load\s*\(|\bMarshal\.load\s*\("),
        message="未安全加载 YAML/Marshal 可能还原意外对象。",
        remediation="YAML 使用 safe_load；不要 Marshal 不可信数据。",
        cwe="CWE-502",
        suffixes=RUBY,
    ),
    PatternRule(
        rule_id="RB003",
        title="system / 反引号插值",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"""\b(?:system|exec|`)\s*\(?['\"][^'\"]*#\{"""),
        message="命令字符串插值会改变命令结构。",
        remediation="使用数组形式调用系统命令，并对参数做白名单。",
        cwe="CWE-78",
        suffixes=RUBY,
    ),
)

CSHARP_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="CS001",
        title="Process.Start 拼接命令",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"Process\.Start\s*\([^)]*\+|ProcessStartInfo\s*\([^)]*\+"),
        message="命令或参数拼接会改变进程启动结构。",
        remediation="分别设置 FileName 与 ArgumentList，不要拼成一条命令行。",
        cwe="CWE-78",
        suffixes=CS,
    ),
    PatternRule(
        rule_id="CS002",
        title="SqlCommand 拼接 SQL",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"(?:SqlCommand|Execute(?:Reader|NonQuery|Scalar))\s*\([^)]*\+"),
        message="用 + 拼 SQL 会破坏查询结构。",
        remediation="使用参数化 SqlParameter。",
        cwe="CWE-89",
        suffixes=CS,
    ),
    PatternRule(
        rule_id="CS003",
        title="BinaryFormatter 反序列化",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"new\s+BinaryFormatter\s*\(|BinaryFormatter\(\)\.Deserialize"),
        message="BinaryFormatter 已被视为不安全。",
        remediation="改用数据契约或 JSON；不要反序列化不可信流。",
        cwe="CWE-502",
        suffixes=CS,
    ),
    PatternRule(
        rule_id="CS004",
        title="Html.Raw / 关闭请求验证",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"Html\.Raw\s*\(|ValidateInput\s*\(\s*false\s*\)|\[AllowHtml\]"),
        message="输出原始 HTML 或关闭输入校验会绕过框架保护。",
        remediation="默认编码输出；富文本先消毒。",
        cwe="CWE-79",
        suffixes=CS,
    ),
)
