"""Go 常见不安全写法。"""

from __future__ import annotations

from deepopen.models import Category, Severity
from deepopen.patterns.base import PatternRule, compile_re as _re

GO = frozenset({".go"})

GO_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="GO001",
        title="shell 执行拼接命令",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"""exec\.Command\s*\(\s*['\"](?:/?bin/)?(?:ba)?sh['\"]\s*,\s*['\"]-c['\"]"""),
        message="sh -c 会把整段字符串交给 shell。",
        remediation="直接 exec.Command(prog, arg...)，不要经过 shell。",
        cwe="CWE-78",
        suffixes=GO,
    ),
    PatternRule(
        rule_id="GO002",
        title="TLS InsecureSkipVerify",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"InsecureSkipVerify\s*:\s*true"),
        message="跳过证书校验会导致中间人替换无法被发现。",
        remediation="保持校验；自签场景加载指定 CA。",
        cwe="CWE-295",
        suffixes=GO,
    ),
    PatternRule(
        rule_id="GO003",
        title="fmt.Sprintf 拼接 SQL",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"""fmt\.Sprintf\s*\(\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)\b"""),
        message="用 Sprintf 拼 SQL 会破坏查询结构。",
        remediation="使用数据库驱动的占位符参数。",
        cwe="CWE-89",
        suffixes=GO,
    ),
    PatternRule(
        rule_id="GO004",
        title="弱哈希 md5/sha1",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        pattern=_re(r"\bmd5\.(?:Sum|New)\b|\bsha1\.(?:Sum|New)\b"),
        message="MD5/SHA1 不适合口令或新的完整性方案。",
        remediation="口令用专用 KDF；完整性用 SHA-256 及以上。",
        cwe="CWE-328",
        suffixes=GO,
    ),
    PatternRule(
        rule_id="GO005",
        title="math/rand 用于可能的安全场景",
        severity=Severity.LOW,
        category=Category.SECURITY,
        pattern=_re(r"\bmath/rand\b"),
        message="math/rand 不是密码学安全随机源。",
        remediation="令牌、会话 ID 使用 crypto/rand。",
        cwe="CWE-330",
        suffixes=GO,
    ),
    PatternRule(
        rule_id="GO006",
        title="ListenAndServe 未配置超时",
        severity=Severity.MEDIUM,
        category=Category.BUG,
        pattern=_re(r"\bhttp\.ListenAndServe\s*\("),
        message="默认 HTTP 服务没有读写超时，慢连接会占住工作线程。",
        remediation="改用 http.Server 并设置 ReadTimeout / WriteTimeout / IdleTimeout。",
        cwe="CWE-400",
        suffixes=GO,
    ),
    PatternRule(
        rule_id="GO007",
        title="template.HTML 跳过转义",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\btemplate\.HTML\s*\("),
        message="template.HTML 会把字符串当已安全 HTML 插入。",
        remediation="默认交给模板转义；必须输出 HTML 时先消毒。",
        cwe="CWE-79",
        suffixes=GO,
    ),
    PatternRule(
        rule_id="GO008",
        title="Chmod 0777",
        severity=Severity.MEDIUM,
        category=Category.CONFIG,
        pattern=_re(r"\b(?:os\.)?Chmod\s*\([^)]*(?:0o777|0777|0x1ff)"),
        message="0777 让任意用户可写。",
        remediation="按最小权限设置，例如 0644 / 0755。",
        cwe="CWE-732",
        suffixes=GO,
    ),
)
