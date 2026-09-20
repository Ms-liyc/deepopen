"""HTML、HTTP、Cookie、CSP 相关模式。"""

from __future__ import annotations

from deepopen.models import Category, Severity
from deepopen.patterns.base import PatternRule, compile_re as _re

CODE = frozenset({
    ".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php", ".rb", ".cs",
})
HTML = frozenset({".html", ".htm", ".vue", ".jsx", ".tsx"})

WEB_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="WEB001",
        title="明文 HTTP 端点",
        severity=Severity.LOW,
        category=Category.SECURITY,
        pattern=_re(r"""['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'\"]+['\"]"""),
        message="代码里硬编码了 http:// 外部地址。",
        remediation="对外通信改用 HTTPS；本地开发用环境变量切换。",
        cwe="CWE-319",
        suffixes=CODE,
    ),
    PatternRule(
        rule_id="WEB002",
        title="target=_blank 缺少 rel",
        severity=Severity.LOW,
        category=Category.SECURITY,
        pattern=_re(r"""target\s*=\s*['\"]_blank['\"](?![^>]*(?:rel\s*=\s*['\"][^'\"]*noopener))"""),
        message="新窗口可能通过 window.opener 反向操作原页面。",
        remediation="加上 rel=\"noopener noreferrer\"。",
        cwe="CWE-1022",
        suffixes=HTML,
    ),
    PatternRule(
        rule_id="WEB003",
        title="内联事件处理器",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        pattern=_re(r"<[^>]*\son(?:click|error|load|mouseover)\s*="),
        message="内联事件处理器不利于 CSP，也容易混入未转义输入。",
        remediation="用 addEventListener；部署 CSP 禁止内联脚本。",
        cwe="CWE-79",
        suffixes=HTML,
    ),
    PatternRule(
        rule_id="WEB004",
        title="Cookie 未限制脚本访问",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        pattern=_re(r"""\bset[_-]cookie\s*\(|Set[-]Cookie:[^\n]*\b(?![^\n]*HttpOnly)"""),
        message="会话 cookie 若能被脚本读取，XSS 的影响会被放大。",
        remediation="会话 cookie 设置 HttpOnly、Secure、SameSite=Lax 或 Strict。",
        cwe="CWE-1004",
        suffixes=CODE | frozenset({".py"}),
    ),
    PatternRule(
        rule_id="WEB005",
        title="密码框开启自动填充",
        severity=Severity.LOW,
        category=Category.SECURITY,
        pattern=_re(
            r"<input[^>]*(?:type\s*=\s*['\"]password['\"][^>]*autocomplete\s*=\s*['\"]on['\"]|autocomplete\s*=\s*['\"]on['\"][^>]*type\s*=\s*['\"]password['\"])"
        ),
        message="密码框允许自动填充时，共享设备上的口令更容易被带出。",
        remediation="敏感表单使用 autocomplete=\"off\" 或更细的 token 值。",
        cwe="CWE-525",
        suffixes=HTML,
    ),
)
