"""鉴权、业务逻辑与运行时配置的启发式规则。"""

from __future__ import annotations

from deepopen.models import Category, Severity
from deepopen.patterns.base import PatternRule, compile_re as _re

PY = frozenset({".py", ".pyw"})
JAVA = frozenset({".java", ".kt"})
JS = frozenset({".js", ".jsx", ".ts", ".tsx"})
YAML = frozenset({".yml", ".yaml"})
PROPS = frozenset({".properties", ".yml", ".yaml", ".conf", ".ini", ".env"})

AUTH_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="AUTH001",
        title="关闭 CSRF 保护",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"csrf" r"_exempt|csrf\(\)\s*\.disable\s*\(|csrf\s*\.disable\s*\("),
        message="关闭 CSRF 后，浏览器会把带身份的请求发到你的改状态接口。",
        remediation="保持 CSRF 中间件；对 API 用 SameSite cookie 或自定义头校验。",
        cwe="CWE-352",
        suffixes=PY | JAVA,
    ),
    PatternRule(
        rule_id="AUTH003",
        title="用请求体直接构造或更新模型",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(
            r"(?:\*\*?request\.(?:POST|data|json|query_params)|request\.(?:POST|data|json)\.dict\(\)|request\.all\(\))"
        ),
        message="把整份请求塞进模型可能改掉 is_admin、price 等本不该由客户端决定的字段。",
        remediation="用显式字段白名单或 serializer 声明可写属性。",
        cwe="CWE-915",
        suffixes=PY,
    ),
    PatternRule(
        rule_id="AUTH004",
        title="用请求参数当对象主键查询",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        pattern=_re(
            r"\.(?:objects\.)?(?:get|filter)\s*\(\s*(?:id|pk|user_id|uid|order_id)\s*=\s*(?:request\.|req\.|params\[)"
        ),
        message="仅按客户端传来的 ID 取对象，可能读到别人的数据。",
        remediation="查询时带上当前用户/租户条件，或先做对象级授权。",
        cwe="CWE-639",
        suffixes=PY,
    ),
    PatternRule(
        rule_id="AUTH005",
        title="金额或数量直接来自请求",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\b(?:price|amount|total|discount|quantity|qty|score)\s*=\s*request\."),
        message="价格、数量、积分若由客户端说了算，业务校验会被绕过。",
        remediation="这些字段只从服务端数据库或计价服务读取。",
        cwe="CWE-472",
        suffixes=PY,
    ),
    PatternRule(
        rule_id="AUTH006",
        title="管理员标记来自请求",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\b(?:is_admin|is_staff|is_superuser|role|roles)\s*=\s*request\."),
        message="把请求里的角色字段写进会话或模型，等于让用户自己授权。",
        remediation="角色只从服务端账号数据读取，不要接受客户端提交的 is_admin。",
        cwe="CWE-807",
        suffixes=PY,
    ),
    PatternRule(
        rule_id="AUTH007",
        title="接口允许匿名任意访问",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"permitAll\s*\(|AnyRequest\(\)\s*\.permitAll|permissions\.AllowAny|authentication_classes\s*=\s*\[\s*\]"),
        message="该配置会关掉登录校验。",
        remediation="默认为需认证；只对健康检查、登录等少数路由放开。",
        cwe="CWE-306",
        suffixes=PY | JAVA,
    ),
    PatternRule(
        rule_id="AUTH013",
        title="跳过授权检查",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"skip_authorization\s*=\s*True|check_auth\s*=\s*False|authorize\s*=\s*False"),
        message="显式关掉了授权开关。",
        remediation="删除该开关，或仅在明确的公开接口上使用。",
        cwe="CWE-306",
        suffixes=PY | JS,
    ),
    PatternRule(
        rule_id="CFG001",
        title="Redis 关闭保护模式",
        severity=Severity.HIGH,
        category=Category.CONFIG,
        pattern=_re(r"(?i)^protected-mode\s+no\b"),
        message="关闭保护模式后，未设口令的 Redis 可能被网络上的人写入。",
        remediation="保持 protected-mode yes，并设置 requirepass，绑定内网地址。",
        cwe="CWE-306",
        names=frozenset({"redis.conf"}),
    ),
    PatternRule(
        rule_id="CFG005",
        title="配置里关闭 TLS",
        severity=Severity.MEDIUM,
        category=Category.CONFIG,
        pattern=_re(r"(?i)(?:ssl|tls)\s*:\s*(?:false|off)|insecure-skip-tls-verify\s*:\s*true"),
        message="运行配置关闭了传输加密或证书校验。",
        remediation="生产环境开启 TLS，并保持证书校验。",
        cwe="CWE-319",
        suffixes=YAML | frozenset({".properties"}),
    ),
    PatternRule(
        rule_id="CFG006",
        title="配置文件写入明文口令",
        severity=Severity.HIGH,
        category=Category.SECRET,
        pattern=_re(
            r"""(?i)\b(?:password|passwd|secret)\s*[:=]\s*['\"]?[^'\"\s#]{6,}"""
        ),
        message="运行配置里出现明文口令。",
        remediation="改用环境变量或密钥托管；仓库只保留占位符。",
        cwe="CWE-798",
        suffixes=PROPS,
        names=frozenset({"application.properties", "application.yml", "application.yaml", "redis.conf"}),
    ),
    PatternRule(
        rule_id="AUTH014",
        title="金额或管理员标记来自前端请求",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=_re(r"\b(?:price|amount|total|isAdmin|is_admin|role)\s*=\s*req\.(?:body|query|params)"),
        message="价格或角色若由请求体决定，业务校验会被绕过。",
        remediation="这些字段只从服务端数据读取，不要用 req.body 赋值。",
        cwe="CWE-472",
        suffixes=JS,
    ),
)
