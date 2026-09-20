"""Python AST checks that regex cannot express reliably."""

from __future__ import annotations

import ast
from pathlib import Path

from deepopen.models import Category, Finding, Severity


def _snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: Path, source: str) -> None:
        self.path = str(path)
        self.source = source
        self.findings: list[Finding] = []
        self._with_open_ids: set[int] = set()

    def _add(
        self,
        node: ast.AST,
        rule_id: str,
        title: str,
        severity: Severity,
        category: Category,
        message: str,
        remediation: str,
        cwe: str | None = None,
    ) -> None:
        lineno = getattr(node, "lineno", 1)
        self.findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category=category,
                path=self.path,
                line=lineno,
                snippet=_snippet(self.source, lineno),
                message=message,
                remediation=remediation,
                cwe=cwe,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)

        if name in {"eval", "exec"}:
            self._add(
                node, "AST001", "eval / exec 动态执行", Severity.HIGH, Category.SECURITY,
                "AST 确认调用了 eval 或 exec。",
                "不要对不可信输入执行动态代码；用解析器或白名单分支替代。", "CWE-95",
            )
        if name in {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "dill.loads", "dill.load"}:
            self._add(
                node, "AST002", "不安全反序列化", Severity.HIGH, Category.SECURITY,
                f"AST 确认调用了 {name}。",
                "对外数据使用 JSON 等数据格式；不要反序列化不可信字节流。", "CWE-502",
            )
        if name in {"os.system", "os.popen"}:
            self._add(
                node, "AST003", "通过 shell 执行命令", Severity.HIGH, Category.SECURITY,
                f"AST 确认调用了 {name}。",
                "改用 subprocess.run([prog, arg...], shell=False)，并对参数做白名单校验。", "CWE-78",
            )
        if name.startswith("subprocess.") and any(
            kw.arg == "shell" and _is_true(kw.value) for kw in node.keywords
        ):
            self._add(
                node, "AST004", "subprocess shell=True", Severity.HIGH, Category.SECURITY,
                "subprocess 以 shell=True 运行，命令字符串可被元字符改写。",
                "传入参数列表并保持 shell=False。", "CWE-78",
            )
        if name.startswith("subprocess.") and node.args and _is_dynamic_string(node.args[0]):
            self._add(
                node, "AST014", "subprocess 动态命令字符串", Severity.HIGH, Category.SECURITY,
                "subprocess 的第一个参数是拼接或格式化出来的字符串。",
                "传入参数列表，而不是拼接后的命令行。", "CWE-78",
            )
        if name in {"yaml.load", "yaml.unsafe_load"} and (name.endswith("unsafe_load") or not _has_loader(node)):
            self._add(
                node, "AST005", "yaml.load 缺少 SafeLoader", Severity.HIGH, Category.SECURITY,
                "yaml.load 未指定安全 Loader。",
                "改用 yaml.safe_load()。", "CWE-502",
            )
        if name in {"hashlib.md5", "hashlib.sha1"}:
            self._add(
                node, "AST006", "弱哈希算法", Severity.MEDIUM, Category.SECURITY,
                f"使用了 {name}。",
                "口令存储用 Argon2/bcrypt；完整性用 SHA-256 及以上。", "CWE-328",
            )
        if name == "hashlib.new" and node.args:
            algo = _const_str(node.args[0])
            if algo and algo.lower() in {"md5", "sha1"}:
                self._add(
                    node, "AST006", "弱哈希算法", Severity.MEDIUM, Category.SECURITY,
                    f"hashlib.new('{algo}') 使用弱哈希。",
                    "口令存储用 Argon2/bcrypt；完整性用 SHA-256 及以上。", "CWE-328",
                )
        if _looks_like_sql_execute(name, node):
            self._add(
                node, "AST008", "疑似拼接 SQL", Severity.HIGH, Category.SECURITY,
                "execute 的第一个参数是拼接/格式化出来的字符串，而不是常量加参数。",
                "使用参数化查询：cursor.execute(sql, (param,))。", "CWE-89",
            )
        if any(kw.arg == "verify" and _is_false(kw.value) for kw in node.keywords):
            self._add(
                node, "AST015", "关闭 TLS 证书校验", Severity.HIGH, Category.SECURITY,
                "调用关闭了证书校验参数。",
                "保持校验；自签证书时指定 CA 包路径。", "CWE-295",
            )
        unverified = "ssl." + "_create_unverified_context"
        if name == unverified:
            self._add(
                node, "AST016", "创建不校验的 SSL 上下文", Severity.HIGH, Category.SECURITY,
                "该 SSL 上下文会关闭证书校验。",
                "使用默认 SSL 上下文，或加载指定 CA。", "CWE-295",
            )
        if name == "tempfile.mktemp":
            self._add(
                node, "AST017", "使用 tempfile.mktemp", Severity.MEDIUM, Category.SECURITY,
                "mktemp 存在创建前的时间窗口。",
                "改用 NamedTemporaryFile 或 mkstemp。", "CWE-377",
            )
        if name in {"mark_safe", "django.utils.safestring.mark_safe", "flask.Markup", "Markup"}:
            self._add(
                node, "AST018", "标记 HTML 为安全", Severity.HIGH, Category.SECURITY,
                f"AST 确认调用了 {name}。",
                "优先模板自动转义；输出 HTML 前使用 sanitizer。", "CWE-79",
            )
        if name == "render_template_string":
            self._add(
                node, "AST019", "动态模板字符串", Severity.HIGH, Category.SECURITY,
                "render_template_string 会把字符串当模板执行。",
                "使用固定模板文件，用户内容作为普通变量传入。", "CWE-94",
            )
        if name in {"compile", "__import__"}:
            dynamic = not node.args or not isinstance(node.args[0], ast.Constant)
            if name == "compile" or dynamic:
                self._add(
                    node, "AST020", "动态编译或导入", Severity.HIGH, Category.SECURITY,
                    f"AST 确认调用了 {name}。",
                    "不要对不可信输入 compile/__import__；用明确模块列表。", "CWE-95",
                )
        if name in {"shelve.open"}:
            self._add(
                node, "AST021", "shelve 基于 pickle", Severity.MEDIUM, Category.SECURITY,
                "shelve 使用 pickle，不适合不可信数据。",
                "改用 sqlite 或 JSON 文件。", "CWE-502",
            )
        if name.endswith("run") and any(kw.arg == "debug" and _is_true(kw.value) for kw in node.keywords):
            self._add(
                node, "AST022", "以调试模式启动服务", Severity.MEDIUM, Category.SECURITY,
                "调试模式可能暴露交互式报错。",
                "生产环境关闭 debug，用环境变量切换。", "CWE-489",
            )
        if name.endswith("decode") and "jwt" in name.lower():
            if any(
                (kw.arg == "verify" and _is_false(kw.value))
                or (kw.arg == "options" and "verify_signature" in ast.dump(kw.value) and "False" in ast.dump(kw.value))
                or (kw.arg == "algorithms" and "none" in ast.dump(kw.value).lower())
                for kw in node.keywords
            ):
                self._add(
                    node, "AST023", "JWT 校验被关闭", Severity.HIGH, Category.SECURITY,
                    "jwt.decode 关闭了签名校验或允许 none 算法。",
                    "显式指定允许的算法并保持校验。", "CWE-347",
                )
        if name == "open" and not _is_binary_open(node):
            if not any(kw.arg == "encoding" for kw in node.keywords):
                self._add(
                    node, "AST024", "open 未指定 encoding", Severity.LOW, Category.QUALITY,
                    "文本模式 open 依赖平台默认编码，在 Windows 上容易出错。",
                    "显式传入 encoding='utf-8'。",
                )
            if id(node) not in self._with_open_ids:
                self._add(
                    node, "AST033", "open 未使用 with", Severity.MEDIUM, Category.BUG,
                    "手动 open 容易忘记 close，异常路径上会泄漏句柄。",
                    "写成 with open(...) as f:",
                    "CWE-772",
                )
        if name in {"datetime.now", "datetime.datetime.now"} and not node.args and not any(
            kw.arg == "tz" for kw in node.keywords
        ):
            self._add(
                node, "AST034", "naive datetime.now()", Severity.LOW, Category.BUG,
                "不带时区的 now() 在跨时区或夏令时下会算错。",
                "传入 tz，例如 datetime.now(timezone.utc)。",
            )
        if name in {"datetime.utcnow", "datetime.datetime.utcnow"}:
            self._add(
                node, "AST034", "naive datetime.now()", Severity.LOW, Category.BUG,
                "utcnow() 返回的是 naive datetime，容易被当成本地时间。",
                "改用 datetime.now(timezone.utc)。",
            )
        http_funcs = {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.patch",
            "requests.delete",
            "requests.head",
            "requests.request",
            "urllib.request.urlopen",
            "urlopen",
            "httpx.get",
            "httpx.post",
            "httpx.request",
        }
        if name in http_funcs:
            timed = any(kw.arg == "timeout" and not _is_none(kw.value) for kw in node.keywords)
            if name in {"urlopen", "urllib.request.urlopen"} and len(node.args) >= 2:
                timed = True
            if not timed:
                self._add(
                    node, "AST058", "HTTP 请求未设置 timeout", Severity.MEDIUM, Category.BUG,
                    "没有超时的请求可能永远卡住调用方。",
                    "传入 timeout=秒数，并处理超时异常。",
                    "CWE-400",
                )
        if name in http_funcs and node.args and _is_dynamic_string(node.args[0]):
            self._add(
                node, "AST029", "请求 URL 由字符串拼接得到", Severity.MEDIUM, Category.SECURITY,
                "HTTP 客户端的地址是动态拼出来的，目标主机可能被外部数据改写。",
                "用白名单限制协议和主机；不要把用户输入直接拼进 URL。", "CWE-918",
            )
        if name.startswith("subprocess.") and name.rsplit(".", 1)[-1] in {
            "run", "call", "check_output", "check_call",
        }:
            if not any(kw.arg == "timeout" and not _is_none(kw.value) for kw in node.keywords):
                self._add(
                    node, "AST059", "subprocess 未设置 timeout", Severity.MEDIUM, Category.BUG,
                    "子进程没有超时，可能挂起当前流程。",
                    "给 run/call 传入 timeout，并处理 TimeoutExpired。",
                    "CWE-400",
                )
        if name == "open" and node.args and _is_dynamic_string(node.args[0]):
            self._add(
                node, "AST030", "文件路径由字符串拼接得到", Severity.MEDIUM, Category.SECURITY,
                "open 的路径是拼接/格式化出来的，可能读到目录外的文件。",
                "先规范化路径，并限制在固定根目录内。", "CWE-22",
            )
        if name in {"send_file", "flask.send_file", "send_from_directory"} and node.args and _is_dynamic_string(node.args[0]):
            self._add(
                node, "AST031", "下载路径由字符串拼接得到", Severity.HIGH, Category.SECURITY,
                "把拼接路径交给 send_file 可能读出目录外文件。",
                "使用 send_from_directory 固定根目录，并对文件名做白名单。", "CWE-22",
            )
        if "chmod" in name:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and arg.value in {0o777, 511}:
                    self._add(
                        node, "AST032", "chmod 权限过宽", Severity.MEDIUM, Category.CONFIG,
                        "权限 777 让任意用户可写。",
                        "按最小权限设置，例如 0o644 / 0o755。", "CWE-732",
                    )
                    break
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        secret_names = {"SECRET_KEY", "SECRET", "AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY"}
        if any(item in secret_names for item in names):
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) >= 8:
                self._add(
                    node, "AST025", "硬编码密钥赋值", Severity.HIGH, Category.SECRET,
                    "框架或云密钥被写成字符串字面量。",
                    "从环境变量或密钥托管读取。", "CWE-798",
                )
        token_names = {"token", "nonce", "otp", "reset_code", "session_id"}
        if any(item.lower() in token_names for item in names) and _uses_insecure_random(node.value):
            self._add(
                node, "AST026", "用非安全随机数生成令牌", Severity.MEDIUM, Category.SECURITY,
                "令牌类变量使用了 random 模块。",
                "改用 secrets 或 os.urandom。", "CWE-330",
            )
        shadowed = {
            "list", "dict", "str", "int", "float", "bool", "set", "tuple", "bytes",
            "type", "input", "open", "hash", "len", "min", "max", "sum", "next",
            "object", "range", "iter", "filter", "map", "zip",
        }
        if any(item in shadowed for item in names):
            self._add(
                node, "AST049", "赋值覆盖内置名", Severity.MEDIUM, Category.BUG,
                f"变量名 {', '.join(item for item in names if item in shadowed)} 覆盖了内置对象。",
                "改用更具体的名字，例如 values、text、kind。",
            )
        if len(node.targets) >= 2 and _is_mutable_literal(node.value):
            self._add(
                node, "AST044", "链式赋值共享可变对象", Severity.MEDIUM, Category.BUG,
                "a = b = [] 让多个名字指向同一容器，改其中一个会牵动另一个。",
                "分别写成 a = [] 和 b = []。",
            )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_mutable_defaults(node)
        self._flag_unreachable(node.body)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_mutable_defaults(node)
        self._flag_unreachable(node.body)
        self._check_blocking_in_async(node)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        comparators = [node.left, *node.comparators]
        for left, op, right in zip(comparators, node.ops, comparators[1:]):
            if isinstance(op, (ast.Eq, ast.NotEq)) and (_is_none(left) or _is_none(right)):
                self._add(
                    node, "AST009", "用 == 比较 None", Severity.LOW, Category.QUALITY,
                    "对 None 应使用 is / is not。",
                    "写成 `x is None` 或 `x is not None`。",
                )
            if isinstance(op, (ast.Is, ast.IsNot)) and (_is_literal_identity(left) or _is_literal_identity(right)):
                self._add(
                    node, "AST027", "用 is 比较字面量", Severity.LOW, Category.QUALITY,
                    "对 int/str 等字面量应使用 ==，is 依赖 intern 行为。",
                    "改用 == / !=；None 才用 is。",
                )
            if isinstance(op, (ast.Eq, ast.NotEq)) and (
                _is_true(left) or _is_true(right) or _is_false(left) or _is_false(right)
            ):
                self._add(
                    node, "AST038", "用 == 比较 True/False", Severity.LOW, Category.QUALITY,
                    "布尔比较通常可以直接使用真值测试。",
                    "写成 if flag: / if not flag:。",
                )
            if isinstance(op, (ast.Is, ast.IsNot)) and (
                _is_true(left) or _is_true(right) or _is_false(left) or _is_false(right)
            ):
                self._add(
                    node, "AST048", "用 is 比较 True/False", Severity.LOW, Category.QUALITY,
                    "对布尔值用 is True 会漏掉其它真值，也绑死了单例身份。",
                    "直接写成 if flag: / if not flag:。",
                )
            if isinstance(op, ast.Eq) and (
                (isinstance(left, ast.Constant) and isinstance(left.value, float))
                or (isinstance(right, ast.Constant) and isinstance(right.value, float))
            ):
                self._add(
                    node, "AST039", "浮点直接相等比较", Severity.LOW, Category.BUG,
                    "二进制浮点常常无法精确表示十进制小数。",
                    "用 math.isclose，金额用 Decimal。",
                )
            if isinstance(op, (ast.Eq, ast.Is)) and _is_type_call(left, right):
                self._add(
                    node, "AST043", "用 type() 做相等判断", Severity.LOW, Category.QUALITY,
                    "用 type() 做相等判断无法识别子类。",
                    "改用 isinstance(x, T)。",
                )
            if isinstance(op, (ast.Eq, ast.NotEq)) and (
                _is_empty_container(left) or _is_empty_container(right)
            ):
                self._add(
                    node, "AST050", "与空容器做相等比较", Severity.LOW, Category.QUALITY,
                    "空列表/字典的相等比较既慢又容易和 None 搞混。",
                    "用 if not items: / if items: 判断空与非空。",
                )
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self._add(
                node, "AST010", "裸 except", Severity.MEDIUM, Category.BUG,
                "except: 会捕获 BaseException。",
                "改成 except Exception，并记录或重新抛出。", "CWE-390",
            )
        if node.body and all(isinstance(stmt, ast.Pass) for stmt in node.body):
            self._add(
                node, "AST011", "空 except 主体 pass", Severity.LOW, Category.BUG,
                "异常被静默丢弃。",
                "记录日志，或在注释中说明为何可以忽略。",
            )
        if node.body and all(isinstance(stmt, ast.Continue) for stmt in node.body):
            if node.type is None or _is_broad_exception(node.type):
                self._add(
                    node, "AST046", "except 后直接 continue", Severity.MEDIUM, Category.BUG,
                    "捕获异常后直接进入下一轮，失败被悄悄跳过。",
                    "至少记录异常，并确认跳过是业务允许的。",
                )
        for stmt in node.body:
            for child in ast.walk(stmt):
                if not isinstance(child, ast.Raise):
                    continue
                if child.exc is None:
                    continue
                if (
                    node.name
                    and isinstance(child.exc, ast.Name)
                    and child.exc.id == node.name
                ):
                    self._add(
                        child, "AST035", "raise e 丢失堆栈", Severity.MEDIUM, Category.BUG,
                        "raise e 会丢掉原始堆栈。",
                        "写成裸 raise。",
                    )
                elif child.cause is None:
                    self._add(
                        child, "AST045", "except 中 raise 新异常未绑定原因", Severity.LOW, Category.BUG,
                        "换成新异常时如果没有 from，调用方看不到原始原因。",
                        "写成 raise NewError(...) from original。",
                    )
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            ctx = item.context_expr
            if isinstance(ctx, ast.Call) and _call_name(ctx.func) == "open":
                self._with_open_ids.add(id(ctx))
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        seen_methods: set[str] = set()
        has_eq = has_hash = has_enter = has_exit = False
        for stmt in node.body:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                value = stmt.value if isinstance(stmt, ast.AnnAssign) else stmt.value
                if isinstance(value, (ast.List, ast.Dict, ast.Set)):
                    self._add(
                        stmt, "AST036", "可变类属性", Severity.MEDIUM, Category.BUG,
                        "类上的 list/dict 会被所有实例共享。",
                        "放到 __init__ 里创建，或用 dataclass field(default_factory=list)。",
                    )
            if isinstance(stmt, ast.Assign):
                names = [target.id for target in stmt.targets if isinstance(target, ast.Name)]
                if "__hash__" in names:
                    has_hash = True
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if stmt.name in seen_methods:
                    self._add(
                        stmt, "AST052", "类中重复方法名", Severity.MEDIUM, Category.BUG,
                        "后定义的方法会静默覆盖先前的同名方法。",
                        "改名，或合并成一个实现。",
                    )
                seen_methods.add(stmt.name)
                has_eq = has_eq or stmt.name == "__eq__"
                has_hash = has_hash or stmt.name == "__hash__"
                has_enter = has_enter or stmt.name == "__enter__"
                has_exit = has_exit or stmt.name == "__exit__"
        if has_eq and not has_hash:
            self._add(
                node, "AST053", "__eq__ 未定义 __hash__", Severity.LOW, Category.BUG,
                "定义相等运算后实例默认不可哈希，放进 set/dict 会报错。",
                "不可哈希时显式 __hash__ = None；要进集合则同时实现 __hash__。",
            )
        if has_enter != has_exit:
            self._add(
                node, "AST054", "上下文管理器协议不完整", Severity.MEDIUM, Category.BUG,
                "__enter__ / __exit__ 必须成对出现，否则 with 会失败或泄漏。",
                "同时实现两个方法，或改用 contextlib.contextmanager。",
            )
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        seen: set[object] = set()
        for key in node.keys:
            if isinstance(key, ast.Constant) and key.value in seen:
                self._add(
                    node, "AST037", "字典重复键", Severity.MEDIUM, Category.BUG,
                    "重复的字面量键会静默覆盖先前的值。",
                    "删掉重复键，或改用明确的更新步骤。",
                )
            if isinstance(key, ast.Constant):
                seen.add(key.value)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names):
            self._add(
                node, "AST040", "通配符 import *", Severity.MEDIUM, Category.BUG,
                "import * 会污染命名空间。",
                "显式导入需要的符号。",
            )
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if _is_true(node.test):
            self._add(
                node, "AST041", "if True 死代码分支", Severity.LOW, Category.QUALITY,
                "条件恒为真，else 永远不会走到。",
                "删掉恒真判断，或改成配置/特性开关。",
            )
        if _is_false(node.test):
            self._add(
                node, "AST042", "if False 死代码", Severity.LOW, Category.QUALITY,
                "条件恒为假，then 分支永远不会执行。",
                "删除这段代码，或改成真正的开关。",
            )
        self._flag_unreachable(node.body)
        self._flag_unreachable(node.orelse)
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, ast.Not) and isinstance(node.operand, ast.Compare):
            self._add(
                node, "AST047", "not 包住比较运算", Severity.LOW, Category.QUALITY,
                "not x == y / not x in y 既难读也容易看错优先级。",
                "改成 x != y、x not in y、x is not None。",
            )
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        if _is_true(node.test) and node.body and all(isinstance(stmt, ast.Pass) for stmt in node.body):
            self._add(
                node, "AST051", "while True 只有 pass", Severity.MEDIUM, Category.BUG,
                "条件恒真且循环体为空，进程会空转占满 CPU。",
                "加入退出条件、阻塞等待，或删掉这段代码。",
            )
        self._flag_unreachable(node.body)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._flag_unreachable(node.body)
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)) and isinstance(node.right, ast.Constant):
            if node.right.value == 0:
                self._add(
                    node, "AST056", "除以或对 0 取模", Severity.HIGH, Category.BUG,
                    "运行时会抛出 ZeroDivisionError。",
                    "先判断除数，或对零返回明确错误。",
                )
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        dumped = ast.dump(node).lower()
        markers = ("admin", "auth", "permission", "token", "password", "role", "login")
        if any(marker in dumped for marker in markers):
            self._add(
                node, "AST012", "用 assert 做安全/权限判断", Severity.MEDIUM, Category.SECURITY,
                "Python 以 -O 运行时 assert 会被去掉，不能当权限检查。",
                "权限与输入校验用普通 if + 异常/错误返回。", "CWE-670",
            )
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        for stmt in node.finalbody:
            for child in ast.walk(stmt):
                if isinstance(child, ast.Return):
                    self._add(
                        child, "AST028", "finally 中 return", Severity.MEDIUM, Category.BUG,
                        "finally 里的 return 会吞掉 try/except 中的异常或返回值。",
                        "不要在 finally 中 return；只做清理。",
                    )
        self.generic_visit(node)

    def _flag_unreachable(self, body: list[ast.stmt]) -> None:
        terminated = False
        for stmt in body:
            if terminated:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                self._add(
                    stmt, "AST057", "不可达代码", Severity.MEDIUM, Category.BUG,
                    "前面已经 return/raise/break/continue，这段永远不会执行。",
                    "删掉死代码，或调整控制流。",
                )
                return
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                terminated = True

    def _check_blocking_in_async(self, node: ast.AsyncFunctionDef) -> None:
        for child in _walk_skip_nested_defs(node):
            if not isinstance(child, ast.Call):
                continue
            name = _call_name(child.func)
            blocking = (
                name in {"time.sleep", "os.system"}
                or name.startswith("subprocess.")
                or name.startswith("requests.")
            )
            if blocking:
                self._add(
                    child, "AST055", "async 函数里调用阻塞 API", Severity.MEDIUM, Category.BUG,
                    "在协程里调用 sleep/subprocess/requests 会卡住整个事件循环。",
                    "改用 asyncio.sleep、asyncio.create_subprocess_exec 或异步 HTTP 客户端。",
                )

    def _check_mutable_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for default in node.args.defaults + node.args.kw_defaults:
            if default is None:
                continue
            if isinstance(default, (ast.List, ast.Dict, ast.Set)) or (
                isinstance(default, ast.Call)
                and isinstance(default.func, ast.Name)
                and default.func.id in {"list", "dict", "set"}
            ):
                self._add(
                    default, "AST013", "可变默认参数", Severity.MEDIUM, Category.BUG,
                    "list/dict/set 默认参数会在调用之间共享。",
                    "默认值用 None，在函数体内初始化新容器。",
                )


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, bool) and node.value


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, bool) and not node.value


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _is_mutable_literal(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"list", "dict", "set"}
        and not node.args
        and not node.keywords
    )


def _is_empty_container(node: ast.AST) -> bool:
    if isinstance(node, ast.List) and not node.elts:
        return True
    if isinstance(node, ast.Dict) and not node.keys:
        return True
    if isinstance(node, ast.Tuple) and not node.elts:
        return True
    if isinstance(node, ast.Set) and not node.elts:
        return True
    return (
        isinstance(node, ast.Call)
        and _call_name(node.func) in {"list", "dict", "set", "tuple"}
        and not node.args
        and not node.keywords
    )


def _walk_skip_nested_defs(node: ast.AST):
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield child
        yield from _walk_skip_nested_defs(child)


def _is_broad_exception(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and node.id in {"Exception", "BaseException"}:
        return True
    if isinstance(node, ast.Tuple):
        return any(_is_broad_exception(elt) for elt in node.elts)
    if isinstance(node, ast.Attribute) and node.attr in {"Exception", "BaseException"}:
        return True
    return False


def _is_type_call(left: ast.AST, right: ast.AST) -> bool:
    for node in (left, right):
        if isinstance(node, ast.Call) and _call_name(node.func) == "type":
            return True
    return False


def _is_literal_identity(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) in {int, float, str, bytes}


def _has_loader(node: ast.Call) -> bool:
    return any(kw.arg in {"Loader", "loader"} for kw in node.keywords)


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and _call_name(node.func).endswith("format"):
        return True
    return False


def _looks_like_sql_execute(name: str, node: ast.Call) -> bool:
    if not name.endswith("execute") and not name.endswith("executemany"):
        return False
    if not node.args:
        return False
    return _is_dynamic_string(node.args[0])


def _is_binary_open(node: ast.Call) -> bool:
    mode = None
    if len(node.args) >= 2:
        mode = _const_str(node.args[1])
    for kw in node.keywords:
        if kw.arg == "mode":
            mode = _const_str(kw.value)
    return bool(mode and "b" in mode)


def _uses_insecure_random(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _call_name(child.func)
            if name.startswith("random."):
                return True
    return False


def analyze_python(path: Path, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []
    visitor = _Visitor(path, source)
    visitor.visit(tree)
    return visitor.findings
