"""High-level hardening reminders. No attack steps."""

CHECKLIST = """
DeepOpen 开发加固清单（防守向）
================================

1. 密钥与配置
   - 口令、令牌、私钥只放在环境变量或密钥托管里，不进仓库。
   - 为每个环境使用不同凭据，泄露后立刻轮换。
   - 生产关闭调试页、目录列表和详细堆栈。
   - SECRET_KEY / JWT 密钥足够长且随机，禁止写死。
   - 配置按环境拆分，禁止把生产地址写进默认值。
   - 功能开关、超时、限流要有明确默认值，不要靠“碰巧能跑”。

2. 输入与数据
   - 所有外部输入（HTTP、文件、消息队列）先校验类型、长度和允许值。
   - SQL、命令、LDAP、模板一律用官方参数化/转义 API，不要拼字符串。
   - 对外输出 HTML 时默认转义；文件下载用固定目录 + 规范化路径。
   - 不要 pickle / Marshal / BinaryFormatter / unserialize 不可信数据。
   - 解析 JSON/YAML 要限制大小，失败时返回明确错误而不是崩溃。
   - 数字转换、日期解析失败要有分支，不要让 ValueError 冒到顶层。

3. 身份与会话
   - 口令哈希用 Argon2 / bcrypt / scrypt，不要用 MD5/SHA1。
   - 会话 cookie 设置 HttpOnly、Secure、SameSite。
   - 权限检查写在业务代码里，不要用 assert（-O 会去掉）。
   - JWT 显式指定算法并校验签名，禁止 none。
   - 重置码、OTP 使用密码学安全随机数（secrets / crypto.random）。

4. 传输与依赖
   - 锁定依赖版本，提交 lock 文件，定期看安全公告并升级。
   - 对外请求保持 TLS 校验，不要关闭证书校验。
   - 管理接口不暴露到公网；容器不要 privileged，不要挂 docker.sock。
   - 不要 curl | sh；先校验校验和再执行。
   - 出站 URL 做协议/主机白名单，避免把用户输入直接当请求地址。

5. 前端
   - 优先 textContent；富文本先消毒。
   - 部署 CSP，避免内联脚本和 javascript: URL。
   - 令牌不要放 localStorage；target=_blank 加 noopener。
   - 用 === 比较，避免 == 的隐式转换。
   - 不要用 var；用 const/let，避免意外提升和全局泄漏。
   - 不要用相等运算比较 NaN；parseInt 必须写进制。
   - 提交前删掉 debugger、console.log。

6. 缺陷与正确性（Python）
   - 禁止裸 except / 空 catch / pass 吞异常；捕获具体类型并记录。
   - except 后不要直接 continue；失败被跳过等于缺陷被藏起来。
   - 在 except 里要用裸 raise 保留堆栈；换成新异常时加 from。
   - 不要 from x import *，也不要给变量起 list/str/type 这种内置名。
   - 可变默认参数、类属性里的 list/dict、a = b = [] 都会共享状态。
   - 对 None 用 is；对 int/str 用 ==；类型检查用 isinstance，不要 type()。
   - 打开文件、锁、连接用 with / 上下文管理器；open 要写 encoding。
   - datetime 带时区；不要用 naive now()/utcnow() 做跨机时间。
   - 浮点不要直接 ==；金额用 Decimal。
   - 字典字面量不要重复键；后面的会静默覆盖前面的。
   - if True / if False、return 之后的语句属于死代码。
   - finally 里不要 return，会丢掉异常。
   - 定义了 __eq__ 就要考虑 __hash__；__enter__/__exit__ 必须成对。
   - async 函数里不要调用 time.sleep / requests / subprocess。
   - HTTP 和 subprocess 必须设置 timeout。
   - 提交前清掉 breakpoint / pdb；不要调用内置 exit 或 quit。

7. 缺陷与正确性（其它语言）
   - Java 字符串用 equals，不要 ==；不要只 printStackTrace。
   - Go 发现 err 必须处理，禁止空的 if err != nil {}，不要 _ = err。
   - JavaScript 用 ===；不要 debugger；parseInt 写进制。
   - C/C++ 不要在 if 条件里赋值；不要用 gets/strcpy。
   - Rust 业务路径少用 unwrap，错误用 ? 传递。
   - SQL 明确列名，不要选出全部列；DELETE/UPDATE 必须有 WHERE。

8. 空值、边界与类型
   - None、空字符串、空列表、0、False 要分开处理，不要互相当“没有”。
   - 容器空判定用 if not items，不要和 [] 做相等比较。
   - 除法、取模前检查零；分页/切片检查上下界。
   - 循环与递归要有终止条件，while True 必须能退出。
   - 公开 API 对非法参数返回明确错误，不要让 TypeError 泄漏实现细节。

9. 并发与资源
   - 共享可变状态要有锁或队列，不要多线程裸写同一 list/dict。
   - 锁与连接的获取/释放成对出现，优先 with。
   - 避免在请求线程里长时间 sleep 或同步等待外部调用。
   - 超时、重试、取消要有上限，防止雪崩。
   - 事件循环里只做非阻塞调用。

10. 日志与可观测
   - 捕获异常至少记录类型、位置、请求 ID，不要空 pass。
   - 日志不要打印口令、cookie、证件号、完整令牌。
   - 用日志库代替临时 print / System.out / console.log。
   - 关键路径要有失败指标，而不是只靠人工看日志。

11. 测试与发布
   - 变更有回归测试，尤其是错误分支、空输入、超时和零值。
   - 合并前处理 TODO/FIXME，安全相关待办不得带进生产。
   - 把 DeepOpen 接入 CI 与 pre-commit：high 及以上即失败。
   - CI 可用 --profile security，本地再用 all 跑缺陷。
   - 团队规范写进 deepopen.toml 的 [[rules]]，id 以 CUSTOM/TEAM 开头。
   - 确认误报写入基线；质量问题可用 deepopen fix 预览后 --apply。

本工具只能发现「源码里能看出来的模式」，不能代替代码评审、测试、依赖审计和专业评估。
""".strip()

CHECKLIST_SECTIONS = [
    {
        "title": "密钥与配置",
        "items": [
            "口令、令牌、私钥只放环境变量或密钥托管，不进仓库",
            "每个环境使用不同凭据，泄露后立刻轮换",
            "生产关闭调试页和详细堆栈",
            "SECRET_KEY / JWT 密钥足够长且随机",
            "配置按环境拆分，禁止把生产地址写进默认值",
            "超时、限流、功能开关要有明确默认值",
        ],
    },
    {
        "title": "输入与数据",
        "items": [
            "外部输入先校验类型、长度和允许值",
            "SQL / 命令 / 模板使用参数化或官方转义 API",
            "HTML 默认转义；下载路径规范化到固定目录",
            "不要对不可信数据做 pickle / 反序列化",
            "解析 JSON/YAML 限制大小，失败返回明确错误",
            "数字和日期解析失败要有分支，不要让异常冒顶",
        ],
    },
    {
        "title": "身份与会话",
        "items": [
            "口令哈希使用 Argon2 / bcrypt / scrypt",
            "会话 cookie 设置 HttpOnly、Secure、SameSite",
            "权限检查不要用 assert",
            "JWT 显式算法并校验签名",
            "OTP / 重置码使用 secrets 或 crypto 随机数",
        ],
    },
    {
        "title": "传输、依赖与运行环境",
        "items": [
            "锁定依赖并提交 lock 文件",
            "保持 TLS 校验",
            "容器非 root、非 privileged、不挂 docker.sock",
            "不要把远程脚本直接交给 shell",
            "出站 URL 做协议和主机白名单",
        ],
    },
    {
        "title": "缺陷检测（Python）",
        "items": [
            "禁止裸 except、空 catch、pass / continue 吞掉异常",
            "except 中用裸 raise；换新异常时加 from",
            "不要 import *，不要覆盖 list/str/type 等内置名",
            "可变默认参数、类级容器、a = b = [] 会共享状态",
            "None 用 is，类型检查用 isinstance，不要 type()",
            "文件/锁/连接用 with；open 指定 encoding",
            "datetime 带时区；浮点不要直接相等比较",
            "清掉 breakpoint、pdb；不要调用内置 exit 或 quit",
            "字典不要重复键；删掉 if True / 不可达代码",
            "finally 不要 return；__eq__/__hash__、enter/exit 成对",
            "async 里不要阻塞调用；HTTP 与 subprocess 必须设置超时",
        ],
    },
    {
        "title": "缺陷检测（多语言）",
        "items": [
            "Java 字符串用 equals，不要只 printStackTrace",
            "Go 必须处理 err，禁止空分支和 _ = err",
            "JavaScript 用 ===，parseInt 写进制，删掉 debugger",
            "C 不要在 if 里赋值；不要 gets/strcpy",
            "Rust 业务路径少用 unwrap",
            "SQL 写明列名；DELETE/UPDATE 必须有 WHERE",
        ],
    },
    {
        "title": "空值、边界与类型",
        "items": [
            "None、空串、空列表、0、False 分开处理",
            "空容器用 if not items，不要和 [] 做相等比较",
            "除法和取模前检查零",
            "循环必须能退出，while True 要有终止条件",
            "公开 API 对非法参数返回明确错误",
        ],
    },
    {
        "title": "并发、超时与资源",
        "items": [
            "共享可变状态加锁或改用队列",
            "锁与连接成对获取/释放，优先 with",
            "外部调用设置超时和重试上限",
            "事件循环里只做非阻塞调用",
        ],
    },
    {
        "title": "日志、测试与发布",
        "items": [
            "记录异常类型、位置、请求 ID，日志脱敏",
            "用日志库代替 print / System.out / console.log",
            "错误分支、空输入、超时、零值要有测试",
            "扫描器接入 CI：high 及以上失败",
            "CI 可用 --profile security，本地用 all 跑缺陷",
            "团队规范写进 [[rules]]，id 以 CUSTOM/TEAM 开头",
            "误报写入基线，质量问题用 deepopen fix 预览修复",
        ],
    },
    {
        "title": "前端",
        "items": [
            "优先 textContent，部署 CSP",
            "令牌不要放 localStorage",
            "比较用 ===，变量用 const/let",
            "NaN 用 Number.isNaN，parseInt 写进制",
            "target=_blank 加 noopener；删掉 debugger",
        ],
    },
]
