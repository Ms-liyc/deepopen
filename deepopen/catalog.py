"""Combined rule index for CLI and the web console."""

from __future__ import annotations

from deepopen.config import Config, load_config
from deepopen.patterns import list_rule_meta

AST_AND_ANALYZER_META: tuple[dict[str, object], ...] = (
    {"rule_id": "AST001", "title": "eval / exec 动态执行", "severity": "high", "category": "security", "cwe": "CWE-95"},
    {"rule_id": "AST002", "title": "不安全反序列化", "severity": "high", "category": "security", "cwe": "CWE-502"},
    {"rule_id": "AST003", "title": "通过 shell 执行命令", "severity": "high", "category": "security", "cwe": "CWE-78"},
    {"rule_id": "AST004", "title": "subprocess shell=True", "severity": "high", "category": "security", "cwe": "CWE-78"},
    {"rule_id": "AST005", "title": "yaml.load 缺少 SafeLoader", "severity": "high", "category": "security", "cwe": "CWE-502"},
    {"rule_id": "AST006", "title": "弱哈希算法", "severity": "medium", "category": "security", "cwe": "CWE-328"},
    {"rule_id": "AST008", "title": "疑似拼接 SQL", "severity": "high", "category": "security", "cwe": "CWE-89"},
    {"rule_id": "AST009", "title": "用 == 比较 None", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "AST010", "title": "裸 except", "severity": "medium", "category": "bug", "cwe": "CWE-390"},
    {"rule_id": "AST011", "title": "空 except 主体 pass", "severity": "low", "category": "bug", "cwe": None},
    {"rule_id": "AST012", "title": "用 assert 做安全/权限判断", "severity": "medium", "category": "security", "cwe": "CWE-670"},
    {"rule_id": "AST013", "title": "可变默认参数", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST014", "title": "subprocess 动态命令字符串", "severity": "high", "category": "security", "cwe": "CWE-78"},
    {"rule_id": "AST015", "title": "关闭 TLS 证书校验", "severity": "high", "category": "security", "cwe": "CWE-295"},
    {"rule_id": "AST016", "title": "创建不校验的 SSL 上下文", "severity": "high", "category": "security", "cwe": "CWE-295"},
    {"rule_id": "AST017", "title": "使用 tempfile.mktemp", "severity": "medium", "category": "security", "cwe": "CWE-377"},
    {"rule_id": "AST018", "title": "标记 HTML 为安全", "severity": "high", "category": "security", "cwe": "CWE-79"},
    {"rule_id": "AST019", "title": "动态模板字符串", "severity": "high", "category": "security", "cwe": "CWE-94"},
    {"rule_id": "AST020", "title": "动态编译或导入", "severity": "high", "category": "security", "cwe": "CWE-95"},
    {"rule_id": "AST021", "title": "shelve 基于 pickle", "severity": "medium", "category": "security", "cwe": "CWE-502"},
    {"rule_id": "AST022", "title": "以调试模式启动服务", "severity": "medium", "category": "security", "cwe": "CWE-489"},
    {"rule_id": "AST023", "title": "JWT 校验被关闭", "severity": "high", "category": "security", "cwe": "CWE-347"},
    {"rule_id": "AST024", "title": "open 未指定 encoding", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "AST025", "title": "硬编码密钥赋值", "severity": "high", "category": "secret", "cwe": "CWE-798"},
    {"rule_id": "AST026", "title": "用非安全随机数生成令牌", "severity": "medium", "category": "security", "cwe": "CWE-330"},
    {"rule_id": "AST027", "title": "用 is 比较字面量", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "AST028", "title": "finally 中 return", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST029", "title": "请求 URL 由字符串拼接得到", "severity": "medium", "category": "security", "cwe": "CWE-918"},
    {"rule_id": "AST030", "title": "文件路径由字符串拼接得到", "severity": "medium", "category": "security", "cwe": "CWE-22"},
    {"rule_id": "AST031", "title": "下载路径由字符串拼接得到", "severity": "high", "category": "security", "cwe": "CWE-22"},
    {"rule_id": "AST032", "title": "chmod 权限过宽", "severity": "medium", "category": "config", "cwe": "CWE-732"},
    {"rule_id": "AST033", "title": "open 未使用 with", "severity": "medium", "category": "bug", "cwe": "CWE-772"},
    {"rule_id": "AST034", "title": "naive datetime.now()", "severity": "low", "category": "bug", "cwe": None},
    {"rule_id": "AST035", "title": "raise e 丢失堆栈", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST036", "title": "可变类属性", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST037", "title": "字典重复键", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST038", "title": "用 == 比较 True/False", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "AST039", "title": "浮点直接相等比较", "severity": "low", "category": "bug", "cwe": None},
    {"rule_id": "AST040", "title": "通配符 import *", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST041", "title": "if True 死代码分支", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "AST042", "title": "if False 死代码", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "AST043", "title": "用 type() 做相等判断", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "AST044", "title": "链式赋值共享可变对象", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST045", "title": "except 中 raise 新异常未绑定原因", "severity": "low", "category": "bug", "cwe": None},
    {"rule_id": "AST046", "title": "except 后直接 continue", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST047", "title": "not 包住比较运算", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "AST048", "title": "用 is 比较 True/False", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "AST049", "title": "赋值覆盖内置名", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST050", "title": "与空容器做相等比较", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "AST051", "title": "while True 只有 pass", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST052", "title": "类中重复方法名", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST053", "title": "__eq__ 未定义 __hash__", "severity": "low", "category": "bug", "cwe": None},
    {"rule_id": "AST054", "title": "上下文管理器协议不完整", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST055", "title": "async 函数里调用阻塞 API", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST056", "title": "除以或对 0 取模", "severity": "high", "category": "bug", "cwe": None},
    {"rule_id": "AST057", "title": "不可达代码", "severity": "medium", "category": "bug", "cwe": None},
    {"rule_id": "AST058", "title": "HTTP 请求未设置 timeout", "severity": "medium", "category": "bug", "cwe": "CWE-400"},
    {"rule_id": "AST059", "title": "subprocess 未设置 timeout", "severity": "medium", "category": "bug", "cwe": "CWE-400"},
    {"rule_id": "AST060", "title": "解压未限制成员路径", "severity": "high", "category": "security", "cwe": "CWE-22"},
    {"rule_id": "AST061", "title": "压缩包 extract 未校验路径", "severity": "high", "category": "security", "cwe": "CWE-22"},
    {"rule_id": "AST062", "title": "argparse type=eval", "severity": "high", "category": "security", "cwe": "CWE-95"},
    {"rule_id": "AST063", "title": "umask(0) 过宽", "severity": "medium", "category": "config", "cwe": "CWE-732"},
    {"rule_id": "AST064", "title": "动态加载本地库", "severity": "high", "category": "security", "cwe": "CWE-427"},
    {"rule_id": "AST065", "title": "明文网络协议客户端", "severity": "medium", "category": "security", "cwe": "CWE-319"},
    {"rule_id": "AST066", "title": "XML-RPC 服务/客户端", "severity": "medium", "category": "security", "cwe": "CWE-502"},
    {"rule_id": "AST067", "title": "socket.create_connection 未设置 timeout", "severity": "medium", "category": "bug", "cwe": "CWE-400"},
    {"rule_id": "AST068", "title": "使用明文 HTTPConnection", "severity": "medium", "category": "security", "cwe": "CWE-319"},
    {"rule_id": "AST069", "title": "路由处理函数未见鉴权", "severity": "medium", "category": "security", "cwe": "CWE-306"},
    {"rule_id": "AUTH010", "title": "Django 中间件缺少 CSRF 保护", "severity": "high", "category": "security", "cwe": "CWE-352"},
    {"rule_id": "AUTH011", "title": "Django 中间件缺少认证", "severity": "high", "category": "security", "cwe": "CWE-306"},
    {"rule_id": "CFG007", "title": "Redis 未设置 requirepass", "severity": "high", "category": "config", "cwe": "CWE-306"},
    {"rule_id": "REV001", "title": "仓库缺少测试文件", "severity": "medium", "category": "quality", "cwe": None},
    {"rule_id": "REV002", "title": "测试文件没有断言", "severity": "low", "category": "quality", "cwe": None},
    {"rule_id": "ADV001", "title": "依赖版本存在公开安全公告", "severity": "high", "category": "security", "cwe": "CWE-1395"},
    {"rule_id": "ADV002", "title": "依赖名属于已知被投毒/滥用包", "severity": "high", "category": "security", "cwe": "CWE-1357"},
    {"rule_id": "DK003", "title": "Dockerfile ADD 远程 URL", "severity": "medium", "category": "config", "cwe": "CWE-494"},
    {"rule_id": "DK004", "title": "Dockerfile 未切换非 root 用户", "severity": "low", "category": "config", "cwe": "CWE-250"},
    {"rule_id": "DK005", "title": "基础镜像未钉标签", "severity": "low", "category": "config", "cwe": "CWE-494"},
    {"rule_id": "DEP002", "title": "Python 依赖未钉版本", "severity": "info", "category": "config", "cwe": None},
    {"rule_id": "DEP003", "title": "npm 依赖使用 * / latest", "severity": "medium", "category": "config", "cwe": None},
    {"rule_id": "DEP004", "title": "Go 模块未钉版本", "severity": "medium", "category": "config", "cwe": None},
    {"rule_id": "DEP005", "title": "Cargo 依赖使用 * / latest", "severity": "medium", "category": "config", "cwe": None},
    {"rule_id": "ENV001", "title": "仓库中出现环境文件", "severity": "medium", "category": "secret", "cwe": "CWE-260"},
    {"rule_id": "GH002", "title": "GitHub Actions 权限 write-all", "severity": "high", "category": "config", "cwe": "CWE-250"},
)


def all_rule_records(config: Config | None = None) -> list[dict[str, object]]:
    seen: set[str] = set()
    records: list[dict[str, object]] = []
    extras = [rule.meta() for rule in (config.custom_rules if config else ())]
    for item in [*list_rule_meta(), *AST_AND_ANALYZER_META, *extras]:
        rule_id = str(item["rule_id"])
        if rule_id in seen:
            continue
        seen.add(rule_id)
        records.append(item)
    records.sort(key=lambda item: str(item["rule_id"]))
    return records


def explain_rule(rule_id: str, config: Config | None = None) -> dict[str, object] | None:
    needle = rule_id.strip().upper()
    for item in all_rule_records(config):
        if str(item["rule_id"]).upper() == needle:
            return item
    return None
