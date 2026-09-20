"""All pattern rules in one catalog."""

from __future__ import annotations

from deepopen.patterns.base import PatternRule
from deepopen.patterns.bugs import BUG_RULES
from deepopen.patterns.extra_langs import C_RULES, KOTLIN_RULES, RUST_RULES, SQL_RULES
from deepopen.patterns.frameworks import FRAMEWORK_RULES
from deepopen.patterns.go import GO_RULES
from deepopen.patterns.infra import INFRA_RULES
from deepopen.patterns.java import JAVA_RULES
from deepopen.patterns.javascript import JAVASCRIPT_RULES
from deepopen.patterns.other_langs import CSHARP_RULES, PHP_RULES, RUBY_RULES
from deepopen.patterns.python_code import PYTHON_RULES
from deepopen.patterns.secrets import SECRET_RULES
from deepopen.patterns.web import WEB_RULES

ALL_PATTERN_RULES: tuple[PatternRule, ...] = (
    SECRET_RULES
    + PYTHON_RULES
    + JAVASCRIPT_RULES
    + JAVA_RULES
    + GO_RULES
    + PHP_RULES
    + RUBY_RULES
    + CSHARP_RULES
    + WEB_RULES
    + INFRA_RULES
    + FRAMEWORK_RULES
    + C_RULES
    + RUST_RULES
    + SQL_RULES
    + KOTLIN_RULES
    + BUG_RULES
)

RULE_BY_ID = {rule.rule_id: rule for rule in ALL_PATTERN_RULES}


def list_rule_meta() -> list[dict[str, object]]:
    items = [rule.meta() for rule in ALL_PATTERN_RULES]
    items.sort(key=lambda item: str(item["rule_id"]))
    return items
