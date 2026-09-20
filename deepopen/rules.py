"""PatternRule catalog (compatibility wrapper)."""

from deepopen.patterns import ALL_PATTERN_RULES, RULE_BY_ID, list_rule_meta
from deepopen.patterns.base import PatternRule

__all__ = ["ALL_PATTERN_RULES", "PatternRule", "RULE_BY_ID", "list_rule_meta"]
