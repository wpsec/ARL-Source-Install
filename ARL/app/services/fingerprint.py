"""
Web应用指纹识别
"""
import hashlib
from .expr import parse_expression, evaluate_expression

# 缓存，避免重复解析
parsed_cache = {}


class FingerPrint:
    def __init__(self, app_name: str, human_rule: str, sources=None):
        self.app_name = app_name
        self.human_rule = human_rule
        self.parsed = None
        self.sources = []
        if isinstance(sources, (list, tuple, set)):
            for item in sources:
                source_name = str(item or "").strip().lower()
                if source_name and source_name not in self.sources:
                    self.sources.append(source_name)
        elif sources is not None:
            source_name = str(sources or "").strip().lower()
            if source_name:
                self.sources.append(source_name)

    def identify(self, variables: dict) -> bool:
        if self.parsed is None:
            self.build_parsed()

        return evaluate_expression(self.parsed, variables)

    def build_parsed(self):
        rule_hash = hashlib.md5(self.human_rule.encode()).hexdigest()
        if rule_hash in parsed_cache:
            self.parsed = parsed_cache[rule_hash]
        else:
            self.parsed = parse_expression(self.human_rule)
            parsed_cache[rule_hash] = self.parsed
