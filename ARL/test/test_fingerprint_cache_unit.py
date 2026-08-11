"""
指纹缓存与打分逻辑单元测试
"""
import importlib.util
import pathlib
import re
import sys
import types
import unittest
from unittest.mock import patch

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]


class _DummyLogger:
    def info(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None

    def error(self, *args, **kwargs):
        return None


class _DummyCollection:
    def find(self, *args, **kwargs):
        return []

    def find_one(self, *args, **kwargs):
        return None


def _load_module(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _bootstrap_test_modules():
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = [str(ROOT_DIR / "app")]
    sys.modules["app"] = app_pkg

    services_pkg = types.ModuleType("app.services")
    services_pkg.__path__ = [str(ROOT_DIR / "app" / "services")]
    sys.modules["app.services"] = services_pkg
    app_pkg.services = services_pkg

    config_module = types.ModuleType("app.config")

    class Config:
        REDIS_ENABLE = False
        REDIS_HOST = "127.0.0.1"
        REDIS_PORT = 6379
        REDIS_DB = 0
        REDIS_PASSWORD = ""
        REDIS_CACHE_EXPIRE = 0
        KSCAN_FINGERPRINT_ENABLE = False
        KSCAN_FINGERPRINT_FILE = str(ROOT_DIR / "app" / "dicts" / "kscan_fingerprint.json")
        KSCAN_FINGERPRINT_NAME_PREFIX = ""
        KSCAN_FINGERPRINT_REGEX_FALLBACK = "literal"
        KSCAN_FINGERPRINT_MIN_LITERAL_LEN = 5
        KSCAN_FINGERPRINT_MAX_RULES_PER_NAME = 30
        KSCAN_FINGERPRINT_MAX_TOTAL_RULES = 12000

    config_module.Config = Config
    sys.modules["app.config"] = config_module
    app_pkg.config = config_module

    utils_module = types.ModuleType("app.utils")
    utils_module.get_logger = lambda: _DummyLogger()
    utils_module.conn_db = lambda *args, **kwargs: _DummyCollection()
    sys.modules["app.utils"] = utils_module
    app_pkg.utils = utils_module

    expr_module = types.ModuleType("app.services.expr")
    token_pattern = re.compile(
        r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(==|!=|=)\s*"((?:[^"\\]|\\.)*)"\s*$'
    )

    def _split_logic(expression, operator_text):
        out = []
        buf = []
        in_quotes = False
        escaped = False
        i = 0
        while i < len(expression):
            ch = expression[i]
            if ch == "\\" and in_quotes and not escaped:
                escaped = True
                buf.append(ch)
                i += 1
                continue
            if ch == '"' and not escaped:
                in_quotes = not in_quotes
            if not in_quotes and expression[i:i + len(operator_text)] == operator_text:
                out.append("".join(buf).strip())
                buf = []
                i += len(operator_text)
                escaped = False
                continue
            buf.append(ch)
            escaped = False
            i += 1
        out.append("".join(buf).strip())
        return [item for item in out if item]

    def _eval_atom(atom, variables):
        match = token_pattern.match(atom)
        if not match:
            raise ValueError("unsupported atom: {}".format(atom))
        field_name, operator_text, expected_value = match.groups()
        actual_value = str(variables.get(field_name, ""))
        if operator_text == "=":
            return expected_value in actual_value
        if operator_text == "==":
            return actual_value == expected_value
        if operator_text == "!=":
            return actual_value != expected_value
        raise ValueError("unsupported operator: {}".format(operator_text))

    def parse_expression(expression):
        return str(expression or "")

    def evaluate_expression(parsed, variables):
        or_items = _split_logic(str(parsed or ""), "||")
        for or_item in or_items:
            and_items = _split_logic(or_item, "&&")
            if and_items and all(_eval_atom(atom, variables) for atom in and_items):
                return True
        return False

    def evaluate(expression, variables):
        return evaluate_expression(parse_expression(expression), variables)

    def check_expression(expression):
        try:
            evaluate(expression, {
                "body": "",
                "header": "",
                "title": "",
                "icon_hash": "",
                "response": "",
                "url": "",
            })
            return True
        except Exception:
            return False

    def check_expression_with_error(expression):
        try:
            check_expression(expression)
            return True, None
        except Exception as exc:
            return False, exc

    expr_module.parse_expression = parse_expression
    expr_module.evaluate_expression = evaluate_expression
    expr_module.evaluate = evaluate
    expr_module.check_expression = check_expression
    expr_module.check_expression_with_error = check_expression_with_error
    sys.modules["app.services.expr"] = expr_module

    fingerprint_module = _load_module("app.services.fingerprint", ROOT_DIR / "app" / "services" / "fingerprint.py")
    services_pkg.fingerprint = fingerprint_module
    kscan_module = _load_module("app.services.kscan_fingerprint", ROOT_DIR / "app" / "services" / "kscan_fingerprint.py")
    services_pkg.kscan_fingerprint = kscan_module
    fingerprint_cache_module = _load_module(
        "app.services.fingerprint_cache",
        ROOT_DIR / "app" / "services" / "fingerprint_cache.py",
    )
    services_pkg.fingerprint_cache = fingerprint_cache_module

    return expr_module, fingerprint_module, kscan_module, fingerprint_cache_module


try:
    _, fingerprint_module, _, fingerprint_cache_module = _bootstrap_test_modules()
    FingerPrint = fingerprint_module.FingerPrint
    estimate_human_rule_confidence = fingerprint_cache_module.estimate_human_rule_confidence
    finger_db_identify_detail = fingerprint_cache_module.finger_db_identify_detail
    normalize_wappalyzer_fingerprint_items = fingerprint_cache_module.normalize_wappalyzer_fingerprint_items
    split_fingerprint_result_items = fingerprint_cache_module.split_fingerprint_result_items
    IMPORT_ERROR = None
except Exception as exc:
    FingerPrint = None
    estimate_human_rule_confidence = None
    finger_db_identify_detail = None
    normalize_wappalyzer_fingerprint_items = None
    split_fingerprint_result_items = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires fingerprint test dependencies: {}".format(IMPORT_ERROR))
class TestFingerprintCacheUnit(unittest.TestCase):
    """
    验证指纹详情聚合与置信度估算逻辑
    """

    def test_estimate_human_rule_confidence(self):
        """
        强特征规则的置信度应高于弱特征规则
        """
        self.assertGreater(
            estimate_human_rule_confidence('icon_hash=="116323821"'),
            estimate_human_rule_confidence('body="Welcome"'),
        )
        self.assertGreater(
            estimate_human_rule_confidence('header="Server: nginx" || body="Welcome"'),
            estimate_human_rule_confidence('header="Server: nginx"'),
        )

    @patch("app.services.fingerprint_cache.finger_db_cache.get_data")
    def test_identify_detail_keeps_highest_confidence(self, mock_get_data):
        """
        同名应用命中多条规则时应保留置信度最高的一条
        """
        mock_get_data.return_value = [
            FingerPrint("禅道", 'url="/zentao/user"'),
            FingerPrint("禅道", 'icon_hash=="116323821"'),
            FingerPrint("Nginx", 'header="server: nginx"'),
        ]

        variables = {
            "body": "",
            "header": "server: nginx",
            "title": "",
            "icon_hash": "116323821",
            "response": "server: nginx\n",
            "url": "https://demo.local/zentao/user-login.html",
        }

        results = finger_db_identify_detail(variables)
        self.assertEqual(results[0]["name"], "禅道")
        self.assertGreaterEqual(results[0]["confidence"], 95)
        self.assertIn("icon_hash", results[0]["match_fields"])
        self.assertEqual(results[0]["matched_rule_count"], 2)
        self.assertEqual(results[0]["confidence_level"], "confirmed")

    @patch("app.services.fingerprint_cache.finger_db_cache.get_data")
    def test_identify_detail_demotes_weak_single_rule(self, mock_get_data):
        """
        单条弱规则命中应进入候选区，避免直接确认为资产指纹
        """
        mock_get_data.return_value = [
            FingerPrint("弱命中应用", 'body="welcome"'),
        ]

        variables = {
            "body": "welcome to demo",
            "header": "",
            "title": "",
            "icon_hash": "",
            "response": "welcome to demo",
            "url": "https://demo.local/",
        }

        results = finger_db_identify_detail(variables)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "弱命中应用")
        self.assertLess(results[0]["confidence"], 85)
        self.assertEqual(results[0]["confidence_level"], "candidate")

    def test_split_fingerprint_result_items_routes_candidates(self):
        """
        合流后的指纹结果应区分 confirmed 与 candidate
        """
        confirmed, candidates = split_fingerprint_result_items([
            {"name": "Nginx", "confidence": 88, "sources": ["rule"]},
            {"name": "WordPress", "confidence": 72, "sources": ["legacy_rule"]},
            {"name": "WordPress", "confidence": 73, "sources": ["wappalyzer"]},
            {"name": "Noise", "confidence": 60, "sources": ["wappalyzer"]},
        ])

        self.assertEqual([item["name"] for item in confirmed], ["Nginx"])
        self.assertEqual([item["name"] for item in candidates], ["WordPress"])
        self.assertGreaterEqual(candidates[0]["confidence"], 73)
        self.assertIn("wappalyzer", candidates[0]["sources"])

    def test_normalize_wappalyzer_filters_low_confidence(self):
        """
        Wappalyzer 低置信度结果不应直接进入指纹结果集
        """
        confirmed, candidates = normalize_wappalyzer_fingerprint_items([
            {"name": "HighConf", "confidence": "90", "version": "", "website": "", "categories": []},
            {"name": "CandidateConf", "confidence": "72", "version": "", "website": "", "categories": []},
            {"name": "LowConf", "confidence": "65", "version": "", "website": "", "categories": []},
        ])

        self.assertEqual([item["name"] for item in confirmed], ["HighConf"])
        self.assertEqual([item["name"] for item in candidates], ["CandidateConf"])
        self.assertEqual(candidates[0]["confidence_level"], "candidate")


if __name__ == "__main__":
    unittest.main()
