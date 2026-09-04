"""计划5 第2阶段B：统一指纹生成器测试。

核心断言（review 收紧版）：
1. 确定性——两次构建字节一致。
2. 严格语义门禁——编译产物命中集必须是运行时命中的**子集**（policy 只允许删，
   不允许编译引入运行时不存在的命中）；差集逐一归因于分支级拒绝动作。
   （expr ≥3 分支 None 缺陷已在 d48541ba 修复，不再存在"已知差异豁免"。）
3. 分支级拒绝——含泛化条件的整个分支作废；`A && login` 绝不降级为 `A`。
4. 括号语法/不支持字段整条拒绝；schema 校验拦截坏文档；service 写入失败回滚 site；
   服务 transport 正确（dns/dhcp/snmp 含 udp）；merge key 标点敏感（A-B ≠ AB）。
"""
import importlib.util
import json
import os
import pathlib
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]


class _DummyLogger:
    def __getattr__(self, _n):
        return lambda *a, **k: None


class _DummyCollection:
    def find(self, *a, **k):
        return iter([])

    def find_one(self, *a, **k):
        return None

    def count_documents(self, *a, **k):
        return 0


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def bootstrap():
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = [str(ROOT_DIR / "app")]
    sys.modules["app"] = app_pkg
    svc = types.ModuleType("app.services")
    svc.__path__ = [str(ROOT_DIR / "app" / "services")]
    sys.modules["app.services"] = svc
    app_pkg.services = svc
    tools = types.ModuleType("app.tools")
    tools.__path__ = [str(ROOT_DIR / "app" / "tools")]
    sys.modules["app.tools"] = tools
    app_pkg.tools = tools
    utils = types.ModuleType("app.utils")
    utils.__path__ = [str(ROOT_DIR / "app" / "utils")]
    utils.get_logger = lambda *a, **k: _DummyLogger()
    utils.conn_db = lambda *a, **k: _DummyCollection()
    utils.load_file = lambda p: open(p, encoding="utf-8").readlines()
    sys.modules["app.utils"] = utils
    app_pkg.utils = utils
    config_module = types.ModuleType("app.config")

    class Config:
        REDIS_ENABLE = False
        REDIS_HOST = "127.0.0.1"
        REDIS_PORT = 6379
        REDIS_DB = 0
        REDIS_PASSWORD = ""
        REDIS_CACHE_EXPIRE = 0
        web_app_rule = str(ROOT_DIR / "app" / "dicts" / "webapp.json")
        FINGERPRINT = str(ROOT_DIR.parent / "tools" / "finger.json")
        KSCAN_FINGERPRINT_ENABLE = True
        KSCAN_FINGERPRINT_FILE = str(ROOT_DIR / "app" / "dicts" / "kscan_fingerprint.local.json")
        KSCAN_FINGERPRINT_NAME_PREFIX = ""
        KSCAN_FINGERPRINT_REGEX_FALLBACK = "literal"
        KSCAN_FINGERPRINT_MIN_LITERAL_LEN = 5
        KSCAN_FINGERPRINT_MAX_RULES_PER_NAME = 30
        KSCAN_FINGERPRINT_MAX_TOTAL_RULES = 12000
        FINGER_CONFIDENCE_MIN = 85
        FINGER_CANDIDATE_CONFIDENCE_MIN = 70
        FINGER_LEGACY_RULE_CONFIDENCE = 72
        WAPPALYZER_CONFIDENCE_MIN = 70
        FINGER_CANDIDATE_MAX_ITEMS = 8

    config_module.Config = Config
    sys.modules["app.config"] = config_module
    app_pkg.config = config_module
    svc.expr = _load("app.services.expr", ROOT_DIR / "app" / "services" / "expr.py")
    svc.fingerprint = _load("app.services.fingerprint", ROOT_DIR / "app" / "services" / "fingerprint.py")
    svc.kscan_fingerprint = _load("app.services.kscan_fingerprint", ROOT_DIR / "app" / "services" / "kscan_fingerprint.py")
    cache = _load("app.services.fingerprint_cache", ROOT_DIR / "app" / "services" / "fingerprint_cache.py")
    svc.fingerprint_cache = cache
    build = _load("app.tools.build_unified_fingerprints", ROOT_DIR / "app" / "tools" / "build_unified_fingerprints.py")
    return cache, build, config_module.Config


CACHE, BUILD, CFG = bootstrap()
SAMPLES = json.loads((ROOT_DIR / "test" / "fixtures" / "fingerprints" / "responses.json").read_text(encoding="utf-8"))["samples"]
KSCAN_LOCAL = str(ROOT_DIR / "app" / "dicts" / "kscan_fingerprint.local.json")


def build_kscan_only():
    merger = BUILD.Merger()
    n = BUILD._load_human_rule_source(KSCAN_LOCAL, "kscan_local", merger)
    return merger.finalize(), n, merger


def evaluate_rule(rule, variables):
    for branch in rule["match"]["any"]:
        ok = True
        for cond in branch["all"]:
            field_value = str(variables.get(cond["field"], "") or "")
            value = cond["value"]
            if cond["operator"] == "contains":
                hit = value in field_value
            elif cond["operator"] == "equals":
                hit = field_value == value
            elif cond["operator"] == "not_equals":
                hit = field_value != value
            else:
                try:
                    hit = re.search(value, field_value) is not None
                except re.error:
                    hit = False
            if not hit:
                ok = False
                break
        if ok:
            return True
    return False


def sample_vars(sample):
    return {
        "body": sample["body"],
        "header": sample["header"],
        "title": sample["title"],
        "icon_hash": sample["icon_hash"],
        "response": "{}\n{}".format(sample["header"], sample["body"]),
        "url": sample["url"],
    }


def main_argv(site_out, service_out):
    return [
        "--webapp", str(ROOT_DIR / "app/dicts/webapp.json"),
        "--finger", str(ROOT_DIR.parent / "tools/finger.json"),
        "--kscan-file", KSCAN_LOCAL,
        "--site-out", site_out,
        "--service-out", service_out,
    ]


class UnifiedFingerprintsBuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules, cls.input_count, cls.merger = build_kscan_only()
        cls.rules_by_name = {r["name"].lower(): r for r in cls.rules}

    def test_deterministic(self):
        rules2, _, _ = build_kscan_only()
        self.assertEqual(
            json.dumps(self.rules, ensure_ascii=False, sort_keys=True),
            json.dumps(rules2, ensure_ascii=False, sort_keys=True),
            "两次构建字节不一致：确定性被破坏",
        )

    def test_strict_subset_semantics_vs_runtime(self):
        for sample in SAMPLES:
            variables = sample_vars(sample)
            CFG.KSCAN_FINGERPRINT_FILE = KSCAN_LOCAL
            CACHE.finger_db_cache.cache = None
            runtime_names = {str(i.get("name", "")).lower() for i in CACHE.finger_db_identify_detail(variables)}
            compiled_names = {r["name"].lower() for r in self.rules if evaluate_rule(r, variables)}

            invented = compiled_names - runtime_names
            self.assertEqual(invented, set(), f"{sample['id']}: 编译引入运行时不存在的命中 {invented}")

            for name in runtime_names - compiled_names:
                key = BUILD.merge_key(name)
                if key in self.merger.rejected_rule_keys:
                    continue
                dropped = self.merger.dropped_branch_values.get(key, set())
                blamed = any(value in str(variables.get(field, "")) for field, value in dropped)
                self.assertTrue(blamed, f"{sample['id']}: {name} 命中丢失无法归因于分支拒绝")

    def test_branch_level_rejection_not_condition_strip(self):
        merger = BUILD.Merger()
        match, problems = BUILD.parse_human_rule('body="unique-app-marker" && body="login"')
        self.assertEqual(problems, [])
        merger.add("DemoProduct", match, "custom")
        rules = merger.finalize()
        self.assertEqual(rules, [], "分支拒绝退化成了条件摘除")
        self.assertEqual(merger.stats["dropped_branches"], 1)
        self.assertEqual(merger.stats["rejected_rules"], 1)

    def test_mixed_rule_keeps_other_branches(self):
        merger = BUILD.Merger()
        match, _ = BUILD.parse_human_rule('body="login" || body="real-marker-x"')
        merger.add("DemoTwo", match, "custom")
        rules = merger.finalize()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["canonical_rule"], 'body="real-marker-x"')

    def test_parentheses_rejected_not_guessed(self):
        match, problems = BUILD.parse_human_rule('body="x" && (title="a" || title="b")')
        self.assertIsNone(match)
        self.assertIn("parentheses_not_supported", problems)

    def test_unsupported_field_rejected(self):
        match, problems = BUILD.parse_human_rule('port="8080"')
        self.assertIsNone(match)
        self.assertIn("unsupported_field:port", problems)

    def test_merge_key_punctuation_sensitive(self):
        merger = BUILD.Merger()
        for name in ("ACME-Router", "ACMERouter"):
            match, _ = BUILD.parse_human_rule('body="marker-%s"' % name)
            merger.add(name, match, "custom")
        self.assertEqual(len({r["id"] for r in merger.finalize()}), 2, "A-B 与 AB 被错误合并")

        merger2 = BUILD.Merger()
        for name in ("Nginx", "  nginx "):
            match, _ = BUILD.parse_human_rule('body="same-marker"')
            merger2.add(name, match, "custom")
        self.assertEqual(len(merger2.finalize()), 1)

    def test_branch_sources_preserved(self):
        merger = BUILD.Merger()
        m1, _ = BUILD.parse_human_rule('body="m1-marker-x"')
        m2, _ = BUILD.parse_human_rule('body="m2-marker-y"')
        merger.add("Merged", m1, "webapp")
        merger.add("Merged", m2, "kscan_local")
        rule = merger.finalize()[0]
        self.assertEqual(rule["sources"], ["kscan_local", "webapp"])
        branch_sources = [b["sources"] for b in rule["match"]["any"]]
        self.assertIn(["kscan_local"], branch_sources)
        self.assertIn(["webapp"], branch_sources)

    def test_anchor_coverage(self):
        for rule in self.rules:
            self.assertTrue(rule["anchors"], f"{rule['id']} 缺 anchors")

    def test_schema_validation(self):
        broken = {"fingerprints": [{
            "id": "site:x", "name": "X", "confidence": 90,
            "anchors": [{"field": "body"}],
            "match": {"any": [{"all": [{"field": "bogus", "operator": "contains", "value": "v"}], "sources": ["custom"]}]},
        }]}
        with self.assertRaises(AssertionError):
            BUILD.validate_site_document(broken)

    def test_service_transports(self):
        rules = {r["id"]: r for r in BUILD.build_service_fingerprints()}
        self.assertEqual({t["proto"] for t in rules["service:dns"]["transports"]}, {"udp", "tcp"})
        self.assertEqual({t["proto"] for t in rules["service:dhcp"]["transports"]}, {"udp"})
        self.assertEqual({t["proto"] for t in rules["service:snmp"]["transports"]}, {"udp"})
        self.assertEqual({t["proto"] for t in rules["service:mysql"]["transports"]}, {"tcp"})
        BUILD.validate_service_document({"meta": {}, "fingerprints": BUILD.build_service_fingerprints()})

    def test_write_failure_keeps_previous_files(self):
        with tempfile.TemporaryDirectory() as d:
            site_out = os.path.join(d, "site.json")
            service_out = os.path.join(d, "service.json")
            BUILD.main(main_argv(site_out, service_out))
            site_before = open(site_out, encoding="utf-8").read()

            real_writer = BUILD.atomic_write_json

            def fail_on_service(path, doc, **kwargs):
                if path == service_out:
                    raise OSError("simulated disk failure")
                real_writer(path, doc, **kwargs)

            with mock.patch.object(BUILD, "atomic_write_json", side_effect=fail_on_service):
                with self.assertRaises(OSError):
                    BUILD.main(main_argv(site_out, service_out))
            self.assertEqual(open(site_out, encoding="utf-8").read(), site_before, "site 被部分更新或回滚失败")
            # last-good 存在且可解析
            self.assertTrue(os.path.isfile(site_out + ".last-good"))
            json.load(open(site_out + ".last-good", encoding="utf-8"))

    def test_compress_roundtrip(self):
        import gzip
        with tempfile.TemporaryDirectory() as d:
            BUILD.main(main_argv(os.path.join(d, "site.json"), os.path.join(d, "service.json")) + ["--compress"])
            with gzip.open(os.path.join(d, "site.json.gz"), "rt", encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual(doc["meta"]["rule_count"], len(doc["fingerprints"]))
            self.assertNotIn("anchors", doc["fingerprints"][0], "anchors 属派生字段，不应进存储产物")
            # 规则内容完整：match/canonical/confidence 在
            rule = doc["fingerprints"][0]
            for key in ("id", "name", "match", "canonical_rule", "confidence", "sources", "enabled"):
                self.assertIn(key, rule)

    def test_stopword_noise_removed(self):
        def canonical_of(name):
            r = self.rules_by_name.get(name.lower())
            return r["canonical_rule"] if r else ""

        self.assertNotIn('body="login"', canonical_of("GROWATT 系统"))
        self.assertNotIn('header="server"', canonical_of("HUAWEI-S5730"))
        self.assertNotIn('header="server"', canonical_of("HUAWEI-S7700"))
        self.assertIn("v3/js/odm/odm.js", canonical_of("GROWATT 系统"))


if __name__ == "__main__":
    unittest.main()
