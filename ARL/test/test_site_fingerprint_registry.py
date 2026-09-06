"""计划5 第3阶段：SiteFingerprintRegistry 测试。

核心断言：
1. 真实提交产物（site_fingerprints.json.gz）可加载，规则数与 meta 一致。
2. 严格结果门禁：unified.match 命中集 == 编译 evaluator 命中集（同 12 样本），
   且不引入运行时旧链没有的命中之外的新语义（等于编译基线即通过——unified 就是新基线）。
3. 降级路径：文件缺失/损坏 → ok=False（调用方据此回退 legacy，不得空规则出结果）。
4. icon_hash 快路径与全量判定去重（priority+full 无双命中条目）。
5. reload_if_stale 内容变更即切换。
"""
import gzip
import importlib.util
import json
import os
import pathlib
import re
import sys
import types
import unittest

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
SITE_GZ = ROOT_DIR / "app" / "dicts" / "site_fingerprints.json.gz"
SAMPLES = json.loads((ROOT_DIR / "test" / "fixtures" / "fingerprints" / "responses.json").read_text(encoding="utf-8"))["samples"]


class _DummyLogger:
    def __getattr__(self, _n):
        return lambda *a, **k: None


class _DummyCollection:
    # 可注入的用户指纹集合内容（第4阶段 overlay 测试用）
    docs = []
    raise_error = False

    def find(self, *a, **k):
        if self.raise_error:
            raise RuntimeError("mongo down")
        return iter(list(self.docs))

    def find_one(self, *a, **k):
        return None

    def count_documents(self, *a, **k):
        return 0



# 测试卫生（计划 1 收敛项）：本文件在模块顶层向 sys.modules 注入 fake 包槽位且
# 旧版无还原，单文件独立运行后会把 fake 留给同进程后续用例（合跑顺序敏感）。
# 统一在守卫/钩子处快照并还原共享父槽位；子模块缓存（真实实现）按 bootstrap
# 理念保留。
_HYGIENE_SHARED_SLOTS = (
    "app", "app.utils", "app.config", "app.modules",
    "app.services", "app.services.fingerprints", "app.tools",
)
_HYGIENE_PRE = {n: sys.modules.get(n) for n in _HYGIENE_SHARED_SLOTS}


def tearDownModule():
    for _name, _original in _HYGIENE_PRE.items():
        if _original is None:
            sys.modules.pop(_name, None)
        else:
            sys.modules[_name] = _original

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
        SITE_FINGERPRINT_SOURCE = "unified"
        SITE_FINGERPRINT_FILE = str(SITE_GZ)

    config_module.Config = Config
    sys.modules["app.config"] = config_module
    app_pkg.config = config_module
    svc.expr = _load("app.services.expr", ROOT_DIR / "app" / "services" / "expr.py")
    svc.fingerprint = _load("app.services.fingerprint", ROOT_DIR / "app" / "services" / "fingerprint.py")
    svc.kscan_fingerprint = _load("app.services.kscan_fingerprint", ROOT_DIR / "app" / "services" / "kscan_fingerprint.py")
    cache = _load("app.services.fingerprint_cache", ROOT_DIR / "app" / "services" / "fingerprint_cache.py")
    svc.fingerprint_cache = cache
    registry_mod = _load("app.services.site_fingerprint_registry", ROOT_DIR / "app" / "services" / "site_fingerprint_registry.py")
    svc.site_fingerprint_registry = registry_mod
    return registry_mod, config_module.Config


REGISTRY, CFG = bootstrap()


def cond_hits(cond, variables):
    field_value = str(variables.get(cond["field"], "") or "")
    value = cond["value"]
    if cond["operator"] == "contains":
        return value in field_value
    if cond["operator"] == "equals":
        return field_value == value
    if cond["operator"] == "not_equals":
        return field_value != value
    try:
        return re.search(value, field_value) is not None
    except re.error:
        return False


def evaluate_doc_rule(rule, variables):
    for branch in rule["match"]["any"]:
        if all(cond_hits(c, variables) for c in branch["all"]):
            return True
    return False


def sample_vars(sample):
    header = sample["header"]
    body = sample["body"]
    return {
        "body": body,
        "header": header,
        "title": sample["title"],
        "icon_hash": sample["icon_hash"],
        "response": "{}\n{}".format(header, body),
        "url": sample["url"],
    }


class SiteFingerprintRegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = REGISTRY.SiteFingerprintRegistry(str(SITE_GZ)).load()

    def test_load_committed_artifact(self):
        self.assertTrue(self.registry.ok, self.registry.load_error)
        with gzip.open(SITE_GZ, "rt", encoding="utf-8") as f:
            meta = json.load(f)["meta"]
        self.assertEqual(len(self.registry.rules), meta["rule_count"])
        self.assertTrue(self.registry.file_token and len(self.registry.file_token) == 16)

    def test_strict_equivalence_with_compiled_baseline(self):
        with gzip.open(SITE_GZ, "rt", encoding="utf-8") as f:
            doc_rules = json.load(f)["fingerprints"]
        for sample in SAMPLES:
            variables = sample_vars(sample)
            expected = {r["name"] for r in doc_rules if evaluate_doc_rule(r, variables)}
            got = {item["name"] for item in self.registry.match(variables)}
            self.assertEqual(got, expected, f"{sample['id']}: unified 命中集偏离编译基线")

    def test_no_duplicate_entries_icon_fastpath(self):
        # icon_hash_1panel 走精确桶 + 全量扫描，去重后条目不得重复
        sample = [s for s in SAMPLES if s["id"] == "icon_hash_1panel"][0]
        items = self.registry.match(sample_vars(sample))
        names = [i["name"] for i in items]
        self.assertEqual(len(names), len(set(names)), "priority+full 出现重复命中")
        self.assertIn("1panel", names, "faviconhash 规则应经规范文件链命中（不再依赖 Mongo 导入）")

    def test_confirmed_candidate_split(self):
        confirmed, candidates = REGISTRY.split_unified_items(
            [{"name": "HighApp", "confidence": 90, "sources": ["kscan_local"], "match_fields": ["body"]},
             {"name": "LowApp", "confidence": 74, "sources": ["tools_finger"], "match_fields": ["body"]}]
        )
        self.assertEqual([c["name"] for c in confirmed], ["HighApp"])
        self.assertEqual([c["name"] for c in candidates], ["LowApp"])

    def test_missing_file_not_ok(self):
        reg = REGISTRY.SiteFingerprintRegistry(str(ROOT_DIR / "app" / "dicts" / "no_such_file.json.gz")).load()
        self.assertFalse(reg.ok)
        self.assertTrue(reg.load_error.startswith("file_unreadable"))
        self.assertEqual(reg.match({"body": "x"}), [])

    def test_corrupt_file_not_ok(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"meta": {"format": "wrong"}, "fingerprints": []}')
            reg = REGISTRY.SiteFingerprintRegistry(path).load()
            self.assertFalse(reg.ok)
            self.assertIn("parse_failed", reg.load_error)

    def test_reload_on_content_change(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "site.json")
            doc = {"meta": {"format": "arl_site_fingerprint_v1"}, "fingerprints": [
                {"id": "site:a", "name": "A", "confidence": 90, "sources": ["custom"],
                 "match": {"any": [{"all": [{"field": "body", "operator": "contains", "value": "aaa-marker"}]}]},
                 "canonical_rule": 'body="aaa-marker"', "enabled": True}]}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            reg = REGISTRY.SiteFingerprintRegistry(path).load()
            self.assertTrue(reg.ok)
            doc["fingerprints"].append(
                {"id": "site:b", "name": "B", "confidence": 90, "sources": ["custom"],
                 "match": {"any": [{"all": [{"field": "title", "operator": "contains", "value": "bbb"}]}]},
                 "canonical_rule": 'title="bbb"', "enabled": True})
            with open(path, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            reg.reload_if_stale()
            self.assertEqual(len(reg.rules), 2)


class SiteFingerprintOverlayTest(unittest.TestCase):
    """第4阶段：Mongo 用户规则 overlay（真相源在 Mongo，policy 豁免用户意图）。"""

    def _make_registry(self, base_rules, docs):
        import tempfile
        _DummyCollection.docs = docs
        try:
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "site.json")
                with open(path, "w", encoding="utf-8") as f:
                    json.dump({"meta": {"format": "arl_site_fingerprint_v1"}, "fingerprints": base_rules}, f)
                return REGISTRY.SiteFingerprintRegistry(path).load()
        finally:
            pass

    def setUp(self):
        _DummyCollection.raise_error = False
        self.base = [{"id": "site:baseapp", "name": "BaseApp", "confidence": 90, "sources": ["kscan_local"],
                      "match": {"any": [{"all": [{"field": "body", "operator": "contains", "value": "base-marker"}]}]},
                      "canonical_rule": 'body="base-marker"', "enabled": True}]
        self.vars = {"body": "base-marker and user-marker and login", "header": "", "title": "",
                     "icon_hash": "0", "response": "", "url": ""}

    def tearDown(self):
        _DummyCollection.docs = []

    def test_new_user_rule_and_same_name_merge(self):
        reg = self._make_registry(self.base, [
            {"name": "UserApp", "human_rule": 'body="user-marker"'},
            {"name": "baseapp", "human_rule": 'title="x-marker-y"'},
        ])
        self.assertTrue(reg.ok)
        by_name = {r["name"]: r for r in reg.rules}
        self.assertIn("UserApp", by_name)
        merged = [r for r in reg.rules if r["id"] == "site:baseapp"]
        self.assertEqual(len(merged), 1)
        rule = merged[0]
        self.assertIn("mongo_user", rule["sources"])
        self.assertEqual(len(rule["match"]["any"]), 2)  # 基线分支 + 用户分支
        names = {i["name"] for i in reg.match(self.vars)}
        self.assertEqual(names, {"BaseApp", "UserApp"})

    def test_user_intent_exempt_from_policy(self):
        # 用户显式 body="login"：编译 policy 会拒绝，overlay 必须保留（用户意图优先）
        reg = self._make_registry(self.base, [{"name": "MyLoginApp", "human_rule": 'body="login"'}])
        names = {i["name"] for i in reg.match(self.vars)}
        self.assertIn("MyLoginApp", names)

    def test_malformed_user_rule_skipped(self):
        reg = self._make_registry(self.base, [
            {"name": "Broken", "human_rule": 'body="x" && (title="a" || title="b")'},
            {"name": "Ok", "human_rule": 'body="ok-marker-z"'},
        ])
        ids = {r["id"] for r in reg.rules}
        self.assertNotIn("site:broken", ids)
        self.assertIn("site:ok", ids)

    def test_mongo_down_baseline_only(self):
        _DummyCollection.raise_error = True
        reg = self._make_registry(self.base, [])
        self.assertTrue(reg.ok, "Mongo 不可达时基线必须继续服务")
        self.assertIn("overlay_unavailable", reg._overlay_error)
        names = {i["name"] for i in reg.match(self.vars)}
        self.assertEqual(names, {"BaseApp"})

    def test_repeated_rebuild_does_not_pollute_base(self):
        reg = self._make_registry(self.base, [{"name": "baseapp", "human_rule": 'title="x-marker-y"'}])
        base_branches_before = len(reg._base_rules[0]["match"]["any"])
        reg._rebuild_with_overlay()
        reg._rebuild_with_overlay()
        reg._rebuild_with_overlay()
        self.assertEqual(len(reg._base_rules[0]["match"]["any"]), base_branches_before, "_base_rules 被 overlay 污染")
        rule = [r for r in reg.rules if r["id"] == "site:baseapp"][0]
        self.assertEqual(len(rule["match"]["any"]), 2, "重复 rebuild 后分支被叠加膨胀")




if __name__ == "__main__":
    unittest.main()
