"""
计划5 第1阶段：指纹三段识别链 golden 快照测试。

为什么：第2-3阶段的"新旧实现结果一致"验收必须先有当前实现的冻结输出；
无在线 Mongo/Redis——Config fake 指向仓库真实规则文件、conn_db 返回空集
（=用户规则未导入的生产子集），锁定文件面行为。
生成快照：ARL_UPDATE_FINGERPRINT_GOLDEN=1 python3 test_fingerprint_golden.py
默认模式：与 golden_v1.json 严格对比，不一致即失败（回归门禁）。
"""
import importlib.util
import json
import os
import pathlib
import sys
import types
import unittest

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT_DIR / "test" / "fixtures" / "fingerprints"
GOLDEN_PATH = FIXTURES / "golden_v1.json"


class _DummyLogger:
    def info(self, *a, **k):
        return None

    def warning(self, *a, **k):
        return None

    def error(self, *a, **k):
        return None

    def debug(self, *a, **k):
        return None


class _DummyCollection:
    """Mongo 空集语义：用户自定义指纹未导入。"""

    def find(self, *a, **k):
        return []

    def find_one(self, *a, **k):
        return None

    def count_documents(self, *a, **k):
        return 0


def _load_module(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _bootstrap():
    """假包遮蔽 + 真实模块加载。

    不走 `import app.services.X`：app/services/__init__.py eager 导入 npoc→xing（仅容器存在）。
    在 sys.modules 预置仅含 __path__ 的假 app/app.services/app.utils 包与假 Config，
    再以 importlib 加载真实 expr/fingerprint/kscan_fingerprint/fingerprint_cache 与
    legacy utils/fingerprint——相对导入经 sys.modules 命中已注册名，解析到真实实现。
    Mongo=空集（用户规则未导入），Redis 关。
    """
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = [str(ROOT_DIR / "app")]
    sys.modules["app"] = app_pkg

    services_pkg = types.ModuleType("app.services")
    services_pkg.__path__ = [str(ROOT_DIR / "app" / "services")]
    sys.modules["app.services"] = services_pkg
    app_pkg.services = services_pkg

    utils_pkg = types.ModuleType("app.utils")
    utils_pkg.__path__ = [str(ROOT_DIR / "app" / "utils")]
    utils_pkg.get_logger = lambda *a, **k: _DummyLogger()
    utils_pkg.conn_db = lambda *a, **k: _DummyCollection()
    utils_pkg.load_file = lambda path: open(path, "r", encoding="utf-8").readlines()
    sys.modules["app.utils"] = utils_pkg
    app_pkg.utils = utils_pkg

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
        KSCAN_FINGERPRINT_FILE = str(ROOT_DIR / "app" / "dicts" / "kscan_fingerprint.json")
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

    def _svc(name):
        return _load_module(f"app.services.{name}", ROOT_DIR / "app" / "services" / f"{name}.py")

    expr = _svc("expr")
    services_pkg.expr = expr
    services_pkg.fingerprint = _svc("fingerprint")
    services_pkg.kscan_fingerprint = _svc("kscan_fingerprint")
    cache_mod = _svc("fingerprint_cache")
    services_pkg.fingerprint_cache = cache_mod

    legacy_mod = _load_module("app.utils.fingerprint", ROOT_DIR / "app" / "utils" / "fingerprint.py")
    utils_pkg.fingerprint = legacy_mod
    return legacy_mod, cache_mod


LEGACY, CACHE = _bootstrap()
SAMPLES = json.loads((FIXTURES / "responses.json").read_text(encoding="utf-8"))["samples"]


def _run_sample(sample):
    """三段链快照：legacy(webapp) + kscan/Mongo 合并确认候选（含置信度）+ wappalyzer 归一。"""
    body_bytes = sample["body"].encode("utf-8")
    legacy_names = sorted(
        LEGACY.fetch_fingerprint(
            content=body_bytes,
            headers=sample["header"],
            title=sample["title"],
            favicon_hash=sample["icon_hash"],
            finger_list=LEGACY.load_fingerprint(),
        )
    )
    variables = {
        "body": sample["body"],
        "header": sample["header"],
        "title": sample["title"],
        "icon_hash": sample["icon_hash"],
        "response": "{}\n{}".format(sample["header"], sample["body"]),
        "url": sample["url"],
    }
    detail = CACHE.finger_db_identify_detail(variables)
    merged = CACHE.build_legacy_fingerprint_items(legacy_names)
    merged.extend(detail)
    confirmed, candidates = CACHE.split_fingerprint_result_items(merged)

    def brief(items):
        return sorted(
            "{}|{}".format(item.get("name"), item.get("confidence"))
            for item in items
        )

    # 第三条路径：wappalyzer 动态证据（以 legacy 命中名构造 applications 输入，
    # 锁定 normalize_wappalyzer_fingerprint_items 的置信度归一行为）
    applications = [{"name": name, "confidence": 100} for name in legacy_names]
    w_confirmed, w_candidates = CACHE.normalize_wappalyzer_fingerprint_items(applications)
    return {
        "legacy": legacy_names,
        "confirmed": brief(confirmed),
        "candidates": brief(candidates),
        "wappalyzer_confirmed": brief(w_confirmed),
        "wappalyzer_candidates": brief(w_candidates),
    }


def _build_snapshot():
    # 全量规则加载只跑一次（kscan 7239 条解析较重），进程内缓存
    return {s["id"]: _run_sample(s) for s in SAMPLES}


class FingerprintGoldenTest(unittest.TestCase):
    def test_golden_snapshot(self):
        snapshot = _build_snapshot()
        update = os.environ.get("ARL_UPDATE_FINGERPRINT_GOLDEN") == "1"
        if update or not GOLDEN_PATH.exists():
            GOLDEN_PATH.write_text(
                json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            self.skipTest("golden_v1.json 已生成/更新，请复核 diff 后再跑回归模式")
        expected = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            json.dumps(snapshot, sort_keys=True, ensure_ascii=False),
            json.dumps(expected, sort_keys=True, ensure_ascii=False),
            "指纹双路径输出与 golden 快照不一致：计划5 第2/3阶段要求行为等价，差异必须显式复核后更新快照",
        )


if __name__ == "__main__":
    unittest.main()
