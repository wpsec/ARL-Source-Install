"""计划5 第5阶段：ServiceFingerprintRegistry 测试（加载真实提交的 service gz 产物）。

断言面：别名 canonical、npoc>nmap 优先级与冲突证据、端口弱候选不确认、
文件缺失降级透传（服务识别链路不中断）、service 名不靠端口确认（§六优先级4）。
"""
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
SERVICE_GZ = ROOT_DIR / "app" / "dicts" / "service_fingerprints.json.gz"



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

def bootstrap():
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = [str(ROOT_DIR / "app")]
    sys.modules.setdefault("app", app_pkg)
    config_module = types.ModuleType("app.config")

    class Config:
        SERVICE_FINGERPRINT_FILE = str(SERVICE_GZ)

    config_module.Config = Config
    sys.modules["app.config"] = config_module
    app_pkg.config = config_module
    spec = importlib.util.spec_from_file_location(
        "app.services.service_fingerprint_registry",
        ROOT_DIR / "app" / "services" / "service_fingerprint_registry.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module, config_module.Config


MOD, CFG = bootstrap()


class ServiceFingerprintRegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = MOD.ServiceFingerprintRegistry(str(SERVICE_GZ))

    def test_load_committed_artifact(self):
        self.assertTrue(self.registry.ok, self.registry.load_error)
        self.assertTrue(self.registry.alias_map)
        self.assertTrue(self.registry.port_map)

    def test_alias_canonical(self):
        self.assertEqual(self.registry.canonical("ms-wbt-server"), "rdp")
        self.assertEqual(self.registry.canonical("SSL/HTTP"), "https")
        self.assertEqual(self.registry.canonical("domain"), "dns")
        # 未知输入原样小写返回（不吞）
        self.assertEqual(self.registry.canonical("WeirdSVC"), "weirdsvc")

    def test_npoc_priority_over_nmap_with_conflict_evidence(self):
        # nmap 说 http、npoc 说 https：取 npoc，冲突证据保留 nmap 侧
        res = self.registry.normalize_result(nmap_service="http", npoc_scheme="https")
        self.assertEqual(res["service"], "https")
        self.assertEqual(res["confidence"], 100)
        self.assertTrue(res["conflict"])
        self.assertEqual(res["conflict"]["chosen"], "npoc_scheme")
        self.assertEqual(res["conflict"]["rejected"][0]["service"], "http")

    def test_agreement_no_conflict(self):
        res = self.registry.normalize_result(nmap_service="ms-wbt-server", npoc_scheme="mstsc")
        self.assertEqual(res["service"], "rdp")
        self.assertIsNone(res["conflict"])
        self.assertEqual(res["confidence"], 100)

    def test_nmap_only_service(self):
        res = self.registry.normalize_result(nmap_service="domain", npoc_scheme="")
        self.assertEqual(res["service"], "dns")
        self.assertEqual(res["confidence"], 90)
        self.assertTrue(res["confirmed"])

    def test_port_only_is_weak_candidate(self):
        res = self.registry.normalize_result(port=3306, proto="tcp")
        self.assertEqual(res["service"], "mysql")
        self.assertFalse(res["confirmed"], "端口号绝不确认服务（05 §六 优先级4）")
        self.assertEqual(res["confidence"], 25)
        self.assertEqual(res["sources"], ["port_only"])

    def test_port_wrong_transport_no_hit(self):
        # 443 是 tcp 服务；udp/443 不应给 https 候选
        res = self.registry.normalize_result(port=443, proto="udp")
        self.assertEqual(res["service"], "")

    def test_unknown_no_conclusion(self):
        res = self.registry.normalize_result(nmap_service="unknown", port=None)
        # unknown 不在别名表 → passthrough "unknown"：由调用方保留 pending 语义（confirmed 但可低置信）
        self.assertIn(res["service"], ("", "unknown"))

    def test_missing_file_passthrough(self):
        reg = MOD.ServiceFingerprintRegistry(str(ROOT_DIR / "app" / "dicts" / "no_such_service.json.gz"))
        self.assertFalse(reg.ok)
        self.assertEqual(reg.canonical("SSL/HTTP"), "ssl/http", "降级=strip+lower 透传（现状行为）")
        res = reg.normalize_result(nmap_service="http", npoc_scheme="https")
        self.assertEqual(res["service"], "https", "无文件时 npoc 优先逻辑仍成立（passthrough 名）")
        self.assertEqual(res["confidence"], 100)

    def test_corrupt_format_not_ok(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "svc.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"meta": {"format": "bogus"}, "fingerprints": []}')
            reg = MOD.ServiceFingerprintRegistry(path)
            self.assertFalse(reg.ok)
            self.assertIn("unsupported format", reg.load_error)




if __name__ == "__main__":
    unittest.main()
