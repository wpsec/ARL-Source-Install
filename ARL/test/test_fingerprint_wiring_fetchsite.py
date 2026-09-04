"""计划5 第3阶段：fetchSite unified 接线运行时测试（回应 review "已接入但无运行时证明"）。

验证 `_try_unified_fingerprint` 三条路径：
1. SOURCE=unified + registry 可用 → 接管并写 finger 字段，真实 gz 规则端到端命中；
2. registry 不可用（文件缺失）→ 返回 False，调用方继续 legacy（显式降级）；
3. SOURCE=legacy → 直接不接管（现网默认行为零变化的证明）。
"""
import importlib.util
import os
import pathlib
import unittest

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
SITE_GZ = ROOT_DIR / "app" / "dicts" / "site_fingerprints.json.gz"

try:
    from app.services import fetchSite
    from app.services.site_fingerprint_registry import SiteFingerprintRegistry
    from app.config import Config
    _IMPORT_ERROR = None
except Exception as exc:  # 本地缺 pyquery/mmh3 等运行依赖时跳过，容器内必跑
    _IMPORT_ERROR = str(exc)


@unittest.skipIf(_IMPORT_ERROR, f"容器内执行（本地缺依赖: {_IMPORT_ERROR}）")
class FingerprintWiringFetchSiteTest(unittest.TestCase):
    def setUp(self):
        self._source = Config.SITE_FINGERPRINT_SOURCE
        self._file = Config.SITE_FINGERPRINT_FILE

    def tearDown(self):
        Config.SITE_FINGERPRINT_SOURCE = self._source
        Config.SITE_FINGERPRINT_FILE = self._file

    def _fake_item(self):
        return {
            "headers": "HTTP/1.1 200 OK\nServer: nginx/1.18.0\n",
            "title": "Welcome to nginx!",
            "favicon": {"hash": 0},
            "site": "http://example.com/",
        }

    def _call(self, item):
        content = "<html><head><title>Welcome to nginx!</title></head><body>hello</body></html>".encode("utf-8")
        return fetchSite.WebSiteFetch._try_unified_fingerprint(None, item, content, 0)

    def test_unified_takes_over_with_real_artifact(self):
        Config.SITE_FINGERPRINT_SOURCE = "unified"
        Config.SITE_FINGERPRINT_FILE = str(SITE_GZ)
        # 绕过进程单例，直接构造加载真实 gz
        registry = SiteFingerprintRegistry(str(SITE_GZ)).load()
        self.assertTrue(registry.ok, registry.load_error)
        orig = fetchSite.get_site_registry
        fetchSite.get_site_registry = lambda: registry
        try:
            item = self._fake_item()
            handled = self._call(item)
        finally:
            fetchSite.get_site_registry = orig
        self.assertTrue(handled, "unified 可用时必须接管")
        finger_names = {
            f["name"] if isinstance(f, dict) else f for f in item.get("finger", [])
        } | {
            f["name"] if isinstance(f, dict) else f for f in item.get("finger_candidates", [])
        }
        self.assertIn("Nginx", finger_names, "真实 gz 规则应端到端命中 Nginx")

    def test_registry_unavailable_falls_back(self):
        Config.SITE_FINGERPRINT_SOURCE = "unified"
        dead = SiteFingerprintRegistry(str(ROOT_DIR / "app" / "dicts" / "no_such.json.gz")).load()
        self.assertFalse(dead.ok)
        orig = fetchSite.get_site_registry
        fetchSite.get_site_registry = lambda: dead
        try:
            handled = self._call(self._fake_item())
        finally:
            fetchSite.get_site_registry = orig
        self.assertFalse(handled, "registry 不可用必须回落 legacy（返回 False 交还调用方）")

    def test_legacy_mode_never_takes_over(self):
        Config.SITE_FINGERPRINT_SOURCE = "legacy"
        Config.SITE_FINGERPRINT_FILE = str(SITE_GZ)
        self.assertFalse(self._call(self._fake_item()),
                         "默认 legacy 时接线必须完全惰性（现网行为零变化）")


if __name__ == "__main__":
    unittest.main()
