"""计划5 第5阶段：IPTask 服务映射接线测试（容器内执行，本地因 xing 依赖 skip）。

验证 NPoC 回填链真正经过 ServiceFingerprintRegistry：
1. `_apply_npoc_service_result` 回填后端口带 service_confidence/service_sources，
   冲突证据保留 nmap 侧结论；
2. `_normalize_scheme` 经规范文件 canonical（ms-wbt-server→rdp）而非仅硬编码表。
"""
import pathlib
import types
import unittest
from unittest import mock

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
SERVICE_GZ = ROOT_DIR / "app" / "dicts" / "service_fingerprints.json.gz"

try:
    from app.tasks.ip import IPTask
    from app.services.service_fingerprint_registry import ServiceFingerprintRegistry
    _IMPORT_ERROR = None
except Exception as exc:  # 本地无 xing/celery → 容器跑
    _IMPORT_ERROR = str(exc)


@unittest.skipIf(_IMPORT_ERROR, f"容器内执行（本地缺依赖: {_IMPORT_ERROR}）")
class FingerprintWiringIpTaskTest(unittest.TestCase):
    def setUp(self):
        self.registry = ServiceFingerprintRegistry(str(SERVICE_GZ))
        self.assertTrue(self.registry.ok, self.registry.load_error)
        patcher = mock.patch(
            "app.services.service_fingerprint_registry.get_service_registry",
            return_value=self.registry,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _fake_task(self, port_info):
        return types.SimpleNamespace(
            ip_info_list=[{"ip": "10.1.2.3", "port_info": [port_info]}],
            _is_low_conf_service=staticmethod(IPTask._is_low_conf_service).__func__,
            _normalize_scheme=staticmethod(IPTask._normalize_scheme).__func__,
        )

    def test_apply_npoc_backfill_carries_evidence(self):
        port_info = {"port_id": 443, "service_name": "unknown", "product": ""}
        task = types.SimpleNamespace(
            ip_info_list=[{"ip": "10.1.2.3", "port_info": [port_info]}],
        )
        # _apply 内用到 self._is_low_conf_service：绑定真实静态方法
        task._is_low_conf_service = staticmethod(IPTask._is_low_conf_service).__func__
        updated = IPTask._apply_npoc_service_result(task, [
            {"host": "10.1.2.3", "port": "443", "scheme": "https"},
        ])
        self.assertEqual(updated, 1)
        self.assertEqual(port_info["service_name"], "https")
        self.assertEqual(port_info["service_confidence"], 100)
        self.assertEqual(port_info["service_sources"], ["npoc_scheme"])
        self.assertTrue(port_info.get("service_conflict"), "unknown 与 https 并存应留冲突证据")
        self.assertEqual(port_info["service_conflict"]["rejected"][0]["service"], "unknown")

    def test_normalize_scheme_goes_through_canonical_file(self):
        task = self._fake_task({})
        self.assertEqual(task._normalize_scheme("ms-wbt-server"), "rdp")
        self.assertEqual(task._normalize_scheme("SSL/HTTP"), "https")


if __name__ == "__main__":
    unittest.main()
