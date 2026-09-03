"""配置域事务服务测试。"""

import importlib.util
import threading
import unittest
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "config_domain_service.py"
_SPEC = importlib.util.spec_from_file_location("config_domain_service_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)
ConfigDomainService = _MODULE.ConfigDomainService


class _ConfigCenter(object):
    def __init__(self):
        self.config = {"ARL": {"value": 1}}
        self.calls = []

    def load(self, _path):
        self.calls.append("load")
        return dict(self.config)

    def persist(self, _path, config):
        self.calls.append("persist")
        self.config = config
        return {"backup_path": "backup", "runtime_refreshed": True}


class TestConfigDomainService(unittest.TestCase):
    def test_update_has_one_transaction_boundary(self):
        center = _ConfigCenter()
        service = ConfigDomainService(
            config_center=center,
            path_resolver=lambda: Path("/tmp/config.yaml"),
            lock=threading.RLock(),
        )

        path, config, result = service.update(
            {"value": 2},
            lambda current, payload: {
                "ARL": {"value": payload["value"]},
                "unchanged": current.get("unchanged", True),
            },
            validator=lambda value: self.assertIn("ARL", value),
        )

        self.assertEqual(Path("/tmp/config.yaml"), path)
        self.assertEqual(2, config["ARL"]["value"])
        self.assertTrue(result["runtime_refreshed"])
        self.assertEqual(["load", "persist"], center.calls)

    def test_save_validates_before_persisting(self):
        center = _ConfigCenter()
        service = ConfigDomainService(
            config_center=center,
            path_resolver=lambda: Path("/tmp/config.yaml"),
            lock=threading.RLock(),
        )

        with self.assertRaises(ValueError):
            service.save({}, validator=lambda _value: (_ for _ in ()).throw(ValueError("invalid")))

        self.assertEqual([], center.calls)


if __name__ == "__main__":
    unittest.main()
