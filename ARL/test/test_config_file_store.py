"""配置文件存储服务回归测试。"""

import importlib.util
import tempfile
import unittest
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "config_file_store.py"
_SPEC = importlib.util.spec_from_file_location("config_file_store_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)
ConfigFileStore = _MODULE.ConfigFileStore

_CENTER_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "config_center.py"
_CENTER_SPEC = importlib.util.spec_from_file_location("config_center_test_module", _CENTER_PATH)
_CENTER_MODULE = importlib.util.module_from_spec(_CENTER_SPEC)
assert _CENTER_SPEC and _CENTER_SPEC.loader
_CENTER_SPEC.loader.exec_module(_CENTER_MODULE)
ConfigCenterService = _CENTER_MODULE.ConfigCenterService


class TestConfigFileStore(unittest.TestCase):
    def test_load_atomic_write_and_backup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            store = ConfigFileStore()
            store.atomic_write(config_path, {"ARL": {"RUST_ACCEL_ENABLE": True}, "items": [1, 2]})

            self.assertEqual(
                {"ARL": {"RUST_ACCEL_ENABLE": True}, "items": [1, 2]},
                store.load(config_path),
            )
            backup_path = store.backup(config_path)
            self.assertTrue(Path(backup_path).is_file())
            self.assertEqual(store.load(config_path), store.load(Path(backup_path)))

    def test_load_rejects_non_mapping_yaml(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text("- invalid\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                ConfigFileStore.load(config_path)

    def test_config_center_persists_and_refreshes_once(self):
        calls = []

        class _Store(object):
            def backup(self, config_path):
                calls.append(("backup", config_path))
                return "backup.yaml"

            def atomic_write(self, config_path, config_obj):
                calls.append(("write", config_path, config_obj))

        service = ConfigCenterService(
            _Store(),
            refresh_runtime_config=lambda force: calls.append(("refresh", force)) or True,
        )
        result = service.persist("config.yaml", {"ARL": {"enabled": True}})

        self.assertEqual("backup.yaml", result["backup_path"])
        self.assertTrue(result["runtime_refreshed"])
        self.assertEqual(
            [
                ("backup", "config.yaml"),
                ("write", "config.yaml", {"ARL": {"enabled": True}}),
                ("refresh", True),
            ],
            calls,
        )


if __name__ == "__main__":
    unittest.main()
