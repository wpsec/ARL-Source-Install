"""运行配置增量同步在 Docker 挂载文件上的回归测试。"""

import errno
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "tools" / "sync_runtime_config.py"
_SPEC = importlib.util.spec_from_file_location("sync_runtime_config_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)


class TestSyncRuntimeConfig(unittest.TestCase):
    def test_atomic_write_falls_back_for_bind_mount(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text("old: value\n", encoding="utf-8")

            def raise_busy(*_args, **_kwargs):
                raise OSError(errno.EBUSY, "Device or resource busy")

            with patch.object(_MODULE.os, "replace", side_effect=raise_busy):
                _MODULE._atomic_write_yaml(config_path, {"new": "value"})

            self.assertEqual({"new": "value"}, _MODULE._load_yaml(config_path))


if __name__ == "__main__":
    unittest.main()
