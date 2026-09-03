import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import patch


def _load_rust_accel_module():
    module_name = "app.services.rust_accel_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    backup_modules = {
        name: sys.modules.get(name)
        for name in ("app", "app.utils", "app.config")
    }
    app_module = types.ModuleType("app")
    utils_module = types.ModuleType("app.utils")
    config_module = types.ModuleType("app.config")
    utils_module.get_logger = lambda: types.SimpleNamespace(
        warning=lambda *args, **kwargs: None,
        debug=lambda *args, **kwargs: None,
    )
    config_module.Config = type(
        "Config",
        (),
        {"RUST_ACCEL_ENABLE": True, "RUST_ACCEL_FALLBACK_ENABLE": True},
    )
    app_module.utils = utils_module
    sys.modules.update(
        {"app": app_module, "app.utils": utils_module, "app.config": config_module}
    )

    try:
        module_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "rust_accel.py"
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in backup_modules.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


rust_accel = _load_rust_accel_module()
Config = rust_accel.Config


class _FakeNativeModule:
    @staticmethod
    def extract_urlfinder_candidates(*args):
        return [
            (
                "urlfinder_url",
                "https://example.com/api/users",
                "https://example.com",
                "https://example.com",
                0,
            )
        ]

    @staticmethod
    def rank_sensitive_targets(*args):
        return [("https://example.com/admin", 31)]

    @staticmethod
    def extract_html_candidates(*args):
        return [
            (
                "page_link",
                "https://example.com/admin",
                "https://example.com",
                "https://example.com",
                1,
            )
        ]

    @staticmethod
    def extract_js_endpoint_candidates(*args):
        return [
            (
                "urlfinder_url",
                "https://example.com/api/users",
                "https://example.com/app.js",
                "https://example.com",
                0,
            )
        ]


class TestRustAccelerationAdapter(unittest.TestCase):
    def test_maps_native_extraction_records(self):
        with patch.object(rust_accel, "_NATIVE_MODULE", _FakeNativeModule):
            with patch.object(Config, "RUST_ACCEL_ENABLE", True):
                result = rust_accel.extract_urlfinder_candidates(
                    pages=[{"base_url": "https://example.com", "text": "body"}],
                    allowed_hosts={"example.com"},
                    allow_js=True,
                    max_url_records=10,
                    max_js_files=10,
                    max_js_depth=2,
                )

        self.assertEqual("urlfinder_url", result[0]["record_type"])
        self.assertEqual("https://example.com/api/users", result[0]["content"])
        self.assertTrue(result.used_native)
        self.assertEqual(0, result.metrics["fallback_count"])

    def test_maps_native_ranking_targets(self):
        with patch.object(rust_accel, "_NATIVE_MODULE", _FakeNativeModule):
            with patch.object(Config, "RUST_ACCEL_ENABLE", True):
                result = rust_accel.rank_sensitive_targets(
                    records=[
                        {
                            "record_type": "urlfinder_url",
                            "content": "https://example.com/admin",
                            "source": "https://example.com",
                            "site": "https://example.com",
                        }
                    ],
                    sites=["https://example.com"],
                    blocked_hosts=[],
                    include_js=True,
                    max_targets=10,
                )

        self.assertEqual([("https://example.com/admin", 31)], result)

    def test_maps_native_html_and_js_endpoint_records(self):
        with patch.object(rust_accel, "_NATIVE_MODULE", _FakeNativeModule):
            with patch.object(Config, "RUST_ACCEL_ENABLE", True):
                html_result = rust_accel.extract_html_candidates(
                    pages=[{"base_url": "https://example.com", "text": "<a href='/admin'>"}],
                    allowed_hosts={"example.com"},
                    allowed_flds={"example.com"},
                    exclude_hosts={"example.com"},
                )
                js_result = rust_accel.extract_js_endpoint_candidates(
                    pages=[{"base_url": "https://example.com/app.js", "text": "fetch('/api/users')"}],
                    allowed_hosts={"example.com"},
                    max_records=10,
                )

        self.assertEqual("page_link", html_result[0]["record_type"])
        self.assertEqual("urlfinder_url", js_result[0]["record_type"])
        self.assertTrue(html_result.used_native)
        self.assertTrue(js_result.used_native)

    def test_unavailable_native_raises_when_fallback_disabled(self):
        with patch.object(rust_accel, "_NATIVE_MODULE", None):
            with patch.object(Config, "RUST_ACCEL_ENABLE", True):
                with patch.object(Config, "RUST_ACCEL_FALLBACK_ENABLE", False):
                    with self.assertRaises(rust_accel.RustAccelerationError):
                        rust_accel.rank_sensitive_targets([], [], [], True, 10)

    def test_fallback_exposes_reason_and_count(self):
        before = rust_accel.get_stats()
        with patch.object(rust_accel, "_NATIVE_MODULE", None):
            with patch.object(Config, "RUST_ACCEL_ENABLE", True):
                with patch.object(Config, "RUST_ACCEL_FALLBACK_ENABLE", True):
                    result = rust_accel.rank_sensitive_targets([], [], [], True, 10)
        self.assertFalse(result.used_native)
        self.assertEqual(1, result.metrics["fallback_count"])
        after = rust_accel.get_stats()

        self.assertEqual(
            before["rank_fallbacks"] + 1,
            after["rank_fallbacks"],
        )
        self.assertTrue(after["last_rank_fallback_reason"])
