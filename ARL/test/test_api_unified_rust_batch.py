"""第 10 批统一 API 面 Rust 批量入口测试（协议面，本机可跑）。

语义一致性（Rust == Python 逐条相等）由两层承担：
- 本文件的 `_FakeUnifiedNative` 只验证 adapter 协议：模式分流、安全子集、
  mismatch 计数、按批回退与 metrics；桩不模拟 Rust 语义（避免自证）；
- 真 native 逐条相等由容器内双跑脚本（release .so + Python 基线）与 golden
  corpus `--run-native` 门禁承担，见计划 6 第 10 批实施记录。

测试卫生：模块级 bootstrap 捕获真实依赖（P2-13 红线），不注入永久桩包。
"""
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import patch

ARL_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import (  # noqa: E402
    assert_no_shell_pollution,
    load_unified_modules,
)

_captured = load_unified_modules()
assert_no_shell_pollution()

_models = _captured["app.services.api_unified_models"]
_registry = _captured["app.services.api_candidate_registry"]
_discovery = _captured["app.services.discovery_context"]


def _load_rust_accel_module():
    module_name = "app.services.rust_accel_batch_test_module"
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
        info=lambda *args, **kwargs: None,
        exception=lambda *args, **kwargs: None,
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
        module_path = ARL_ROOT / "app" / "services" / "rust_accel.py"
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


class _FakeUnifiedNative:
    """协议桩：输出可识别标记值（与任何 Python 基线都不同），驱动分支覆盖。"""

    def __init__(self, fail=False, short_output=False):
        self.fail = fail
        self.short_output = short_output
        self.calls = []

    def _run(self, name, items):
        self.calls.append((name, [str(item) for item in items]))
        if self.fail:
            raise RuntimeError("fake native failure")
        out = ["rust:{}".format(item) for item in items]
        if self.short_output:
            out = out[:-1]
        return out

    def unified_normalize_urls(self, items):
        return self._run("normalize", items)

    def unified_document_type_hints(self, items):
        return self._run("hint", items)

    def unified_canonical_methods(self, items):
        return self._run("methods", items)

    def unified_dedupe_endpoints(self, items):
        self.calls.append(("dedupe", [tuple(item) for item in items]))
        if self.fail:
            raise RuntimeError("fake native failure")
        return [list(item) for item in _models.merge_endpoint_records(
            [tuple(item) for item in items]
        )]


class TestUnifiedSafeSubset(unittest.TestCase):
    def test_normalize_safe_subset_accepts_and_rejects(self):
        accepts = [
            "https://example.test/Path?x=1#frag",
            "http://a.b",
            "https://a.b:8080/x?q=%3D",
            "https://user:pw@a.b/x",
            "https://a.b/中文路径?q=1",
            "https://a.b/x?a=b c",
        ]
        rejects = [
            "",
            "HTTPS://a.b/x",           # 大写 scheme：Python 会规范化，子集外
            "ftp://a.b/x",
            "//a.b/x",
            "https://a.b\tc/x",        # CPython 整串删除 \t\r\n
            "https://[::1]:8080/x",    # bracketed 校验跨版本漂移
            "https://Éxample.test/x",  # 非 ASCII host case mapping
            "https://a.b/x\x01y",      # 控制字符
            "https:///x",              # 空 host
        ]
        for item in accepts:
            self.assertTrue(rust_accel.unified_url_is_safe(item), item)
        for item in rejects:
            self.assertFalse(rust_accel.unified_url_is_safe(item), item)


class TestUnifiedBatchModes(unittest.TestCase):
    def setUp(self):
        self.saved_mode = getattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", None)

    def tearDown(self):
        if self.saved_mode is None:
            if hasattr(Config, "RUST_ACCEL_API_UNIFIED_MODE"):
                delattr(Config, "RUST_ACCEL_API_UNIFIED_MODE")
        else:
            setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", self.saved_mode)

    def test_off_mode_uses_python_baseline(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "off")
        fake = _FakeUnifiedNative()
        with patch.object(rust_accel, "_NATIVE_MODULE", fake):
            result = rust_accel.unified_document_type_hints(["https://a.b/swagger"])
        self.assertFalse(fake.calls)
        self.assertFalse(result.used_native)
        self.assertEqual(["swagger"], list(result))
        self.assertEqual("off", result.metrics["mode"])

    def test_shadow_mode_keeps_python_output_and_counts_mismatch(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "shadow")
        fake = _FakeUnifiedNative()
        before = rust_accel.get_stats()["unified_shadow_mismatches"]
        with patch.object(rust_accel, "_NATIVE_MODULE", fake):
            result = rust_accel.unified_document_type_hints(["https://a.b/swagger"])
        self.assertEqual(["swagger"], list(result))  # 基线为准
        self.assertEqual(1, result.metrics["mismatch_count"])  # 桩值必然不一致
        self.assertEqual("shadow", result.metrics["mode"])
        after = rust_accel.get_stats()["unified_shadow_mismatches"]
        self.assertEqual(before + 1, after)

    def test_rust_mode_adopts_native_for_safe_subset_only(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "rust")
        fake = _FakeUnifiedNative()
        # 第二条含控制字符：hint 安全子集要求纯可打印 ASCII → 子集外走基线
        mixed = ["https://a.b/graphql", "https://a.b/graphql\x01"]
        with patch.object(rust_accel, "_NATIVE_MODULE", fake):
            result = rust_accel.unified_document_type_hints(mixed)
        self.assertTrue(result.used_native)
        self.assertEqual("rust:https://a.b/graphql", result[0])
        self.assertEqual("graphql", result[1])  # 子集外取 Python 基线
        self.assertEqual(["https://a.b/graphql"], fake.calls[0][1])  # native 只见安全条目
        self.assertEqual(1, result.metrics["safe_count"])

    def test_native_failure_falls_back_per_batch(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "rust")
        fake = _FakeUnifiedNative(fail=True)
        with patch.object(rust_accel, "_NATIVE_MODULE", fake):
            result = rust_accel.unified_document_type_hints(["https://a.b/wsdl"])
        self.assertFalse(result.used_native)
        self.assertEqual(["wsdl"], list(result))
        self.assertEqual(1, result.metrics["fallback_count"])

    def test_native_failure_raises_when_fallback_disabled(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "rust")
        fake = _FakeUnifiedNative(fail=True)
        with patch.object(Config, "RUST_ACCEL_FALLBACK_ENABLE", False):
            with patch.object(rust_accel, "_NATIVE_MODULE", fake):
                with self.assertRaises(rust_accel.RustAccelerationError):
                    rust_accel.unified_document_type_hints(["https://a.b/wsdl"])

    def test_short_native_output_treated_as_failure(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "rust")
        fake = _FakeUnifiedNative(short_output=True)
        with patch.object(rust_accel, "_NATIVE_MODULE", fake):
            result = rust_accel.unified_normalize_urls(["https://a.b/x", "https://a.b/y"])
        self.assertEqual(2, result.metrics["batch_size"])
        self.assertEqual(1, result.metrics["fallback_count"])

    def test_native_absent_means_off(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "rust")
        with patch.object(rust_accel, "_NATIVE_MODULE", None):
            result = rust_accel.unified_normalize_urls(["https://a.b"])
        self.assertEqual("off", result.metrics["mode"])
        self.assertEqual(["https://a.b/"], list(result))

    def test_dedupe_rejects_malformed_records(self):
        with self.assertRaises(ValueError):
            rust_accel.unified_dedupe_endpoints([("only", "four", "fields", "here")])

    def test_dedupe_rust_mode_output_matches_baseline(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "rust")
        fake = _FakeUnifiedNative()
        records = [
            ("https://a.b/u", "GET", "rest", "", "js"),
            ("https://a.b/u", "GET", "rest", "", "browser"),
        ]
        with patch.object(rust_accel, "_NATIVE_MODULE", fake):
            result = rust_accel.unified_dedupe_endpoints(records)
        self.assertEqual(_models.merge_endpoint_records(records), list(result))
        self.assertTrue(result.used_native)


class TestMergeEndpointRecordsBaseline(unittest.TestCase):
    """merge_endpoint_records 语义钉（与 Rust core 对齐的 Python 事实源）。"""

    def setUp(self):
        self.merge = _models.merge_endpoint_records

    def test_grouping_first_seen_order_and_source_merge(self):
        records = [
            ("https://a.b/u", "GET", "rest", "", "js"),
            ("https://a.b/u", "POST", "rest", "", "doc"),
            ("https://a.b/u", "GET", "rest", "", "browser"),
            ("https://a.b/u", "GET", "graphql", "", "   "),
            ("https://a.b/u", "GET", "rest", "/v1", "page"),
        ]
        self.assertEqual(
            [(0, ["browser", "js"]), (1, ["doc"]), (3, []), (4, ["page"])],
            self.merge(records),
        )

    def test_empty_batch(self):
        self.assertEqual([], self.merge([]))

    def test_sources_sorted_by_codepoint(self):
        records = [
            ("u", "GET", "rest", "", "中文"),
            ("u", "GET", "rest", "", "abc"),
            ("u", "GET", "rest", "", "中文"),
        ]
        first, sources = self.merge(records)[0]
        self.assertEqual(0, first)
        self.assertEqual(["abc", "中文"], sources)  # 字节/码点序：ascii 在前


class TestUnifiedBaselinesAreProductionFunctions(unittest.TestCase):
    """防口径漂移：adapter 基线即生产函数（models/registry/context 同一实现）。"""

    def test_baselines_identity(self):
        self.assertEqual(
            "https://a.b/",
            _discovery.normalize_url("https://a.b"),
        )
        self.assertEqual("swagger", _registry.document_type_hint("x/swagger"))
        self.assertEqual("GET", _models.canonical_method("weird"))


if __name__ == "__main__":
    unittest.main()


class TestBackflowHintBatch(unittest.TestCase):
    """queue._batch_document_hints 语义钉：输出恒等于逐条基线（native 缺席路径）。"""

    class _FakeSelf:
        def __init__(self):
            self.context = None
            self.backflow_hint_batch_count = 0
            self.backflow_hint_input_count = 0
            self.backflow_hint_mismatch_count = 0
            self.backflow_hint_fallback_count = 0

        def _record_metric(self, *args, **kwargs):
            pass

    def test_hint_map_equals_per_item_baseline(self):
        # 生产场景模拟：app.services.rust_accel 已在 sys.modules（避免宿主轻
        # 依赖环境触发包级 __init__——那走的是 import 失败回退基线的另一分支）。
        sentinel = "app.services.rust_accel"
        had_entry = sentinel in sys.modules
        sys.modules.setdefault(sentinel, rust_accel)
        try:
            self._assert_hint_map_baseline()
        finally:
            if not had_entry:
                sys.modules.pop(sentinel, None)

    def _assert_hint_map_baseline(self):
        urls = [
            "https://a.b/v3/api-docs", "https://a.b/graphql", "https://a.b/x",
            "https://a.b/service.wsdl", "", "https://a.b/swagger.json",
            "https://a.b/v3/api-docs",  # 重复去重
        ]
        fake_self = self._FakeSelf()
        hint_map = _registry.ApiDocumentQueue._batch_document_hints(fake_self, urls)
        unique = [u for u in dict.fromkeys(urls) if u]
        self.assertEqual(len(unique), fake_self.backflow_hint_input_count)
        self.assertEqual(1, fake_self.backflow_hint_batch_count)
        for url in unique:
            self.assertEqual(
                _registry.document_type_hint(url), hint_map.get(url), url)

    def test_empty_input_returns_empty_map(self):
        fake_self = self._FakeSelf()
        self.assertEqual(
            {}, _registry.ApiDocumentQueue._batch_document_hints(fake_self, ["", None]))
        self.assertEqual(0, fake_self.backflow_hint_batch_count)
