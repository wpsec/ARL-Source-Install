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

    def __init__(self, fail=False, short_output=False, match_baseline=False):
        self.fail = fail
        self.short_output = short_output
        self.match_baseline = match_baseline
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
        # 桩不模拟 Rust 语义（文件头红线）：默认输出刻意偏离基线（首组下标+1），
        # shadow mismatch/结构校验路径可测；与基线相等的采纳性测试显式开
        # match_baseline，验证的是 wrapper 形态转换而非分组语义。
        self.calls.append(("dedupe", [tuple(item) for item in items]))
        if self.fail:
            raise RuntimeError("fake native failure")
        merged = [list(item) for item in _models.merge_endpoint_records(
            [tuple(item) for item in items]
        )]
        if not self.match_baseline and merged:
            # 结构合法但内容偏离：sources 加桩标记（下标+1 会被引擎结构校验
            # fail-closed 拦成 fallback，覆盖的是另一条路径）。
            merged[0][1] = merged[0][1] + ["zz-stub-marker"]
        return merged


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
        # E2 钉：shadow 输出未采纳 native——attribute 与 metrics 必须同一口径。
        self.assertFalse(result.used_native)
        self.assertFalse(result.metrics["used_native"])
        self.assertEqual("python", result.metrics["backend"])
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
        fake = _FakeUnifiedNative(match_baseline=True)
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


class TestUnifiedAggregateValidation(unittest.TestCase):
    """rust 模式聚合输出的最小结构校验（native 回归丢组/乱序 fail-closed）。"""

    def setUp(self):
        self.saved = getattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", None)

    def tearDown(self):
        if self.saved is None:
            if hasattr(Config, "RUST_ACCEL_API_UNIFIED_MODE"):
                delattr(Config, "RUST_ACCEL_API_UNIFIED_MODE")
        else:
            setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", self.saved)

    def test_rust_mode_rejects_out_of_range_group_index(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "rust")

        class _BadIndex(_FakeUnifiedNative):
            def unified_dedupe_endpoints(self, items):
                return [[99, ["x"]]]

        with patch.object(rust_accel, "_NATIVE_MODULE", _BadIndex()):
            result = rust_accel.unified_dedupe_endpoints(
                [("u", "GET", "rest", "", "js")])
        self.assertFalse(result.used_native)  # 结构非法 → 当前批回退基线
        self.assertEqual(1, result.metrics["fallback_count"])

    def test_rust_mode_rejects_disordered_group_indices(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "rust")

        class _Disordered(_FakeUnifiedNative):
            def unified_dedupe_endpoints(self, items):
                return [[1, ["b"]], [0, ["a"]]]

        records = [("u", "GET", "rest", "", "a"), ("u", "POST", "rest", "", "b")]
        with patch.object(rust_accel, "_NATIVE_MODULE", _Disordered()):
            result = rust_accel.unified_dedupe_endpoints(records)
        self.assertFalse(result.used_native)

    def test_shadow_aggregate_counts_mismatch_with_deviant_stub(self):
        setattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", "shadow")
        fake = _FakeUnifiedNative()  # 默认桩：首组下标+1，与基线不同
        with patch.object(rust_accel, "_NATIVE_MODULE", fake):
            result = rust_accel.unified_dedupe_endpoints(
                [("u", "GET", "rest", "", "js"), ("u", "POST", "rest", "", "doc")])
        self.assertEqual(1, result.metrics["mismatch_count"])
        self.assertEqual(_models.merge_endpoint_records(
            [("u", "GET", "rest", "", "js"), ("u", "POST", "rest", "", "doc")]), list(result))


class TestBackflowHintWhitelist(unittest.TestCase):
    """E4 钉：批通道输出的枚举外值按 unknown 处理（控制流不得被 native 回归扩大）。"""

    class _GarbageNative:
        def unified_document_type_hints(self, items):
            return ["fetch-me-please"] * len(items)

    def _queue_self(self):
        fake_self = TestBackflowHintBatch._FakeSelf()
        return fake_self

    def test_non_enum_hint_collapses_to_unknown(self):
        original_native = rust_accel._NATIVE_MODULE
        original_mode = getattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", None)
        # 生产函数内的懒导入命中的是 app.services.rust_accel 槽位，桩注入同位。
        sys.modules.setdefault("app.services.rust_accel", rust_accel)
        Config.RUST_ACCEL_API_UNIFIED_MODE = "rust"
        rust_accel._NATIVE_MODULE = self._GarbageNative()
        try:
            fake_self = self._queue_self()
            hint_map = _registry.ApiDocumentQueue._batch_document_hints(
                fake_self, ["https://a.b/api/users"])
        finally:
            rust_accel._NATIVE_MODULE = original_native
            if original_mode is None:
                delattr(Config, "RUST_ACCEL_API_UNIFIED_MODE")
            else:
                Config.RUST_ACCEL_API_UNIFIED_MODE = original_mode
        self.assertEqual(
            {"unknown"}, set(hint_map.values()),
            "枚举外 hint 必须收敛为 unknown，不得参与入队判定")

    def test_hard_fail_propagates_rust_acceleration_error(self):
        """E1 钉：rust 模式 + FALLBACK_ENABLE=False 的 hard-fail 不被接线层吞掉。"""
        original_native = rust_accel._NATIVE_MODULE
        original_mode = getattr(Config, "RUST_ACCEL_API_UNIFIED_MODE", None)
        original_fallback = Config.RUST_ACCEL_FALLBACK_ENABLE
        sys.modules.setdefault("app.services.rust_accel", rust_accel)
        Config.RUST_ACCEL_API_UNIFIED_MODE = "rust"
        Config.RUST_ACCEL_FALLBACK_ENABLE = False
        rust_accel._NATIVE_MODULE = _FakeUnifiedNative(fail=True)
        try:
            fake_self = self._queue_self()
            with self.assertRaises(rust_accel.RustAccelerationError):
                _registry.ApiDocumentQueue._batch_document_hints(
                    fake_self, ["https://a.b/swagger"])
        finally:
            rust_accel._NATIVE_MODULE = original_native
            Config.RUST_ACCEL_FALLBACK_ENABLE = original_fallback
            if original_mode is None:
                delattr(Config, "RUST_ACCEL_API_UNIFIED_MODE")
            else:
                Config.RUST_ACCEL_API_UNIFIED_MODE = original_mode


class TestBenchBaselinePins(unittest.TestCase):
    """钉住 bench 副本=生产语义一致（A7 重设计：比函数体+符号别名映射）。

    bench 必须在无 app 重依赖的 native 容器运行，故以逐字副本替代导入；
    副本函数名/签名允许带 py_ 前缀差异，比较对象是去 docstring 的函数体
    AST unparse，且把已知别名符号（bench 常量表名）映射到生产名后比对。
    """

    _SYMBOL_ALIASES = {
        "_HINT_KEYWORDS": "_TYPE_HINT_KEYWORDS",
    }

    @classmethod
    def setUpClass(cls):
        module_path = ARL_ROOT / "app" / "tools" / "bench_api_unified_rust.py"
        spec = importlib.util.spec_from_file_location("bench_api_unified_pin", module_path)
        cls.bench = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(cls.bench)
        cls.bench_text = module_path.read_text(encoding="utf-8")

    @staticmethod
    def _body_src(fn):
        import ast
        import textwrap

        tree = ast.parse(textwrap.dedent(fn))
        body = tree.body[0].body
        if body and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            body = body[1:]
        return "\n".join(ast.unparse(node) for node in body)

    def _assert_body_equal(self, copy_fn, prod_fn):
        import re

        copy_src = self._body_src(inspect_getsource(copy_fn))
        prod_src = self._body_src(inspect_getsource(prod_fn))
        for alias, target in self._SYMBOL_ALIASES.items():
            copy_src = re.sub(r"\b{}\b".format(alias), target, copy_src)
        self.assertEqual(
            prod_src, copy_src,
            "{} 函数体与生产 {} 漂移：基准数据作废，需同步副本并重跑".format(
                copy_fn.__name__, prod_fn.__name__),
        )

    def test_function_bodies_match_production(self):
        pairs = [
            (self.bench.py_normalize_url, _discovery.normalize_url),
            (self.bench.py_document_type_hint, _registry.document_type_hint),
            (self.bench.py_canonical_method, _models.canonical_method),
            (self.bench.py_merge_endpoint_records, _models.merge_endpoint_records),
        ]
        for copy_fn, prod_fn in pairs:
            self._assert_body_equal(copy_fn, prod_fn)

    def test_constant_tables_match_production(self):
        self.assertEqual(
            tuple(self.bench._HINT_KEYWORDS),
            _models.API_DOC_TYPE_HINT_KEYWORDS,
        )
        self.assertEqual(self.bench.HTTP_METHODS, _models.HTTP_METHODS)

    def test_preflight_regex_text_matches_adapter(self):
        bench_patterns = set(re_findall_strings(self.bench_text))
        self.assertIn(
            rust_accel._UNIFIED_SAFE_URL_RE.pattern, bench_patterns,
            "bench 预检正则与 adapter 不一致：预检开销测的是不存在的守门人",
        )


def inspect_getsource(fn):
    import inspect

    return inspect.getsource(fn)


def re_findall_strings(bench_text):
    import re

    return re.findall(r'r"((?:[^"\\]|\\.)*)"', bench_text)


if __name__ == "__main__":
    unittest.main()
