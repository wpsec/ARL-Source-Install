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


class TestApiDocKeywordAlignment(unittest.TestCase):
    """第 10 批口径钉：Rust 原生面、Python 镜像、统一面关键词集合保持一致。

    三面漂移会让 golden corpus 静默失去意义，且本机通常无 arl_accel，
    只能以源码文本为事实源做结构校验（ast/定位解析，不做行为模拟）。
    """

    _ROOT = pathlib.Path(__file__).resolve().parents[1]

    def _python_mirror_tokens(self):
        import ast

        tree = ast.parse(
            (self._ROOT / "app" / "services" / "js_intel_scan.py").read_text(encoding="utf-8")
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_is_api_doc_candidate":
                return {
                    item.value
                    for item in ast.walk(node)
                    if isinstance(item, ast.Constant)
                    and isinstance(item.value, str)
                    and item.value  # 排除 str(url or "") 的空串常量
                }
        raise AssertionError("js_intel_scan._is_api_doc_candidate not found")

    def _rust_tokens(self):
        text = (self._ROOT / "native" / "arl_accel" / "src" / "lib.rs").read_text(encoding="utf-8")
        start = text.index("fn is_api_doc_candidate")
        body = text[start : text.index("\nfn ", start + 10)]
        return set(__import__("re").findall(r'"([a-z0-9-]+)"', body))

    def _unified_hint_keywords(self):
        import ast

        tree = ast.parse(
            (self._ROOT / "app" / "services" / "api_candidate_registry.py").read_text(
                encoding="utf-8"
            )
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names = [node.target.id]
                value = node.value
            else:
                continue
            if "_TYPE_HINT_KEYWORDS" in names and isinstance(value, ast.Tuple):
                return {
                    pair.elts[0].value
                    for pair in value.elts
                    if isinstance(pair, ast.Tuple) and len(pair.elts) == 2
                }
        raise AssertionError("_TYPE_HINT_KEYWORDS not found")

    def test_three_faces_share_same_doc_keyword_set(self):
        expected = {
            "swagger", "openapi", "api-docs", "postman",
            "wsdl", "graphql", "graphiql",
        }
        self.assertEqual(expected, self._unified_hint_keywords())
        self.assertEqual(expected, self._python_mirror_tokens())
        self.assertEqual(expected, self._rust_tokens())

    def test_legacy_doc_keywords_stay_narrow(self):
        """flag-off 请求面不变钉：ApiDocScanner._DOC_KEYWORDS 维持第 1 批四 token。"""
        import ast

        tree = ast.parse(
            (self._ROOT / "app" / "services" / "api_doc_scan.py").read_text(encoding="utf-8")
        )
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "_DOC_KEYWORDS"
                    for target in node.targets
                )
            ):
                tokens = {item.value for item in node.value.elts}
                self.assertEqual({"swagger", "openapi", "api-docs", "postman"}, tokens)
                return
        raise AssertionError("_DOC_KEYWORDS not found")
