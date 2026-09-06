import importlib.util
import pathlib
import re
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


def _LIBRS_EXISTS() -> bool:
    return (pathlib.Path(__file__).resolve().parents[1] / "native" / "arl_accel" / "src" / "lib.rs").exists()


class TestApiDocKeywordAlignment(unittest.TestCase):
    """第 10 批口径钉（Review A7/D8/S3 重设计）。

    Python 面单一事实源 = api_unified_models.API_DOC_TYPE_HINT_KEYWORDS：
    registry._TYPE_HINT_KEYWORDS 与 js_intel_scan._is_api_doc_candidate 均以
    名字引用该表（钉引用关系，钉不住复制回去）；Rust 面两处数组
    （is_api_doc_candidate token 集、document_type_hint_unified HINTS 有序对）
    以括号配平切片提取，比较集合与**顺序值**（顺序即优先级）。
    """

    _ROOT = pathlib.Path(__file__).resolve().parents[1]
    _LIB_RS = _ROOT / "native" / "arl_accel" / "src" / "lib.rs"
    _EXPECTED = (
        ("postman", "postman"),
        ("openapi", "openapi"),
        ("swagger", "swagger"),
        ("api-docs", "swagger"),
        ("wsdl", "wsdl"),
        ("graphql", "graphql"),
        ("graphiql", "graphql"),
    )

    def _models_table(self):
        import ast

        tree = ast.parse(
            (self._ROOT / "app" / "services" / "api_unified_models.py").read_text(
                encoding="utf-8"
            )
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                    and node.target.id == "API_DOC_TYPE_HINT_KEYWORDS":
                return tuple(
                    tuple(el.value for el in pair.elts)
                    for pair in node.value.elts
                )
        raise AssertionError("API_DOC_TYPE_HINT_KEYWORDS not found in models")

    def _rust_section(self, lib_text, fn_name):
        """从 fn 签名起点到下一个顶层 fn，按括号配平取函数体（防注释误伤）。"""
        start = lib_text.index("fn {}".format(fn_name))
        body_start = lib_text.index("{", start)
        depth = 0
        for pos in range(body_start, len(lib_text)):
            if lib_text[pos] == "{":
                depth += 1
            elif lib_text[pos] == "}":
                depth -= 1
                if depth == 0:
                    return lib_text[start : pos + 1]
        raise AssertionError("unbalanced braces in {}".format(fn_name))

    def _rust_doc_tokens(self):
        lib_text = (self._ROOT / "native" / "arl_accel" / "src" / "lib.rs").read_text(
            encoding="utf-8"
        )
        body = self._rust_section(lib_text, "is_api_doc_candidate")
        array = body[body.index("[") : body.rindex("]") + 1]
        return set(re.findall(r'"([a-z0-9-]+)"', array))

    def _rust_hint_pairs(self):
        lib_text = (self._ROOT / "native" / "arl_accel" / "src" / "lib.rs").read_text(
            encoding="utf-8"
        )
        body = self._rust_section(lib_text, "document_type_hint_unified")
        array = body[body.index("[") : body.index("];")]
        pairs = re.findall(r'\("([a-z0-9-]+)", "([a-z0-9-]+)"\)', array)
        self.assertTrue(pairs, "HINTS 数组未解析到条目")
        return pairs

    def _assert_symbol_reference(self, module_file, target, symbol):
        import ast

        tree = ast.parse((self._ROOT / module_file).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                names = []
                if isinstance(node, ast.AnnAssign):
                    names = [node.target.id] if isinstance(node.target, ast.Name) else []
                else:
                    names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                if target in names:
                    value = node.value
                    return isinstance(value, ast.Name) and value.id == symbol
            if isinstance(node, ast.FunctionDef) and node.name == target:
                used = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                return symbol in used
        raise AssertionError("{} not found in {}".format(target, module_file))

    def test_models_table_is_expected(self):
        self.assertEqual(self._EXPECTED, self._models_table())

    def test_python_faces_reference_shared_table(self):
        self.assertTrue(
            self._assert_symbol_reference(
                "app/services/api_candidate_registry.py",
                "_TYPE_HINT_KEYWORDS",
                "API_DOC_TYPE_HINT_KEYWORDS",
            ),
            "registry 表必须是共享表引用而非字面量副本",
        )
        self.assertTrue(
            self._assert_symbol_reference(
                "app/services/js_intel_scan.py",
                "_is_api_doc_candidate",
                "API_DOC_CANDIDATE_KEYWORDS",
            ),
            "js 镜像必须引用共享表而非字面量副本",
        )

    @unittest.skipUnless(_LIBRS_EXISTS(), "lib.rs 不在运行镜像内（native 构建层），"
                              "钉在源码仓 CI 执行；镜像侧由 --run-native golden 门禁覆盖")
    def test_rust_faces_align_with_models_table(self):
        expected_keywords = {keyword for keyword, _ in self._EXPECTED}
        self.assertEqual(expected_keywords, self._rust_doc_tokens())
        # HINTS 序与值必须逐项等于共享表（顺序=优先级，S3 缺口）。
        self.assertEqual([list(pair) for pair in self._EXPECTED],
                         [list(pair) for pair in self._rust_hint_pairs()])

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


if __name__ == "__main__":
    unittest.main()
