"""Rust/Python golden corpus 比较器回归测试。"""
import importlib.util
import json
import unittest
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "tools" / "compare_rust_python_corpus.py"
_SPEC = importlib.util.spec_from_file_location("compare_rust_python_corpus_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)
compare_corpus = _MODULE.compare_corpus
compare_native_corpus = _MODULE.compare_native_corpus

_CORPUS_PATH = Path(__file__).resolve().parent / "data" / "rust_accel_golden_corpus.json"


class _FakeNativeModule:
    @staticmethod
    def extract_urlfinder_candidates(*args):
        return [
            tuple(record) + (0,)
            for record in json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))["cases"][0]["rust"]
        ]

    @staticmethod
    def extract_html_candidates(*args):
        return [
            tuple(record) + (0,)
            for record in json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))["cases"][2]["rust"]
        ]

    @staticmethod
    def extract_js_endpoint_candidates(*args):
        return [
            tuple(record) + (0,)
            for record in json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))["cases"][3]["rust"]
        ]

    @staticmethod
    def rank_sensitive_targets(*args):
        return json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))["cases"][1]["rust"]


class TestCompareRustPythonCorpus(unittest.TestCase):
    def _load_fixture(self):
        with _CORPUS_PATH.open("r", encoding="utf-8") as stream:
            return json.load(stream)

    def test_golden_corpus_has_matching_semantic_results(self):
        report = compare_corpus(self._load_fixture())

        self.assertTrue(report["ok"])
        self.assertEqual(4, report["case_count"])
        self.assertTrue(all(case["order_equal"] for case in report["cases"]))

    def test_order_difference_is_reported_but_not_semantic_failure(self):
        corpus = self._load_fixture()
        corpus["cases"][1]["rust"] = list(reversed(corpus["cases"][1]["rust"]))

        report = compare_corpus(corpus)
        strict_report = compare_corpus(corpus, strict_order=True)

        self.assertTrue(report["ok"])
        self.assertFalse(report["cases"][1]["order_equal"])
        self.assertFalse(strict_report["ok"])

    def test_missing_record_fails_the_gate(self):
        corpus = self._load_fixture()
        corpus["cases"][0]["rust"] = corpus["cases"][0]["rust"][:-1]

        report = compare_corpus(corpus)

        self.assertFalse(report["ok"])
        self.assertEqual(1, len(report["cases"][0]["missing_from_rust"]))

    def test_native_runner_compares_against_python_golden(self):
        report = compare_native_corpus(
            self._load_fixture(),
            native_module=_FakeNativeModule,
        )

        self.assertTrue(report["ok"])
        self.assertEqual("native_vs_python_golden", report["execution_mode"])


_UNIFIED_CORPUS_PATH = Path(__file__).resolve().parent / "data" / "api_unified_rust_corpus.json"


class TestApiUnifiedRustCorpus(unittest.TestCase):
    """第 10 批统一面 golden corpus 门禁（python=生产基线实测，rust=编译 .so 实测）。

    本测试用冻结的 rust 字段验证 corpus 自洽；真机 .so 逐条复验由容器内
    `compare_rust_python_corpus.py --run-native --strict-order` 执行（构建证据
    记录于计划 6 第 10 批实施节）。rust 字段为空的 corpus 视为未回填，失败。
    """

    def _load(self):
        with _UNIFIED_CORPUS_PATH.open("r", encoding="utf-8") as stream:
            return json.load(stream)

    def test_unified_corpus_strict_equal(self):
        report = compare_corpus(self._load(), strict_order=True)

        self.assertEqual([], report["errors"])
        self.assertEqual(4, report["case_count"])
        self.assertTrue(report["ok"], json.dumps(report["cases"], ensure_ascii=False)[:800])

    def test_unified_kinds_dispatch_to_native_functions(self):
        class _Recorder:
            def __init__(self):
                self.calls = []

            def unified_normalize_urls(self, values):
                self.calls.append(("normalize", values))
                return list(values)

            def unified_document_type_hints(self, values):
                self.calls.append(("hint", values))
                return ["unknown"] * len(values)

            def unified_canonical_methods(self, values):
                self.calls.append(("method", values))
                return ["GET"] * len(values)

            def unified_dedupe_endpoints(self, records):
                self.calls.append(("dedupe", records))
                return []

        native = _Recorder()
        report = compare_native_corpus(self._load(), native_module=native)

        self.assertEqual(
            ["normalize", "hint", "method", "dedupe"], [call[0] for call in native.calls]
        )
        self.assertFalse(report["ok"])  # 桩输出必然与 golden 不一致


if __name__ == "__main__":
    unittest.main()
