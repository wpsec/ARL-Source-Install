import importlib.util
import pathlib
import sys
import types
import unittest


def _build_logger():
    return types.SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )


def _load_common_task_module():
    module_name = "commonTask_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    app_module = types.ModuleType("app")
    utils_module = types.ModuleType("app.utils")
    utils_module.get_logger = _build_logger

    services_module = types.ModuleType("app.services")
    services_module.run_risk_cruising = lambda *args, **kwargs: None
    services_module.BaseUpdateTask = object

    config_module = types.ModuleType("app.config")
    config_module.Config = type("Config", (), {})
    config_module.normalize_dict_path_compat = lambda value: value

    modules_module = types.ModuleType("app.modules")
    modules_module.CollectSource = object
    modules_module.WebSiteFetchStatus = object
    modules_module.WebSiteFetchOption = object

    nuclei_scan_module = types.ModuleType("app.services.nuclei_scan")
    nuclei_scan_module.nuclei_scan = lambda *args, **kwargs: None
    nuclei_scan_module.NucleiScan = object

    afrog_scan_module = types.ModuleType("app.services.afrog_scan")
    afrog_scan_module.run_afrog_scan = lambda *args, **kwargs: None

    waf_guard_module = types.ModuleType("app.services.waf_guard")
    waf_guard_module.WAFSmartSkipGuard = object

    bson_module = types.ModuleType("bson")
    bson_module.ObjectId = lambda value=None: value

    pymongo_module = types.ModuleType("pymongo")
    pymongo_errors_module = types.ModuleType("pymongo.errors")
    pymongo_errors_module.NetworkTimeout = type("NetworkTimeout", (Exception,), {})
    pymongo_errors_module.AutoReconnect = type("AutoReconnect", (Exception,), {})
    pymongo_errors_module.ServerSelectionTimeoutError = type("ServerSelectionTimeoutError", (Exception,), {})
    pymongo_module.errors = pymongo_errors_module

    sys.modules.setdefault("app", app_module)
    sys.modules["app.utils"] = utils_module
    sys.modules["app.services"] = services_module
    sys.modules["app.config"] = config_module
    sys.modules["app.modules"] = modules_module
    sys.modules["app.services.nuclei_scan"] = nuclei_scan_module
    sys.modules["app.services.afrog_scan"] = afrog_scan_module
    sys.modules["app.services.waf_guard"] = waf_guard_module
    sys.modules["bson"] = bson_module
    sys.modules["pymongo"] = pymongo_module
    sys.modules["pymongo.errors"] = pymongo_errors_module

    app_module.utils = utils_module
    app_module.services = services_module

    common_task_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "commonTask.py"
    spec = importlib.util.spec_from_file_location(module_name, common_task_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


WebSiteFetch = _load_common_task_module().WebSiteFetch


class TestAiPenJsContext(unittest.TestCase):
    def test_sensitive_info_js_noise_is_downgraded(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/_nuxt/app.js",
            body_text='function a(){var x=\'\';token="+n)}localStorage[location.host]=r.webCustomize.title?r.webCustomize.title:"demo"}',
            headers={"Content-Type": "application/javascript"},
            risk_type="sensitive_info",
            payload_type="replay",
            evidence_seed='token="+n)}localStorage[location.host]=r.webCustomize.title',
        )

        self.assertEqual("likely_false_positive", result.get("decision"))
        self.assertIn("未发现硬编码敏感值", str(result.get("reason") or ""))

    def test_sensitive_info_hardcoded_client_secret_is_promoted(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/static/main.js",
            body_text='const client_secret = "AbCdEf1234567890ZXCVBNMqwerty";',
            headers={"Content-Type": "application/javascript"},
            risk_type="sensitive_info",
            payload_type="replay",
            evidence_seed="client_secret",
        )

        self.assertEqual("verified", result.get("decision"))
        self.assertIn("硬编码", str(result.get("reason") or ""))

    def test_dom_xss_framework_chunk_without_sink_is_downgraded(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/_nuxt/chunk-vendors.js",
            body_text='window.__NUXT__={};__webpack_require__.e=function(){return Promise.resolve()};',
            headers={"Content-Type": "application/javascript"},
            risk_type="xss",
            payload_type="xss_probe",
            evidence_seed="<svg/onload=alert(1)>",
        )

        self.assertEqual("likely_false_positive", result.get("decision"))
        self.assertIn("未发现危险 DOM sink", str(result.get("reason") or ""))

    def test_dom_xss_source_and_sink_keeps_manual_review(self):
        result = WebSiteFetch._analyze_ai_pen_js_context(
            target_url="https://example.com/static/app.js",
            body_text="const hashValue = location.hash; document.body.innerHTML = hashValue;",
            headers={"Content-Type": "application/javascript"},
            risk_type="xss",
            payload_type="xss_probe",
            evidence_seed="innerHTML",
        )

        self.assertEqual("needs_manual_review", result.get("decision"))
        self.assertIn("危险 DOM sink", str(result.get("reason") or ""))


if __name__ == "__main__":
    unittest.main()
