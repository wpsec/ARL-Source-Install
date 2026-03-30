import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest


def _build_logger():
    return types.SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        debug=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )


def _load_info_hunter_module():
    module_name = "app.services.infoHunter_timeout_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    temp_dir = tempfile.mkdtemp(prefix="arl_wih_test_")

    app_module = types.ModuleType("app")
    utils_module = types.ModuleType("app.utils")
    utils_module.get_logger = _build_logger
    utils_module.random_choices = lambda k=6: "timeout"
    utils_module.resolve_executable = lambda command: str(command or "").strip()
    utils_module.check_output = lambda *args, **kwargs: b"wih help"
    utils_module.is_valid_domain = lambda value: "." in str(value or "")
    utils_module.exec_system = lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout=b"", stderr=b"")

    config_module = types.ModuleType("app.config")
    config_module.Config = type(
        "Config",
        (),
        {
            "TMP_PATH": temp_dir,
            "WIH_TIMEOUT_SEC": 7200,
            "WIH_CONCURRENCY": 6,
            "WIH_CONCURRENCY_PER_SITE": 2,
            "WIH_RULE_PATH": "",
            "PROXY_URL": "",
        },
    )

    modules_module = types.ModuleType("app.modules")

    class WihRecord(object):
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    modules_module.WihRecord = WihRecord

    services_module = types.ModuleType("app.services")

    url_candidate_filter_module = types.ModuleType("app.services.url_candidate_filter")
    url_candidate_filter_module.has_route_template_markers = lambda value: False
    url_candidate_filter_module.is_js_resource_path = lambda value: str(value or "").endswith(".js")
    url_candidate_filter_module.is_non_js_static_resource_path = lambda value: False
    url_candidate_filter_module.is_noise_single_segment_path = lambda value: False
    url_candidate_filter_module.strip_route_method_suffix = lambda value: str(value or "")

    sys.modules.setdefault("app", app_module)
    sys.modules["app.utils"] = utils_module
    sys.modules["app.config"] = config_module
    sys.modules["app.modules"] = modules_module
    sys.modules["app.services"] = services_module
    sys.modules["app.services.url_candidate_filter"] = url_candidate_filter_module

    app_module.utils = utils_module
    app_module.services = services_module

    module_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "infoHunter.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


info_hunter_module = _load_info_hunter_module()
InfoHunter = info_hunter_module.InfoHunter


class TestWihTimeoutSplit(unittest.TestCase):
    def test_exec_wih_splits_timeout_batch_and_keeps_results(self):
        hunter = InfoHunter(
            [
                "https://a.example.com",
                "https://b.example.com",
                "https://c.example.com",
            ]
        )

        hunter.check_have_wih = lambda: True
        hunter._supports_flag = lambda flag_text: flag_text in {"-c", "-v"}

        def _fake_exec_system(command, **kwargs):
            command_list = list(command or [])
            if "--version" in command_list:
                return subprocess.CompletedProcess(command_list, 0, stdout=b"1.0.0", stderr=b"")
            if "-h" in command_list:
                return subprocess.CompletedProcess(command_list, 0, stdout=b"wih help", stderr=b"")

            target_path = command_list[command_list.index("-t") + 1]
            result_path = command_list[command_list.index("-o") + 1]
            with open(target_path, "r", encoding="utf-8") as f:
                sites = [line.strip() for line in f.readlines() if line.strip()]

            if len(sites) > 1:
                raise subprocess.TimeoutExpired(command_list, kwargs.get("timeout"))

            payload = [
                {
                    "target": sites[0],
                    "records": [
                        {
                            "id": "path",
                            "content": "/api/user/list",
                            "source": sites[0],
                        }
                    ],
                }
            ]
            with open(result_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False))

            return subprocess.CompletedProcess(command_list, 0, stdout=b"", stderr=b"")

        info_hunter_module.utils.exec_system = _fake_exec_system

        try:
            self.assertTrue(hunter.exec_wih())
            results = hunter.dump_result()
        finally:
            hunter._delete_file()

        self.assertEqual(3, len(results))
        self.assertEqual(
            sorted(["https://a.example.com", "https://b.example.com", "https://c.example.com"]),
            sorted([item.site for item in results]),
        )


if __name__ == "__main__":
    unittest.main()
