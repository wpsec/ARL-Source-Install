import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


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
            "WIH_MAX_BATCH_SIZE": 12,
            "WIH_ADAPTIVE_RUNTIME_ENABLE": True,
            "WIH_RUNTIME_ENABLE": True,
            "WIH_RUNTIME_DRIVER": "playwright",
            "WIH_RUNTIME_COMMAND": "",
            "WIH_RUNTIME_TIMEOUT_SEC": 60,
            "WIH_RUNTIME_MAX_PAGES": 12,
            "WIH_RUNTIME_MAX_ACTIONS": 32,
            "WIH_RUNTIME_MAX_REQUESTS": 180,
            "WIH_LIGHT_TIMEOUT_SEC": 900,
            "WIH_LIGHT_RUNTIME_TIMEOUT_SEC": 20,
            "WIH_LIGHT_RUNTIME_MAX_PAGES": 4,
            "WIH_LIGHT_RUNTIME_MAX_ACTIONS": 10,
            "WIH_LIGHT_RUNTIME_MAX_REQUESTS": 60,
            "WIH_MINIMAL_TIMEOUT_SEC": 900,
            "WIH_MINIMAL_RUNTIME_ENABLE": False,
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
    url_candidate_filter_module.strip_url_annotation = lambda value: str(value or "")
    url_candidate_filter_module.strip_route_method_suffix = lambda value: str(value or "")

    managed_module_names = [
        "app",
        "app.utils",
        "app.config",
        "app.modules",
        "app.services",
        "app.services.url_candidate_filter",
    ]
    backup_modules = {
        name: sys.modules.get(name) for name in managed_module_names
    }
    try:
        sys.modules["app"] = app_module
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
    finally:
        for name, original in backup_modules.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


info_hunter_module = _load_info_hunter_module()
InfoHunter = info_hunter_module.InfoHunter


class TestWihTimeoutSplit(unittest.TestCase):
    def test_resolve_rule_path_falls_back_to_repo_template_when_immutable_copy_missing(self):
        def _fake_isfile(path):
            path_text = str(path or "").replace("\\", "/")
            return path_text.endswith("tools/wih/config/rules.yml")

        with patch.object(info_hunter_module.Config, "WIH_RULE_PATH", "/usr/local/share/arl/wih/config/rules.yml", create=True):
            with patch.object(info_hunter_module.os.path, "isfile", side_effect=_fake_isfile):
                resolved = InfoHunter._resolve_rule_path()

        self.assertTrue(str(resolved or "").replace("\\", "/").endswith("tools/wih/config/rules.yml"))

    def test_resolve_wih_binary_prefers_configured_image_binary(self):
        def _fake_resolve_executable(command):
            command_text = str(command or "").strip()
            if command_text == "/usr/bin/wih":
                return "/usr/bin/wih"
            if command_text == "/code/tools/wih/wih":
                return "/code/tools/wih/wih"
            return ""

        with patch.object(info_hunter_module.Config, "WIH_BIN_PATH", "/usr/bin/wih", create=True):
            with patch.object(info_hunter_module.utils, "resolve_executable", side_effect=_fake_resolve_executable):
                self.assertEqual("/usr/bin/wih", InfoHunter._resolve_wih_binary())

    def test_check_have_wih_logs_binary_version(self):
        hunter = InfoHunter(["https://a.example.com"])
        messages = []
        origin_logger = info_hunter_module.logger
        info_hunter_module.logger = types.SimpleNamespace(
            info=lambda message, *args, **kwargs: messages.append(str(message)),
            warning=lambda *args, **kwargs: None,
            debug=lambda *args, **kwargs: None,
            error=lambda *args, **kwargs: None,
        )

        def _fake_exec_system(command, **kwargs):
            command_list = list(command or [])
            if "--version" in command_list:
                return subprocess.CompletedProcess(command_list, 0, stdout=b"version: 1.2.1", stderr=b"")
            return subprocess.CompletedProcess(command_list, 0, stdout=b"", stderr=b"")

        try:
            with patch.object(info_hunter_module.utils, "exec_system", side_effect=_fake_exec_system):
                self.assertTrue(hunter.check_have_wih())
        finally:
            info_hunter_module.logger = origin_logger

        self.assertEqual("version: 1.2.1", hunter._load_wih_version_text())
        self.assertTrue(
            any("using wih binary path:" in item and "version_text:version: 1.2.1" in item for item in messages)
        )

    def test_initial_batch_size_respects_max_batch_size(self):
        hunter = InfoHunter(["https://{}.example.com".format(index) for index in range(21)])
        hunter.wih_concurrency = 15
        hunter.wih_max_batch_size = 12

        self.assertEqual(12, hunter._initial_batch_size())

    def test_build_command_includes_explicit_runtime_flags(self):
        hunter = InfoHunter(["https://a.example.com"])
        hunter._supports_flag = lambda flag_text: flag_text in {
            "--concurrency",
            "--concurrency-per-site",
            "--log-level",
            "--disable-ak-sk-output",
            "--disable-structured-output",
            "--runtime-enable",
            "--runtime-driver",
            "--runtime-timeout",
            "--runtime-max-pages",
            "--runtime-max-actions",
            "--runtime-max-requests",
        }

        command = hunter._build_command(minimal=False)

        self.assertIn("--disable-structured-output", command)
        self.assertIn("--runtime-enable=true", command)
        self.assertIn("--runtime-driver", command)
        self.assertIn("playwright", command)
        self.assertIn("--runtime-timeout", command)
        self.assertIn("60", command)
        self.assertIn("--runtime-max-pages", command)
        self.assertIn("12", command)
        self.assertIn("--runtime-max-actions", command)
        self.assertIn("32", command)
        self.assertIn("--runtime-max-requests", command)
        self.assertIn("180", command)

        minimal_command = hunter._build_command(minimal=True)
        self.assertIn("--disable-structured-output", minimal_command)
        self.assertIn("--runtime-enable=false", minimal_command)
        self.assertIn("--runtime-driver", minimal_command)
        self.assertIn("noop", minimal_command)
        self.assertNotIn("--runtime-max-pages", minimal_command)

    def test_build_command_light_profile_uses_smaller_runtime_budget(self):
        hunter = InfoHunter(["https://a.example.com"], prefer_fast_mode=True)
        hunter._supports_flag = lambda flag_text: flag_text in {
            "--concurrency",
            "--concurrency-per-site",
            "--log-level",
            "--disable-ak-sk-output",
            "--disable-structured-output",
            "--runtime-enable",
            "--runtime-driver",
            "--runtime-timeout",
            "--runtime-max-pages",
            "--runtime-max-actions",
            "--runtime-max-requests",
        }

        light_command = hunter._build_command(runtime_profile=hunter._build_runtime_profile("light"))

        self.assertIn("--runtime-enable=true", light_command)
        self.assertIn("--runtime-timeout", light_command)
        self.assertIn("20", light_command)
        self.assertIn("--runtime-max-pages", light_command)
        self.assertIn("4", light_command)
        self.assertIn("--runtime-max-actions", light_command)
        self.assertIn("10", light_command)
        self.assertIn("--runtime-max-requests", light_command)
        self.assertIn("60", light_command)

    def test_endpoint_sensitive_light_result_without_endpoint_escalates_to_full(self):
        hunter = InfoHunter(["https://a.example.com"], prefer_fast_mode=True)
        hunter.require_endpoint_results = True
        raw_text = json.dumps(
            [
                {
                    "target": "https://a.example.com",
                    "records": [
                        {"type": "path", "content": "/api/user"},
                        {"type": "urlfinder_url", "content": "https://a.example.com/api/user"},
                        {"type": "page_url", "content": "https://a.example.com/home"},
                    ],
                }
            ],
            ensure_ascii=False,
        )

        self.assertTrue(hunter._should_escalate_light_result(raw_text, ["https://a.example.com"]))

    def test_endpoint_sensitive_light_result_with_endpoint_is_accepted(self):
        hunter = InfoHunter(["https://a.example.com"], prefer_fast_mode=True)
        hunter.require_endpoint_results = True
        raw_text = json.dumps(
            [
                {
                    "target": "https://a.example.com",
                    "endpoints": [
                        {
                            "method": "GET",
                            "url": "https://a.example.com/api/user",
                        }
                    ],
                }
            ],
            ensure_ascii=False,
        )

        self.assertFalse(hunter._should_escalate_light_result(raw_text, ["https://a.example.com"]))

    def test_normalize_wih_record_collapses_secret_duplicates_across_same_site_pages(self):
        record_a = types.SimpleNamespace(
            recordType="secret_key",
            content='token:"base64:demo-profile"',
            source="https://cdn.example.com/app.js",
            site="https://example.com/Page_1.html",
            fnv_hash=1,
        )
        record_b = types.SimpleNamespace(
            recordType="secret_key",
            content='token:"base64:demo-profile"',
            source="https://cdn.example.com/app.js",
            site="https://example.com/",
            fnv_hash=2,
        )

        normalized_a = InfoHunter.normalize_wih_record(record_a)
        normalized_b = InfoHunter.normalize_wih_record(record_b)

        self.assertEqual("https://example.com", normalized_a.site)
        self.assertEqual("https://example.com", normalized_b.site)
        self.assertEqual(normalized_a.fnv_hash, normalized_b.fnv_hash)

    def test_normalize_wih_record_collapses_root_slash_url_duplicates(self):
        record_a = types.SimpleNamespace(
            recordType="urlfinder_url",
            content="https://example.com/",
            source="https://example.com/index.html",
            site="https://example.com/",
            fnv_hash=11,
        )
        record_b = types.SimpleNamespace(
            recordType="urlfinder_url",
            content="https://example.com",
            source="https://example.com/index.html",
            site="https://example.com",
            fnv_hash=12,
        )

        normalized_a = InfoHunter.normalize_wih_record(record_a)
        normalized_b = InfoHunter.normalize_wih_record(record_b)

        self.assertEqual("https://example.com", normalized_a.content)
        self.assertEqual("https://example.com", normalized_b.content)
        self.assertEqual(normalized_a.fnv_hash, normalized_b.fnv_hash)

    def test_normalize_endpoint_record_builds_detail_payload(self):
        endpoint = {
            "endpoint_id": "search",
            "site": "https://example.com",
            "page_url": "https://example.com/search",
            "url": "https://example.com/api/search",
            "method": "GET",
            "response_status": 200,
            "response_size": 128,
            "request_template": {
                "headers": {"Accept": "application/json"},
                "query": {"scene": "web", "keyword": "<value>"},
            },
        }

        normalized = InfoHunter._normalize_endpoint_record(endpoint, "https://example.com")

        self.assertEqual("https://example.com/api/search?scene=web&keyword=%3Cvalue%3E", normalized["url"])
        self.assertEqual("GET", normalized["method"])
        self.assertEqual(200, normalized["status_code"])
        self.assertEqual(128, normalized["response_size"])
        self.assertIn("GET /api/search?scene=web&keyword=%3Cvalue%3E HTTP/1.1", normalized["request_packet"])
        self.assertIsInstance(normalized["fnv_hash"], str)

    def test_normalize_endpoint_record_keeps_post_body_in_request_packet(self):
        endpoint = {
            "endpoint_id": "login",
            "site": "https://example.com",
            "trigger_context": {"page": "https://example.com/login"},
            "url": "https://example.com/api/login",
            "method": "POST",
            "request_template": {
                "headers": {"Content-Type": "application/json"},
                "body": {"username": "<value>", "password": "<value>"},
            },
        }

        normalized = InfoHunter._normalize_endpoint_record(endpoint, "https://example.com")

        self.assertEqual("https://example.com/login", normalized["page_url"])
        self.assertEqual("https://example.com/api/login", normalized["url"])
        self.assertIn("POST /api/login HTTP/1.1", normalized["request_packet"])
        self.assertIn('"username": "<value>"', normalized["request_packet"])
        self.assertIn('"password": "<value>"', normalized["request_packet"])
        self.assertIsNone(normalized["status_code"])
        self.assertIsNone(normalized["response_size"])

    def test_normalize_endpoint_record_deduplicates_existing_query(self):
        endpoint = {
            "endpoint_id": "syno_auth",
            "site": "https://test.example.com:6001",
            "url": "https://test.example.com:6001/scripts/synocredential.js/webapi/entry.cgi?api=SYNO.API.Auth",
            "method": "POST",
            "request_template": {
                "headers": {"Accept": "application/json, text/plain, */*"},
                "query": {"api": "SYNO.API.Auth"},
            },
        }

        normalized = InfoHunter._normalize_endpoint_record(endpoint, "https://test.example.com:6001")

        self.assertEqual(
            "https://test.example.com:6001/scripts/synocredential.js/webapi/entry.cgi?api=SYNO.API.Auth",
            normalized["url"],
        )
        self.assertIn("POST /scripts/synocredential.js/webapi/entry.cgi?api=SYNO.API.Auth HTTP/1.1", normalized["request_packet"])
        self.assertNotIn("api=SYNO.API.Auth&api=SYNO.API.Auth", normalized["url"])
        self.assertNotIn("api=SYNO.API.Auth&api=SYNO.API.Auth", normalized["request_packet"])
        self.assertIsNone(normalized["status_code"])
        self.assertIsNone(normalized["response_size"])

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

    def test_execute_profile_once_clamps_timeout_by_deadline(self):
        hunter = InfoHunter(["https://a.example.com"])
        hunter._supports_flag = lambda flag_text: flag_text in {"-c", "-v"}
        hunter.wih_deadline_ts = 145
        timeout_holder = {}

        def _fake_run_wih_command(command, batch_sites, command_name, timeout_sec=None):
            timeout_holder["timeout_sec"] = timeout_sec
            return {
                "ok": True,
                "timed_out": False,
                "completed": None,
                "stderr": "",
                "stdout": "",
                "error": "",
            }

        with patch.object(info_hunter_module.time, "time", return_value=100):
            with patch.object(hunter, "_run_wih_command", side_effect=_fake_run_wih_command):
                with patch.object(hunter, "_read_current_result_text", return_value="[]"):
                    result = hunter._execute_profile_once(
                        ["https://a.example.com"],
                        [],
                        0,
                        "minimal",
                        "minimal",
                    )

        self.assertTrue(result["ok"])
        self.assertEqual(45, timeout_holder["timeout_sec"])

    def test_exec_wih_sets_batch_deadline_when_missing(self):
        hunter = InfoHunter(
            [
                "https://a.example.com",
                "https://b.example.com",
                "https://c.example.com",
            ]
        )
        hunter.check_have_wih = lambda: True
        hunter.wih_timeout_sec = 300
        hunter.wih_minimal_timeout_sec = 120
        observed_deadlines = []

        def _fake_exec_wih_batch(batch_sites, aggregate_result_texts, depth=0):
            observed_deadlines.append(hunter.wih_deadline_ts)
            return True

        hunter._exec_wih_batch = _fake_exec_wih_batch

        with patch.object(info_hunter_module.time, "time", return_value=100):
            self.assertTrue(hunter.exec_wih())

        self.assertEqual([535], observed_deadlines)
        self.assertIsNone(hunter.wih_deadline_ts)

    def test_exec_wih_enforces_total_budget_across_batches(self):
        hunter = InfoHunter(
            [
                "https://a.example.com",
                "https://b.example.com",
            ]
        )
        hunter.wih_max_batch_size = 1
        hunter.wih_total_budget_sec = 30
        hunter.check_have_wih = lambda: True
        executed_batches = []

        def _fake_exec_wih_batch(batch_sites, aggregate_result_texts, depth=0):
            executed_batches.append(list(batch_sites))
            return True

        hunter._exec_wih_batch = _fake_exec_wih_batch

        with patch.object(
            info_hunter_module.time,
            "time",
            side_effect=[100, 100, 131, 131],
        ):
            self.assertTrue(hunter.exec_wih())

        self.assertEqual([["https://a.example.com"]], executed_batches)
        self.assertEqual("budget_exhausted", hunter.last_run_metrics["end_reason"])
        self.assertEqual("partial", hunter.last_run_metrics["status"])
        self.assertEqual(1, hunter.last_run_metrics["completed_batch_count"])
        self.assertIsNone(hunter.wih_deadline_ts)

    def test_exec_wih_keeps_external_deadline(self):
        hunter = InfoHunter(
            [
                "https://a.example.com",
                "https://b.example.com",
                "https://c.example.com",
            ]
        )
        hunter.check_have_wih = lambda: True
        hunter.wih_deadline_ts = 145
        observed_deadlines = []

        def _fake_exec_wih_batch(batch_sites, aggregate_result_texts, depth=0):
            observed_deadlines.append(hunter.wih_deadline_ts)
            return True

        hunter._exec_wih_batch = _fake_exec_wih_batch

        with patch.object(info_hunter_module.time, "time", return_value=100):
            self.assertTrue(hunter.exec_wih())

        self.assertEqual([145], observed_deadlines)
        self.assertEqual(145, hunter.wih_deadline_ts)

    def test_exec_wih_skips_timeout_split_when_deadline_exhausted(self):
        hunter = InfoHunter(
            [
                "https://a.example.com",
                "https://b.example.com",
                "https://c.example.com",
            ]
        )
        call_batches = []

        def _fake_execute_profile_once(batch_sites, aggregate_result_texts, depth, profile_name, stage_name):
            call_batches.append(list(batch_sites))
            return {
                "ok": False,
                "timed_out": True,
                "partial_saved": False,
                "remaining_sites": list(batch_sites),
                "raw_text": "",
                "profile": {},
                "deadline_exhausted": False,
            }

        hunter._execute_profile_once = _fake_execute_profile_once
        hunter._is_wih_deadline_exhausted = lambda: True

        result = hunter._exec_wih_batch(
            [
                "https://a.example.com",
                "https://b.example.com",
                "https://c.example.com",
            ],
            [],
            depth=0,
        )

        self.assertFalse(result)
        self.assertEqual(
            [[
                "https://a.example.com",
                "https://b.example.com",
                "https://c.example.com",
            ]],
            call_batches,
        )

    def test_exec_wih_timeout_salvages_completed_sites_before_retry(self):
        hunter = InfoHunter(
            [
                "https://a.example.com",
                "https://b.example.com",
                "https://c.example.com",
            ]
        )

        hunter.check_have_wih = lambda: True
        hunter._supports_flag = lambda flag_text: flag_text in {"-c", "-v"}
        seen_batches = []

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
            seen_batches.append(list(sites))

            if len(sites) > 1:
                payload = [
                    {
                        "target": "https://a.example.com",
                        "records": [
                            {
                                "id": "path",
                                "content": "/api/a",
                                "source": "https://a.example.com",
                            }
                        ],
                    },
                    {
                        "target": "https://b.example.com",
                        "records": [
                            {
                                "id": "path",
                                "content": "/api/b",
                                "source": "https://b.example.com",
                            }
                        ],
                    },
                ]
                with open(result_path, "w", encoding="utf-8") as f:
                    f.write(json.dumps(payload, ensure_ascii=False))
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

        self.assertEqual(
            [
                [
                    "https://a.example.com",
                    "https://b.example.com",
                    "https://c.example.com",
                ],
                ["https://c.example.com"],
            ],
            seen_batches,
        )
        self.assertEqual(
            sorted(["https://a.example.com", "https://b.example.com", "https://c.example.com"]),
            sorted([item.site for item in results]),
        )


if __name__ == "__main__":
    unittest.main()
