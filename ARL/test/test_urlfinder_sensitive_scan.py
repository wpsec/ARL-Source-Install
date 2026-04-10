import importlib.util
import pathlib
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from urllib.parse import urlparse


def _build_logger():
    return types.SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        debug=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )


def _load_urlfinder_sensitive_module():
    module_name = "app.services.urlfinder_sensitive_scan_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    temp_dir = tempfile.mkdtemp(prefix="arl_urlfinder_sensitive_")
    backup_modules = {}
    managed_module_names = [
        "app",
        "app.utils",
        "app.config",
        "app.modules",
        "app.services",
        "app.services.infoHunter",
        "app.services.url_candidate_filter",
    ]
    for item in managed_module_names:
        backup_modules[item] = sys.modules.get(item)

    app_module = types.ModuleType("app")
    app_module.__path__ = []

    utils_module = types.ModuleType("app.utils")
    utils_module.get_logger = _build_logger

    config_module = types.ModuleType("app.config")
    config_module.Config = type(
        "Config",
        (),
        {
            "TMP_PATH": temp_dir,
            "URLFINDER_SENSITIVE_ENABLE": True,
            "URLFINDER_SENSITIVE_MAX_TARGETS": 300,
            "URLFINDER_SENSITIVE_INCLUDE_JS": True,
            "URLFINDER_SENSITIVE_WIH_TIMEOUT_SEC": 600,
            "URLFINDER_SENSITIVE_STAGE_TIMEOUT_SEC": 1800,
        },
    )

    modules_module = types.ModuleType("app.modules")

    class WihRecord(object):
        def __init__(self, record_type, content, source, site, fnv_hash):
            self.recordType = record_type
            self.content = content
            self.source = source
            self.site = site
            self.fnv_hash = fnv_hash

        def __hash__(self):
            return hash(self.fnv_hash)

        def __eq__(self, other):
            return getattr(other, "fnv_hash", None) == self.fnv_hash

    modules_module.WihRecord = WihRecord

    services_module = types.ModuleType("app.services")
    services_module.__path__ = []

    info_hunter_module = types.ModuleType("app.services.infoHunter")

    class DummyInfoHunter(object):
        def __init__(self, targets):
            self.targets = list(targets or [])
            self.wih_timeout_sec = 0
            self.wih_runtime_enable = True
            self.wih_runtime_driver = "playwright"
            self.wih_runtime_command = "node runtime"

        def run(self):
            return []

    info_hunter_module.InfoHunter = DummyInfoHunter

    url_candidate_filter_module = types.ModuleType("app.services.url_candidate_filter")

    def normalize_http_url_candidate(value, allowed_hosts=None, allow_js=True):
        parsed = urlparse(str(value or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if allowed_hosts and host not in allowed_hosts:
            return ""
        if (not allow_js) and str(parsed.path or "").lower().endswith(".js"):
            return ""
        return parsed.geturl()

    url_candidate_filter_module.normalize_http_url_candidate = normalize_http_url_candidate

    try:
        sys.modules["app"] = app_module
        sys.modules["app.utils"] = utils_module
        sys.modules["app.config"] = config_module
        sys.modules["app.modules"] = modules_module
        sys.modules["app.services"] = services_module
        sys.modules["app.services.infoHunter"] = info_hunter_module
        sys.modules["app.services.url_candidate_filter"] = url_candidate_filter_module

        app_module.utils = utils_module
        app_module.services = services_module

        module_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "urlfinder_sensitive_scan.py"
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        for item in managed_module_names:
            original = backup_modules.get(item)
            if original is None:
                sys.modules.pop(item, None)
            else:
                sys.modules[item] = original


urlfinder_sensitive_module = _load_urlfinder_sensitive_module()
Config = urlfinder_sensitive_module.Config
WihRecord = urlfinder_sensitive_module.WihRecord
run_urlfinder_sensitive_scan = urlfinder_sensitive_module.run_urlfinder_sensitive_scan


def _build_urlfinder_records(count, host="example.com"):
    records = []
    for idx in range(count):
        records.append(
            WihRecord(
                "urlfinder_url",
                "https://{}/hidden/{}".format(host, idx),
                "https://{}/assets/app.js".format(host),
                "https://{}".format(host),
                idx + 1,
            )
        )
    return records


class TestUrlfinderSensitiveScan(unittest.TestCase):
    def test_secondary_scan_batches_targets_and_disables_runtime(self):
        instances = []

        class FakeInfoHunter(object):
            def __init__(self, targets):
                self.targets = list(targets or [])
                self.wih_timeout_sec = 0
                self.wih_runtime_enable = True
                self.wih_runtime_driver = "playwright"
                self.wih_runtime_command = "node runtime"
                instances.append(self)

            def run(self):
                records = []
                for idx, target in enumerate(self.targets):
                    records.append(
                        WihRecord(
                            "token",
                            "secret-{}".format(target.rsplit("/", 1)[-1]),
                            target,
                            "https://example.com",
                            "{}-{}".format(len(instances), idx),
                        )
                    )
                return records

        with patch.object(Config, "URLFINDER_SENSITIVE_ENABLE", True):
            with patch.object(Config, "URLFINDER_SENSITIVE_MAX_TARGETS", 30):
                with patch.object(Config, "URLFINDER_SENSITIVE_INCLUDE_JS", True):
                    with patch.object(Config, "URLFINDER_SENSITIVE_WIH_TIMEOUT_SEC", 180):
                        with patch.object(Config, "URLFINDER_SENSITIVE_STAGE_TIMEOUT_SEC", 600):
                            with patch.object(urlfinder_sensitive_module, "InfoHunter", FakeInfoHunter):
                                results = run_urlfinder_sensitive_scan(
                                    sites=["https://example.com"],
                                    wih_records=_build_urlfinder_records(30),
                                )

        self.assertEqual(30, len(results))
        self.assertEqual(2, len(instances))
        self.assertEqual(24, len(instances[0].targets))
        self.assertEqual(6, len(instances[1].targets))
        self.assertEqual(180, instances[0].wih_timeout_sec)
        self.assertEqual(180, instances[1].wih_timeout_sec)
        self.assertFalse(instances[0].wih_runtime_enable)
        self.assertFalse(instances[1].wih_runtime_enable)
        self.assertEqual("noop", instances[0].wih_runtime_driver)
        self.assertEqual("noop", instances[1].wih_runtime_driver)
        self.assertEqual("", instances[0].wih_runtime_command)
        self.assertEqual("", instances[1].wih_runtime_command)

    def test_secondary_scan_honors_stage_timeout_budget(self):
        instances = []

        class FakeInfoHunter(object):
            def __init__(self, targets):
                self.targets = list(targets or [])
                self.wih_timeout_sec = 0
                self.wih_runtime_enable = True
                self.wih_runtime_driver = "playwright"
                self.wih_runtime_command = "node runtime"
                instances.append(self)

            def run(self):
                return [
                    WihRecord(
                        "token",
                        "secret-stage-timeout",
                        self.targets[0],
                        "https://example.com",
                        "batch-{}".format(len(instances)),
                    )
                ]

        with patch.object(Config, "URLFINDER_SENSITIVE_ENABLE", True):
            with patch.object(Config, "URLFINDER_SENSITIVE_MAX_TARGETS", 30):
                with patch.object(Config, "URLFINDER_SENSITIVE_INCLUDE_JS", True):
                    with patch.object(Config, "URLFINDER_SENSITIVE_WIH_TIMEOUT_SEC", 90):
                        with patch.object(Config, "URLFINDER_SENSITIVE_STAGE_TIMEOUT_SEC", 120):
                            with patch.object(urlfinder_sensitive_module, "InfoHunter", FakeInfoHunter):
                                with patch.object(
                                    urlfinder_sensitive_module.time,
                                    "time",
                                    side_effect=[0, 0, 30, 95],
                                ):
                                    results = run_urlfinder_sensitive_scan(
                                        sites=["https://example.com"],
                                        wih_records=_build_urlfinder_records(30),
                                    )

        self.assertEqual(1, len(instances))
        self.assertEqual(1, len(results))
        self.assertEqual(90, instances[0].wih_timeout_sec)


if __name__ == "__main__":
    unittest.main()
