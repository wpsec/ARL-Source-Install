import importlib.util
import pathlib
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


def _nested_get(item, dotted_key):
    current = item
    for part in str(dotted_key or "").split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _match_query(item, query):
    for key, expected in (query or {}).items():
        actual = _nested_get(item, key)
        if isinstance(expected, dict):
            if "$ne" in expected and actual == expected["$ne"]:
                return False
            if "$in" in expected and actual not in list(expected["$in"] or []):
                return False
            continue
        if actual != expected:
            return False
    return True


class _FakeCursor(object):
    def __init__(self, items):
        self.items = list(items or [])

    def sort(self, spec):
        for key, direction in reversed(list(spec or [])):
            reverse = int(direction or 0) < 0
            self.items.sort(key=lambda item: _nested_get(item, key), reverse=reverse)
        return self

    def limit(self, size):
        self.items = self.items[: int(size or 0)]
        return self

    def __iter__(self):
        return iter(self.items)


class _FakeCollection(object):
    def __init__(self, bucket):
        self.bucket = bucket

    @staticmethod
    def _project(item, fields):
        if not isinstance(fields, dict) or not fields:
            return dict(item)
        projected = {}
        for key, enabled in fields.items():
            if not enabled:
                continue
            if "." in key:
                continue
            if key in item:
                projected[key] = item[key]
        if "_id" in item and fields.get("_id", 1):
            projected["_id"] = item["_id"]
        return projected

    def find(self, query=None, fields=None):
        matched = [
            self._project(item, fields)
            for item in list(self.bucket)
            if _match_query(item, query)
        ]
        return _FakeCursor(matched)

    def find_one(self, query=None, fields=None):
        for item in list(self.bucket):
            if _match_query(item, query):
                return self._project(item, fields)
        return None

    def distinct(self, field_name, query=None):
        values = []
        seen = set()
        for item in list(self.bucket):
            if not _match_query(item, query):
                continue
            value = _nested_get(item, field_name)
            marker = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str) if isinstance(value, (dict, list)) else str(value)
            if marker in seen:
                continue
            seen.add(marker)
            values.append(value)
        return values

    def insert_many(self, docs):
        for doc in list(docs or []):
            copied = dict(doc)
            copied["_id"] = copied.get("_id", FakeObjectId())
            self.bucket.append(copied)


class FakeObjectId(str):
    _counter = 0

    def __new__(cls, value=None):
        if value is None:
            cls._counter += 1
            value = "{:024x}".format(cls._counter)
        return str.__new__(cls, str(value))

    @staticmethod
    def is_valid(value):
        text = str(value or "").strip().lower()
        if len(text) != 24:
            return False
        return all(ch in "0123456789abcdef" for ch in text)


def _load_module():
    module_name = "app.services.wih_periodic_reuse_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    temp_dir = tempfile.mkdtemp(prefix="arl_wih_periodic_reuse_test_")

    app_module = types.ModuleType("app")
    bson_module = types.ModuleType("bson")
    bson_module.ObjectId = FakeObjectId
    utils_module = types.ModuleType("app.utils")
    utils_module.get_logger = _build_logger
    utils_module.curr_date = lambda: "2026-04-13 12:00:00"
    utils_module.conn_db = lambda name: None

    config_module = types.ModuleType("app.config")
    config_module.Config = type(
        "Config",
        (),
        {
            "WIH_PERIODIC_REUSE_ENABLE": True,
            "WIH_PERIODIC_REUSE_MAX_BASELINE_TASKS": 5,
            "WIH_PERIODIC_REUSE_LOG_DETAIL": False,
        },
    )

    modules_module = types.ModuleType("app.modules")

    class CollectSource(object):
        WIH_URL_PROBE = "wih_url_probe"

    class TaskStatus(object):
        DONE = "done"

    modules_module.CollectSource = CollectSource
    modules_module.TaskStatus = TaskStatus

    services_pkg = types.ModuleType("app.services")
    info_hunter_module = types.ModuleType("app.services.infoHunter")
    wih_endpoint_probe_module = types.ModuleType("app.services.wih_endpoint_probe")

    class _InfoHunter(object):
        @staticmethod
        def normalize_wih_record(record):
            record_type = str(getattr(record, "record_type", "") or getattr(record, "recordType", "") or "").strip()
            content = str(getattr(record, "content", "") or "").strip()
            source = str(getattr(record, "source", "") or "").strip()
            site = str(getattr(record, "site", "") or "").strip()
            if not record_type or not content:
                return None
            return types.SimpleNamespace(
                recordType=record_type,
                content=content,
                source=source,
                site=site,
                fnv_hash="{}|{}|{}|{}".format(record_type, content, source, site),
            )

    info_hunter_module.InfoHunter = _InfoHunter
    wih_endpoint_probe_module.run_wih_endpoint_probe = lambda endpoints, waf_guard=None: list(endpoints or [])

    sys.modules["app"] = app_module
    sys.modules["bson"] = bson_module
    sys.modules["app.utils"] = utils_module
    sys.modules["app.config"] = config_module
    sys.modules["app.modules"] = modules_module
    sys.modules["app.services"] = services_pkg
    sys.modules["app.services.infoHunter"] = info_hunter_module
    sys.modules["app.services.wih_endpoint_probe"] = wih_endpoint_probe_module

    app_module.utils = utils_module

    module_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "wih_periodic_reuse.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


reuse_module = _load_module()
WihPeriodicReuseService = reuse_module.WihPeriodicReuseService


class TestWihPeriodicReuseService(unittest.TestCase):
    def test_build_site_signature_stable(self):
        site_doc = {
            "site": "https://example.com",
            "title": "Example",
            "status": 200,
            "http_server": "nginx",
            "body_length": 1024,
            "favicon": {"hash": 12345},
            "finger": [{"name": "Vue"}, {"name": "Nginx"}],
        }

        site_a, signature_a = WihPeriodicReuseService.build_site_signature(site_doc)
        site_b, signature_b = WihPeriodicReuseService.build_site_signature(dict(site_doc))

        self.assertEqual("https://example.com", site_a)
        self.assertEqual(site_a, site_b)
        self.assertEqual(signature_a, signature_b)

    @patch.object(reuse_module, "run_wih_endpoint_probe")
    def test_run_reuses_previous_task_when_site_signature_matches(self, mock_reprobe):
        current_task_id = FakeObjectId()
        previous_task_id = FakeObjectId()
        store = {
            "task": [
                {
                    "_id": current_task_id,
                    "target": "example.com",
                    "status": "running",
                    "options": {
                        "from_task_schedule": True,
                        "task_schedule_id": "schedule-1",
                    },
                },
                {
                    "_id": previous_task_id,
                    "target": "example.com",
                    "status": "done",
                    "end_time": "2026-04-12 10:00:00",
                    "options": {
                        "from_task_schedule": True,
                        "task_schedule_id": "schedule-1",
                    },
                },
            ],
            "site": [
                {
                    "task_id": str(current_task_id),
                    "site": "https://example.com",
                    "title": "Portal",
                    "status": 200,
                    "http_server": "nginx",
                    "body_length": 4096,
                    "favicon": {"hash": 1001},
                    "finger": [{"name": "Vue"}],
                },
                {
                    "task_id": str(previous_task_id),
                    "site": "https://example.com",
                    "title": "Portal",
                    "status": 200,
                    "http_server": "nginx",
                    "body_length": 4096,
                    "favicon": {"hash": 1001},
                    "finger": [{"name": "Vue"}],
                },
            ],
            "wih": [
                {
                    "_id": FakeObjectId(),
                    "task_id": str(previous_task_id),
                    "record_type": "urlfinder_url",
                    "content": "https://example.com/api/list",
                    "source": "https://example.com/app.js",
                    "site": "https://example.com",
                    "fnv_hash": "hash-1",
                }
            ],
            "wih_endpoint": [
                {
                    "_id": FakeObjectId(),
                    "task_id": str(previous_task_id),
                    "target": "https://example.com",
                    "page_url": "https://example.com/",
                    "url": "https://example.com/api/list",
                    "method": "GET",
                    "fnv_hash": "endpoint-1",
                    "status_code": 200,
                    "response_status": 200,
                    "verification_status": "probed",
                    "verification_note": "历史响应",
                    "ai_fill_status": "tested",
                    "ai_fill_note": "历史 AI 填充",
                }
            ],
            "fileleak": [],
            "url": [
                {
                    "_id": FakeObjectId(),
                    "task_id": str(previous_task_id),
                    "source": "wih_url_probe",
                    "url": "https://example.com/api/list",
                    "site": "https://example.com/api/list",
                }
            ],
        }

        reuse_module.utils.conn_db = lambda name: _FakeCollection(store[name])
        captured_probe_inputs = []

        def fake_reprobe(endpoints, waf_guard=None):
            captured_probe_inputs.extend(list(endpoints or []))
            return [
                {
                    **dict((endpoints or [])[0]),
                    "status_code": 401,
                    "response_status": 401,
                    "response_size": 128,
                    "verification_status": "probed",
                    "verification_note": "已按 GET 方法轻量验证",
                    "verification_method": "GET",
                }
            ]

        mock_reprobe.side_effect = fake_reprobe

        service = WihPeriodicReuseService(
            task_id=str(current_task_id),
            sites=["https://example.com"],
            options={
                "from_task_schedule": True,
                "task_schedule_id": "schedule-1",
                "task_schedule_name": "周期任务",
                "task_schedule_run_number": 2,
            },
        )
        summary = service.run()

        self.assertEqual("ok", summary["reason"])
        self.assertEqual(str(previous_task_id), summary["previous_task_id"])
        self.assertEqual(["https://example.com"], summary["reused_sites"])
        self.assertEqual(1, summary["reused_record_count"])
        self.assertEqual(1, summary["reused_endpoint_count"])
        self.assertEqual(1, summary["reused_endpoint_candidate_count"])
        self.assertEqual(0, summary["dropped_endpoint_count"])
        self.assertEqual(1, summary["reused_url_count"])
        self.assertEqual(["https://example.com/api/list"], summary["reused_urls"])
        self.assertEqual(str(current_task_id), store["wih"][-1]["task_id"])
        self.assertEqual(str(current_task_id), store["wih_endpoint"][-1]["task_id"])
        self.assertEqual(str(current_task_id), store["url"][-1]["task_id"])
        self.assertEqual(401, store["wih_endpoint"][-1]["status_code"])
        self.assertEqual("probed", store["wih_endpoint"][-1]["verification_status"])
        self.assertNotIn("ai_fill_status", store["wih_endpoint"][-1])
        self.assertEqual(1, len(captured_probe_inputs))
        self.assertNotIn("status_code", captured_probe_inputs[0])
        self.assertNotIn("verification_status", captured_probe_inputs[0])
        self.assertNotIn("ai_fill_status", captured_probe_inputs[0])

    @patch.object(reuse_module, "run_wih_endpoint_probe")
    def test_run_drops_reused_endpoint_when_reprobe_reports_404(self, mock_reprobe):
        current_task_id = FakeObjectId()
        previous_task_id = FakeObjectId()
        store = {
            "task": [
                {
                    "_id": current_task_id,
                    "target": "example.com",
                    "status": "running",
                    "options": {
                        "from_task_schedule": True,
                        "task_schedule_id": "schedule-1",
                    },
                },
                {
                    "_id": previous_task_id,
                    "target": "example.com",
                    "status": "done",
                    "end_time": "2026-04-12 10:00:00",
                    "options": {
                        "from_task_schedule": True,
                        "task_schedule_id": "schedule-1",
                    },
                },
            ],
            "site": [
                {
                    "task_id": str(current_task_id),
                    "site": "https://example.com",
                    "title": "Portal",
                    "status": 200,
                    "http_server": "nginx",
                    "body_length": 4096,
                    "favicon": {"hash": 1001},
                    "finger": [{"name": "Vue"}],
                },
                {
                    "task_id": str(previous_task_id),
                    "site": "https://example.com",
                    "title": "Portal",
                    "status": 200,
                    "http_server": "nginx",
                    "body_length": 4096,
                    "favicon": {"hash": 1001},
                    "finger": [{"name": "Vue"}],
                },
            ],
            "wih": [],
            "wih_endpoint": [
                {
                    "_id": FakeObjectId(),
                    "task_id": str(previous_task_id),
                    "target": "https://example.com",
                    "page_url": "https://example.com/",
                    "url": "https://example.com/api/legacy",
                    "method": "GET",
                    "fnv_hash": "endpoint-legacy",
                }
            ],
            "fileleak": [],
            "url": [],
        }

        reuse_module.utils.conn_db = lambda name: _FakeCollection(store[name])
        mock_reprobe.return_value = [
            {
                "task_id": str(current_task_id),
                "target": "https://example.com",
                "page_url": "https://example.com/",
                "url": "https://example.com/api/legacy",
                "method": "GET",
                "fnv_hash": "endpoint-legacy",
                "status_code": 404,
                "response_status": 404,
                "verification_status": "probed",
                "verification_note": "已按 GET 方法轻量验证",
                "verification_method": "GET",
            }
        ]

        service = WihPeriodicReuseService(
            task_id=str(current_task_id),
            sites=["https://example.com"],
            options={
                "from_task_schedule": True,
                "task_schedule_id": "schedule-1",
                "task_schedule_name": "周期任务",
                "task_schedule_run_number": 2,
            },
        )
        summary = service.run()

        self.assertEqual("ok", summary["reason"])
        self.assertEqual(1, summary["reused_endpoint_candidate_count"])
        self.assertEqual(0, summary["reused_endpoint_count"])
        self.assertEqual(1, summary["dropped_endpoint_count"])
        self.assertEqual(1, len(store["wih_endpoint"]))

    @patch.object(reuse_module, "run_wih_endpoint_probe")
    def test_run_keeps_reused_endpoint_when_reprobe_is_inconclusive(self, mock_reprobe):
        current_task_id = FakeObjectId()
        previous_task_id = FakeObjectId()
        store = {
            "task": [
                {
                    "_id": current_task_id,
                    "target": "example.com",
                    "status": "running",
                    "options": {
                        "from_task_schedule": True,
                        "task_schedule_id": "schedule-1",
                    },
                },
                {
                    "_id": previous_task_id,
                    "target": "example.com",
                    "status": "done",
                    "end_time": "2026-04-12 10:00:00",
                    "options": {
                        "from_task_schedule": True,
                        "task_schedule_id": "schedule-1",
                    },
                },
            ],
            "site": [
                {
                    "task_id": str(current_task_id),
                    "site": "https://example.com",
                    "title": "Portal",
                    "status": 200,
                    "http_server": "nginx",
                    "body_length": 4096,
                    "favicon": {"hash": 1001},
                    "finger": [{"name": "Vue"}],
                },
                {
                    "task_id": str(previous_task_id),
                    "site": "https://example.com",
                    "title": "Portal",
                    "status": 200,
                    "http_server": "nginx",
                    "body_length": 4096,
                    "favicon": {"hash": 1001},
                    "finger": [{"name": "Vue"}],
                },
            ],
            "wih": [],
            "wih_endpoint": [
                {
                    "_id": FakeObjectId(),
                    "task_id": str(previous_task_id),
                    "target": "https://example.com",
                    "page_url": "https://example.com/",
                    "url": "https://example.com/api/list",
                    "method": "GET",
                    "fnv_hash": "endpoint-list",
                }
            ],
            "fileleak": [],
            "url": [],
        }

        reuse_module.utils.conn_db = lambda name: _FakeCollection(store[name])
        mock_reprobe.return_value = [
            {
                "task_id": str(current_task_id),
                "target": "https://example.com",
                "page_url": "https://example.com/",
                "url": "https://example.com/api/list",
                "method": "GET",
                "fnv_hash": "endpoint-list",
                "verification_status": "error",
                "verification_note": "轻量验证失败: Timeout",
            }
        ]

        service = WihPeriodicReuseService(
            task_id=str(current_task_id),
            sites=["https://example.com"],
            options={
                "from_task_schedule": True,
                "task_schedule_id": "schedule-1",
                "task_schedule_name": "周期任务",
                "task_schedule_run_number": 2,
            },
        )
        summary = service.run()

        self.assertEqual("ok", summary["reason"])
        self.assertEqual(1, summary["reused_endpoint_candidate_count"])
        self.assertEqual(1, summary["reused_endpoint_count"])
        self.assertEqual(0, summary["dropped_endpoint_count"])
        self.assertEqual(str(current_task_id), store["wih_endpoint"][-1]["task_id"])
        self.assertEqual("error", store["wih_endpoint"][-1]["verification_status"])
        self.assertEqual("unverified", store["wih_endpoint"][-1]["reuse_verification_status"])

    def test_run_skips_reused_url_when_fileleak_already_exists(self):
        current_task_id = FakeObjectId()
        previous_task_id = FakeObjectId()
        store = {
            "task": [
                {
                    "_id": current_task_id,
                    "target": "example.com",
                    "status": "running",
                    "options": {
                        "from_task_schedule": True,
                        "task_schedule_id": "schedule-1",
                    },
                },
                {
                    "_id": previous_task_id,
                    "target": "example.com",
                    "status": "done",
                    "end_time": "2026-04-12 10:00:00",
                    "options": {
                        "from_task_schedule": True,
                        "task_schedule_id": "schedule-1",
                    },
                },
            ],
            "site": [
                {
                    "task_id": str(current_task_id),
                    "site": "https://example.com",
                    "title": "Portal",
                    "status": 200,
                    "http_server": "nginx",
                    "body_length": 4096,
                    "favicon": {"hash": 1001},
                    "finger": [{"name": "Vue"}],
                },
                {
                    "task_id": str(previous_task_id),
                    "site": "https://example.com",
                    "title": "Portal",
                    "status": 200,
                    "http_server": "nginx",
                    "body_length": 4096,
                    "favicon": {"hash": 1001},
                    "finger": [{"name": "Vue"}],
                },
            ],
            "wih": [],
            "wih_endpoint": [],
            "fileleak": [
                {
                    "_id": FakeObjectId(),
                    "task_id": str(current_task_id),
                    "url": "https://example.com/api/list",
                }
            ],
            "url": [
                {
                    "_id": FakeObjectId(),
                    "task_id": str(previous_task_id),
                    "source": "wih_url_probe",
                    "url": "https://example.com/api/list",
                    "site": "https://example.com/api/list",
                }
            ],
        }

        reuse_module.utils.conn_db = lambda name: _FakeCollection(store[name])

        service = WihPeriodicReuseService(
            task_id=str(current_task_id),
            sites=["https://example.com"],
            options={
                "from_task_schedule": True,
                "task_schedule_id": "schedule-1",
                "task_schedule_name": "周期任务",
                "task_schedule_run_number": 3,
            },
        )
        summary = service.run()

        self.assertEqual("ok", summary["reason"])
        self.assertEqual(0, summary["reused_url_count"])
        self.assertEqual([], summary["reused_urls"])
        self.assertEqual(1, len(store["url"]))


if __name__ == "__main__":
    unittest.main()
