import datetime
import importlib.util
import logging
import pathlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _build_logger():
    return types.SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
        debug=lambda *args, **kwargs: None,
        exception=lambda *args, **kwargs: None,
    )


def _install_shared_stubs():
    try:
        import bson  # type: ignore  # noqa: F401
    except ModuleNotFoundError:
        bson_module = types.ModuleType("bson")

        class ObjectId(str):
            def __new__(cls, value=""):
                return str.__new__(cls, str(value or ""))

            @staticmethod
            def is_valid(value):
                return len(str(value or "")) == 24

            @property
            def generation_time(self):
                return datetime.datetime.utcnow()

        bson_module.ObjectId = ObjectId
        sys.modules["bson"] = bson_module

    try:
        import colorlog  # type: ignore  # noqa: F401
    except ModuleNotFoundError:
        colorlog_module = types.ModuleType("colorlog")
        colorlog_module.StreamHandler = logging.StreamHandler
        colorlog_module.ColoredFormatter = logging.Formatter
        colorlog_module.getLogger = logging.getLogger
        sys.modules["colorlog"] = colorlog_module

    try:
        import dns.resolver  # type: ignore  # noqa: F401
    except ModuleNotFoundError:
        dns_module = types.ModuleType("dns")
        dns_resolver_module = types.ModuleType("dns.resolver")
        dns_module.resolver = dns_resolver_module
        sys.modules["dns"] = dns_module
        sys.modules["dns.resolver"] = dns_resolver_module

    try:
        import tld  # type: ignore  # noqa: F401
    except ModuleNotFoundError:
        tld_module = types.ModuleType("tld")
        tld_module.get_tld = lambda *args, **kwargs: None
        sys.modules["tld"] = tld_module

    try:
        import pymongo  # type: ignore  # noqa: F401
    except ModuleNotFoundError:
        pymongo_module = types.ModuleType("pymongo")

        class MongoClient(object):
            def __init__(self, *args, **kwargs):
                pass

        pymongo_module.MongoClient = MongoClient
        sys.modules["pymongo"] = pymongo_module


def _load_utils_recovery_module():
    module_name = "testapp.utils"
    if module_name in sys.modules:
        return sys.modules[module_name]

    _install_shared_stubs()

    managed_module_names = [
        "testapp",
        "testapp.config",
        "testapp.utils",
        "testapp.utils.conn",
        "testapp.utils.http",
        "testapp.utils.domain",
        "testapp.utils.ip",
        "testapp.utils.arl",
        "testapp.utils.time",
        "testapp.utils.url",
        "testapp.utils.cert",
        "testapp.utils.arlupdate",
        "testapp.utils.cdn",
        "testapp.utils.device",
        "testapp.utils.cron",
        "testapp.utils.query_loader",
        "testapp.utils.user",
        "testapp.utils.push",
        "testapp.utils.fingerprint",
    ]
    backup_modules = {name: sys.modules.get(name) for name in managed_module_names}

    testapp_module = types.ModuleType("testapp")
    testapp_module.__path__ = []

    config_module = types.ModuleType("testapp.config")
    config_module.Config = type(
        "Config",
        (),
        {
            "PROXY_URL": "",
            "MONGO_URL": "mongodb://localhost:27017/arl",
            "MONGO_MAX_POOL_SIZE": 10,
            "MONGO_MIN_POOL_SIZE": 0,
            "MONGO_MAX_IDLE_TIME_MS": 0,
            "MONGO_SERVER_SELECTION_TIMEOUT_MS": 1000,
            "MONGO_CONNECT_TIMEOUT_MS": 1000,
            "MONGO_SOCKET_TIMEOUT_MS": 1000,
            "PHANTOMJS_BIN": "",
        },
    )

    conn_module = types.ModuleType("testapp.utils.conn")
    conn_module.http_req = lambda *args, **kwargs: None
    conn_module.conn_db = lambda *args, **kwargs: None

    http_module = types.ModuleType("testapp.utils.http")
    http_module.get_title = lambda *args, **kwargs: ""
    http_module.get_headers = lambda *args, **kwargs: {}

    domain_module = types.ModuleType("testapp.utils.domain")
    domain_module.check_domain_black = lambda *args, **kwargs: False
    domain_module.is_valid_domain = lambda *args, **kwargs: True
    domain_module.is_in_scope = lambda *args, **kwargs: True
    domain_module.is_in_scopes = lambda *args, **kwargs: True
    domain_module.is_valid_fuzz_domain = lambda *args, **kwargs: True
    domain_module.normalize_domain = lambda value: value
    domain_module.normalize_fuzz_domain = lambda value: value

    ip_module = types.ModuleType("testapp.utils.ip")
    ip_module.is_vaild_ip_target = lambda *args, **kwargs: True
    ip_module.not_in_black_ips = lambda *args, **kwargs: True
    ip_module.get_ip_asn = lambda *args, **kwargs: ""
    ip_module.get_ip_city = lambda *args, **kwargs: ""
    ip_module.get_ip_type = lambda *args, **kwargs: ""

    arl_module = types.ModuleType("testapp.utils.arl")
    arl_module.arl_domain = lambda *args, **kwargs: ""
    arl_module.get_asset_domain_by_id = lambda *args, **kwargs: ""

    time_module = types.ModuleType("testapp.utils.time")
    time_module.curr_date = lambda: "2026-03-19 17:00:00"
    time_module.time2date = lambda *args, **kwargs: ""
    time_module.curr_date_obj = lambda: None

    url_module = types.ModuleType("testapp.utils.url")
    url_module.rm_similar_url = lambda *args, **kwargs: []
    url_module.get_hostname = lambda *args, **kwargs: ""
    url_module.normal_url = lambda value, *args, **kwargs: value
    url_module.same_netloc = lambda *args, **kwargs: True
    url_module.verify_cert = lambda *args, **kwargs: True
    url_module.url_ext = lambda *args, **kwargs: ""

    cert_module = types.ModuleType("testapp.utils.cert")
    cert_module.get_cert = lambda *args, **kwargs: {}

    arlupdate_module = types.ModuleType("testapp.utils.arlupdate")
    arlupdate_module.arl_update = lambda *args, **kwargs: None

    cdn_module = types.ModuleType("testapp.utils.cdn")
    cdn_module.get_cdn_name_by_cname = lambda *args, **kwargs: ""
    cdn_module.get_cdn_name_by_ip = lambda *args, **kwargs: ""
    cdn_module.infer_cdn_by_dns = lambda *args, **kwargs: ""

    device_module = types.ModuleType("testapp.utils.device")
    device_module.device_info = lambda *args, **kwargs: {}

    cron_module = types.ModuleType("testapp.utils.cron")
    cron_module.check_cron = lambda *args, **kwargs: True
    cron_module.check_cron_interval = lambda *args, **kwargs: True

    query_loader_module = types.ModuleType("testapp.utils.query_loader")
    query_loader_module.load_query_plugins = lambda *args, **kwargs: []

    user_module = types.ModuleType("testapp.utils.user")
    user_module.user_login = lambda *args, **kwargs: None
    user_module.user_login_header = lambda *args, **kwargs: None
    user_module.auth = lambda *args, **kwargs: None
    user_module.user_logout = lambda *args, **kwargs: None
    user_module.change_pass = lambda *args, **kwargs: None

    push_module = types.ModuleType("testapp.utils.push")
    push_module.message_push = lambda *args, **kwargs: None

    fingerprint_module = types.ModuleType("testapp.utils.fingerprint")
    fingerprint_module.parse_human_rule = lambda *args, **kwargs: {}
    fingerprint_module.transform_rule_map = lambda *args, **kwargs: {}

    try:
        sys.modules["testapp"] = testapp_module
        sys.modules["testapp.config"] = config_module
        sys.modules["testapp.utils.conn"] = conn_module
        sys.modules["testapp.utils.http"] = http_module
        sys.modules["testapp.utils.domain"] = domain_module
        sys.modules["testapp.utils.ip"] = ip_module
        sys.modules["testapp.utils.arl"] = arl_module
        sys.modules["testapp.utils.time"] = time_module
        sys.modules["testapp.utils.url"] = url_module
        sys.modules["testapp.utils.cert"] = cert_module
        sys.modules["testapp.utils.arlupdate"] = arlupdate_module
        sys.modules["testapp.utils.cdn"] = cdn_module
        sys.modules["testapp.utils.device"] = device_module
        sys.modules["testapp.utils.cron"] = cron_module
        sys.modules["testapp.utils.query_loader"] = query_loader_module
        sys.modules["testapp.utils.user"] = user_module
        sys.modules["testapp.utils.push"] = push_module
        sys.modules["testapp.utils.fingerprint"] = fingerprint_module

        testapp_module.config = config_module

        module_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "utils" / "__init__.py"
        spec = importlib.util.spec_from_file_location(
            module_name,
            module_path,
            submodule_search_locations=[str(module_path.parent)],
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        testapp_module.utils = module
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in backup_modules.items():
            if original is None:
                if name != module_name:
                    sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


def _load_celerytask_module():
    module_name = "app.celerytask"
    if module_name in sys.modules:
        return sys.modules[module_name]

    _install_shared_stubs()

    app_module = types.ModuleType("app")
    app_module.__path__ = []

    config_module = types.ModuleType("app.config")
    config_module.Config = type(
        "Config",
        (),
        {
            "CELERY_BROKER_URL": "memory://",
            "CELERY_TASK_TIME_LIMIT_SEC": 0,
            "CELERY_TASK_SOFT_TIME_LIMIT_SEC": 0,
            "CELERY_PREFETCH_MULTIPLIER": 1,
            "CELERY_BROKER_HEARTBEAT": 120,
            "CELERY_BROKER_HEARTBEAT_CHECKRATE": 2.0,
            "CELERY_MAX_TASKS_PER_CHILD": 100,
            "CELERY_MAX_MEMORY_PER_CHILD": 0,
        },
    )
    config_module.refresh_runtime_config_best_effort = lambda *args, **kwargs: None

    utils_module = types.ModuleType("app.utils")
    utils_module.get_logger = _build_logger
    utils_module.curr_date = lambda: "2026-04-10 12:00:00"
    utils_module.conn_db = lambda *args, **kwargs: None

    tasks_module = types.ModuleType("app.tasks")

    modules_module = types.ModuleType("app.modules")
    modules_module.CeleryAction = type(
        "CeleryAction",
        (),
        {
            "DOMAIN_TASK_SYNC_TASK": "domain_task_sync_task",
            "DOMAIN_EXEC_TASK": "domain_exec_task",
            "IP_EXEC_TASK": "ip_exec_task",
            "DOMAIN_TASK": "domain_task",
            "IP_TASK": "ip_task",
            "RUN_RISK_CRUISING": "run_risk_cruising",
            "FOFA_TASK": "fofa_task",
            "GITHUB_TASK_TASK": "github_task_task",
            "GITHUB_TASK_MONITOR": "github_task_monitor",
            "ASSET_SITE_UPDATE": "asset_site_update",
            "ADD_ASSET_SITE_TASK": "add_asset_site_task",
            "ASSET_WIH_UPDATE": "asset_wih_update",
            "AI_DENOISE_TASK": "ai_denoise_task",
            "AI_DENOISE_MODULE_TASK": "ai_denoise_module_task",
            "EXPORT_REPORT_TASK": "export_report_task",
        },
    )
    modules_module.TaskSyncStatus = type(
        "TaskSyncStatus",
        (),
        {
            "RUNNING": "running",
            "DEFAULT": "default",
            "ERROR": "error",
        },
    )
    modules_module.TaskStatus = type(
        "TaskStatus",
        (),
        {
            "DONE": "done",
            "STOP": "stop",
            "ERROR": "error",
        },
    )
    modules_module.TaskTag = type(
        "TaskTag",
        (),
        {
            "MONITOR": "monitor",
        },
    )
    modules_module.TaskType = type(
        "TaskType",
        (),
        {
            "DOMAIN": "domain",
            "IP": "ip",
            "RISK_CRUISING": "risk_cruising",
            "ASSET_SITE_UPDATE": "asset_site_update",
            "FOFA": "fofa",
            "ASSET_SITE_ADD": "asset_site_add",
            "ASSET_WIH_UPDATE": "asset_wih_update",
        },
    )

    sys.modules["app"] = app_module
    sys.modules["app.config"] = config_module
    sys.modules["app.utils"] = utils_module
    sys.modules["app.tasks"] = tasks_module
    sys.modules["app.modules"] = modules_module

    app_module.config = config_module
    app_module.utils = utils_module
    app_module.tasks = tasks_module

    module_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "celerytask.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


utils_recovery_module = _load_utils_recovery_module()
celerytask_module = _load_celerytask_module()

recover_interrupted_tasks_on_worker_start = utils_recovery_module.recover_interrupted_tasks_on_worker_start
celery = celerytask_module.celery
requeue_orphan_waiting_tasks_on_worker_start = celerytask_module.requeue_orphan_waiting_tasks_on_worker_start
recover_orphan_waiting_tasks_on_worker_start = celerytask_module.recover_orphan_waiting_tasks_on_worker_start


class TestCeleryRecovery(unittest.TestCase):
    def test_celery_uses_early_ack_for_long_running_tasks(self):
        self.assertFalse(celery.conf.task_acks_late)

    def test_celery_worker_prefetch_multiplier_effective_value_is_one(self):
        self.assertEqual(int(celery.conf.worker_prefetch_multiplier), 1)

    @patch.object(celerytask_module.logger, "warning")
    def test_resolve_worker_prefetch_multiplier_clamps_to_one(self, mock_warning):
        self.assertEqual(celerytask_module._resolve_worker_prefetch_multiplier(0), 1)
        self.assertEqual(celerytask_module._resolve_worker_prefetch_multiplier(""), 1)
        self.assertEqual(celerytask_module._resolve_worker_prefetch_multiplier(1), 1)
        self.assertEqual(celerytask_module._resolve_worker_prefetch_multiplier(3), 1)
        mock_warning.assert_called_once()

    def test_celery_sets_explicit_broker_heartbeat_defaults(self):
        self.assertEqual(int(celery.conf.broker_heartbeat), 120)
        self.assertEqual(float(celery.conf.broker_heartbeat_checkrate), 2.0)

    def test_build_live_task_recovery_guard_marks_partial_inspect_untrusted(self):
        guard = celerytask_module._build_live_task_recovery_guard(
            live_ok=True,
            reply_worker_set={"arlweb@worker-2"},
            consumer_ok=True,
            consumer_count_map={
                "arltask": 1,
                "arlheavy": 1,
                "arlweb": 1,
                "arlgithub": 1,
            },
        )

        self.assertFalse(guard["trusted"])
        self.assertEqual(guard["reply_worker_count"], 1)
        self.assertEqual(guard["consumer_total"], 4)

    @patch.object(celerytask_module.utils, "curr_date", return_value="2026-04-10 12:30:00")
    @patch.object(celerytask_module.utils, "conn_db")
    @patch.object(celerytask_module.arl_task_web, "delay")
    @patch.object(celerytask_module.arl_task, "delay", return_value="queued-ai-denoise-id")
    def test_enqueue_ai_denoise_routes_to_arl_task_queue(
        self,
        mock_task_delay,
        mock_task_web_delay,
        mock_conn_db,
        _mock_curr_date,
    ):
        task_collection = MagicMock()
        task_collection.find_one.return_value = {
            "_id": "69d86dc9bcb1c2046e6f0088",
            "status": "running",
            "options": {"ai_denoise": True},
        }
        task_collection.update_one.return_value = SimpleNamespace(modified_count=1)

        def fake_conn_db(name):
            if name == "task":
                return task_collection
            raise AssertionError("unexpected collection {}".format(name))

        mock_conn_db.side_effect = fake_conn_db

        celerytask_module._enqueue_ai_denoise_task(
            task_id="69d86dc9bcb1c2046e6f0088",
            task_options={"ai_denoise": True},
            trigger="stage:ssl_cert",
            modules=["cert"],
            action=celerytask_module.CeleryAction.AI_DENOISE_MODULE_TASK,
        )

        task_collection.update_one.assert_called_once()
        update_query, update_doc = task_collection.update_one.call_args[0]
        self.assertIn("_id", update_query)
        self.assertEqual(update_doc["$set"]["ai_denoise_status"]["status"], "queued")
        self.assertEqual(update_doc["$set"]["ai_denoise_status"]["trigger"], "stage:ssl_cert")
        self.assertEqual(update_doc["$set"]["ai_denoise_status"]["requested_modules"], ["cert"])

        mock_task_delay.assert_called_once_with(
            options={
                "celery_action": celerytask_module.CeleryAction.AI_DENOISE_MODULE_TASK,
                "data": {
                    "task_id": "69d86dc9bcb1c2046e6f0088",
                    "trigger": "stage:ssl_cert",
                    "modules": ["cert"],
                },
            }
        )
        mock_task_web_delay.assert_not_called()

    @patch.object(utils_recovery_module, "get_logger")
    @patch.object(utils_recovery_module, "curr_date", return_value="2026-03-19 17:00:00")
    @patch.object(utils_recovery_module, "conn_db")
    def test_recover_interrupted_tasks_marks_running_tasks_as_error(
        self,
        mock_conn_db,
        _mock_curr_date,
        mock_get_logger,
    ):
        logger = MagicMock()
        mock_get_logger.return_value = logger

        task_collection = MagicMock()
        task_collection.update_many.return_value = SimpleNamespace(modified_count=2)
        github_collection = MagicMock()
        github_collection.update_many.return_value = SimpleNamespace(modified_count=1)

        def fake_conn_db(name):
            if name == "task":
                return task_collection
            if name == "github_task":
                return github_collection
            raise AssertionError("unexpected collection {}".format(name))

        mock_conn_db.side_effect = fake_conn_db

        result = recover_interrupted_tasks_on_worker_start(reason="worker restarted")

        expected_query = {
            "status": {"$nin": ["waiting", "done", "stop", "error"]},
            "start_time": {"$nin": ["", "-"]},
        }

        task_collection.update_many.assert_called_once()
        github_collection.update_many.assert_called_once()

        task_query, task_update = task_collection.update_many.call_args[0]
        self.assertEqual(task_query, expected_query)
        self.assertEqual(task_update["$set"]["status"], "error")
        self.assertEqual(task_update["$set"]["end_time"], "2026-03-19 17:00:00")
        self.assertEqual(task_update["$set"]["stop_reason"], "worker restarted")
        self.assertTrue(task_update["$set"]["interrupted"])

        self.assertEqual(result, {"task": 2, "github_task": 1})
        logger.warning.assert_called()

    @patch.object(celerytask_module, "_get_broker_queue_message_counts")
    @patch.object(celerytask_module, "_collect_live_task_recovery_guard")
    @patch.object(celerytask_module.utils, "curr_date", return_value="2026-03-19 18:00:00")
    @patch.object(celerytask_module.time, "time", return_value=2000)
    @patch.object(celerytask_module.utils, "conn_db")
    @patch.object(celerytask_module.arl_github, "delay", return_value="new-github-celery-id")
    @patch.object(celerytask_module.arl_task, "delay", return_value="new-task-celery-id")
    def test_requeue_orphan_waiting_tasks_re_dispatches_safe_waiting_tasks(
        self,
        _mock_task_delay,
        _mock_github_delay,
        mock_conn_db,
        _mock_time,
        _mock_curr_date,
        mock_live_guard,
        mock_queue_counts,
    ):
        mock_live_guard.return_value = {
            "trusted": True,
            "task_id_set": set(),
            "live_ok": True,
            "consumer_ok": True,
            "reply_worker_count": 4,
            "consumer_total": 4,
        }
        mock_queue_counts.return_value = (
            {"arltask": 0, "arlheavy": 0, "arlweb": 0, "arlgithub": 0},
            True,
        )

        task_collection = MagicMock()
        task_collection.find.return_value = [
            {
                "_id": "task-orphan",
                "celery_id": "lost-task-id",
                "dispatch_queue": "arltask",
                "dispatch_ts": 1000,
                "type": "domain",
                "task_tag": "task",
                "target": "example.com",
                "name": "demo-task",
                "options": {},
            },
        ]
        task_collection.update_one.return_value = SimpleNamespace(modified_count=1)

        github_collection = MagicMock()
        github_collection.find.return_value = [
            {
                "_id": "github-orphan",
                "celery_id": "lost-github-id",
                "dispatch_queue": "arlgithub",
                "dispatch_ts": 1000,
                "task_tag": "monitor",
                "target": "keyword",
                "name": "demo-github",
            },
        ]
        github_collection.update_one.return_value = SimpleNamespace(modified_count=1)

        def fake_conn_db(name):
            if name == "task":
                return task_collection
            if name == "github_task":
                return github_collection
            raise AssertionError("unexpected collection {}".format(name))

        mock_conn_db.side_effect = fake_conn_db

        result = requeue_orphan_waiting_tasks_on_worker_start(reason="worker restarted")

        task_update_query, task_update_doc = task_collection.update_one.call_args[0]
        github_update_query, github_update_doc = github_collection.update_one.call_args[0]
        self.assertEqual(task_update_query["celery_id"], "lost-task-id")
        self.assertEqual(task_update_doc["$set"]["celery_id"], "new-task-celery-id")
        self.assertEqual(task_update_doc["$set"]["dispatch_queue_reason"], "worker_start_requeue_waiting")
        self.assertEqual(github_update_query["celery_id"], "lost-github-id")
        self.assertEqual(github_update_doc["$set"]["celery_id"], "new-github-celery-id")
        self.assertEqual(result, {"task": 1, "github_task": 1})

    @patch.object(celerytask_module, "_get_broker_queue_message_counts")
    @patch.object(celerytask_module, "_collect_live_task_recovery_guard")
    @patch.object(celerytask_module.utils, "curr_date", return_value="2026-03-19 18:00:00")
    @patch.object(celerytask_module.time, "time", return_value=2000)
    @patch.object(celerytask_module.utils, "conn_db")
    def test_recover_orphan_waiting_tasks_marks_only_high_confidence_orphans(
        self,
        mock_conn_db,
        _mock_time,
        _mock_curr_date,
        mock_live_guard,
        mock_queue_counts,
    ):
        mock_live_guard.return_value = {
            "trusted": True,
            "task_id_set": {"live-task-id"},
            "live_ok": True,
            "consumer_ok": True,
            "reply_worker_count": 4,
            "consumer_total": 4,
        }
        mock_queue_counts.return_value = (
            {"arltask": 0, "arlheavy": 3, "arlweb": 2, "arlgithub": 0},
            True,
        )

        task_collection = MagicMock()
        task_collection.find.return_value = [
            {
                "_id": "task-orphan",
                "celery_id": "lost-task-id",
                "dispatch_queue": "arltask",
                "dispatch_ts": 1000,
            },
            {
                "_id": "task-live",
                "celery_id": "live-task-id",
                "dispatch_queue": "arltask",
                "dispatch_ts": 1000,
            },
            {
                "_id": "task-queued",
                "celery_id": "queued-heavy-id",
                "dispatch_queue": "arlheavy",
                "dispatch_ts": 1000,
            },
            {
                "_id": "task-web-queued",
                "celery_id": "queued-web-id",
                "dispatch_queue": "arlweb",
                "dispatch_ts": 1000,
            },
        ]
        task_collection.update_many.return_value = SimpleNamespace(modified_count=1)

        github_collection = MagicMock()
        github_collection.find.return_value = [
            {
                "_id": "github-orphan",
                "celery_id": "lost-github-id",
                "dispatch_queue": "arlgithub",
                "dispatch_ts": 1000,
            }
        ]
        github_collection.update_many.return_value = SimpleNamespace(modified_count=1)

        def fake_conn_db(name):
            if name == "task":
                return task_collection
            if name == "github_task":
                return github_collection
            raise AssertionError("unexpected collection {}".format(name))

        mock_conn_db.side_effect = fake_conn_db

        result = recover_orphan_waiting_tasks_on_worker_start(reason="worker restarted")

        task_update_query = task_collection.update_many.call_args[0][0]
        github_update_query = github_collection.update_many.call_args[0][0]
        self.assertEqual(task_update_query["_id"]["$in"], ["task-orphan"])
        self.assertEqual(github_update_query["_id"]["$in"], ["github-orphan"])
        self.assertEqual(result, {"task": 1, "github_task": 1})

    @patch.object(celerytask_module, "_get_broker_queue_message_counts")
    @patch.object(celerytask_module, "_collect_live_task_recovery_guard")
    def test_requeue_orphan_waiting_tasks_skips_when_live_inspect_untrusted(
        self,
        mock_live_guard,
        mock_queue_counts,
    ):
        mock_live_guard.return_value = {
            "trusted": False,
            "task_id_set": set(),
            "live_ok": True,
            "consumer_ok": True,
            "reply_worker_count": 1,
            "consumer_total": 4,
        }

        result = requeue_orphan_waiting_tasks_on_worker_start(reason="worker restarted")

        self.assertEqual(result, {"task": 0, "github_task": 0})
        mock_queue_counts.assert_not_called()


if __name__ == "__main__":
    unittest.main()
