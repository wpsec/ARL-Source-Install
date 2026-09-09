"""ICP 查询适配层单元测试。"""

import importlib.util
import pathlib
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT_DIR / "app" / "services" / "icp_query.py"
SPEC = importlib.util.spec_from_file_location("icp_query_test_module", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class FakeResponse(object):
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.text = ""

    def json(self):
        return self.payload


class FakeSession(object):
    def __init__(self, responses):
        self.responses = list(responses)
        self.headers = {}
        self.calls = []
        self.mounts = []

    def mount(self, prefix, adapter):
        self.mounts.append((prefix, adapter))

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        return None


class FakeCursor(list):
    def sort(self, *args, **kwargs):
        return self

    def skip(self, _count):
        return self

    def limit(self, _count):
        return self


class FakeLogCollection(object):
    def __init__(self):
        self.query = None

    def count_documents(self, query):
        self.query = query
        return 0

    def find(self, query):
        self.query = query
        return FakeCursor()


class TestIcpRecordNormalization(unittest.TestCase):
    def test_normalize_record_keeps_common_and_extra_fields(self):
        record = MODULE.normalize_record(
            {
                "unitName": "测试主体",
                "domainName": "example.com",
                "serviceLicence": "京ICP备123号",
                "provinceName": "北京",
                "updateRecordTime": "2026-09-09",
                "customField": "保留",
                "token": "不得进入结果",
                "dataId": "内部关联值",
            },
            "web",
        )

        self.assertEqual("web", record["record_type"])
        self.assertEqual("测试主体", record["company_name"])
        self.assertEqual("example.com", record["domain"])
        self.assertEqual("京ICP备123号", record["license_number"])
        self.assertEqual("北京", record["province"])
        self.assertEqual("2026-09-09", record["update_time"])
        self.assertEqual("保留", record["extra"]["customField"])
        self.assertNotIn("token", record["extra"])
        self.assertNotIn("dataId", record["extra"])

    def test_serialize_does_not_expose_mongo_internal_id(self):
        serialized = MODULE._serialize({"_id": "internal-id", "safe": "value"})

        self.assertEqual({"safe": "value"}, serialized)

    def test_redact_text_covers_json_style_sensitive_assignments(self):
        redacted = MODULE._redact_text(
            '{"token":"synthetic-token", "sign": "synthetic-sign", "safe": "value"}'
        )

        self.assertNotIn("synthetic-token", redacted)
        self.assertNotIn("synthetic-sign", redacted)
        self.assertIn("[REDACTED]", redacted)
        self.assertIn('"safe": "value"', redacted)

    def test_serialize_filters_sensitive_keys_and_redacts_text_values(self):
        serialized = MODULE._serialize({
            "token": "synthetic-token",
            "nested": {"password": "synthetic-password"},
            "message": "authorization: synthetic-authorization",
            "long_value": "x" * 700,
            "safe": "value",
        })

        self.assertNotIn("token", serialized)
        self.assertNotIn("password", serialized["nested"])
        self.assertNotIn("synthetic-authorization", serialized["message"])
        self.assertEqual(700, len(serialized["long_value"]))
        self.assertEqual("value", serialized["safe"])

    def test_normalize_record_handles_non_mapping_values(self):
        normalized = MODULE.normalize_record(["unexpected"], "web")

        self.assertEqual({"record_type": "web", "extra": {}}, normalized)

    @unittest.skipUnless(MODULE.Image is not None and MODULE.np is not None, "验证码图像依赖未安装")
    def test_slider_offset_finds_downsampled_square_gap(self):
        small = MODULE.Image.new("RGB", (20, 20), "white")
        big = MODULE.Image.new("RGB", (100, 60), "white")
        for x in range(40, 60):
            for y in range(20, 40):
                big.putpixel((x, y), (10, 10, 10))

        def encode(image):
            output = MODULE.io.BytesIO()
            image.save(output, format="PNG")
            return MODULE.base64.b64encode(output.getvalue()).decode("ascii")

        self.assertEqual(40, MODULE.IcpQueryEngine._slider_offset(encode(small), encode(big)))


class TestIcpQueryEngine(unittest.TestCase):
    def _engine(self, responses):
        session = FakeSession(responses)
        engine = MODULE.IcpQueryEngine(session_factory=lambda: session)
        engine._get_token = lambda _session: ("test-token", 1000)
        engine._get_captcha = lambda _session, _token: ("captcha-id", "captcha-sign")
        return engine, session

    def test_query_page_uses_fixed_official_endpoint_and_normalizes_result(self):
        engine, session = self._engine([
            FakeResponse({
                "code": 200,
                "success": True,
                "params": {
                    "total": 1,
                    "list": [{"unitName": "测试主体", "domainName": "example.com"}],
                },
            }),
        ])

        result = engine.query_page("web", "example.com", page=1, page_size=26)

        self.assertEqual(1, result["total"])
        self.assertEqual("测试主体", result["records"][0]["company_name"])
        self.assertTrue(all(
            MODULE.urlparse(call[1]).hostname in MODULE.ICP_ALLOWED_HOSTS
            for call in session.calls
        ))
        self.assertTrue(session.calls[0][2]["verify"])
        self.assertIs(session.trust_env, False)
        self.assertRegex(session.headers["Cookie"], r"^__jsluid_s=[0-9a-f]{32}$")

    def test_ipv6_discovery_filters_to_public_scope_global_addresses(self):
        output = """
2: eth0    inet6 240e:1234::10/64 scope global dynamic
    inet6 fe80::1/64 scope link
    inet6 fd00::1/64 scope global
    inet6 240e:1234::10/64 scope global dynamic
"""

        self.assertEqual(
            ["240e:1234::10"], MODULE._discover_global_ipv6_addresses(output)
        )

    def test_ipv6_pool_rotates_addresses_after_local_discovery(self):
        completed = SimpleNamespace(
            stdout=(
                "inet6 240e:1234::10/64 scope global\n"
                "inet6 240e:1234::11/64 scope global\n"
            )
        )
        pool = MODULE.IcpIpv6Pool()
        with patch.object(MODULE.subprocess, "run", return_value=completed) as run:
            self.assertEqual("240e:1234::10", pool.next_address(True, 60))
            self.assertEqual("240e:1234::11", pool.next_address(True, 60))

        run.assert_called_once_with(
            ["ip", "-6", "addr", "show"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )

    def test_proxy_candidate_requires_explicit_host_and_port(self):
        self.assertEqual(
            "http://proxy.example:8080",
            MODULE._normalize_proxy_candidate("proxy.example:8080"),
        )
        self.assertEqual(
            "http://[2001:db8::20]:8080",
            MODULE._normalize_proxy_candidate("http://[2001:db8::20]:8080"),
        )
        self.assertIsNone(MODULE._normalize_proxy_candidate("proxy.example"))
        self.assertIsNone(MODULE._normalize_proxy_candidate("http://proxy.example:0"))
        self.assertIsNone(MODULE._normalize_proxy_candidate("http://proxy.example:8080/path"))

    def test_proxy_pool_fetches_checks_and_reuses_random_candidates(self):
        pool = MODULE.IcpProxyPool()
        candidates = ["http://proxy.example:8080", "http://proxy.example:8081"]
        with patch.object(pool, "_fetch_candidates", return_value=candidates) as fetch, \
                patch.object(pool, "_check_proxy", side_effect=lambda proxy, _timeout, _verify: proxy) as check, \
                patch.object(MODULE.random, "choice", side_effect=lambda values: values[0]) as choice:
            selected = pool.choose(
                "https://proxy-api.example/list",
                True,
                refresh_sec=180,
                pool_size=2,
                check_enabled=True,
                timeout=5,
                concurrency=2,
            )
            selected_again = pool.choose(
                "https://proxy-api.example/list",
                True,
                refresh_sec=180,
                pool_size=2,
                check_enabled=True,
                timeout=5,
                concurrency=2,
            )

        self.assertEqual("http://proxy.example:8080", selected)
        self.assertEqual(selected, selected_again)
        fetch.assert_called_once_with("https://proxy-api.example/list", 5, True)
        self.assertEqual(2, check.call_count)
        self.assertEqual(2, choice.call_count)

    def test_icp_session_binds_only_its_own_ipv6_source(self):
        session = FakeSession([])
        with patch.object(MODULE, "_select_icp_proxy", return_value=None), \
                patch.object(MODULE._ICP_IPV6_POOL, "next_address", return_value="2001:db8::10"):
            engine = MODULE.IcpQueryEngine(session_factory=lambda: session)
            engine.config["ipv6_enable"] = True
            engine._session()

        self.assertEqual(["http://", "https://"], [item[0] for item in session.mounts])
        self.assertTrue(all(
            item[1].source_address == "2001:db8::10" for item in session.mounts
        ))

    def test_query_page_normalizes_query_type_case(self):
        engine, _session = self._engine([
            FakeResponse({
                "code": 200,
                "success": True,
                "params": {"total": 0, "list": []},
            }),
        ])

        result = engine.query_page("WEB", "example.com")

        self.assertEqual("web", result["query_type"])

    def test_black_query_accepts_list_params_without_pagination(self):
        engine, session = self._engine([
            FakeResponse({
                "code": 200,
                "success": True,
                "params": [{"domainName": "blocked.example.com", "status": "违规"}],
            }),
        ])

        result = engine.query_page("bweb", "blocked.example.com")

        self.assertEqual(1, result["total"])
        self.assertEqual("blocked.example.com", result["records"][0]["domain"])
        self.assertIn("blackListDomain", session.calls[0][1])

    def test_all_query_types_use_expected_service_type_and_endpoint(self):
        expected_service_types = {
            "web": 1,
            "app": 6,
            "mapp": 7,
            "kapp": 8,
            "bweb": 1,
            "bapp": 6,
            "bmapp": 7,
            "bkapp": 8,
        }
        for query_type, service_type in expected_service_types.items():
            with self.subTest(query_type=query_type):
                params = [] if MODULE.ICP_QUERY_TYPES[query_type]["black"] else {"total": 0, "list": []}
                engine, session = self._engine([
                    FakeResponse({"code": 200, "success": True, "params": params}),
                ])

                engine.query_page(query_type, "example.test")

                request = session.calls[-1]
                body = request[2]["json"]
                expected_endpoint = (
                    MODULE.ICP_BLACK_DOMAIN_URL
                    if query_type == "bweb"
                    else MODULE.ICP_BLACK_APP_URL
                    if MODULE.ICP_QUERY_TYPES[query_type]["black"]
                    else MODULE.ICP_QUERY_URL
                )
                self.assertEqual(expected_endpoint, request[1])
                if query_type == "bweb":
                    self.assertEqual("example.test", body.get("domainName"))
                elif MODULE.ICP_QUERY_TYPES[query_type]["black"]:
                    self.assertEqual(service_type, body.get("serviceType"))
                    self.assertEqual("example.test", body.get("serviceName"))
                else:
                    self.assertEqual(service_type, body.get("serviceType"))
                    self.assertEqual("example.test", body.get("unitName"))

    def test_batch_query_deduplicates_in_original_order_and_enforces_limit(self):
        with patch.object(MODULE, "_new_task", return_value={"task_id": "batch-1"}) as new_task:
            result = MODULE.create_batch_task("web", [" first ", "second", "first", "", "second"])

        self.assertEqual({"task_id": "batch-1"}, result)
        new_task.assert_called_once_with("batch", "web", ["first", "second"])

        with patch.object(MODULE.Config, "ICP_QUERY_MAX_ITEMS", 2), \
                patch.object(MODULE, "_new_task") as new_task:
            with self.assertRaises(MODULE.IcpQueryError) as context:
                MODULE.create_batch_task("web", ["one", "two", "three"])

        self.assertEqual("validation_error", context.exception.category)
        new_task.assert_not_called()

    def test_query_page_retries_retryable_error_only_within_configured_limit(self):
        engine, _session = self._engine([])
        response = {"code": 200, "success": True, "params": {"total": 0, "list": []}}
        with patch.object(
            engine,
            "_query_once",
            side_effect=[
                MODULE.IcpQueryError("temporary", category="network_error", retryable=True),
                (response, "token", "captcha", "sign"),
            ],
        ) as query_once, patch.object(MODULE.time, "sleep") as sleep:
            result = engine.query_page("web", "example.test")

        self.assertEqual([], result["records"])
        self.assertEqual(2, query_once.call_count)
        sleep.assert_called_once()

        engine.config["retry"] = 0
        with patch.object(
            engine,
            "_query_once",
            side_effect=MODULE.IcpQueryError("temporary", category="network_error", retryable=True),
        ) as query_once:
            with self.assertRaises(MODULE.IcpQueryError):
                engine.query_page("web", "example.test")
        query_once.assert_called_once()

    def test_query_all_pages_merges_pages_until_total_is_reached(self):
        engine, _session = self._engine([])
        pages = [
            {"records": [{"domain": "one.example.test"}], "total": 2, "page": 1, "page_size": 1},
            {"records": [{"domain": "two.example.test"}], "total": 2, "page": 2, "page_size": 1},
        ]
        with patch.object(engine, "query_page", side_effect=pages) as query_page:
            result = engine.query_all_pages("web", "example.test")

        self.assertEqual(2, len(result["records"]))
        self.assertEqual(2, result["page_count"])
        self.assertEqual(2, query_page.call_count)

    def test_ensure_indexes_creates_ttl_and_pagination_indexes(self):
        collections = {name: MagicMock() for name in (
            "task", "history", "result", "log",
        )}
        old_ready = MODULE._INDEXES_READY
        MODULE._INDEXES_READY = False
        try:
            with patch.object(MODULE, "_task_collection", return_value=collections["task"]), \
                    patch.object(MODULE, "_history_collection", return_value=collections["history"]), \
                    patch.object(MODULE, "_result_collection", return_value=collections["result"]), \
                    patch.object(MODULE, "_log_collection", return_value=collections["log"]):
                MODULE.ensure_indexes()
        finally:
            MODULE._INDEXES_READY = old_ready

        collections["task"].create_index.assert_any_call("task_id", unique=True)
        collections["task"].create_index.assert_any_call("expires_at", expireAfterSeconds=0)
        collections["history"].create_index.assert_any_call("expires_at", expireAfterSeconds=0)
        collections["result"].create_index.assert_any_call([("history_id", 1), ("page", 1), ("order", 1)])
        collections["result"].create_index.assert_any_call("expires_at", expireAfterSeconds=0)
        collections["log"].create_index.assert_any_call("expires_at", expireAfterSeconds=0)

    def test_query_all_pages_stops_before_next_page_when_cancelled(self):
        engine, _session = self._engine([])
        pages = [
            {
                "records": [{"domain": "example.com"}],
                "total": 2,
                "page": 1,
                "page_size": 1,
            },
        ]
        with patch.object(engine, "query_page", side_effect=pages) as query_page:
            cancel_states = iter([False, True])

            with self.assertRaises(MODULE.IcpTaskCancelled):
                engine.query_all_pages("web", "example.com", cancel_check=lambda: next(cancel_states))

        self.assertEqual(1, query_page.call_count)

    def test_app_query_reuses_query_auth_for_detail_lookup(self):
        engine, session = self._engine([
            FakeResponse({
                "code": 200,
                "success": True,
                "params": {
                    "total": 1,
                    "list": [{"appName": "测试应用", "dataId": "detail-1"}],
                },
            }),
            FakeResponse({
                "code": 200,
                "success": True,
                "params": {"appName": "测试应用", "licenseNo": "京ICP备456号"},
            }),
        ])

        result = engine.query_page("app", "测试应用")

        self.assertEqual("京ICP备456号", result["records"][0]["license_number"])
        self.assertEqual(2, len(session.calls))
        self.assertIn("queryByCondition", session.calls[0][1])
        self.assertIn("queryDetailByAppAndMiniId", session.calls[1][1])

    def test_invalid_query_target_is_rejected(self):
        engine, session = self._engine([])

        with self.assertRaises(MODULE.IcpQueryError) as context:
            engine._request(session, "GET", "https://example.com/anything")

        self.assertEqual("policy_error", context.exception.category)

    def test_official_request_keeps_tls_validation_and_disables_redirects(self):
        engine, session = self._engine([FakeResponse({"code": 200, "success": True})])

        engine._request(session, "GET", MODULE.ICP_HOME_URL)

        request_options = session.calls[0][2]
        self.assertIs(request_options["verify"], True)
        self.assertIs(request_options["allow_redirects"], False)

    def test_tls_verification_can_be_disabled_for_icp_session_only(self):
        with patch.object(MODULE.Config, "ICP_QUERY_TLS_VERIFY", False):
            engine, session = self._engine([FakeResponse({"code": 200, "success": True})])
            engine._request(session, "GET", MODULE.ICP_HOME_URL)

        self.assertIs(session.calls[0][2]["verify"], False)

    def test_keyword_validation_rejects_control_characters(self):
        with self.assertRaises(MODULE.IcpQueryError) as context:
            MODULE._validate_keyword("example.com\x00")

        self.assertEqual("validation_error", context.exception.category)

    def test_keyword_validation_rejects_non_text_values(self):
        with self.assertRaises(MODULE.IcpQueryError) as context:
            MODULE._validate_keyword({"keyword": "example.com"})

        self.assertEqual("validation_error", context.exception.category)

    def test_history_date_filter_uses_utc_day_bounds(self):
        start = MODULE._parse_history_time("2026-09-08")
        end = MODULE._parse_history_time("2026-09-08", end=True)

        self.assertEqual("2026-09-08T00:00:00+00:00", start.isoformat())
        self.assertEqual("2026-09-09T00:00:00+00:00", end.isoformat())

    def test_timeout_is_classified_as_retryable(self):
        engine, session = self._engine([MODULE.requests.exceptions.Timeout()])

        with self.assertRaises(MODULE.IcpQueryError) as context:
            engine._request(session, "GET", MODULE.ICP_HOME_URL)

        self.assertEqual("timeout", context.exception.category)
        self.assertTrue(context.exception.retryable)

    def test_transport_errors_are_classified_without_exposing_exception_details(self):
        cases = (
            (MODULE.requests.exceptions.ProxyError("synthetic proxy failure"), "代理连接失败"),
            (MODULE.requests.exceptions.SSLError("certificate verify failed"), "TLS 证书校验失败"),
            (MODULE.requests.exceptions.ConnectionError("name resolution failed"), "无法连接官方接口"),
        )
        for exception, expected in cases:
            with self.subTest(expected=expected):
                session = FakeSession([exception])
                engine = MODULE.IcpQueryEngine(session_factory=lambda: session)
                prepared_session = engine._session()

                with self.assertRaises(MODULE.IcpQueryError) as context:
                    engine._request(prepared_session, "GET", MODULE.ICP_HOME_URL)

                self.assertEqual("network_error", context.exception.category)
                self.assertIn(expected, str(context.exception))
                self.assertNotIn("synthetic", str(context.exception))

    def test_rate_limit_is_classified_as_retryable(self):
        engine, session = self._engine([FakeResponse({}, status_code=429)])

        with self.assertRaises(MODULE.IcpQueryError) as context:
            engine._request(session, "GET", MODULE.ICP_HOME_URL)

        self.assertEqual("rate_limited", context.exception.category)
        self.assertTrue(context.exception.retryable)

    def test_log_date_filter_uses_exclusive_end_day(self):
        collection = FakeLogCollection()
        with patch.object(MODULE.utils, "conn_db", return_value=collection):
            result = MODULE.list_logs(
                level="ERROR",
                created_from="2026-09-08",
                created_to="2026-09-08",
            )

        self.assertEqual(0, result["total"])
        self.assertEqual("ERROR", collection.query["level"])
        self.assertEqual(
            "2026-09-08T00:00:00+00:00",
            collection.query["created_at"]["$gte"].isoformat(),
        )
        self.assertEqual(
            "2026-09-09T00:00:00+00:00",
            collection.query["created_at"]["$lt"].isoformat(),
        )


class TestIcpPersistenceCleanup(unittest.TestCase):
    def test_delete_task_cleans_histories_written_before_item_link(self):
        task_collection = MagicMock()
        task_collection.find_one.return_value = {
            "task_id": "task-1",
            "status": "succeeded",
            "items": [{"history_id": "linked-history"}, {"history_id": ""}],
        }
        task_collection.delete_one.return_value = SimpleNamespace(deleted_count=1)

        history_collection = MagicMock()
        history_collection.find.return_value = [
            {"history_id": "linked-history"},
            {"history_id": "orphan-history"},
        ]
        history_collection.delete_many.return_value = SimpleNamespace(deleted_count=2)

        result_collection = MagicMock()
        result_collection.delete_many.return_value = SimpleNamespace(deleted_count=3)

        with patch.object(MODULE, "_task_collection", return_value=task_collection), \
                patch.object(MODULE, "_history_collection", return_value=history_collection), \
                patch.object(MODULE, "_result_collection", return_value=result_collection), \
                patch.object(MODULE, "_write_log"):
            deleted = MODULE.delete_task("task-1")

        self.assertTrue(deleted)
        history_collection.find.assert_called_once_with({"task_id": "task-1"}, {"history_id": 1})
        result_collection.delete_many.assert_called_once_with(
            {"history_id": {"$in": ["linked-history", "orphan-history"]}}
        )
        history_collection.delete_many.assert_called_once_with(
            {"history_id": {"$in": ["linked-history", "orphan-history"]}}
        )
        task_collection.delete_one.assert_called_once_with({"task_id": "task-1"})

    def test_clear_history_removes_all_results_and_resets_all_item_links(self):
        task_collection = MagicMock()
        task_collection.update_many.return_value = SimpleNamespace(modified_count=2)
        history_collection = MagicMock()
        history_collection.delete_many.return_value = SimpleNamespace(deleted_count=4)
        result_collection = MagicMock()
        result_collection.delete_many.return_value = SimpleNamespace(deleted_count=6)

        with patch.object(MODULE, "_task_collection", return_value=task_collection), \
                patch.object(MODULE, "_history_collection", return_value=history_collection), \
                patch.object(MODULE, "_result_collection", return_value=result_collection):
            deleted = MODULE.clear_history()

        self.assertEqual(4, deleted)
        result_collection.delete_many.assert_called_once_with({})
        task_collection.update_many.assert_called_once_with(
            {"items.history_id": {"$exists": True}},
            {
                "$set": {
                    "items.$[item].history_id": "",
                    "items.$[item].result_count": 0,
                }
            },
            array_filters=[{"item.history_id": {"$exists": True, "$ne": ""}}],
        )
        history_collection.delete_many.assert_called_once_with({})

    def test_json_export_joins_results_and_omits_internal_or_sensitive_fields(self):
        history_collection = MagicMock()
        history_collection.find.return_value.sort.return_value.limit.return_value = [
            {
                "_id": "history-internal",
                "history_id": "history-1",
                "query_type": "web",
                "keyword": "example.test",
                "status": "succeeded",
                "created_at": MODULE._utc_now(),
            },
        ]
        result_collection = MagicMock()
        result_collection.find.return_value.sort.return_value = [
            {
                "_id": "result-internal",
                "history_id": "history-1",
                "domain": "example.test",
                "token": "must-not-export",
            },
        ]
        response = SimpleNamespace(headers={})

        with patch.object(MODULE, "_history_collection", return_value=history_collection), \
                patch.object(MODULE, "_result_collection", return_value=result_collection), \
                patch.object(MODULE, "make_response", return_value=response) as make_response:
            result = MODULE.export_history("json")

        self.assertIs(response, result)
        body = make_response.call_args.args[0].decode("utf-8")
        self.assertIn('"history_id": "history-1"', body)
        self.assertIn('"domain": "example.test"', body)
        self.assertNotIn("history-internal", body)
        self.assertNotIn("result-internal", body)
        self.assertNotIn("must-not-export", body)


class TestIcpTaskLifecycle(unittest.TestCase):
    def test_recount_marks_mixed_terminal_items_as_partial(self):
        task = {
            "task_id": "task-partial",
            "status": "running",
            "cancel_requested": False,
            "items": [
                {"status": "succeeded"},
                {"status": "failed"},
            ],
        }
        collection = MagicMock()
        collection.find_one.side_effect = [task, task]

        with patch.object(MODULE, "_task_collection", return_value=collection):
            result = MODULE._recount_task("task-partial")

        self.assertIs(task, result)
        update = collection.update_one.call_args[0][1]["$set"]
        self.assertEqual("partial", update["status"])
        self.assertEqual(1, update["succeeded_count"])
        self.assertEqual(1, update["failed_count"])
        self.assertEqual(0, update["queued_count"])

    def test_recount_marks_cancelled_task_when_cancelled_items_are_terminal(self):
        task = {
            "task_id": "task-cancelled",
            "status": "running",
            "cancel_requested": True,
            "items": [{"status": "cancelled"}],
        }
        collection = MagicMock()
        collection.find_one.side_effect = [task, task]

        with patch.object(MODULE, "_task_collection", return_value=collection):
            MODULE._recount_task("task-cancelled")

        update = collection.update_one.call_args[0][1]["$set"]
        self.assertEqual("cancelled", update["status"])
        self.assertEqual(1, update["cancelled_count"])

    def test_execute_task_item_persists_successful_result_and_history_link(self):
        collection = MagicMock()
        collection.update_one.return_value = SimpleNamespace(modified_count=1)
        engine = MagicMock()
        engine.query_page.return_value = {
            "records": [{"domain": "example.test"}],
            "total": 1,
            "page": 1,
            "page_size": 26,
        }
        item = {"item_id": "item-1", "keyword": "example.test", "status": "queued"}

        with patch.object(MODULE, "get_task", return_value={"cancel_requested": False}), \
                patch.object(MODULE, "_task_collection", return_value=collection), \
                patch.object(MODULE, "IcpQueryEngine", return_value=engine), \
                patch.object(MODULE, "_save_history", return_value={"history_id": "history-1"}) as save_history, \
                patch.object(MODULE, "_update_item") as update_item, \
                patch.object(MODULE, "_recount_task") as recount_task:
            MODULE._execute_task_item(
                "task-1", "single", "web", 1, 26, item,
            )

        engine.query_page.assert_called_once_with("web", "example.test", 1, 26)
        save_history.assert_called_once()
        update_item.assert_called_once_with(
            "task-1",
            "item-1",
            "succeeded",
            history_id="history-1",
            result_count=1,
        )
        recount_task.assert_called_once_with("task-1")

    def test_execute_task_item_marks_cancelled_before_network_request(self):
        item = {"item_id": "item-1", "keyword": "example.test", "status": "queued"}
        with patch.object(MODULE, "get_task", return_value={"cancel_requested": True}), \
                patch.object(MODULE, "_update_item") as update_item, \
                patch.object(MODULE, "_recount_task") as recount_task, \
                patch.object(MODULE, "IcpQueryEngine") as engine:
            MODULE._execute_task_item(
                "task-1", "single", "web", 1, 26, item,
            )

        update_item.assert_called_once_with("task-1", "item-1", "cancelled")
        recount_task.assert_called_once_with("task-1")
        engine.assert_not_called()

    def test_execute_task_dispatches_all_batch_items(self):
        task = {
            "task_id": "task-batch",
            "task_kind": "batch",
            "query_type": "web",
            "status": "queued",
            "items": [
                {"item_id": "item-1", "keyword": "one.test", "status": "queued"},
                {"item_id": "item-2", "keyword": "two.test", "status": "queued"},
            ],
        }
        collection = MagicMock()
        collection.update_one.return_value = SimpleNamespace(modified_count=1)

        with patch.object(MODULE, "get_task", side_effect=[task, task]), \
                patch.object(MODULE, "_task_collection", return_value=collection), \
                patch.object(MODULE, "_execute_task_item") as execute_item, \
                patch.object(MODULE, "_recount_task", return_value=task):
            result = MODULE.execute_task("task-batch")

        self.assertIs(task, result)
        self.assertEqual(2, execute_item.call_count)
        dispatched = {
            call.args[5]["item_id"] for call in execute_item.call_args_list
        }
        self.assertEqual({"item-1", "item-2"}, dispatched)


if __name__ == "__main__":
    unittest.main()
