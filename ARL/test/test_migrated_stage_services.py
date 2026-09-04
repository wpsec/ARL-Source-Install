"""迁移后 stage service 的等价性与隔离回归。

覆盖 IPCertStageService、IPServiceSummaryStageService、WihResultPersistService、
WebSiteNucleiScanStageService/WebSiteAfrogScanStageService 的关键边界。
"""

import unittest
from types import SimpleNamespace

try:
    from app.services.ip_cert_service_stage_services import (
        IPCertStageService,
        IPServiceSummaryStageService,
    )
    from app.services.wih_result_persist_services import WihResultPersistService
    from app.services.web_site_poc_stage_services import (
        WebSiteNucleiScanStageService,
        WebSiteAfrogScanStageService,
    )
except Exception:
    IPCertStageService = None


@unittest.skipIf(IPCertStageService is None, "运行依赖未安装")
class TestIPCertStageService(unittest.TestCase):
    class _FakeFetchCert(object):
        @staticmethod
        def split_host_port(endpoint):
            host, _, port = str(endpoint).rpartition(":")
            try:
                return host, int(port)
            except ValueError:
                return "", 0

        @staticmethod
        def normalize_domains(values):
            out = []
            for value in list(values or []):
                text = str(value or "").strip().lower()
                if text and text not in out:
                    out.append(text)
            return out

        @staticmethod
        def match_cert_domains(cert_data, domains):
            return [domain for domain in list(domains or []) if domain in (cert_data.get("subject_cn") or "")]

    class _FakeDB(object):
        def __init__(self):
            self.upserts = []

        def update_one(self, query, update, upsert=False):
            self.upserts.append((query, update, upsert))

    class _FakeUtils(object):
        def __init__(self):
            self.cert_db = TestIPCertStageService._FakeDB()

        def conn_db(self, name):
            return self.cert_db

    def _meta(self, endpoint, mode, sni="", domains=None, observe=""):
        return {
            "_scan_meta": {
                "endpoint": endpoint,
                "scan_mode": mode,
                "sni_domain": sni,
                "domains": domains or [],
                "observe_id": observe,
            }
        }

    def setUp(self):
        # 用可记录的 utils 简化断言
        class _RecordingDB(object):
            def __init__(self, sink):
                self.sink = sink

            def update_one(self, query, update, upsert=False):
                self.sink.append((query, update, upsert))

        class _RecordingUtils(object):
            def __init__(self):
                self.sink = []

            def conn_db(self, name):
                return _RecordingDB(self.sink)

        self.recording_utils = _RecordingUtils()

    def test_sni_and_default_dedup_via_recording_utils(self):
        cert_map = {
            "sni-1": dict(
                self._meta("1.2.3.4:443", "sni", sni="a.example.com", domains=["a.example.com"]),
                subject_cn="a.example.com",
                fingerprint={"sha256": "AA:BB"},
                validity={"end": "2027-01-01"},
            ),
            "default-1": dict(
                self._meta("1.2.3.4:443", "default", domains=["a.example.com"]),
                subject_cn="placeholder",
            ),
        }
        task = SimpleNamespace(options={}, ip_set=set(), ip_info_list=[], cert_map={}, task_id="t-1")
        service = IPCertStageService(
            task,
            fetchcert_module=self._FakeFetchCert(),
            utils_module=self.recording_utils,
            cert_fetcher=lambda targets: cert_map,
        )

        service.run()

        saved = self.recording_utils.sink
        modes = [query.get("scan_mode") for query, _update, _up in saved]
        self.assertEqual(["sni"], modes)


@unittest.skipIf(IPCertStageService is None, "运行依赖未安装")
class TestIPServiceSummaryStageService(unittest.TestCase):
    class _FakeDB(object):
        def __init__(self, find_items=None):
            self.find_items = find_items or []
            self.ops = []

        def find(self, query):
            self.ops.append(("find", query))
            return iter(self.find_items)

        def delete_many(self, query):
            self.ops.append(("delete_many", query))

        def insert_many(self, items):
            self.ops.append(("insert_many", items))

    class _FakeUtils(object):
        def __init__(self, npoc_items):
            self.npoc_db = TestIPServiceSummaryStageService._FakeDB(npoc_items)
            self.service_db = TestIPServiceSummaryStageService._FakeDB()

        def conn_db(self, name):
            if name == "npoc_service":
                return self.npoc_db
            return self.service_db

    def test_merge_dedup_and_product_fallback(self):
        task = SimpleNamespace(
            task_id="t-1",
            ip_info_list=[
                {
                    "ip": "1.1.1.1",
                    "port_info": [
                        {"port_id": 80, "service_name": "http", "product": "", "version": ""},
                        {"port_id": 80, "service_name": "http", "product": "nginx", "version": "1.0"},
                        {"port_id": 443, "service_name": "ssl/http", "product": "", "version": ""},
                    ],
                }
            ],
            service_info_list=None,
            _normalize_scheme=staticmethod(lambda value: {"ssl/http": "https"}.get(str(value), str(value))),
            _extract_detected_service=staticmethod(
                lambda service_name, product="": str(service_name or "").strip().lower()
            ),
        )
        utils = self._FakeUtils(
            npoc_items=[{"host": "2.2.2.2", "port": 8080, "scheme": "http", "version": ""}],
        )

        IPServiceSummaryStageService(task, utils_module=utils).run()

        by_service = {item["service_name"]: item["service_info"] for item in task.service_info_list}
        http_items = by_service["http"]
        # 1.1.1.1:80 两条 http 记录按 (service, ip, port) 去重，先进带 product 为空的回退值
        self.assertIn({"ip": "1.1.1.1", "port_id": 80, "product": "http", "version": ""}, http_items)
        self.assertEqual(1, len([i for i in http_items if i["ip"] == "1.1.1.1" and i["port_id"] == 80]))
        # npoc 兜底来源并入
        self.assertIn({"ip": "2.2.2.2", "port_id": 8080, "product": "http", "version": ""}, http_items)
        # ssl/http 归一为 https
        self.assertIn("https", by_service)
        ops = [op[0] for op in utils.service_db.ops]
        self.assertEqual(["delete_many", "insert_many"], ops)
        deleted_query = utils.service_db.ops[0][1]
        self.assertEqual({"task_id": "t-1"}, deleted_query)


@unittest.skipIf(IPCertStageService is None, "运行依赖未安装")
class TestWihResultPersistService(unittest.TestCase):
    class _ItemService(object):
        def build_wih_record_document(self, record):
            return {"fnv_hash": getattr(record, "fnv_hash", None), "record_type": record.recordType}

        def build_wih_endpoint_document(self, raw):
            return {"fnv_hash": raw.get("fnv_hash")}

        def build_wih_vuln_document(self, **kwargs):
            record = kwargs["record"]
            if not kwargs["should_promote"](record):
                return None
            return {"wih_fnv_hash": record.fnv_hash}

    class _Writer(object):
        def __init__(self):
            self.ops = []

        def replace_one(self, coll, query, doc, upsert=False):
            self.ops.append(("replace", coll, query.get("fnv_hash")))

        def update_one(self, coll, query, doc, upsert=False):
            self.ops.append(("update", coll, query.get("wih_fnv_hash")))

    def _task(self):
        return SimpleNamespace(
            task_id="t-1",
            scope_domain=["example.com"],
            wih_domain_set=set(),
            wih_record_set=set(),
            _url_in_task_scope=lambda value: True,
            _host_in_task_scope=lambda value: True,
            _result_item_service=self._ItemService(),
            _result_writer=self._Writer(),
        )

    class _FakeUtils(object):
        def check_domain_black(self, value):
            return value.startswith("black.")

    def test_add_domain_set_scope_and_blacklist(self):
        task = self._task()
        service = WihResultPersistService(task, utils_module=self._FakeUtils())
        service.add_domain_set(SimpleNamespace(recordType="domain", content="api.example.com"))
        service.add_domain_set(SimpleNamespace(recordType="domain", content="black.example.com"))
        service.add_domain_set(SimpleNamespace(recordType="urlfinder_url", content="https://x.example.com/a"))
        self.assertEqual({"api.example.com"}, task.wih_domain_set)

    def test_save_record_requires_fnv_and_promotes_sensitive(self):
        task = self._task()
        service = WihResultPersistService(task, utils_module=self._FakeUtils())
        record = SimpleNamespace(recordType="private_key", content="-----BEGIN RSA", source="", site="", fnv_hash=123)

        service.save_record(record)

        ops = task._result_writer.ops
        self.assertIn(("replace", "wih", 123), ops)
        self.assertIn(("update", "vuln", 123), ops)
        self.assertIn(123, task.wih_record_set)

    def test_apply_reused_records_dedups(self):
        task = self._task()
        # 注入恒等 normalize，聚焦去重/风险链本身；真实 normalize 语义由 infoHunter 测试覆盖。
        fake_infohunter = SimpleNamespace(
            normalize_wih_record=lambda record: record,
            _is_secret_like_record_type=lambda t: False,
            _should_keep_secret_content=lambda *args, **kwargs: True,
        )
        service = WihResultPersistService(
            task, infohunter_module=fake_infohunter, utils_module=self._FakeUtils()
        )
        record = SimpleNamespace(recordType="token", content="abc", source="", site="", fnv_hash=9)
        task.wih_record_set.add(9)

        applied = service.apply_reused_records([record])

        self.assertEqual(0, applied)

        fresh = SimpleNamespace(recordType="token", content="xyz", source="", site="", fnv_hash=10)
        self.assertEqual(1, service.apply_reused_records([fresh]))
        self.assertIn(10, task.wih_record_set)


@unittest.skipIf(IPCertStageService is None, "运行依赖未安装")
class TestPoCStageDelegation(unittest.TestCase):
    def test_nuclei_service_run_uses_injected_scan(self):
        calls = {}

        def fake_nuclei_scan(targets, scan_profile=None):
            calls["targets"] = targets
            calls["profile"] = scan_profile
            return [{"vuln_url": "https://a.example.com/x", "matcher_name": "m"}]

        task = SimpleNamespace(
            task_id="t-1",
            poc_sites=["https://a.example.com"],
            NUCLEI_TARGET_BUILD_RETRY_COUNT=1,
            NUCLEI_TARGET_BUILD_RETRY_SLEEP_SEC=1,
            RETRYABLE_MONGO_ERRORS=(RuntimeError,),
            _scan_result_in_task_scope=lambda item, target_keys=None: True,
            _result_item_service=SimpleNamespace(build_nuclei_document=lambda item: {"doc": item}),
            _result_writer=SimpleNamespace(insert_one=lambda *args: None),
            _nuclei_deferred_retry_needed=False,
            _nuclei_final_skip=False,
        )

        class _FakeDB(object):
            def find(self, query, fields, max_time_ms=None):
                return iter([{"site": "https://a.example.com", "finger": [{"name": "Tomcat"}], "http_server": "", "title": ""}])

        service = WebSiteNucleiScanStageService(
            task,
            utils_module=SimpleNamespace(conn_db=lambda name: _FakeDB()),
            scanner_factory=fake_nuclei_scan,
        )
        results = service.run()

        self.assertEqual(1, len(results))
        self.assertIsNone(calls["profile"])
        self.assertEqual(1, len(calls["targets"]))
        self.assertEqual(["tomcat"], calls["targets"][0]["finger"])

    def test_afrog_service_runs_with_default_params(self):
        saved = []

        def fake_afrog(targets, search_keywords=None, severity=None):
            saved.append((list(targets), search_keywords, severity))
            return [{"target": "https://a.example.com", "poc_id": "p1"}]

        task = SimpleNamespace(
            task_id="t-1",
            poc_sites={"https://a.example.com"},
            smart_skip_waf=False,
            _filter_waf_blocked_targets=lambda targets, stage_name="": list(targets),
            _scan_result_in_task_scope=lambda item, target_keys=None: True,
            _result_item_service=SimpleNamespace(build_afrog_document=lambda r, t, p: {"doc": p}),
            _result_writer=SimpleNamespace(insert_one=lambda *args: saved.append(("insert", args))),
        )

        WebSiteAfrogScanStageService(task, afrog_runner=fake_afrog).run()

        self.assertIsNone(saved[0][1])
        self.assertIsNone(saved[0][2])


if __name__ == "__main__":
    unittest.main()
