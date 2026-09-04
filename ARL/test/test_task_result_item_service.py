"""任务结果文档组装服务回归测试。"""

import unittest
from types import SimpleNamespace

from app.services.task_result_item_service import TaskResultItemService


class _Record(object):
    recordType = "api_key"
    content = "real-value"
    source = "https://example.com/app.js"
    site = "https://example.com"
    fnv_hash = "hash-1"

    def dump_json(self):
        return {
            "recordType": self.recordType,
            "content": self.content,
            "source": self.source,
            "site": self.site,
            "fnv_hash": self.fnv_hash,
        }


class TestTaskResultItemService(unittest.TestCase):
    def _service(self):
        return TaskResultItemService("task-1", curr_date=lambda: "now")

    def test_external_result_documents_keep_legacy_fields(self):
        service = self._service()
        afrog = service.build_afrog_document(
            {"vuln_name": "demo", "severity": "high", "verify_data": "{}"},
            "https://example.com",
            "poc-1",
        )
        self.assertEqual("afrog:poc-1", afrog["plg_name"])
        self.assertEqual("task-1", afrog["task_id"])
        self.assertEqual("now", afrog["save_date"])

    def test_wih_risk_builder_preserves_scope_and_hash_fields(self):
        service = self._service()
        item = service.build_wih_vuln_document(
            _Record(),
            should_promote=lambda _record: True,
            record_in_scope=lambda _record: True,
            is_http_url=lambda value: str(value).startswith("http"),
            url_in_scope=lambda _value: True,
            infer_severity=lambda _type, _content: "medium",
        )
        self.assertEqual("hash-1", item["wih_fnv_hash"])
        self.assertEqual("api_key", item["wih_record_type"])
        self.assertEqual("medium", item["severity"])

    def test_wih_endpoint_fallback_hash_is_stable_for_idempotency(self):
        """无 fnv_hash 的接口回退串必须稳定，保证 replace_one(task_id, fnv_hash) 幂等。"""
        service = self._service()
        raw = {"target": "t", "page_url": "p", "method": "GET", "url": "u"}

        first = service.build_wih_endpoint_document(dict(raw))
        second = service.build_wih_endpoint_document(dict(raw))

        self.assertEqual(first["fnv_hash"], second["fnv_hash"])
        self.assertEqual("t|p|GET|u", first["fnv_hash"])
        self.assertEqual("task-1", first["task_id"])
        self.assertEqual("now", first["save_date"])

        given = service.build_wih_endpoint_document({"fnv_hash": 42, "url": "u"})
        self.assertEqual("42", given["fnv_hash"])

    def test_invalid_result_does_not_create_document(self):
        service = self._service()
        self.assertEqual({}, service.build_fileleak_document(None, {}))
        self.assertEqual({}, service.build_nuclei_document(None))


if __name__ == "__main__":
    unittest.main()
