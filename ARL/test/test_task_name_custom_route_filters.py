"""Regression tests for task-name filters handled by custom result routes."""

import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR / "ARL-NPoC"))

IMPORT_ERROR = None
try:
    from flask import Flask
    from bson import ObjectId
    from app.routes import cert as cert_module
    from app.routes import nuclei_result as nuclei_result_module
    from app.routes import service as service_module
    from app.routes import waf_host as waf_host_module
except ModuleNotFoundError as exc:
    Flask = None
    ObjectId = None
    cert_module = None
    nuclei_result_module = None
    service_module = None
    waf_host_module = None
    IMPORT_ERROR = exc


class _Cursor(object):
    def __init__(self, items):
        self.items = list(items)

    def sort(self, _order):
        return self

    def __iter__(self):
        return iter(self.items)


class _Collection(object):
    def __init__(self, items=None, aggregate_items=None):
        self.items = list(items or [])
        self.aggregate_items = list(aggregate_items or [])
        self.find_calls = []

    def find(self, query, projection=None):
        self.find_calls.append((query, projection))
        return _Cursor(self.items)

    def aggregate(self, _pipeline, **_kwargs):
        return list(self.aggregate_items)


@unittest.skipIf(
    Flask is None or ObjectId is None or any(
        module is None
        for module in (cert_module, nuclei_result_module, service_module, waf_host_module)
    ),
    "自定义结果路由导入失败：{}".format(IMPORT_ERROR),
)
class TaskNameCustomRouteFilterTest(unittest.TestCase):
    def _call_get(self, resource_class, path, query, prepare=None):
        app = Flask(__name__)
        resource = resource_class()
        if prepare:
            prepare(resource)
        with app.test_request_context(path, query_string=query):
            return resource_class.get.__wrapped__(resource), resource

    def test_cert_route_resolves_task_name_before_aggregation(self):
        task_ids = ["task-a", "task-b"]
        captured = {}

        def prepare(resource):
            def build_data(args):
                captured["args"] = args
                return {"args": args, "collection": "cert"}

            resource._build_data_prefer_domain_cert = build_data

        with patch.object(cert_module, "get_task_ids_by_name", return_value=task_ids):
            response, _resource = self._call_get(
                cert_module.ARLCert,
                "/cert/",
                {"task_name": "weekly scan", "page": "2", "size": "5"},
                prepare=prepare,
            )

        self.assertEqual("task-a,task-b", captured["args"]["task_id"])
        self.assertNotIn("task_name", captured["args"])
        self.assertEqual("cert", response["collection"])

    def test_cert_route_returns_empty_without_querying_all_certificates(self):
        with patch.object(cert_module, "get_task_ids_by_name", return_value=[]):
            with patch.object(cert_module.ARLCert, "_build_data_prefer_domain_cert") as query:
                response, _resource = self._call_get(
                    cert_module.ARLCert,
                    "/cert/",
                    {"task_name": "missing task"},
                )

        self.assertEqual(0, response["total"])
        self.assertEqual([], response["items"])
        query.assert_not_called()

    def test_service_route_resolves_task_name_for_primary_collection(self):
        task_ids = ["task-a", "task-b"]

        def prepare(resource):
            resource.build_data = lambda args, collection: {
                "args": args,
                "collection": collection,
            }

        with patch.object(service_module, "get_task_ids_by_name", return_value=task_ids):
            with patch.object(service_module, "_service_collection_has_records", return_value=True):
                response, _resource = self._call_get(
                    service_module.ARLService,
                    "/service/",
                    {"task_name": "weekly scan"},
                    prepare=prepare,
                )

        self.assertEqual("task-a,task-b", response["args"]["task_id"])
        self.assertNotIn("task_name", response["args"])
        self.assertEqual("service", response["collection"])

    def test_service_route_returns_empty_when_task_name_has_no_matches(self):
        with patch.object(service_module, "get_task_ids_by_name", return_value=[]):
            with patch.object(service_module, "_service_collection_has_records") as has_records:
                response, _resource = self._call_get(
                    service_module.ARLService,
                    "/service/",
                    {"task_name": "missing task"},
                )

        self.assertEqual(0, response["total"])
        self.assertEqual([], response["items"])
        has_records.assert_not_called()

    def test_nuclei_route_resolves_task_name_before_building_pipeline(self):
        task_ids = ["task-a", "task-b"]
        collection = _Collection(aggregate_items=[{"total": 3}])
        query_info = {"include_nuclei": True, "include_afrog": False}
        with patch.object(nuclei_result_module, "get_task_ids_by_name", return_value=task_ids):
            with patch.object(
                nuclei_result_module,
                "_build_collection_queries",
                return_value=query_info,
            ) as build_queries:
                with patch.object(
                    nuclei_result_module,
                    "_build_poc_scan_pipeline",
                    return_value=("nuclei_result", []),
                ):
                    with patch.object(
                        nuclei_result_module.utils,
                        "conn_db",
                        return_value=collection,
                    ):
                        with patch.object(
                            nuclei_result_module,
                            "_format_poc_result_items",
                            return_value=[],
                        ):
                            response, _resource = self._call_get(
                                nuclei_result_module.ARLUrl,
                                "/nuclei_result/",
                                {"task_name": "weekly scan"},
                            )

        query_args = build_queries.call_args.args[0]
        self.assertEqual("task-a,task-b", query_args["task_id"])
        self.assertNotIn("task_name", query_args)
        self.assertEqual(3, response["total"])

    def test_nuclei_route_returns_empty_without_aggregating_for_unknown_name(self):
        with patch.object(nuclei_result_module, "get_task_ids_by_name", return_value=[]):
            with patch.object(nuclei_result_module.utils, "conn_db") as conn_db:
                response, _resource = self._call_get(
                    nuclei_result_module.ARLUrl,
                    "/nuclei_result/",
                    {"task_name": "missing task"},
                )

        self.assertEqual(0, response["total"])
        self.assertEqual([], response["items"])
        conn_db.assert_not_called()

    def test_waf_host_route_filters_task_documents_by_exact_name(self):
        task_id = ObjectId()
        task = {
            "_id": task_id,
            "waf_skip_summary": {
                "detected_hosts": [{"host": "203.0.113.7", "last_url": "http://203.0.113.7"}],
            },
        }
        collection = _Collection([task])
        with patch.object(waf_host_module.utils, "conn_db", return_value=collection):
            response, _resource = self._call_get(
                waf_host_module.ARLWafHost,
                "/waf_host/",
                {"task_name": "weekly scan"},
            )

        self.assertEqual("weekly scan", collection.find_calls[0][0]["name"])
        self.assertEqual(1, response["total"])
        self.assertEqual(str(task_id), response["items"][0]["task_id"])

    def test_waf_host_route_keeps_unknown_name_scoped_to_empty_result(self):
        collection = _Collection()
        with patch.object(waf_host_module.utils, "conn_db", return_value=collection):
            response, _resource = self._call_get(
                waf_host_module.ARLWafHost,
                "/waf_host/",
                {"task_name": "missing task"},
            )

        self.assertEqual("missing task", collection.find_calls[0][0]["name"])
        self.assertEqual(0, response["total"])
        self.assertEqual([], response["items"])


if __name__ == "__main__":
    unittest.main()
