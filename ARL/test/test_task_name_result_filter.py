import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch

from bson import ObjectId


def _load_collection_query_service():
    module_name = "collection_query_service_task_name_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    service_path = pathlib.Path(__file__).resolve().parents[1] / "app/services/collection_query_service.py"
    spec = importlib.util.spec_from_file_location(module_name, service_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


collection_query_service = _load_collection_query_service()


class _Cursor(object):
    def sort(self, _order):
        return self

    def skip(self, _offset):
        return self

    def limit(self, _size):
        return self

    def __iter__(self):
        return iter([])


class _Collection(object):
    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.find_calls = []
        self.count_calls = []

    def find(self, query, projection=None):
        self.find_calls.append((query, projection))
        return list(self.rows) if projection else _Cursor()

    def count_documents(self, query):
        self.count_calls.append(query)
        return 0


class TaskNameResultFilterTest(unittest.TestCase):
    def _query_result(self, collection_name, task_rows):
        task_collection = _Collection(task_rows)
        result_collection = _Collection()

        def get_collection(name):
            return task_collection if name == "task" else result_collection

        with patch.object(collection_query_service, "conn", side_effect=get_collection), \
                patch.object(
                    collection_query_service,
                    "cached_call",
                    side_effect=lambda _key, loader, **_kwargs: loader(),
                ):
            result = collection_query_service.build_collection_data(
                args={"page": 1, "size": 10, "task_name": "weekly scan"},
                collection=collection_name,
                item_builder=list,
                query_serializer=lambda query: query,
            )

        return result, task_collection, result_collection

    def test_task_name_resolves_exactly_to_result_task_ids(self):
        task_ids = [ObjectId(), ObjectId()]
        result, task_collection, result_collection = self._query_result(
            "site",
            [{"_id": task_id} for task_id in task_ids],
        )

        self.assertEqual(task_collection.find_calls[0][0], {"name": "weekly scan"})
        self.assertEqual(result_collection.find_calls[0][0], {
            "task_id": {"$in": [str(task_id) for task_id in task_ids]},
        })
        self.assertEqual(result["total"], 0)

    def test_unmatched_task_name_keeps_results_empty(self):
        result, _task_collection, result_collection = self._query_result("site", [])

        self.assertEqual(result_collection.find_calls[0][0], {"task_id": {"$in": []}})
        self.assertEqual(result["total"], 0)

    def test_task_collection_uses_exact_task_name(self):
        result, task_collection, _result_collection = self._query_result("task", [])

        self.assertEqual(task_collection.find_calls[0][0], {"name": "weekly scan"})
        self.assertEqual(result["query"], {"name": "weekly scan"})


if __name__ == "__main__":
    unittest.main()
