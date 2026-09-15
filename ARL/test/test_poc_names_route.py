"""PoC批量选择名称接口回归测试。"""

import unittest
from unittest.mock import patch


class _Cursor(object):
    def __init__(self, documents):
        self.documents = documents
        self.sort_args = None
        self.skip_value = None
        self.limit_value = None

    def sort(self, value):
        self.sort_args = value
        return self

    def skip(self, value):
        self.skip_value = value
        return self

    def limit(self, value):
        self.limit_value = value
        return self

    def __iter__(self):
        return iter(self.documents)


class _Collection(object):
    def __init__(self):
        self.cursor = _Cursor([
            {"plugin_name": "poc.nginx"},
            {"plugin_name": ""},
        ])
        self.find_args = None
        self.find_called = False

    def find(self, query, projection):
        self.find_called = True
        self.find_args = (query, projection)
        return self.cursor

    def count_documents(self, query):
        return 1


class TestPocNamesRoute(unittest.TestCase):
    def test_returns_only_plugin_names_with_pagination(self):
        from flask import Flask
        from app.routes import poc as poc_module

        app = Flask(__name__)
        collection = _Collection()
        query_string = {
            "page": "2",
            "size": "10000",
            "q": "nginx",
            "status": "ready",
            "plugin_type": "poc",
            "order": "plugin_name",
        }
        with patch.object(poc_module.utils, "conn_db", return_value=collection):
            with app.test_request_context("/poc/names/", query_string=query_string):
                response = poc_module.ARLPoCNames.get.__wrapped__(poc_module.ARLPoCNames())

        self.assertEqual(200, response["code"])
        self.assertEqual(2, response["page"])
        self.assertEqual(10000, response["size"])
        self.assertEqual([{"plugin_name": "poc.nginx"}], response["items"])
        self.assertEqual({"_id": 0, "plugin_name": 1}, collection.find_args[1])
        self.assertEqual([("plugin_name", 1)], collection.cursor.sort_args)
        self.assertEqual(10000, collection.cursor.skip_value)
        self.assertEqual(10000, collection.cursor.limit_value)

    def test_rejects_deep_pagination_before_query(self):
        from flask import Flask
        from app.routes import poc as poc_module

        app = Flask(__name__)
        collection = _Collection()
        with patch.object(poc_module.Config, "API_MAX_PAGE_OFFSET", 50000):
            with patch.object(poc_module.utils, "conn_db", return_value=collection):
                with app.test_request_context(
                    "/poc/names/",
                    query_string={"page": "7", "size": "10000"},
                ):
                    response = poc_module.ARLPoCNames.get.__wrapped__(poc_module.ARLPoCNames())

        self.assertEqual(400, response["code"])
        self.assertEqual("分页过深，请缩小筛选范围或使用导出任务", response["message"])
        self.assertFalse(collection.find_called)


if __name__ == "__main__":
    unittest.main()
