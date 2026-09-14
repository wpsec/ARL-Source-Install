"""第七轮 Review 整改回归：删除确认、截图路径和重定向范围。"""

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class TestReviewFixesRound7(unittest.TestCase):
    def test_screenshot_path_rejects_symlink_and_allows_real_file(self):
        from app.routes import image as image_module
        from app.config import Config

        with tempfile.TemporaryDirectory() as temp_dir:
            task_id = "507f1f77bcf86cd799439011"
            task_dir = os.path.join(temp_dir, task_id)
            os.makedirs(task_dir)
            real_file = os.path.join(task_dir, "ok.jpg")
            with open(real_file, "wb") as file_obj:
                file_obj.write(b"image")

            outside_file = os.path.join(temp_dir, "outside.jpg")
            with open(outside_file, "wb") as file_obj:
                file_obj.write(b"outside")
            os.symlink(outside_file, os.path.join(task_dir, "link.jpg"))

            with patch.object(Config, "SCREENSHOT_DIR", temp_dir):
                self.assertEqual(os.path.realpath(real_file), image_module._safe_screenshot_path(task_id, "ok.jpg"))
                self.assertEqual("", image_module._safe_screenshot_path(task_id, "link.jpg"))

    def test_poc_delete_requires_api_principal_and_confirmation(self):
        from flask import Flask
        from app.routes import poc as poc_module

        app = Flask(__name__)
        deleted = []

        class Collection(object):
            def insert_one(self, _document):
                return SimpleNamespace(inserted_id="audit-1")

            def update_one(self, *_args, **_kwargs):
                return SimpleNamespace(modified_count=1)

            def delete_many(self, _query):
                deleted.append(True)
                return SimpleNamespace(deleted_count=2)

        collection = Collection()

        def conn_db(_name):
            return collection

        with patch.object(poc_module.utils, "conn_db", side_effect=conn_db), \
                patch.object(poc_module.utils, "current_principal", return_value={"type": "login", "username": "user"}):
            with app.test_request_context("/poc/delete/", method="POST", json={"confirm": True}):
                response = poc_module.ARLPoCDelete.post.__wrapped__(poc_module.ARLPoCDelete())
        self.assertEqual(403, response[1])
        self.assertEqual([], deleted)

        with patch.object(poc_module.utils, "conn_db", side_effect=conn_db), \
                patch.object(poc_module.utils, "current_principal", return_value={"type": "api", "username": "ARL-API"}):
            with app.test_request_context("/poc/delete/", method="POST", json={}):
                response = poc_module.ARLPoCDelete.post.__wrapped__(poc_module.ARLPoCDelete())
        self.assertEqual(400, response[1])
        self.assertEqual([], deleted)

        with patch.object(poc_module.utils, "conn_db", side_effect=conn_db), \
                patch.object(poc_module.utils, "current_principal", return_value={"type": "api", "username": "ARL-API"}):
            with app.test_request_context("/poc/delete/", method="POST", json={"confirm": True}):
                response = poc_module.ARLPoCDelete.post.__wrapped__(poc_module.ARLPoCDelete())
        self.assertEqual(200, response["code"])
        self.assertEqual([True], deleted)

    def test_endpoint_redirect_is_stopped_before_out_of_scope_request(self):
        from app.services import wih_endpoint_probe as probe_module

        initial_url = "https://example.test/api"
        redirect_url = "http://127.0.0.1:8080/admin"

        class Response(object):
            status_code = 302
            headers = {"Location": redirect_url}
            content = b""

        with patch.object(probe_module.utils, "check_dns_policy_for_url", return_value=(True, {})), \
                patch.object(probe_module.requests, "request", return_value=Response()) as request_mock, \
                patch.object(probe_module.Config, "WIH_ENDPOINT_PROBE_MAX_REDIRECTS", 3, create=True):
            result = probe_module._request_with_safe_redirects(
                initial_url,
                "GET",
                {"allow_redirects": False},
                url_in_scope=lambda value: value == initial_url,
            )

        self.assertIsNone(result[0])
        self.assertEqual("redirect_out_of_scope", result[2])
        request_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
