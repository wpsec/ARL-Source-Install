"""YAML POC 导入器、受限 DSL 和 HTTP/TCP 执行器测试。"""

import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ARL-NPoC"))
sys.path.insert(0, str(ROOT / "ARL-NPoC" / "tools"))

from tools import import_dt_pocs
from xing import yaml_poc


class FakeResponse:
    def __init__(self, text="ok", status_code=200, headers=None):
        self.text = text
        self.content = text.encode("utf-8")
        self.status_code = status_code
        self.headers = headers or {}


class YamlPocTest(unittest.TestCase):
    def test_import_alias_and_duplicate_id_are_audited(self):
        rule = {
            "id": "rule-one",
            "info": {"name": "示例", "severity": "high"},
            "requests": [{"method": "GET", "path": "/", "expression": "contains(body, \"ok\")"}],
        }
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_dir:
            rules_dir = pathlib.Path(input_dir) / "rules"
            rules_dir.mkdir()
            (rules_dir / "one.yaml").write_text(yaml.safe_dump(rule, allow_unicode=True), encoding="utf-8")
            alias = dict(rule)
            alias["id"] = "rule-two"
            (rules_dir / "two.yaml").write_text(yaml.safe_dump(alias, allow_unicode=True), encoding="utf-8")
            duplicate_id = dict(rule)
            duplicate_id["info"] = dict(rule["info"])
            duplicate_id["info"]["name"] = "不同规则"
            (rules_dir / "three.yaml").write_text(yaml.safe_dump(duplicate_id, allow_unicode=True), encoding="utf-8")
            (rules_dir / "bad.yaml").write_text("id: [broken\n", encoding="utf-8")

            manifest = import_dt_pocs.import_rules(input_dir, output_dir)
            statuses = {item["source_path"]: item["status"] for item in manifest["entries"]}
            self.assertEqual(manifest["rule_count"], 4)
            self.assertEqual(manifest["ready_count"], 1)
            self.assertEqual(manifest["duplicate_count"], 1)
            self.assertEqual(manifest["quarantine_count"], 2)
            self.assertEqual(statuses["rules/two.yaml"], "duplicate")
            self.assertEqual(statuses["rules/three.yaml"], "quarantine")
            self.assertTrue((pathlib.Path(output_dir) / "yaml/rule-one.yaml").is_file())

            upload_rule = import_dt_pocs.normalize_rule({
                "id": "upload-rule",
                "info": {"name": "上传"},
                "requests": [{
                    "method": "POST",
                    "path": "/upload",
                    "files": {"file": {"name": "payload.txt", "data": "payload"}},
                    "expression": "status_code == 200",
                }],
            })
            self.assertEqual(upload_rule["requests"][0]["files"]["file"]["filename"], "payload.txt")
            self.assertEqual(upload_rule["requests"][0]["files"]["file"]["content"], "payload")

    def test_expression_dsl_has_logic_headers_and_no_eval_escape(self):
        context = yaml_poc._ResponseContext(
            FakeResponse(
                "body-value",
                headers={"Set-Cookie": "session=secret", "Content-Type": "application/json"},
            )
        ).as_context()
        evaluator = yaml_poc._ExpressionEvaluator(context)
        self.assertTrue(evaluator.evaluate('contains(body, "body-value") && headers["Set-Cookie"] == "session=secret"'))
        self.assertTrue(evaluator.evaluate("status_code == 200 || contains(body, 'missing')"))
        with self.assertRaises(yaml_poc.YamlPocError):
            evaluator.evaluate('__import__("os").system("id")')

    def test_http_sequence_variables_files_and_target_scope(self):
        calls = []

        def fake_http(url, method="get", **kwargs):
            calls.append((url, method, kwargs))
            if kwargs.get("files"):
                self.assertEqual(kwargs["files"]["upload"][0], "a.txt")
                return FakeResponse('{"uploaded":true}')
            return FakeResponse("ok")

        rule = {
            "id": "sequence",
            "info": {"name": "sequence"},
            "transport": "http",
            "requests": [
                {"method": "GET", "path": "/set", "expression": "contains(body, 'ok')", "output": ["set_var('token', 'next')"]},
                {"method": "POST", "path": "/{{.token}}", "files": {"upload": {"filename": "a.txt", "content": "x"}}, "expression": "contains(body, 'uploaded')"},
            ],
        }
        with mock.patch.object(yaml_poc, "http_req", side_effect=fake_http):
            self.assertTrue(yaml_poc.YamlPocExecutor(rule).execute("https://example.test/base"))
        self.assertEqual([call[0] for call in calls], ["https://example.test/set", "https://example.test/next"])

        external_rule = dict(rule)
        external_rule["requests"] = [{"method": "GET", "path": "http://evil.test/poc", "expression": "contains(body, 'ok')"}]
        calls.clear()
        with mock.patch.object(yaml_poc, "http_req", side_effect=fake_http):
            self.assertTrue(yaml_poc.YamlPocExecutor(external_rule).execute("https://example.test"))
        self.assertEqual(calls[0][0], "https://example.test/http://evil.test/poc")

    def test_http_raw_redirect_timeout_and_response_context(self):
        calls = []

        def fake_http(url, method="get", **kwargs):
            calls.append((url, method, kwargs))
            return FakeResponse(
                "<title>Raw response</title>",
                status_code=200,
                headers={"X-Test": "passed"},
            )

        rule = {
            "id": "raw-http",
            "info": {"name": "raw-http"},
            "transport": "http",
            "requests": [{
                "raw": "PUT /raw-endpoint HTTP/1.1\nX-Raw: yes\n\npayload",
                "redirect": True,
                "timeout": 2,
                "expression": "status_code == 200 && title == 'Raw response' && contains(header, 'X-Test: passed')",
            }],
        }
        with mock.patch.object(yaml_poc, "http_req", side_effect=fake_http):
            self.assertTrue(yaml_poc.YamlPocExecutor(rule).execute("https://example.test"))
        self.assertEqual(calls[0][0], "https://example.test/raw-endpoint")
        self.assertEqual(calls[0][1], "put")
        self.assertEqual(calls[0][2]["timeout"], 2.0)
        self.assertTrue(calls[0][2]["allow_redirects"])
        self.assertEqual(calls[0][2]["headers"]["X-Raw"], "yes")

    def test_tcp_sequence_reads_plain_protocol_payload(self):
        class FakeConnection:
            def __init__(self, *_args, **_kwargs):
                self.writes = []

            def WriteStr(self, value):
                self.writes.append(value)
                return True

            def ReadStr(self):
                return "STAT version 1.6"

            def Close(self):
                return True

        rule = {
            "id": "tcp-rule",
            "info": {"name": "tcp-rule"},
            "transport": "tcp",
            "tcpRequests": [{"expression": ["conn.WriteStr('stats')", "conn.ReadStr()", "contains(res, 'STAT version')"]}],
        }
        with mock.patch.object(yaml_poc, "_TcpConnection", FakeConnection):
            self.assertTrue(yaml_poc.YamlPocExecutor(rule).execute("tcp://127.0.0.1:11211"))

    def test_evidence_redacts_structured_secrets(self):
        evidence = yaml_poc._limited_text(
            json.dumps({"password": "plain-password", "token": "plain-token", "safe": "kept"})
        )
        self.assertNotIn("plain-password", evidence)
        self.assertNotIn("plain-token", evidence)
        self.assertIn("safe", evidence)


if __name__ == "__main__":
    unittest.main()
