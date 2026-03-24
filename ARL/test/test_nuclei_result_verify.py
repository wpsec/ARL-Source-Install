"""
PoC 结果验证信息格式化回归测试。
"""
import json
import unittest

try:
    from app.routes.nuclei_result import (
        _build_curl_from_http_request,
        _normalize_afrog_verify_data,
        _resolve_afrog_vuln_name,
    )
except ModuleNotFoundError:
    _build_curl_from_http_request = None
    _normalize_afrog_verify_data = None
    _resolve_afrog_vuln_name = None


@unittest.skipIf(
    _build_curl_from_http_request is None
    or _normalize_afrog_verify_data is None
    or _resolve_afrog_vuln_name is None,
    "运行依赖未安装，跳过 PoC 验证信息回归",
)
class TestNucleiResultVerifyFormat(unittest.TestCase):
    """
    验证 afrog verify_data 到 curl 的兼容转换逻辑。
    """

    def test_build_curl_from_http_request(self):
        request_text = "\n".join(
            [
                "GET /admin/login?next=%2F HTTP/1.1",
                "Host: demo.example.com",
                "User-Agent: afrog",
                "Accept: */*",
                "",
            ]
        )
        curl_cmd = _build_curl_from_http_request(request_text, "https://demo.example.com")
        self.assertIn("curl -k -i -sS -X GET", curl_cmd)
        self.assertIn("https://demo.example.com/admin/login?next=%2F", curl_cmd)
        self.assertIn("User-Agent: afrog", curl_cmd)

    def test_normalize_afrog_verify_data_prefers_existing_curl(self):
        payload = {
            "target": "https://demo.example.com/login",
            "curl_command": "curl -k -i -sS 'https://demo.example.com/login'",
            "request": "GET /login HTTP/1.1\nHost: demo.example.com\n\n",
        }
        result = _normalize_afrog_verify_data(json.dumps(payload, ensure_ascii=False), payload["target"])
        self.assertEqual(payload["curl_command"], result)

    def test_normalize_afrog_verify_data_builds_curl_from_request(self):
        payload = {
            "target": "https://demo.example.com/login",
            "request": "POST /api/check HTTP/1.1\nHost: demo.example.com\nContent-Type: application/json\n\n{\"id\":1}",
        }
        result = _normalize_afrog_verify_data(json.dumps(payload, ensure_ascii=False), payload["target"])
        self.assertIn("curl -k -i -sS -X POST", result)
        self.assertIn("https://demo.example.com/api/check", result)
        self.assertIn("--data-raw", result)

    def test_resolve_afrog_vuln_name_prefers_rule_id_when_generic(self):
        resolved = _resolve_afrog_vuln_name("afrog 漏洞", "afrog:CVE-2026-0001", "")
        self.assertEqual("CVE-2026-0001", resolved)

    def test_resolve_afrog_vuln_name_reads_verify_data_when_generic(self):
        payload = {"id": "poc-raw-download", "target": "https://demo.example.com"}
        resolved = _resolve_afrog_vuln_name("afrog 漏洞", "afrog", json.dumps(payload, ensure_ascii=False))
        self.assertEqual("poc-raw-download", resolved)


if __name__ == "__main__":
    unittest.main()
