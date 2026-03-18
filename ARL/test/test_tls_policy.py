"""
TLS 合规基线与导出列测试。

测试内容：
- TLS 协议/套件合规判定
- TLS 1.3 套件命名归一化
- SSL 导出工作表新增列的内容生成
"""

import unittest
import importlib.util
from pathlib import Path
from unittest.mock import patch

_TLS_POLICY_PATH = Path(__file__).resolve().parents[1] / "app" / "utils" / "tls_policy.py"
_TLS_POLICY_SPEC = importlib.util.spec_from_file_location("arl_tls_policy", str(_TLS_POLICY_PATH))
_TLS_POLICY_MODULE = importlib.util.module_from_spec(_TLS_POLICY_SPEC)
_TLS_POLICY_SPEC.loader.exec_module(_TLS_POLICY_MODULE)

analyze_ssl_security_compliance = _TLS_POLICY_MODULE.analyze_ssl_security_compliance
normalize_cipher_suite_name = _TLS_POLICY_MODULE.normalize_cipher_suite_name

try:
    from app.routes.export import _extract_cert_rows
except ModuleNotFoundError:
    _extract_cert_rows = None


class TestTLSPolicy(unittest.TestCase):
    """
    TLS 合规规则测试。
    """

    def test_analyze_ssl_security_compliance_flags_weak_suites(self):
        """
        弱协议参数、CBC、静态 RSA 等应被识别为不合规。
        """
        ssl_security = {
            "protocol_names": ["TLSv1.2", "TLSv1.3"],
            "cipher_suites": [
                {
                    "protocol": "TLSv1.2",
                    "name": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024)",
                    "strength": "D",
                },
                {
                    "protocol": "TLSv1.2",
                    "name": "TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa 2048)",
                    "strength": "A",
                },
                {
                    "protocol": "TLSv1.3",
                    "name": "TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519)",
                    "strength": "A",
                },
            ],
        }

        compliance = analyze_ssl_security_compliance(ssl_security)

        self.assertTrue(compliance["has_issue"])
        self.assertIn("weak_dh_param", compliance["issue_codes"])
        self.assertIn("cbc_mode", compliance["issue_codes"])
        self.assertIn("no_forward_secrecy", compliance["issue_codes"])
        self.assertIn("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", compliance["non_compliant_text"])
        self.assertIn("TLS_RSA_WITH_AES_128_GCM_SHA256", compliance["non_compliant_text"])
        self.assertIn("ingress-nginx", compliance["remediation_text"])

    def test_analyze_ssl_security_compliance_keeps_baseline_clean(self):
        """
        推荐的 TLS 1.2 / TLS 1.3 套件不应被误判。
        """
        ssl_security = {
            "protocol_names": ["TLSv1.2", "TLSv1.3"],
            "cipher_suites": [
                {
                    "protocol": "TLSv1.2",
                    "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1)",
                    "strength": "A",
                },
                {
                    "protocol": "TLSv1.3",
                    "name": "TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519)",
                    "strength": "A",
                },
            ],
        }

        compliance = analyze_ssl_security_compliance(ssl_security)

        self.assertFalse(compliance["has_issue"])
        self.assertEqual("", compliance["non_compliant_text"])
        self.assertEqual("", compliance["remediation_text"])

    def test_normalize_cipher_suite_name_maps_tls13_alias(self):
        """
        兼容扫描器输出的 TLS 1.3 旧命名。
        """
        self.assertEqual(
            "TLS_AES_128_GCM_SHA256",
            normalize_cipher_suite_name("TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519)"),
        )

    @patch("app.routes.export.get_ip_data")
    @patch("app.routes.export.get_domain_data")
    @patch("app.routes.export.get_cert_data")
    @unittest.skipIf(_extract_cert_rows is None, "export 依赖未安装，跳过导出列校验")
    def test_extract_cert_rows_includes_tls_compliance_columns(
        self,
        mock_get_cert_data,
        mock_get_domain_data,
        mock_get_ip_data,
    ):
        """
        SSL 导出行应包含不合规项与修复建议两列。
        """
        mock_get_domain_data.return_value = []
        mock_get_ip_data.return_value = []
        mock_get_cert_data.return_value = [
            {
                "task_id": "task-1",
                "ip": "1.1.1.1",
                "port": "443",
                "host": "1.1.1.1:443",
                "domain": "example.com",
                "cert": {
                    "subject_dn": "CN=example.com",
                    "issuer_dn": "CN=Example CA",
                    "validity": {
                        "start": "2026-01-01 00:00:00",
                        "end": "2026-12-31 00:00:00",
                    },
                    "fingerprint": {
                        "sha256": "deadbeef",
                    },
                    "extensions": {
                        "subjectAltName": "DNS:example.com,DNS:www.example.com",
                    },
                    "ssl_security": {
                        "protocol_names": ["TLSv1.2", "TLSv1.3"],
                        "cipher_suites": [
                            {
                                "protocol": "TLSv1.2",
                                "name": "TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa 2048)",
                                "strength": "A",
                            },
                            {
                                "protocol": "TLSv1.3",
                                "name": "TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519)",
                                "strength": "A",
                            },
                        ],
                    },
                },
            }
        ]

        rows = _extract_cert_rows(["task-1"])

        self.assertEqual(1, len(rows))
        self.assertEqual(15, len(rows[0]))
        self.assertIn("TLS_RSA_WITH_AES_128_GCM_SHA256", rows[0][11])
        self.assertIn("Nginx", rows[0][12])
        self.assertIn("ingress-nginx", rows[0][12])


if __name__ == "__main__":
    unittest.main()
