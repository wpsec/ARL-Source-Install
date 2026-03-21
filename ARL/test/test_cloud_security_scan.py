"""
云安全只读检测回归测试。
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

try:
    from app.services.cloud_security_scan import CloudSecurityScanService
except ModuleNotFoundError:
    CloudSecurityScanService = None


@unittest.skipIf(
    CloudSecurityScanService is None,
    "运行依赖未安装，跳过云安全检测回归",
)
class TestCloudSecurityScan(unittest.TestCase):
    """
    云安全扫描服务测试。
    """

    def test_scan_cloud_keys_detects_provider_specific_record(self):
        service = CloudSecurityScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        findings = []
        records = [
            {
                "record_type": "Aliyun_AK_ID",
                "content": "LTAI1A2b3C4d5E6f7G8h9J0k",
                "source": "https://example.com/app.js",
                "site": "https://example.com",
            }
        ]

        service._scan_cloud_keys(records, findings)

        self.assertEqual(1, len(findings))
        self.assertEqual("cloud_key_leak", findings[0]["type"])

    def test_collect_bucket_targets_extracts_bucket_origin(self):
        service = CloudSecurityScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        records = [
            {
                "record_type": "urlfinder_url",
                "content": "https://demo-bucket.oss-cn-beijing.aliyuncs.com/static/app.js",
                "source": "https://example.com/index",
                "site": "https://example.com",
            }
        ]

        with patch("app.services.cloud_security_scan.utils.check_dns_policy_for_url", return_value=(True, {})):
            targets = service._collect_bucket_targets(records)

        self.assertEqual(1, len(targets))
        self.assertEqual("https://demo-bucket.oss-cn-beijing.aliyuncs.com", targets[0]["url"])

    def test_bucket_policy_variant_records_policy_leak(self):
        service = CloudSecurityScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )
        findings = []
        target = {
            "url": "https://demo-bucket.oss-cn-beijing.aliyuncs.com",
            "provider": "aliyun_oss",
            "source": "urlfinder_url",
        }
        response = SimpleNamespace(
            status_code=200,
            text='{"Version":"1","Statement":[{"Effect":"Allow"}]}',
            headers={},
        )

        with patch.object(service, "_request", return_value=response):
            service._test_bucket_variants(
                target,
                findings,
                variant_key="policy_tests",
                vuln_type="cloud_bucket_policy_leak",
                vuln_name="云存储桶 Policy 泄露",
                severity="high",
            )

        self.assertEqual(1, len(findings))
        self.assertEqual("cloud_bucket_policy_leak", findings[0]["type"])


if __name__ == "__main__":
    unittest.main()
