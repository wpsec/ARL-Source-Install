"""
Web 专项渗透测试链路回归测试。
"""
import unittest
from unittest.mock import patch

try:
    from app.services.nuclei_scan import NucleiScan
    from app.services.penetration_scan import PenetrationScanService
except ModuleNotFoundError:
    NucleiScan = None
    PenetrationScanService = None


@unittest.skipIf(
    NucleiScan is None or PenetrationScanService is None,
    "运行依赖未安装，跳过专项渗透测试回归",
)
class TestPenetrationScan(unittest.TestCase):
    """
    专项渗透测试服务测试。
    """

    def test_nuclei_profile_force_tags_builds_single_profile_batch(self):
        """
        当指定专项 profile tag 时，应直接构建单批次 profile 扫描。
        """
        scanner = NucleiScan(
            targets=["https://example.com/api/user?id=1"],
            scan_profile={
                "name": "penetration",
                "force_tags": ["sqli", "xss", "xxe"],
            },
        )

        batches = scanner._build_target_batches()

        self.assertEqual(1, len(batches))
        self.assertEqual("profile:penetration", batches[0]["batch_type"])
        self.assertEqual("sqli,xss,xxe", batches[0]["tags"])
        self.assertEqual(["https://example.com/api/user?id=1"], batches[0]["targets"])

    def test_penetration_target_collection_filters_static_and_out_of_scope_urls(self):
        """
        仅保留同范围内的高价值 URL，静态资源与跨域候选应被过滤。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set={
                "https://example.com/static/app.js",
                "https://example.com/api/user?id=1",
            },
        )

        with patch.object(service, "_load_db_urls", return_value=[
            "https://example.com/swagger/index.html",
            "https://example.com/assets/logo.png",
        ]), patch.object(service, "_load_wih_urls", return_value=[
            "https://example.com/graphql?query=1",
            "https://api.other.com/openapi.json",
        ]):
            targets = service.collect_targets()

        self.assertIn("https://example.com", targets)
        self.assertIn("https://example.com/api/user?id=1", targets)
        self.assertIn("https://example.com/swagger/index.html", targets)
        self.assertIn("https://example.com/graphql?query=1", targets)
        self.assertNotIn("https://example.com/static/app.js", targets)
        self.assertNotIn("https://example.com/assets/logo.png", targets)
        self.assertNotIn("https://api.other.com/openapi.json", targets)

    def test_penetration_afrog_target_prefers_query_urls(self):
        """
        afrog 目标应优先挑选带参数或高价值路径的 URL。
        """
        service = PenetrationScanService(
            task_id="task-demo",
            sites=["https://example.com"],
            page_url_set=[],
        )

        selected = service._select_afrog_targets(
            [
                "https://example.com",
                "https://example.com/api/search?q=test",
                "https://example.com/swagger/index.html",
            ]
        )

        self.assertEqual("https://example.com/api/search?q=test", selected[0])
        self.assertIn("https://example.com/swagger/index.html", selected)


if __name__ == "__main__":
    unittest.main()
