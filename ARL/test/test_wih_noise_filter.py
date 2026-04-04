import unittest

IMPORT_ERROR = None
try:
    from app.services.infoHunter import InfoHunter
except Exception as exc:
    InfoHunter = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires wih test dependencies: {}".format(IMPORT_ERROR))
class TestWihNoiseFilter(unittest.TestCase):
    """WIH 噪声记录过滤回归测试。"""

    def test_should_drop_static_asset_fake_email(self):
        self.assertEqual(
            InfoHunter._normalize_record_content("email", "avatar@2x.png"),
            "",
        )
        self.assertEqual(
            InfoHunter._normalize_record_content("email", "image_login@2x-48a49a1f.png"),
            "",
        )

    def test_should_keep_real_email(self):
        self.assertEqual(
            InfoHunter._normalize_record_content("email", "security@example.com"),
            "security@example.com",
        )

    def test_should_drop_noise_path_from_js(self):
        source = "https://example.com/static/app.js"
        site = "https://example.com"
        for content in [
            "/.test(r)",
            "/img.alicdn.com/imgextra/i1/demo.png",
            "/git.io/vwTVl",
            "/localhost:8899/",
            "/license",
            "/template/plugin.css",
            "/return",
            "/1e3)",
        ]:
            self.assertEqual(
                InfoHunter._normalize_record_content("path", content, source=source, site=site),
                "",
            )

    def test_should_keep_useful_path_from_js(self):
        source = "https://example.com/static/app.js"
        site = "https://example.com"
        self.assertEqual(
            InfoHunter._normalize_record_content("path", "/api/user/list", source=source, site=site),
            "/api/user/list",
        )
        self.assertEqual(
            InfoHunter._normalize_record_content("path", "/bscSysTheme/addTheme", source=source, site=site),
            "/bscSysTheme/addTheme",
        )

    def test_should_drop_secret_concat_noise_from_js(self):
        source = "https://example.com/static/js/main.81433c50.js"
        site = "https://example.com"
        self.assertEqual(
            InfoHunter._normalize_record_content("secret_key", 'secret=").concat(t.publish)', source=source, site=site),
            "",
        )

    def test_should_drop_placeholder_basic_token_from_js(self):
        source = "https://example.com/js/app.9cc81352.js"
        site = "https://example.com"
        self.assertEqual(
            InfoHunter._normalize_record_content("basic_token", "Basic c2FiZXI6c2FiZXJfc2VjcmV0", source=source, site=site),
            "",
        )

    def test_should_drop_base64_profile_secret_from_js(self):
        source = "https://example.com/cyberplayer.js"
        site = "https://example.com"
        self.assertEqual(
            InfoHunter._normalize_record_content(
                "secret_key",
                'token:"base64:QXV0aG9yOmNoYW5neWFubG9uZ3xHaXRIdWI6aHR0cHM6Ly9naXRodWIuY29tL251bWJlcndvbGZ8RW1haWw6cG9yc2NoZWd0MjNAZm94bWFpbC5jb218RGlzY29yZDpudW1iZXJ3b2xmIzg2OTR8V29ya0luOkJhaWR1"',
                source=source,
                site=site,
            ),
            "",
        )


if __name__ == '__main__':
    unittest.main()
