import unittest
from unittest.mock import patch

try:
    from app.services.browser_intel_scan import run_browser_intel_scan
except Exception:
    run_browser_intel_scan = None


@unittest.skipIf(run_browser_intel_scan is None, "requires browser intel service")
class TestBrowserIntelScan(unittest.TestCase):
    @patch("app.services.browser_intel_scan.Config.BROWSER_INTEL_ENABLE", True)
    @patch("app.services.browser_intel_scan.sync_playwright")
    def test_browser_intel_collects_runtime_calls_forms_and_scripts(self, mock_sync_playwright):
        class FakePage:
            def __init__(self):
                self._handlers = {}
                self.url = "https://example.com/dashboard"

            def on(self, event, handler):
                self._handlers[event] = handler

            def goto(self, site, wait_until=None, timeout=None):
                class Req:
                    method = "GET"
                    resource_type = "fetch"
                class Resp:
                    request = Req()
                    url = "https://example.com/api/me"
                    status = 200
                if "response" in self._handlers:
                    self._handlers["response"](Resp())

            def wait_for_timeout(self, ms):
                return None

            def title(self):
                return "Example Dashboard"

            def evaluate(self, script):
                if "querySelectorAll('form')" in script:
                    return [{"action": "/login", "method": "POST", "fields": "username,password"}]
                return [{"src": "/static/app.js"}]

        class FakeContext:
            def new_page(self):
                return FakePage()

            def close(self):
                return None

        class FakeBrowser:
            def new_context(self, **kwargs):
                return FakeContext()

            def close(self):
                return None

        class FakeChromium:
            def launch(self, **kwargs):
                return FakeBrowser()

        class FakePlaywright:
            chromium = FakeChromium()

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        mock_sync_playwright.return_value = FakePlaywright()

        result = run_browser_intel_scan(["https://example.com"])
        item = result.get("https://example.com", {})

        self.assertEqual("Example Dashboard", item.get("browser_surface_summary", {}).get("page_title"))
        self.assertEqual(1, item.get("browser_surface_summary", {}).get("runtime_api_count"))
        self.assertEqual(1, len(item.get("runtime_api_calls", [])))
        self.assertEqual(1, len(item.get("dom_form_summary", [])))


if __name__ == "__main__":
    unittest.main()
