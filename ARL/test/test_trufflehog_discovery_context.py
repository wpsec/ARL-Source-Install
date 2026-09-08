"""TruffleHog JS 下载复用任务级 HTTP 观察面的回归测试。"""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import load_modules  # noqa: E402


MODULE = load_modules("app.services.trufflehog_scan")["app.services.trufflehog_scan"]


class TrufflehogDiscoveryContextTest(unittest.TestCase):
    def test_js_download_uses_shared_fetch_text_when_context_is_present(self):
        scanner = MODULE.TrufflehogJSScanner(
            ["https://example.test"],
            [SimpleNamespace(source="https://example.test/assets/app.js", content="")],
            discovery_context=object(),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            scanner.scan_dir = temp_dir
            with mock.patch.object(
                MODULE,
                "fetch_text",
                return_value=("console.log('ok')", SimpleNamespace(status_code=200)),
            ) as fetch:
                self.assertEqual(
                    1,
                    scanner._download_js_files(["https://example.test/assets/app.js"]),
                )

        kwargs = fetch.call_args.kwargs
        self.assertIs(kwargs["discovery_context"], scanner.discovery_context)
        self.assertEqual("html_get", kwargs["request_profile"])
        self.assertEqual("wih", kwargs["traffic_class"])


if __name__ == "__main__":
    unittest.main()
