import importlib.util
import pathlib
import re
import sys
import types
import unittest


def _build_logger():
    return types.SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        debug=lambda *args, **kwargs: None,
    )


def _load_site_spider_module():
    module_name = "app.services.siteUrlSpider"
    if module_name in sys.modules:
        return sys.modules[module_name]

    app_module = types.ModuleType("app")
    app_module.__path__ = []

    utils_module = types.ModuleType("app.utils")
    utils_module.get_logger = _build_logger
    utils_module.check_dns_policy_for_url = lambda *args, **kwargs: (True, {})
    utils_module.http_req = lambda *args, **kwargs: None

    services_module = types.ModuleType("app.services")
    services_module.__path__ = []

    base_thread_module = types.ModuleType("app.services.baseThread")
    pyquery_module = types.ModuleType("pyquery")

    class _FakeElement(object):
        def __init__(self, attrs=None):
            self.attrs = dict(attrs or {})

        def attr(self, name):
            return self.attrs.get(name)

    class _FakeSelection(object):
        def __init__(self, elements=None):
            self._elements = list(elements or [])

        def items(self):
            return list(self._elements)

    class _FakePyQuery(object):
        _PATTERN_MAP = {
            "a": ("a", "href"),
            "a[href]": ("a", "href"),
            "form": ("form", None),
            "iframe": ("iframe", None),
            "iframe[src]": ("iframe", "src"),
            "script": ("script", None),
            "script[src]": ("script", "src"),
        }

        def __init__(self, html_text):
            if isinstance(html_text, bytes):
                self.html_text = html_text.decode("utf-8", "ignore")
            else:
                self.html_text = str(html_text or "")

        def __call__(self, selector):
            tag_name, attr_name = self._PATTERN_MAP.get(str(selector or "").strip(), ("", None))
            if not tag_name:
                return _FakeSelection([])

            pattern = re.compile(r"<{}\b([^>]*)>".format(re.escape(tag_name)), re.I | re.S)
            elements = []
            for match in pattern.finditer(self.html_text):
                attrs_text = str(match.group(1) or "")
                attrs = {}
                for attr_match in re.finditer(r'([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*["\']([^"\']*)["\']', attrs_text):
                    attrs[str(attr_match.group(1) or "").strip().lower()] = str(attr_match.group(2) or "").strip()
                if attr_name and attr_name.lower() not in attrs:
                    continue
                elements.append(_FakeElement(attrs))
            return _FakeSelection(elements)

    class _BaseThread(object):
        def __init__(self, targets=None, concurrency=1):
            self.targets = list(targets or [])
            self.concurrency = concurrency

        def _run(self):
            for target in list(self.targets or []):
                self.work(target)

    base_thread_module.BaseThread = _BaseThread

    url_utils_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "utils" / "url.py"
    url_spec = importlib.util.spec_from_file_location("app.utils.url", url_utils_path)
    url_module = importlib.util.module_from_spec(url_spec)
    assert url_spec and url_spec.loader
    sys.modules["app.utils.url"] = url_module
    url_spec.loader.exec_module(url_module)

    utils_module.url_ext = url_module.url_ext
    utils_module.same_netloc = url_module.same_netloc
    utils_module.normal_url = url_module.normal_url

    sys.modules["app"] = app_module
    sys.modules["app.utils"] = utils_module
    sys.modules["app.services"] = services_module
    sys.modules["app.services.baseThread"] = base_thread_module
    pyquery_module.PyQuery = _FakePyQuery
    sys.modules["pyquery"] = pyquery_module

    app_module.utils = utils_module

    module_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "siteUrlSpider.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


site_spider_module = None


def setUpModule():
    global site_spider_module, _ORIGINAL_SYS_MODULES
    _ORIGINAL_SYS_MODULES = dict(sys.modules)
    site_spider_module = _load_site_spider_module()


def tearDownModule():
    # 替身环境只服务本文件的字符串 patch；退出时全量还原 sys.modules，
    # 避免合跑进程中污染其它测试对真实 app 包的解析。
    original_modules = globals().get("_ORIGINAL_SYS_MODULES")
    if original_modules is not None:
        sys.modules.clear()
        sys.modules.update(original_modules)





class _FakeResponse:
    def __init__(self, body: str, status_code: int = 200, content_type: str = "text/html"):
        self.status_code = status_code
        self.content = body.encode("utf-8")
        self.headers = {"Content-Type": content_type}


class TestSiteSpiderEnhance(unittest.TestCase):
    def test_site_spider_collects_same_host_sitemap_urls(self):
        site_spider_module.utils.check_dns_policy_for_url = lambda *args, **kwargs: (
            True,
            {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]},
        )

        def _http_req(url, *args, **kwargs):
            if url == "https://example.com/robots.txt":
                return _FakeResponse(
                    "User-agent: *\nSitemap: https://example.com/sitemap.xml\n",
                    content_type="text/plain",
                )
            if url == "https://example.com/sitemap.xml":
                return _FakeResponse(
                    """
                    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                      <url><loc>https://example.com/docs</loc></url>
                      <url><loc>https://example.com/api/list</loc></url>
                      <url><loc>https://other.example.com/out</loc></url>
                    </urlset>
                    """,
                    content_type="application/xml",
                )
            if url == "https://example.com":
                return _FakeResponse(
                    """
                    <html>
                      <body>
                        <a href="/portal">portal</a>
                      </body>
                    </html>
                    """,
                    content_type="text/html",
                )
            if url in {"https://example.com/docs", "https://example.com/api/list", "https://example.com/portal"}:
                return _FakeResponse("<html><body>ok</body></html>", content_type="text/html")
            raise AssertionError("unexpected url {}".format(url))

        site_spider_module.utils.http_req = _http_req

        crawled_urls = sorted(list(site_spider_module.site_spider(["https://example.com"], deep_num=1) or []))

        self.assertIn("https://example.com/docs", crawled_urls)
        self.assertIn("https://example.com/api/list", crawled_urls)
        self.assertIn("https://example.com/portal", crawled_urls)
        self.assertNotIn("https://other.example.com/out", crawled_urls)


if __name__ == "__main__":
    unittest.main()
