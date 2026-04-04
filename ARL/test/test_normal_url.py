import importlib.util
import pathlib
import unittest


def _load_url_utils_module():
    module_name = "url_utils_test_module"
    module_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "utils" / "url.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


url_utils_module = _load_url_utils_module()
normal_url = url_utils_module.normal_url
urlsimilar = url_utils_module.urlsimilar


class TestNormalURL(unittest.TestCase):
    def test_normal_url(self):
        u1 = "https://www.baidu.com:443/test?a=1"
        u2 = "https://www.baidu.com/test?a=1"
        normal1 = normal_url(u1)

        self.assertTrue(normal1 == u2)

    def test_urlsimilar_keeps_path_identity_when_query_keys_match(self):
        first = "https://example.com/api/user/detail?id=1"
        second = "https://example.com/api/order/detail?id=2"

        self.assertNotEqual(urlsimilar(first), urlsimilar(second))
