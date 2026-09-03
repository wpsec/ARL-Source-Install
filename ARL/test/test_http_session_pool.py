"""普通 HTTP 路径连接池收编的回归测试。

验证点：
- 共享适配器单例：连续请求复用同一 HTTPAdapter(同一 urllib3 连接池);
- pooled Session 永不 close()：close 会连带摧毁共享适配器;
- cookie 隔离语义保持：每请求新建 Session(独立 cookiejar);
- connect_ip 直连路径不受池化影响，仍用即建即关的临时 Session。
"""

import unittest
from types import SimpleNamespace

try:
    from app.utils import conn as conn_mod
except Exception:
    conn_mod = None


@unittest.skipIf(conn_mod is None, "运行依赖未安装")
class TestHttpSessionPool(unittest.TestCase):
    def setUp(self):
        # 重置模块级单例，避免用例间串扰。
        self._saved_adapter = conn_mod._PLAIN_POOL_ADAPTER
        conn_mod._PLAIN_POOL_ADAPTER = None

    def tearDown(self):
        conn_mod._PLAIN_POOL_ADAPTER = self._saved_adapter

    class _FakeResponse(object):
        def __init__(self):
            self.status_code = 200
            self.headers = {}
            self.raw = None
            self._content = False
            self._content_consumed = False
            self.closed = False

        def close(self):
            self.closed = True

    def _make_recording_session(self, bucket):
        test = self

        class _RecordingSession(object):
            trust_env = True

            def __init__(self):
                self.mounted = {}
                self.closed = False
                self.cookie_like_state = set()
                bucket.append(self)

            def mount(self, prefix, adapter):
                self.mounted[prefix] = adapter

            def request(self, method, url, **kwargs):
                return test._FakeResponse()

            def close(self):
                self.closed = True

        return _RecordingSession

    def _call_plain(self):
        return conn_mod.http_req(
            "http://target.example.com/",
            "get",
            timeout=(1, 2),
            allow_redirects=False,
        )

    def test_plain_path_shares_adapter_and_never_closes_pooled_session(self):
        from unittest.mock import patch

        sessions = []
        original = conn_mod.requests.Session
        conn_mod.requests.Session = self._make_recording_session(sessions)
        try:
            self._call_plain()
            self._call_plain()
        finally:
            conn_mod.requests.Session = original

        self.assertEqual(2, len(sessions))
        first, second = sessions
        self.assertIs(first.mounted["https://"], second.mounted["https://"])
        self.assertIs(first.mounted["http://"], second.mounted["http://"])
        self.assertFalse(first.closed)
        self.assertFalse(second.closed)
        # 不同 Session 实例 → 独立 cookiejar，扫描语义不变。
        self.assertIsNot(first, second)

    def test_adapter_singleton_respects_pool_sizes(self):
        adapter = conn_mod._plain_pool_adapter()
        self.assertIs(adapter, conn_mod._plain_pool_adapter())
        self.assertGreaterEqual(adapter._pool_maxsize, 1)

    def test_connect_ip_path_uses_ephemeral_session_and_closes(self):
        from unittest.mock import patch

        sessions = []

        class _EphemeralSession(object):
            trust_env = True

            def __init__(self):
                self.mounted = {}
                self.closed = False
                sessions.append(self)

            def mount(self, prefix, adapter):
                self.mounted[prefix] = adapter

            def request(self, method, url, **kwargs):
                return TestHttpSessionPool._FakeResponse()

            def close(self):
                self.closed = True

        original_session = conn_mod.requests.Session
        original_direct = conn_mod.DirectIPHTTPAdapter
        conn_mod.requests.Session = _EphemeralSession
        conn_mod.DirectIPHTTPAdapter = lambda **kwargs: SimpleNamespace()
        try:
            conn_mod.http_req(
                "http://target.example.com/",
                "get",
                connect_ip="192.0.2.7",
                timeout=(1, 2),
            )
        finally:
            conn_mod.requests.Session = original_session
            conn_mod.DirectIPHTTPAdapter = original_direct

        self.assertEqual(1, len(sessions))
        self.assertTrue(sessions[0].closed)


if __name__ == "__main__":
    unittest.main()
