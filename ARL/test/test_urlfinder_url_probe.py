import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

from test._api_unified_bootstrap import load_modules  # noqa: E402

# P2-13 口径：真实子模块经 bootstrap 临时桩窗口加载（绕开 app.services.__init__
# 的 npoc→xing 重依赖链），槽位还原后缓存条目保留、运行期懒导入可用。
_BUNDLE = load_modules(
    "app.services.urlfinder_url_probe",
    "app.services.pageFetch",
    "app.services.url_candidate_filter",
)
Config = _BUNDLE["app.services.urlfinder_url_probe"].Config
WihRecord = _BUNDLE["app.services.urlfinder_url_probe"].WihRecord
CollectSource = _BUNDLE["app.services.urlfinder_url_probe"].CollectSource
run_urlfinder_url_probe = _BUNDLE["app.services.urlfinder_url_probe"].run_urlfinder_url_probe
_PROBE_MOD = _BUNDLE["app.services.urlfinder_url_probe"]


class _FakeUrlCollection:
    def __init__(self, existing_urls=None):
        self._existing_urls = set(existing_urls or [])
        self.inserted = []

    def distinct(self, field_name, query):
        if field_name != "url":
            return []
        urls = query.get("url", {}).get("$in", [])
        return [url for url in urls if url in self._existing_urls]

    def insert_one(self, item):
        self.inserted.append(item)

    def update_one(self, query, update, upsert=False):
        # 幂等写路径：记录最终文档，模拟 upsert 命中即覆盖。
        self.inserted.append(dict((update or {}).get("$set") or {}))


class _FakeDb:
    def __init__(self, existing_url_assets=None, existing_fileleak_urls=None):
        self.url = _FakeUrlCollection(existing_url_assets)
        self.fileleak = _FakeUrlCollection(existing_fileleak_urls)

    def collection(self, name):
        if name == "url":
            return self.url
        if name == "fileleak":
            return self.fileleak
        return _FakeUrlCollection()


class TestUrlfinderUrlProbe(unittest.TestCase):
    @patch.object(_PROBE_MOD, "page_fetch")
    @patch.object(_PROBE_MOD.utils, "check_dns_policy_for_url")
    @patch.object(_PROBE_MOD.utils, "conn_db")
    def test_probe_insert_and_filter(self, mock_conn_db, mock_dns_policy, mock_page_fetch):
        fake_db = _FakeDb(existing_url_assets=["https://example.com/already"])
        mock_conn_db.side_effect = fake_db.collection

        def _dns_policy(url, cache_map=None):
            if "blocked" in url:
                return False, {"reason": "dns_drift_no_overlap", "resolver_ips": [], "system_ips": []}
            return True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]}

        mock_dns_policy.side_effect = _dns_policy
        mock_page_fetch.return_value = {
            "https://example.com/api/user": {
                "url": "https://example.com/api/user",
                "title": "ok",
                "content_length": 12,
                "status_code": 200,
            }
        }

        records = [
            WihRecord("urlfinder_url", "https://example.com/api/user", "https://example.com", "https://example.com", 1),
            WihRecord("urlfinder_url", "https://example.com/blocked", "https://example.com", "https://example.com", 2),
            WihRecord("urlfinder_url", "https://example.com/a.js", "https://example.com", "https://example.com", 3),
            WihRecord("urlfinder_url", "https://other.com/api", "https://example.com", "https://example.com", 4),
            WihRecord("domain", "sub.example.com", "https://example.com", "https://example.com", 5),
        ]

        page_url_set = {"https://example.com/already"}
        inserted_count = run_urlfinder_url_probe(
            task_id="task_1",
            sites=["https://example.com"],
            wih_records=records,
            page_url_set=page_url_set,
        )

        self.assertEqual(inserted_count, 1)
        self.assertEqual(len(fake_db.url.inserted), 1)
        self.assertEqual(fake_db.url.inserted[0]["source"], CollectSource.WIH_URL_PROBE)
        self.assertEqual(len(fake_db.fileleak.inserted), 0)
        self.assertIn("https://example.com/api/user", page_url_set)
        mock_page_fetch.assert_called_once_with(
            ["https://example.com/api/user"],
            concurrency=Config.URLFINDER_URL_PROBE_CONCURRENCY,
            waf_guard=None,
            waf_module="urlfinder_url_probe",
        )

    @patch.object(_PROBE_MOD, "page_fetch")
    @patch.object(_PROBE_MOD.utils, "check_dns_policy_for_url")
    @patch.object(_PROBE_MOD.utils, "conn_db")
    def test_probe_filters_template_static_and_annotation_noise(self, mock_conn_db, mock_dns_policy, mock_page_fetch):
        fake_db = _FakeDb()
        mock_conn_db.side_effect = fake_db.collection
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})
        mock_page_fetch.return_value = {
            "https://example.com/api/user": {
                "url": "https://example.com/api/user",
                "title": "ok",
                "content_length": 12,
                "status_code": 200,
            }
        }

        records = [
            WihRecord("path_url", "https://example.com/api/user (path_probe status=200)", "https://example.com/a.js", "https://example.com", 11),
            WihRecord("path_url", "https://example.com/static/app.css (path_probe status=200)", "https://example.com/a.js", "https://example.com", 12),
            WihRecord("path_url", "https://example.com/announcement/{id}/detail|get (path_probe status=200)", "https://example.com/a.js", "https://example.com", 13),
            WihRecord("path_url", "https://example.com/head (path_probe status=200)", "https://example.com/a.js", "https://example.com", 14),
        ]

        inserted_count = run_urlfinder_url_probe(
            task_id="task_3",
            sites=["https://example.com"],
            wih_records=records,
        )

        self.assertEqual(inserted_count, 1)
        self.assertEqual(len(fake_db.url.inserted), 1)
        self.assertEqual(len(fake_db.fileleak.inserted), 0)
        mock_page_fetch.assert_called_once_with(
            ["https://example.com/api/user"],
            concurrency=Config.URLFINDER_URL_PROBE_CONCURRENCY,
            waf_guard=None,
            waf_module="urlfinder_url_probe",
        )

    @patch.object(_PROBE_MOD, "page_fetch")
    @patch.object(_PROBE_MOD.utils, "check_dns_policy_for_url")
    @patch.object(_PROBE_MOD.utils, "conn_db")
    def test_probe_supports_page_url_hidden_candidates(self, mock_conn_db, mock_dns_policy, mock_page_fetch):
        fake_db = _FakeDb()
        mock_conn_db.side_effect = fake_db.collection
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})
        mock_page_fetch.return_value = {
            "https://example.com/portal?tenant=demo": {
                "url": "https://example.com/portal?tenant=demo",
                "title": "portal",
                "content_length": 24,
                "status_code": 200,
            }
        }

        inserted_count = run_urlfinder_url_probe(
            task_id="task_3_page",
            sites=["https://example.com"],
            wih_records=[
                WihRecord("page_url", "https://example.com/portal?tenant=demo", "https://example.com", "https://example.com", 31),
            ],
        )

        self.assertEqual(inserted_count, 1)
        self.assertEqual(len(fake_db.url.inserted), 1)
        self.assertEqual(fake_db.url.inserted[0]["site"], "https://example.com/portal?tenant=demo")
        self.assertEqual(len(fake_db.fileleak.inserted), 0)
        mock_page_fetch.assert_called_once_with(
            ["https://example.com/portal?tenant=demo"],
            concurrency=Config.URLFINDER_URL_PROBE_CONCURRENCY,
            waf_guard=None,
            waf_module="urlfinder_url_probe",
        )

    @patch.object(_PROBE_MOD, "page_fetch")
    @patch.object(_PROBE_MOD.utils, "check_dns_policy_for_url")
    @patch.object(_PROBE_MOD.utils, "conn_db")
    def test_probe_skips_when_url_asset_exists(self, mock_conn_db, mock_dns_policy, mock_page_fetch):
        fake_db = _FakeDb(existing_url_assets=["https://example.com/api/user"])
        mock_conn_db.side_effect = fake_db.collection
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})
        mock_page_fetch.return_value = {
            "https://example.com/api/user": {
                "url": "https://example.com/api/user",
                "title": "ok",
                "content_length": 12,
                "status_code": 200,
            }
        }

        inserted_count = run_urlfinder_url_probe(
            task_id="task_4",
            sites=["https://example.com"],
            wih_records=[
                WihRecord("path_url", "https://example.com/api/user", "https://example.com/a.js", "https://example.com", 21),
            ],
            page_url_set={"https://example.com/api/user"},
        )

        self.assertEqual(inserted_count, 0)
        self.assertEqual(len(fake_db.url.inserted), 0)
        self.assertEqual(len(fake_db.fileleak.inserted), 0)

    @patch.object(_PROBE_MOD, "page_fetch")
    @patch.object(_PROBE_MOD.utils, "check_dns_policy_for_url")
    @patch.object(_PROBE_MOD.utils, "conn_db")
    def test_probe_skips_when_fileleak_asset_exists(self, mock_conn_db, mock_dns_policy, mock_page_fetch):
        fake_db = _FakeDb(existing_fileleak_urls=["https://example.com/api/user"])
        mock_conn_db.side_effect = fake_db.collection
        mock_dns_policy.return_value = (True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})

        inserted_count = run_urlfinder_url_probe(
            task_id="task_5",
            sites=["https://example.com"],
            wih_records=[
                WihRecord("path_url", "https://example.com/api/user", "https://example.com/a.js", "https://example.com", 22),
            ],
        )

        self.assertEqual(inserted_count, 0)
        self.assertEqual(len(fake_db.url.inserted), 0)
        self.assertEqual(len(fake_db.fileleak.inserted), 0)
        mock_page_fetch.assert_not_called()

    @patch.object(_PROBE_MOD.utils, "conn_db")
    def test_probe_skip_when_disabled(self, mock_conn_db):
        records = [
            WihRecord("urlfinder_url", "https://example.com/api/user", "https://example.com", "https://example.com", 100)
        ]

        with patch.object(_PROBE_MOD.Config, "URLFINDER_URL_PROBE_ENABLE", False):
            inserted_count = run_urlfinder_url_probe(
                task_id="task_2",
                sites=["https://example.com"],
                wih_records=records,
            )

        self.assertEqual(inserted_count, 0)
        mock_conn_db.assert_not_called()

    @patch.object(_PROBE_MOD, "page_fetch")
    @patch.object(_PROBE_MOD.utils, "check_dns_policy_for_url")
    @patch.object(_PROBE_MOD.utils, "conn_db")
    def test_candidate_graph_urls_feed_probe(self, mock_conn_db, mock_dns_policy, mock_page_fetch):
        # "发布了却无人消费"的断链修复：url/page 候选进入探测源，探后状态迁移。
        import types

        fake_db = _FakeDb()
        mock_conn_db.side_effect = fake_db.collection
        mock_dns_policy.return_value = (
            True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})
        mock_page_fetch.return_value = {
            "https://example.com/from/graph": {
                "url": "https://example.com/from/graph",
                "title": "ok",
                "content_length": 9,
                "status_code": 200,
            }
        }

        candidates = [
            types.SimpleNamespace(candidate="https://example.com/from/graph",
                                  candidate_type="url", status="discovered"),
            types.SimpleNamespace(candidate="https://example.com/covered",
                                  candidate_type="url", status="covered"),
            types.SimpleNamespace(candidate="https://example.com/js.js",
                                  candidate_type="js", status="discovered"),
        ]

        class _GraphCtx:
            def __init__(self):
                self.candidate_registry = types.SimpleNamespace(
                    values=lambda: list(candidates))
                self.marked = []

            def mark_candidate_status(self, candidate, ctype, status, **_kw):
                self.marked.append((candidate, status))

        ctx = _GraphCtx()
        run_urlfinder_url_probe(
            task_id="task_1",
            sites=["https://example.com"],
            wih_records=[],
            discovery_context=ctx,
        )

        probed = mock_page_fetch.call_args[0][0]
        self.assertIn("https://example.com/from/graph", probed)
        self.assertNotIn("https://example.com/covered", probed)
        self.assertIn(("https://example.com/from/graph", "covered"), ctx.marked)

    @patch.object(_PROBE_MOD, "page_fetch")
    @patch.object(_PROBE_MOD.utils, "check_dns_policy_for_url")
    @patch.object(_PROBE_MOD.utils, "conn_db")
    def test_registry_endpoint_urls_excluded_when_attached(self, mock_conn_db, mock_dns_policy, mock_page_fetch):
        # 计划 6 第 8 批 §7.3：统一 Endpoint Registry 挂载后（flag-on），
        # 已登记 Endpoint 的 URL 不再进 URL Probe 自建列表（同 URL 不在
        # html_get 与 page_fetch 两个桶各打一次）。
        import types

        fake_db = _FakeDb()
        mock_conn_db.side_effect = fake_db.collection
        mock_dns_policy.return_value = (
            True, {"reason": "pass", "resolver_ips": ["1.1.1.1"], "system_ips": ["1.1.1.1"]})
        mock_page_fetch.return_value = {
            "https://example.com/from/graph": {
                "url": "https://example.com/from/graph",
                "title": "ok", "content_length": 9, "status_code": 200,
            }
        }

        class _Registry:
            def snapshot_endpoints(self):
                return [
                    {"url": "https://example.com/endpoint/known", "method": "GET"},
                    {"url": "https://example.com/graphql", "method": "POST"},
                ]

        candidates = [
            types.SimpleNamespace(candidate="https://example.com/from/graph",
                                  candidate_type="url", status="discovered"),
            types.SimpleNamespace(candidate="https://example.com/endpoint/known",
                                  candidate_type="url", status="discovered"),
        ]

        class _Ctx:
            def __init__(self):
                self.candidate_registry = types.SimpleNamespace(
                    values=lambda: list(candidates))
                self.api_candidate_registry = _Registry()

            def mark_candidate_status(self, *_a, **_k):
                return None

        run_urlfinder_url_probe(
            task_id="task_1",
            sites=["https://example.com"],
            wih_records=[],
            discovery_context=_Ctx(),
        )
        probed = mock_page_fetch.call_args[0][0]
        self.assertEqual(["https://example.com/from/graph"], probed)


if __name__ == "__main__":
    unittest.main()
