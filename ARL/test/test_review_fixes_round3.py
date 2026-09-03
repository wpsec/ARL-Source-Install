"""第三轮 review 修复回归：probe wrapper 透传、URLInfo.__eq__、upsert_one、统计重建。"""

import unittest
from unittest import mock
from types import SimpleNamespace

try:
    from app.services import wih_endpoint_probe as probe_mod
    from app.services import siteUrlSpider as spider_mod
    from app.services.task_result_write_service import TaskResultWriteService
except Exception:
    probe_mod = None


@unittest.skipIf(probe_mod is None, "运行依赖未安装")
class TestProbeWrapperPassthrough(unittest.TestCase):
    def test_run_wih_endpoint_probe_forwards_context(self):
        captured = {}

        def fake_enrich(items, waf_guard=None, discovery_context=None):
            captured["waf_guard"] = waf_guard
            captured["context"] = discovery_context
            return [dict(i) for i in items]

        sentinel = object()
        with mock.patch.object(probe_mod, "enrich_wih_endpoints", side_effect=fake_enrich):
            probe_mod.run_wih_endpoint_probe(
                [{"url": "https://a.example.com/api", "method": "GET"}],
                waf_guard="guard-x",
                discovery_context=sentinel,
            )
        self.assertIs(captured["context"], sentinel)
        self.assertEqual("guard-x", captured["waf_guard"])


@unittest.skipIf(probe_mod is None, "运行依赖未安装")
class TestUrlInfoEquality(unittest.TestCase):
    def test_eq_compares_against_other(self):
        a = spider_mod.URLInfo("https://e.com/", "https://e.com/x", "document")
        b = spider_mod.URLInfo("https://e.com/", "https://e.com/y", "document")
        c = spider_mod.URLInfo("https://e.com/", "https://e.com/x", "document")
        self.assertNotEqual(a, b)
        self.assertEqual(a, c)

    def test_url_list_dedup_works(self):
        items = spider_mod.URLList()
        a = spider_mod.URLInfo("https://e.com/", "https://e.com/1", "document")
        b = spider_mod.URLInfo("https://e.com/", "https://e.com/2", "document")
        self.assertTrue(items.add(a))
        self.assertFalse(items.add(spider_mod.URLInfo("https://e.com/", "https://e.com/1", "document")))
        self.assertTrue(items.add(b))
        self.assertEqual(2, len(items))


@unittest.skipIf(probe_mod is None, "运行依赖未安装")
class TestUpsertOne(unittest.TestCase):
    def test_upsert_one_uses_key_and_excludes_id(self):
        calls = []

        class _Coll(object):
            def update_one(self, query, update, upsert=False):
                calls.append((query, update, upsert))

        svc = TaskResultWriteService("task-1")
        with mock.patch.object(
                TaskResultWriteService, "_collection", side_effect=lambda name: _Coll()):
            svc.upsert_one(
                "url",
                {"task_id": "task-1", "source": "wih_url_probe", "url": "https://a/x"},
                {"_id": "should-drop", "url": "https://a/x", "status_code": 200},
            )
        query, update, upsert = calls[0]
        self.assertEqual(
            {"task_id": "task-1", "source": "wih_url_probe", "url": "https://a/x"}, query)
        self.assertTrue(upsert)
        self.assertNotIn("_id", update["$set"])
        self.assertEqual(200, update["$set"]["status_code"])


@unittest.skipIf(probe_mod is None, "运行依赖未安装")
class TestStatRebuild(unittest.TestCase):
    def test_finger_and_cip_delete_before_insert(self):
        from app.services import task_lifecycle_service as tls_mod

        ops = []

        class _Coll(object):
            def __init__(self, name):
                self.name = name

            def delete_many(self, query):
                ops.append(("delete", self.name, query))

            def insert_one(self, doc):
                ops.append(("insert", self.name, doc))

        fake_arl = SimpleNamespace(
            gen_stat_finger_map=lambda task_id, force_refresh=False: {
                "a": {"finger": "a", "count": 1}},
            gen_cip_map=lambda task_id: {
                "1.1.1.0/24": {"ip_set": {"1.1.1.1"}, "domain_set": {"a.example.com"}}},
        )
        with mock.patch.object(tls_mod.utils, "arl", fake_arl), \
                mock.patch.object(tls_mod.utils, "conn_db", side_effect=lambda name: _Coll(name)):
            svc = tls_mod.TaskLifecycleService(SimpleNamespace(task_id="task-1"))
            svc.insert_finger_stat()
            svc.insert_cip_stat()

        kinds = [o[0] + ":" + o[1] for o in ops]
        self.assertEqual("delete:stat_finger", kinds[0])
        self.assertIn("insert:stat_finger", kinds)
        self.assertIn("delete:cip", kinds)
        self.assertIn("insert:cip", kinds)
        # 每个 delete 的同类 insert 都在其后
        self.assertLess(kinds.index("delete:stat_finger"), max(i for i, k in enumerate(kinds) if k == "insert:stat_finger"))


if __name__ == "__main__":
    unittest.main()
