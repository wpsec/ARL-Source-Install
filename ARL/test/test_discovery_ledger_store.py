"""
created by arrows:
- task: 重写 ledger store 测试（原子 claim + owner/lease 接管）
- original-file: test_discovery_ledger_store.py
"""

import time
import unittest

from app.services.discovery_ledger_store import MongoLedgerBackend


class DuplicateKeyError(Exception):
    pass


def _match_value(actual, spec):
    if isinstance(spec, dict):
        if "$in" in spec:
            return actual in spec["$in"]
        if "$regex" in spec:
            import re as _re
            try:
                return bool(actual is not None and _re.search(spec["$regex"], str(actual)))
            except _re.error:
                return False
        if "$lt" in spec:
            try:
                return actual is not None and float(actual) < float(spec["$lt"])
            except (TypeError, ValueError):
                return False
        return actual == spec
    return actual == spec


def _match(doc, query):
    for key, cond in (query or {}).items():
        if key == "$and":
            if not all(_match(doc, sub) for sub in cond):
                return False
            continue
        if key == "$or":
            if not any(_match(doc, sub) for sub in cond):
                return False
            continue
        if not _match_value(doc.get(key), cond):
            return False
    return True


class FakeCollection(object):
    def __init__(self):
        self.docs = {}
        self.calls = []

    @staticmethod
    def _key_of(query):
        for sub in (query or {}).get("$and", []):
            if "key" in sub:
                return sub["key"]
        return (query or {}).get("key")

    def find(self, query, projection=None):
        key_hint = self._key_of(query)
        for doc in self.docs.values():
            if _match(doc, query):
                yield dict(doc)

    def find_one(self, query, projection=None):
        self.calls.append(("find_one", query))
        doc = self.docs.get(self._key_of(query))
        return dict(doc) if doc else None

    def replace_one(self, query, doc, upsert=False):
        key = self._key_of(query)
        self.calls.append(("replace_one", query, dict(doc)))
        self.docs[key] = dict(doc)

    def update_one(self, query, update, upsert=False):
        key = self._key_of(query)
        self.calls.append(("update_one", query, dict(update)))
        existing = self.docs.get(key)
        result = type("R", (), {"matched_count": 0})()
        if existing is not None and _match(existing, query):
            existing.update(dict(update.get("$set") or {}))
            result = type("R", (), {"matched_count": 1})()
            return result
        if existing is None and upsert:
            created = {"key": key}
            created.update(dict(update.get("$setOnInsert") or {}))
            created.update(dict(update.get("$set") or {}))
            self.docs[key] = created
        return result

    def find_one_and_update(self, query, update, return_document=None,
                             upsert=False, sort=None, **kwargs):
        key = self._key_of(query)
        self.calls.append(("find_one_and_update", query, dict(update)))
        existing = self.docs.get(key)
        if existing is not None:
            if _match(existing, query):
                existing.update(dict(update.get("$set") or {}))
                return dict(existing)
            raise DuplicateKeyError("E11000 duplicate key: " + str(key))
        if not upsert:
            return None
        created = {"key": key}
        created.update(dict(update.get("$setOnInsert") or {}))
        created.update(dict(update.get("$set") or {}))
        self.docs[key] = created
        return dict(created)


class LedgerBackendTests(unittest.TestCase):
    def setUp(self):
        self.col = FakeCollection()

    def _new_backend(self):
        backend = MongoLedgerBackend("task-1")
        backend._db = lambda: self.col
        return backend

    def test_claim_sets_claiming_with_owner_and_lease(self):
        backend = self._new_backend()
        self.assertTrue(backend.claim("job-1", input_count=3))
        doc = self.col.docs["job-1"]
        self.assertEqual("claiming", doc["status"])
        self.assertEqual(backend.owner, doc["owner"])
        self.assertEqual(3, doc["input_count"])
        self.assertGreater(doc["lease_expires_at"], time.time())

    def test_second_claim_rejected_and_not_stolen(self):
        first = self._new_backend()
        second = self._new_backend()
        self.assertTrue(first.claim("job-1"))
        self.assertFalse(second.claim("job-1"))
        self.assertEqual(first.owner, self.col.docs["job-1"]["owner"])
        self.assertEqual("claiming", self.col.docs["job-1"]["status"])

    def test_expired_lease_can_be_taken_over(self):
        first = self._new_backend()
        self.assertTrue(first.claim("job-1"))
        self.col.docs["job-1"]["lease_expires_at"] = 0.0
        second = self._new_backend()
        self.assertTrue(second.claim("job-1"))
        self.assertEqual(second.owner, self.col.docs["job-1"]["owner"])

    def test_covered_cannot_be_claimed_again(self):
        backend = self._new_backend()
        self.assertTrue(backend.claim("job-1"))
        backend.finish("job-1", "covered", input_count=1, output_count=1)
        other = self._new_backend()
        self.assertFalse(other.claim("job-1"))
        self.assertEqual("covered", self.col.docs["job-1"]["status"])

    def test_failed_can_be_reclaimed(self):
        backend = self._new_backend()
        self.assertTrue(backend.claim("job-1"))
        backend.finish("job-1", "failed", input_count=2)
        self.assertTrue(backend.claim("job-1"))
        self.assertEqual("claiming", self.col.docs["job-1"]["status"])

    def test_finish_replaces_full_doc_and_clears_lease(self):
        backend = self._new_backend()
        self.assertTrue(backend.claim("job-1", input_count=2))
        result = backend.finish("job-1", "covered", input_count=2,
                                output_count=3)
        self.assertEqual("covered", result.status)
        doc = self.col.docs["job-1"]
        self.assertEqual(3, doc["output_count"])
        self.assertEqual("", doc["owner"])
        self.assertEqual(0.0, doc["lease_expires_at"])

    def test_finish_creates_record_when_absent(self):
        backend = self._new_backend()
        backend.finish("job-1", "failed", input_count=2)
        self.assertEqual("failed", self.col.docs["job-1"]["status"])
        self.assertEqual("task-1", self.col.docs["job-1"]["task_id"])

    def test_finish_fenced_from_takeover_owner(self):
        first = self._new_backend()
        self.assertTrue(first.claim("job-1"))
        # 租约过期，second 接管
        self.col.docs["job-1"]["lease_expires_at"] = 0.0
        second = self._new_backend()
        self.assertTrue(second.claim("job-1"))
        # 旧 worker 回写必须被拒
        before = dict(self.col.docs["job-1"])
        first.finish("job-1", "covered", input_count=1, output_count=99)
        self.assertEqual(before["owner"], self.col.docs["job-1"]["owner"])
        self.assertEqual(before["status"], self.col.docs["job-1"]["status"])
        self.assertNotEqual(99, self.col.docs["job-1"].get("output_count"))
        # 新 owner 正常回写
        second.finish("job-1", "covered", input_count=1, output_count=3)
        self.assertEqual("covered", self.col.docs["job-1"]["status"])
        self.assertEqual(3, self.col.docs["job-1"]["output_count"])

    def test_finish_confirm_query_failure_does_not_overwrite_takeover(self):
        # 已被他人接管：update 正常判负后确认查询抛异常，
        # 必须拒写而不是退回整条覆盖写。
        first = self._new_backend()
        second = self._new_backend()
        second.claim("job-1", input_count=5)
        before = dict(self.col.docs["job-1"])

        def boom(*args, **kwargs):
            raise RuntimeError("db read down")

        self.col.find_one = boom
        first.finish("job-1", "covered", input_count=1, output_count=99)
        self.assertEqual(before["owner"], self.col.docs["job-1"]["owner"])
        self.assertEqual("claiming", self.col.docs["job-1"]["status"])
        self.assertNotIn(
            "replace_one", [c[0] for c in self.col.calls])

    def test_finish_update_and_confirm_failure_does_not_overwrite(self):
        # update 与确认查询都故障：归属未知，拒写、不阻断、不覆盖。
        other = self._new_backend()
        other.claim("job-1", input_count=5)
        before = dict(self.col.docs["job-1"])
        backend = self._new_backend()

        def boom_update(*args, **kwargs):
            raise RuntimeError("db write down")

        def boom_read(*args, **kwargs):
            raise RuntimeError("db read down")

        self.col.update_one = boom_update
        self.col.find_one = boom_read
        entry = backend.finish("job-1", "covered", output_count=99)
        self.assertEqual("covered", entry.status)
        self.assertEqual(before["owner"], self.col.docs["job-1"]["owner"])
        self.assertEqual(5, self.col.docs["job-1"]["input_count"])
        self.assertNotIn(
            "replace_one", [c[0] for c in self.col.calls])

    def test_finish_update_failure_but_still_owned_rewrites(self):
        # update 误报异常但归属确认仍是自己：允许整条覆盖写落结果。
        backend = self._new_backend()
        backend.claim("job-1", input_count=2)

        def boom_update(*args, **kwargs):
            raise RuntimeError("transient write error")

        self.col.update_one = boom_update
        backend.finish("job-1", "covered", input_count=2, output_count=3)
        doc = self.col.docs["job-1"]
        self.assertEqual("covered", doc["status"])
        self.assertEqual(3, doc["output_count"])
        self.assertEqual("", doc["owner"])

    def test_covered_finish_is_idempotent_noop(self):
        backend = self._new_backend()
        backend.claim("job-1")
        backend.finish("job-1", "covered", input_count=1, output_count=2)
        other = self._new_backend()
        result = other.finish("job-1", "covered", input_count=1, output_count=77)
        self.assertEqual(2, self.col.docs["job-1"]["output_count"])
        self.assertEqual("covered", result.status)


    def test_duplicate_error_detection_variants(self):
        dup_cls = type("DuplicateKeyError", (Exception,), {})
        self.assertTrue(
            MongoLedgerBackend.is_duplicate_key_error(
                DuplicateKeyError("E11000 duplicate key")))
        self.assertTrue(
            MongoLedgerBackend.is_duplicate_key_error(dup_cls()))
        self.assertFalse(
            MongoLedgerBackend.is_duplicate_key_error(
                RuntimeError("network unreachable")))

    def test_service_unavailable_fails_open_not_covered(self):
        class Broken(object):
            def find_one(self, query, projection=None):
                raise RuntimeError("db down")

            def find_one_and_update(self, *args, **kwargs):
                raise RuntimeError("db down")

        backend = self._new_backend()
        backend._db = lambda: self.col and None or Broken()
        self.assertTrue(backend.claim("job-1"))
        self.assertIsNone(backend.get("job-1"))
        self.assertFalse(backend.is_covered("job-1"))

    def test_overflow_persist_and_list_pending(self):
        from app.services.discovery_context import DiscoveryContext, DiscoveryLedger
        backend = MongoLedgerBackend("task-1")
        backend._db = lambda: self.col
        context = DiscoveryContext("task-1", ledger=DiscoveryLedger(backend), candidate_max_entries=120)
        # 注册超过上限触发驱逐：新入队者应把旧的 discovered 候选写入 overflow 账本
        for i in range(140):
            context.register_candidate("UrlCandidateDiscovered", "https://example.com/p%d" % i, "url", "page_intel")
        self.assertGreater(context.metrics_snapshot().get("candidate_evicted_count", 0), 0)
        pending = backend.list_pending("candidate_overflow|")
        self.assertGreaterEqual(len(pending), 1)

        restored = context.restore_overflow_candidates()
        self.assertGreaterEqual(restored, 1)
        # 恢复后再次注册同源候选应为幂等合并（不新增条目数超界恶化）
        self.assertGreater(len(context.candidate_registry), 100)



if __name__ == "__main__":
    unittest.main()
