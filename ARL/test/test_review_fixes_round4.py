"""第四轮 review 修复回归：吞异常观测化、驱逐回调计数。"""
import unittest
from unittest.mock import patch

from app.services.discovery_context import DiscoveryContext


@unittest.skipIf(DiscoveryContext is None, "运行依赖未安装")
class TestEvictCallbackObservability(unittest.TestCase):
    def test_registry_counts_callback_failure(self):
        # 驱逐回调失败意味着这批候选没有落进 overflow 账本，
        # 必须计数可观测而非静默吞。
        def boom(count, records):
            raise RuntimeError("ledger down")

        ctx = DiscoveryContext("task-1", candidate_max_entries=120)
        ctx.candidate_registry._on_evict = boom
        for i in range(150):
            ctx.register_candidate(
                "UrlCandidateDiscovered",
                "https://evict.test/p%d" % i, "url", "unit")
        self.assertGreaterEqual(
            getattr(ctx.candidate_registry, "evict_callback_failed_count", 0), 1)
        self.assertGreaterEqual(
            ctx.observation_snapshot()["candidate_evict_callback_failures"], 1)


class TestFileLeakResponseReflow(unittest.TestCase):
    def test_child_responses_registered_with_dedicated_profile(self):
        import base64

        from app.services.fileLeak import _apply_child_responses

        ctx = DiscoveryContext("task-1")
        result = {
            "responses": [
                {
                    "url": "http://leak.test/.env",
                    "status_code": 200,
                    "headers": {"Content-Type": "text/plain"},
                    "body_b64": base64.b64encode(b"SECRET=x").decode("ascii"),
                },
            ],
        }
        _apply_child_responses(ctx, result)

        record = ctx.get_response(
            "http://leak.test/.env", request_profile="file_leak_get",
            consumer="unit")
        self.assertIsNotNone(record, "子进程命中响应必须回登记")
        self.assertIn(b"SECRET", record.body)
        # 目录语义不得伪装成页面抓取 profile
        self.assertIsNone(ctx.get_response(
            "http://leak.test/.env", request_profile="html_get", consumer="unit"))


class TestWafLedgerReflow(unittest.TestCase):
    def _ledger(self):
        from app.services.discovery_context import DiscoveryLedger
        return DiscoveryLedger()

    def test_class_block_persisted_once_and_restored(self):
        ledger = self._ledger()
        ctx1 = DiscoveryContext("task-x", ledger=ledger)
        first = ctx1.record_waf_signal(
            "http://waf.test/api", "wih", reason="unit", force=True)
        self.assertTrue(first.get("newly_blocked"))
        second = ctx1.record_waf_signal(
            "http://waf.test/api", "wih", reason="again", force=True)
        self.assertFalse(second.get("newly_blocked"), "重复信号不得重复落账")

        # 新 context（模拟重投）未回灌前是放行态，回灌后恢复熔断。
        ctx2 = DiscoveryContext("task-x", ledger=ledger)
        self.assertTrue(ctx2.waf_policy.allow("http://waf.test/api", "wih"))
        self.assertEqual(1, ctx2.restore_waf_state())
        self.assertFalse(ctx2.waf_policy.allow("http://waf.test/api", "wih"))
        self.assertTrue(ctx2.waf_policy.allow("http://waf.test/api", "normal"))

    def test_host_wide_block_restores_all_classes(self):
        ledger = self._ledger()
        DiscoveryContext("task-y", ledger=ledger).record_waf_signal(
            "http://wide.test/x", "normal", reason="unit", host_wide=True)
        ctx2 = DiscoveryContext("task-y", ledger=ledger)
        self.assertEqual(1, ctx2.restore_waf_state())
        for traffic_class in ("normal", "wih", "directory"):
            self.assertFalse(
                ctx2.waf_policy.allow("http://wide.test/x", traffic_class))


class TestDomainTrailingColonNormalize(unittest.TestCase):
    """x86 真实扫描发现 https://host:/ 脏 URL：入口+出口双向收敛。"""

    def test_domain_info_strips_empty_port_colon(self):
        from app.modules.domainInfo import DomainInfo
        info = DomainInfo("host.example.com:", [], "A", [])
        self.assertEqual("host.example.com", info.domain)

    def test_probe_targets_normalized_and_empty_skipped(self):
        from app.services.probeHTTP import ProbeHTTP
        self_arg = object.__new__(ProbeHTTP)
        targets = ProbeHTTP._build_targets(
            self_arg, ["dirty.example.com:", "ok.example.com", " ", ""])
        self.assertIn("https://dirty.example.com", targets)
        self.assertNotIn("https://dirty.example.com:", targets)
        self.assertNotIn("https://", targets)


class TestScopeGuardFailureVisible(unittest.TestCase):
    def test_task_doc_db_failure_logs(self):
        from app.services import task_scope_guard as guard_mod
        tid = "507f1f77bcf86cd799439011"

        class BrokenDB(object):
            def find_one(self, *a, **k):
                raise RuntimeError("db down")

            def find(self, *a, **k):
                raise RuntimeError("db down")

        with patch.object(guard_mod.utils, "conn_db", return_value=BrokenDB()), \
                patch.object(guard_mod.logger, "warning") as warn:
            ctx = guard_mod.load_task_scope_context(
                task_id=tid, seed_sites=["http://seed.test"])
        self.assertIn("seed.test", ctx["allowed_hosts"])
        messages = [str(c.args[0]) for c in warn.call_args_list]
        self.assertTrue(any("scope guard" in m for m in messages),
                        "scope 静默缩小必须留 warning")


if __name__ == "__main__":
    unittest.main()
