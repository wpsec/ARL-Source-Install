"""第六轮 Review 整改回归：阶段推进、POC 异常和子进程计数契约。"""

import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class _TaskCollection(object):
    def __init__(self, document):
        self.document = dict(document)
        self.update_calls = []

    def find_one(self, query, projection=None):
        return dict(self.document)

    def update_one(self, query, update, **kwargs):
        self.update_calls.append((query, update))
        return SimpleNamespace(modified_count=1)


class TestReviewFixesRound6(unittest.TestCase):
    def test_stage_transition_requires_current_stage(self):
        import app.celerytask as celerytask

        collection = _TaskCollection({
            "status": "deep_scan_running",
            "deep_scan": {
                "status": "running",
                "stage": "site",
            },
        })
        with patch.object(celerytask.utils, "conn_db", return_value=collection):
            self.assertTrue(
                celerytask._complete_domain_deep_stage(
                    "task-1", "site", next_stage="vhost"
                )
            )
        query, update = collection.update_calls[0]
        self.assertEqual("site", query["deep_scan.stage"])
        self.assertEqual("vhost", update["$set"]["deep_scan.stage"])
        self.assertEqual("pending", update["$set"]["deep_scan.status"])

    def test_n_poc_preserves_partial_runner_and_parse_errors(self):
        from app.services.npoc import NPoC
        from xing.conf import Conf

        with tempfile.TemporaryDirectory() as temp_dir:
            runner_holder = {}

            class BrokenRunner(object):
                errors = []

                def run(self):
                    with open(Conf.SAVE_JSON_RESULT_FILENAME, "w", encoding="utf-8") as file_obj:
                        file_obj.write("not-json\n")
                    raise RuntimeError("runner failed /Users/test")

            instance = NPoC(tmp_dir=temp_dir)
            instance.runner = BrokenRunner()
            result = instance.run_poc(["poc-example"], ["https://example.test"])

        self.assertGreaterEqual(len(result), 2)
        self.assertTrue(all(item.get("result_status") == "partial" for item in result))
        self.assertTrue(all("/Users/test" not in item.get("error", "") for item in result))

    def test_file_leak_child_metrics_record_incomplete_state(self):
        from app.services.fileLeak import _record_child_request_metrics

        class Context(object):
            def __init__(self):
                self.metrics = {}

            def record_metric(self, name, amount=1):
                self.metrics[name] = self.metrics.get(name, 0) + amount

        context = Context()
        _record_child_request_metrics(context, {"metrics": {
            "request_count": 3,
            "dedup_hit": 2,
            "metrics_complete": False,
        }})
        self.assertEqual(3, context.metrics["external_network_file_leak_request_count"])
        self.assertEqual(2, context.metrics["external_network_file_leak_dedup_hit"])
        self.assertEqual(1, context.metrics["external_network_file_leak_metrics_incomplete"])


if __name__ == "__main__":
    unittest.main()
