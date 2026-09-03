"""验证 WebSiteFetch 接入统一阶段执行器。"""

import unittest

try:
    from app.services.commonTask import WebSiteFetch
except Exception as exc:
    WebSiteFetch = None
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None


@unittest.skipIf(
    WebSiteFetch is None,
    "requires commonTask dependencies: {}".format(IMPORT_ERROR),
)
class TestWebSiteFetchStageExecutor(unittest.TestCase):
    def test_run_func_uses_shared_stage_executor(self):
        class FakeBaseUpdateTask(object):
            def __init__(self):
                self.calls = []

            def update_task_field(self, field, value):
                self.calls.append(("update", field, value))

            def start_stage(self, name, **kwargs):
                self.calls.append(("start", name, kwargs))
                return {"name": name}

            def finish_stage(self, context, **kwargs):
                self.calls.append(("finish", context, kwargs))

        task = WebSiteFetch(
            task_id="task-1",
            sites=["https://example.com"],
            options={},
        )
        task.base_update_task = FakeBaseUpdateTask()

        task.run_func("find_site", lambda: ["https://example.com"])

        self.assertEqual(("update", "status", "find_site"), task.base_update_task.calls[0])
        self.assertEqual("start", task.base_update_task.calls[1][0])
        self.assertEqual("find_site", task.base_update_task.calls[1][1])
        self.assertEqual("finish", task.base_update_task.calls[2][0])
        self.assertEqual(1, task.base_update_task.calls[2][2]["output_count"])


if __name__ == "__main__":
    unittest.main()
