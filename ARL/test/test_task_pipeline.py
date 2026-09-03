"""任务阶段流水线测试。"""

import importlib.util
import unittest
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "task_pipeline.py"
_SPEC = importlib.util.spec_from_file_location("task_pipeline_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)
TaskPipeline = _MODULE.TaskPipeline


class _Executor(object):
    def __init__(self):
        self.calls = []

    def execute(self, name, func, **kwargs):
        self.calls.append((name, kwargs))
        return func()


class _Task(object):
    def __init__(self):
        self.executor = _Executor()

    def _get_stage_executor(self):
        return self.executor


class TestTaskPipeline(unittest.TestCase):
    def test_disabled_stage_is_not_executed(self):
        task = _Task()
        called = []
        result = TaskPipeline(task).run_many([
            {"name": "disabled", "enabled": False, "func": lambda: called.append(True)},
        ])

        self.assertIsNone(result["disabled"])
        self.assertEqual([], called)
        self.assertEqual([], task.executor.calls)

    def test_enabled_stages_keep_order_and_use_executor(self):
        task = _Task()
        result = TaskPipeline(task).run_many([
            {"name": "first", "func": lambda: "one"},
            {"name": "second", "func": lambda: "two", "detail": "targets=1"},
        ])

        self.assertEqual({"first": "one", "second": "two"}, result)
        self.assertEqual(["first", "second"], [item[0] for item in task.executor.calls])
        self.assertTrue(task.executor.calls[0][1]["trigger_ai"])


if __name__ == "__main__":
    unittest.main()
