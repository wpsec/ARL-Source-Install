"""阶段执行器回归测试。"""

import importlib.util
import time
import unittest
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "stage_executor.py"
_SPEC = importlib.util.spec_from_file_location("stage_executor_test_module", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)
StageExecutor = _MODULE.StageExecutor


class _Logger(object):
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(("info", message))

    def warning(self, message):
        self.messages.append(("warning", message))


class _BaseUpdateTask(object):
    def __init__(self):
        self.calls = []

    def update_task_field(self, field, value):
        self.calls.append(("update", field, value))

    def start_stage(self, name, **kwargs):
        self.calls.append(("start", name, kwargs))
        return {"name": name}

    def finish_stage(self, context, **kwargs):
        self.calls.append(("finish", context, kwargs))


class TestStageExecutor(unittest.TestCase):
    def _executor(self, base_update_task):
        logger = _Logger()
        executor = StageExecutor(
            task_id="task-1",
            base_update_task=base_update_task,
            logger=logger,
            input_count_provider=lambda _name: 4,
            budget_provider=lambda _name: 12,
            result_metadata_provider=lambda _result: (2, {"cpu_elapsed_sec": 0.2}),
            failure_reason_provider=lambda exc: "timeout" if isinstance(exc, TimeoutError) else "exception",
            description_provider=lambda: "task-description",
        )
        return executor, logger

    def test_success_records_stage_metadata(self):
        base_update_task = _BaseUpdateTask()
        executor, logger = self._executor(base_update_task)

        result = executor.execute(
            "wih_primary_scan",
            lambda: ["record-1", "record-2"],
            detail="targets=4",
            stage_kind="execution",
            log_kind="substage",
        )

        self.assertEqual(["record-1", "record-2"], result)
        self.assertEqual(("update", "status", "wih_primary_scan"), base_update_task.calls[0])
        self.assertEqual("start", base_update_task.calls[1][0])
        self.assertEqual("wih_primary_scan", base_update_task.calls[1][1])
        self.assertEqual(4, base_update_task.calls[1][2]["input_count"])
        self.assertEqual(12, base_update_task.calls[1][2]["budget_sec"])
        self.assertEqual("finish", base_update_task.calls[2][0])
        self.assertEqual(2, base_update_task.calls[2][2]["output_count"])
        self.assertEqual({"cpu_elapsed_sec": 0.2}, base_update_task.calls[2][2]["metrics"])
        self.assertEqual("substage", logger.messages[-1][1].split()[1])

    def test_failure_records_timeout_and_reraises(self):
        base_update_task = _BaseUpdateTask()
        executor, logger = self._executor(base_update_task)

        with self.assertRaises(TimeoutError):
            executor.execute("wih_urlfinder_sensitive", lambda: (_ for _ in ()).throw(TimeoutError("deadline")))

        finish_call = base_update_task.calls[-1]
        self.assertEqual("finish", finish_call[0])
        self.assertEqual("timeout", finish_call[2]["status"])
        self.assertEqual("timeout", finish_call[2]["end_reason"])
        self.assertEqual("warning", logger.messages[-1][0])

    def test_result_metrics_mark_degraded_stage_without_raising(self):
        base_update_task = _BaseUpdateTask()
        logger = _Logger()
        executor = StageExecutor(
            task_id="task-1",
            base_update_task=base_update_task,
            logger=logger,
            result_metadata_provider=lambda _result: (
                3,
                {
                    "status": "partial",
                    "end_reason": "provider_timeout",
                    "timeout_count": 1,
                },
            ),
        )

        result = executor.execute("search_engines", lambda: ["a", "b", "c"])

        self.assertEqual(["a", "b", "c"], result)
        finish_call = base_update_task.calls[-1]
        self.assertEqual("partial", finish_call[2]["status"])
        self.assertEqual("provider_timeout", finish_call[2]["end_reason"])

    def test_metadata_failure_records_stage_error_and_reraises(self):
        base_update_task = _BaseUpdateTask()
        logger = _Logger()
        executor = StageExecutor(
            task_id="task-1",
            base_update_task=base_update_task,
            logger=logger,
            input_count_provider=lambda _name: 4,
            budget_provider=lambda _name: 12,
            result_metadata_provider=lambda _result: (_ for _ in ()).throw(
                ValueError("metadata unavailable")
            ),
            failure_reason_provider=lambda _exc: "metadata_error",
            description_provider=lambda: "task-description",
        )

        with self.assertRaises(ValueError):
            executor.execute("wih_metadata", lambda: ["record-1"])

        finish_call = base_update_task.calls[-1]
        self.assertEqual("finish", finish_call[0])
        self.assertEqual("error", finish_call[2]["status"])
        self.assertEqual("metadata_error", finish_call[2]["end_reason"])
        self.assertEqual("warning", logger.messages[-1][0])

    def test_budget_context_marks_overrun_as_partial(self):
        base_update_task = _BaseUpdateTask()
        executor, _logger = self._executor(base_update_task)

        def slow_stage():
            time.sleep(0.02)
            return ["record-1", "record-2"]

        result = executor.execute(
            "budgeted_stage",
            slow_stage,
            budget_sec=0.001,
        )

        self.assertEqual(["record-1", "record-2"], result)
        finish_call = base_update_task.calls[-1]
        self.assertEqual("partial", finish_call[2]["status"])
        self.assertEqual("budget_exceeded", finish_call[2]["end_reason"])
        self.assertTrue(finish_call[2]["metrics"]["budget_exceeded"])

    def test_failure_beyond_budget_records_budget_evidence(self):
        # deadline 收敛导致 provider 在预算外抛错：异常分支必须留超预算证据，
        # 否则"拖满预算倒下"与普通报错在观测数据里不可区分。
        base_update_task = _BaseUpdateTask()
        executor, logger = self._executor(base_update_task)

        def slow_fail():
            time.sleep(0.02)
            raise TimeoutError("deadline")

        with self.assertRaises(TimeoutError):
            executor.execute("budgeted_fail_stage", slow_fail, budget_sec=0.001)

        finish_call = base_update_task.calls[-1]
        self.assertEqual("timeout", finish_call[2]["status"])
        self.assertTrue(finish_call[2]["metrics"]["budget_exceeded"])
        self.assertEqual(0.001, finish_call[2]["metrics"]["budget_sec"])
        self.assertGreater(
            finish_call[2]["metrics"]["elapsed_sec"], 0.001)
        self.assertIn("budget_exceeded:True", logger.messages[-1][1])


if __name__ == "__main__":
    unittest.main()
