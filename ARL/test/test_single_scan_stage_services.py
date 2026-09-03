"""单扫描阶段服务回退边界测试。"""

import unittest

from app.services.single_scan_stage_services import WebSiteSingleStageService


class _Task(object):
    task_id = "task-1"

    def __init__(self):
        self.details = []

    def run_func(self, _name, func):
        return func()

    def _mark_service_detail_override(self, name, detail):
        self.details.append((name, detail))


class _Logger(object):
    def __init__(self):
        self.messages = []

    def warning(self, message):
        self.messages.append(message)


class TestSingleScanStageServices(unittest.TestCase):
    def test_explicit_fallback_is_observable_and_scoped_to_current_stage(self):
        task = _Task()
        logger = _Logger()
        result = WebSiteSingleStageService(task, logger=logger).run(
            "file_leak",
            lambda: (_ for _ in ()).throw(RuntimeError("probe failed")),
            fallback=[],
            fallback_note="continue",
        )
        self.assertEqual([], result)
        self.assertEqual("file_leak", task.details[0][0])
        self.assertIn("degraded=true", task.details[0][1])
        self.assertTrue(logger.messages)

    def test_no_fallback_reraises_instead_of_silent_success(self):
        task = _Task()
        with self.assertRaises(RuntimeError):
            WebSiteSingleStageService(task).run(
                "fetch_site",
                lambda: (_ for _ in ()).throw(RuntimeError("required failed")),
            )


if __name__ == "__main__":
    unittest.main()
