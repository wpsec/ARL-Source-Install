import importlib.util
import pathlib
import signal
import subprocess
import sys
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "check-test-hygiene.py"
SPEC = importlib.util.spec_from_file_location("check_test_hygiene", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CheckTestHygieneTest(unittest.TestCase):
    def test_checker_reports_the_requested_module_import_error(self):
        proc = subprocess.run(
            [sys.executable, "-c", MODULE.CHECKER, "test.module_that_does_not_exist"],
            cwd=str(MODULE.ARL_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertIn("load-fail(ModuleNotFoundError:", proc.stdout)
        self.assertNotIn("load-fail(test.module_that_does_not_exist)", proc.stdout)

    def test_run_one_starts_an_isolated_process_session_on_posix(self):
        with mock.patch.object(MODULE.subprocess, "Popen") as popen:
            MODULE.run_one("test.example", {})

        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    @unittest.skipUnless(MODULE.os.name == "posix", "进程组回收仅在 POSIX 下验证")
    def test_timeout_terminates_process_group_and_drains_pipes(self):
        proc = mock.Mock(pid=1234)
        proc.wait.side_effect = [None]

        with mock.patch.object(MODULE.os, "killpg") as killpg:
            MODULE.terminate_process_tree(proc)

        killpg.assert_called_once_with(1234, signal.SIGTERM)
        proc.wait.assert_called_once_with(timeout=5)
        proc.communicate.assert_called_once_with(timeout=1)

    def test_collect_output_reaps_descendant_holding_pipe_after_parent_exit(self):
        proc = mock.Mock(pid=1234)
        proc.communicate.side_effect = subprocess.TimeoutExpired("checker", 10)

        with mock.patch.object(MODULE, "terminate_process_tree", return_value=True) as terminate:
            record = MODULE.collect_output("test.example", proc)

        self.assertEqual("test.example\ttimeout\t?", record)
        terminate.assert_called_once_with(proc)

    @unittest.skipUnless(MODULE.os.name == "posix", "进程组回收仅在 POSIX 下验证")
    def test_timeout_escalates_to_sigkill_and_still_drains_output(self):
        proc = mock.Mock(pid=1234)
        proc.wait.side_effect = [subprocess.TimeoutExpired("checker", 5), None]

        with mock.patch.object(MODULE.os, "killpg") as killpg:
            self.assertTrue(MODULE.terminate_process_tree(proc))

        self.assertEqual(
            [mock.call(1234, signal.SIGTERM), mock.call(1234, signal.SIGKILL)],
            killpg.call_args_list,
        )
        proc.wait.assert_has_calls([mock.call(timeout=5), mock.call(timeout=5)])
        proc.communicate.assert_called_once_with(timeout=1)

    def test_main_classifies_direct_timeout_as_load_failure(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        fake_time = mock.Mock()
        fake_time.monotonic.side_effect = [0.0, 1000.0]
        with mock.patch.object(MODULE, "run_one", return_value=proc), \
                mock.patch.object(MODULE, "terminate_process_tree", return_value=True), \
                mock.patch.object(MODULE, "time", fake_time):
            exit_code = MODULE.main(["check-test-hygiene", "test.example"])

        self.assertEqual(1, exit_code)


if __name__ == "__main__":
    unittest.main()
