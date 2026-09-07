import importlib.util
import pathlib
import signal
import subprocess
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "check-test-hygiene.py"
SPEC = importlib.util.spec_from_file_location("check_test_hygiene", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CheckTestHygieneTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
