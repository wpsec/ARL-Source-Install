import importlib.util
import pathlib
import sys
import tempfile
import unittest
from pathlib import Path


def _load_process_monitor_module():
    module_name = "system_monitor_processes_test_module"
    if module_name in sys.modules:
        return sys.modules[module_name]
    module_path = (
        pathlib.Path(__file__).resolve().parents[1]
        / "app"
        / "services"
        / "system_monitor_processes.py"
    )
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


process_monitor = _load_process_monitor_module()


class TestSystemMonitorProcesses(unittest.TestCase):
    def test_aggregate_counts_only_live_container_snapshots(self):
        with tempfile.TemporaryDirectory() as monitor_dir:
            self.assertTrue(process_monitor.write_process_snapshot(4, "web", monitor_dir, updated_at=100.0))
            self.assertTrue(process_monitor.write_process_snapshot(9, "worker_1", monitor_dir, updated_at=100.0))
            self.assertTrue(process_monitor.write_process_snapshot(20, "worker_2", monitor_dir, updated_at=80.0))

            total, snapshots = process_monitor.aggregate_process_counts(
                expected_instances=("web", "worker_1", "worker_2", "scheduler"),
                monitor_dir=monitor_dir,
                now=100.0,
                stale_after_sec=15.0,
            )

            self.assertEqual(13, total)
            self.assertEqual({"web", "worker_1"}, set(snapshots))
            self.assertFalse((Path(monitor_dir) / "scheduler.json").exists())

    def test_invalid_snapshot_is_ignored_without_breaking_other_containers(self):
        with tempfile.TemporaryDirectory() as monitor_dir:
            self.assertTrue(process_monitor.write_process_snapshot(7, "web", monitor_dir, updated_at=200.0))
            (Path(monitor_dir) / "worker_1.json").write_text("not-json", encoding="utf-8")

            snapshots = process_monitor.read_process_snapshots(
                expected_instances=("web", "worker_1"),
                monitor_dir=monitor_dir,
                now=200.0,
                stale_after_sec=15.0,
            )

            self.assertEqual([7], [item["process_count"] for item in snapshots.values()])


if __name__ == "__main__":
    unittest.main()
