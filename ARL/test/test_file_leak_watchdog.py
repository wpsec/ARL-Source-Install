import unittest
from unittest.mock import MagicMock, patch

IMPORT_ERROR = None
try:
    import app.services.fileLeak as file_leak_module
    from app.services.commonTask import WebSiteFetch
except Exception as exc:
    file_leak_module = None
    WebSiteFetch = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires file leak test dependencies: {}".format(IMPORT_ERROR))
class TestFileLeakWatchdog(unittest.TestCase):
    def test_watchdog_kills_hanging_worker_on_no_progress(self):
        class HangingProc(object):
            pid = 43210
            returncode = None

            def poll(self):
                return None

            def wait(self, timeout=None):
                return None

        time_values = iter([0, 3, 3, 3])

        with patch.object(file_leak_module, "_read_heartbeat_timestamp", return_value=0), \
             patch.object(file_leak_module, "_kill_file_leak_subprocess") as mock_kill:
            result = file_leak_module._run_file_leak_site_with_watchdog(
                target="https://example.com",
                urls={file_leak_module.URL("https://example.com/admin", "admin")},
                concurrency=2,
                site_timeout_sec=30,
                no_progress_timeout_sec=2,
                popen_factory=lambda *args, **kwargs: HangingProc(),
                sleep_fn=lambda *args, **kwargs: None,
                time_fn=lambda: next(time_values),
            )

        self.assertEqual(result, [])
        mock_kill.assert_called_once()

    def test_watchdog_returns_serialized_pages_on_success(self):
        expected_pages = [
            {
                "url": "https://example.com/admin",
                "title": "Admin",
                "content_length": 128,
                "status_code": 200,
            }
        ]

        class DoneProc(object):
            pid = 12345
            returncode = 0

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

        with patch.object(file_leak_module, "_read_json_file", return_value={"ok": True, "pages": expected_pages}):
            result = file_leak_module._run_file_leak_site_with_watchdog(
                target="https://example.com",
                urls={file_leak_module.URL("https://example.com/admin", "admin")},
                concurrency=2,
                site_timeout_sec=30,
                no_progress_timeout_sec=10,
                popen_factory=lambda *args, **kwargs: DoneProc(),
                sleep_fn=lambda *args, **kwargs: None,
                time_fn=lambda: 0,
            )

        self.assertEqual(result, expected_pages)

    @patch("app.services.commonTask.utils.load_file", return_value=["admin"])
    @patch("app.services.commonTask.os.path.isfile", return_value=False)
    @patch("app.services.commonTask.services.file_leak")
    @patch("app.services.commonTask.utils.conn_db")
    def test_common_task_file_leak_accepts_serialized_items(
        self,
        mock_conn_db,
        mock_file_leak,
        mock_isfile,
        mock_load_file,
    ):
        mock_file_leak.return_value = [
            {
                "title": "Admin",
                "url": "https://example.com/admin",
                "content_length": 128,
                "status_code": 200,
            }
        ]
        collection = MagicMock()
        mock_conn_db.return_value = collection

        task = WebSiteFetch(task_id="task-1", sites=["https://example.com"], options={})
        task._poc_sites = {"https://example.com"}
        task.file_leak()

        collection.insert_one.assert_called_once_with(
            {
                "title": "Admin",
                "url": "https://example.com/admin",
                "content_length": 128,
                "status_code": 200,
                "task_id": "task-1",
                "site": "https://example.com",
            }
        )


if __name__ == "__main__":
    unittest.main()
