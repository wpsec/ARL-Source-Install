import unittest
from bson import ObjectId
from unittest.mock import MagicMock, patch

from app.helpers.task import restart_task, submit_task
from app.modules import AssetScopeType, TaskStatus, TaskType
from app.scheduler import _should_dispatch_monitor_heavy_queue, submit_job


class TestQueueDispatch(unittest.TestCase):
    def _build_task_data(self, task_type=TaskType.DOMAIN, options=None):
        return {
            "name": "queue-test",
            "target": "" if task_type != TaskType.IP else "198.51.100.1",
            "start_time": "-",
            "status": TaskStatus.WAITING,
            "type": task_type,
            "task_tag": "task",
            "options": options or {},
            "end_time": "-",
            "service": [],
            "celery_id": "",
        }

    def _build_task_collection(self, object_id_hex):
        collection = MagicMock()

        def fake_insert_one(doc):
            doc["_id"] = ObjectId(object_id_hex)
            return MagicMock(inserted_id=doc["_id"])

        collection.insert_one.side_effect = fake_insert_one
        return collection

    def test_submit_task_routes_web_heavy_domain_task_to_arlweb(self):
        task_collection = self._build_task_collection("65f000000000000000000001")

        with patch("app.helpers.task.utils.conn_db", return_value=task_collection), \
                patch("app.helpers.task.is_dispatch_queue_available", side_effect=lambda name: name == "arlweb"), \
                patch("app.celerytask.arl_task") as mock_main_task, \
                patch("app.celerytask.arl_task_heavy") as mock_heavy_task, \
                patch("app.celerytask.arl_task_web") as mock_web_task:
            mock_web_task.delay.return_value = "web-celery-id"

            result = submit_task(self._build_task_data(options={"file_leak": True}))

        self.assertEqual(result["dispatch_queue"], "arlweb")
        self.assertEqual(result["dispatch_queue_reason"], "web_heavy=file_leak")
        mock_web_task.delay.assert_called_once()
        mock_main_task.delay.assert_not_called()
        mock_heavy_task.delay.assert_not_called()

        update_payload = task_collection.update_one.call_args[0][1]["$set"]
        self.assertEqual(update_payload["dispatch_queue"], "arlweb")
        self.assertEqual(update_payload["dispatch_queue_reason"], "web_heavy=file_leak")

    def test_submit_task_keeps_heavy_queue_priority_over_web_queue(self):
        task_collection = self._build_task_collection("65f000000000000000000002")

        with patch("app.helpers.task.utils.conn_db", return_value=task_collection), \
                patch("app.helpers.task.is_dispatch_queue_available", side_effect=lambda name: name in {"arlheavy", "arlweb"}), \
                patch("app.celerytask.arl_task") as mock_main_task, \
                patch("app.celerytask.arl_task_heavy") as mock_heavy_task, \
                patch("app.celerytask.arl_task_web") as mock_web_task:
            mock_heavy_task.delay.return_value = "heavy-celery-id"

            result = submit_task(
                self._build_task_data(
                    options={"port_scan": True, "port_scan_type": "all", "file_leak": True}
                )
            )

        self.assertEqual(result["dispatch_queue"], "arlheavy")
        self.assertEqual(result["dispatch_queue_reason"], "port_scan_type=all")
        mock_heavy_task.delay.assert_called_once()
        mock_web_task.delay.assert_not_called()
        mock_main_task.delay.assert_not_called()

    def test_submit_task_routes_heavy_ip_to_arlip_with_consumer(self):
        task_collection = self._build_task_collection("65f000000000000000000005")

        with patch("app.helpers.task.utils.conn_db", return_value=task_collection), \
                patch("app.helpers.task.is_dispatch_queue_available", side_effect=lambda name: name == "arlip"), \
                patch("app.celerytask.arl_task") as mock_main_task, \
                patch("app.celerytask.arl_task_heavy") as mock_heavy_task, \
                patch("app.celerytask.arl_task_ip") as mock_ip_task:
            mock_ip_task.delay.return_value = "ip-celery-id"

            result = submit_task(
                self._build_task_data(
                    task_type=TaskType.IP,
                    options={"port_scan": True, "port_scan_type": "all"},
                )
            )

        self.assertEqual(result["dispatch_queue"], "arlip")
        mock_ip_task.delay.assert_called_once()
        mock_main_task.delay.assert_not_called()
        mock_heavy_task.delay.assert_not_called()

    def test_submit_task_falls_back_when_heavy_ip_consumer_is_unavailable(self):
        task_collection = self._build_task_collection("65f000000000000000000010")

        with patch("app.helpers.task.utils.conn_db", return_value=task_collection), \
                patch("app.helpers.task.is_dispatch_queue_available", return_value=False), \
                patch("app.celerytask.arl_task") as mock_main_task, \
                patch("app.celerytask.arl_task_ip") as mock_ip_task:
            mock_main_task.delay.return_value = "fallback-ip-celery-id"

            result = submit_task(
                self._build_task_data(
                    task_type=TaskType.IP,
                    options={"port_scan": True, "port_scan_type": "all"},
                )
            )

        self.assertEqual(result["dispatch_queue"], "arltask")
        self.assertEqual(result["dispatch_queue_reason"], "fallback:ip_queue_unavailable")
        mock_main_task.delay.assert_called_once()
        mock_ip_task.delay.assert_not_called()

    def test_restart_task_reclassifies_heavy_ip_to_arlip(self):
        task_id = "65f000000000000000000008"
        old_task = self._build_task_data(
            task_type=TaskType.IP,
            options={"port_scan": True, "port_scan_type": "all"},
        )
        old_task.update({
            "_id": ObjectId(task_id),
            "dispatch_queue": "arltask",
            "dispatch_queue_reason": "restart_force_main_queue",
            "dispatch_time": "2026-10-17 13:00:00",
            "dispatch_ts": 1792209600,
        })
        task_collection = self._build_task_collection("65f000000000000000000009")

        with patch("app.helpers.task.get_task_data", return_value=old_task), \
                patch("app.helpers.task.utils.conn_db", return_value=task_collection), \
                patch("app.helpers.task.is_dispatch_queue_available", side_effect=lambda name: name == "arlip"), \
                patch("app.celerytask.arl_task") as mock_main_task, \
                patch("app.celerytask.arl_task_heavy") as mock_heavy_task, \
                patch("app.celerytask.arl_task_ip") as mock_ip_task:
            mock_ip_task.delay.return_value = "restart-ip-celery-id"

            result = restart_task(task_id)

        self.assertEqual(result["dispatch_queue"], "arlip")
        self.assertEqual(result["dispatch_queue_reason"], "port_scan_type=all")
        mock_ip_task.delay.assert_called_once()
        mock_main_task.delay.assert_not_called()
        mock_heavy_task.delay.assert_not_called()

    def test_submit_task_keeps_light_ip_on_existing_main_queue(self):
        task_collection = self._build_task_collection("65f000000000000000000007")

        with patch("app.helpers.task.utils.conn_db", return_value=task_collection), \
                patch("app.helpers.task.is_dispatch_queue_available", return_value=False), \
                patch("app.celerytask.arl_task") as mock_main_task, \
                patch("app.celerytask.arl_task_ip") as mock_ip_task:
            mock_main_task.delay.return_value = "light-ip-celery-id"

            result = submit_task(
                self._build_task_data(
                    task_type=TaskType.IP,
                    options={"port_scan": True, "port_scan_type": "test"},
                )
            )

        self.assertEqual(result["dispatch_queue"], "arltask")
        mock_main_task.delay.assert_called_once()
        mock_ip_task.delay.assert_not_called()

    def test_domain_heavy_scan_stays_on_arlheavy(self):
        task_collection = self._build_task_collection("65f000000000000000000006")

        with patch("app.helpers.task.utils.conn_db", return_value=task_collection), \
                patch("app.helpers.task.is_dispatch_queue_available", return_value=True), \
                patch("app.celerytask.arl_task") as mock_main_task, \
                patch("app.celerytask.arl_task_heavy") as mock_heavy_task, \
                patch("app.celerytask.arl_task_ip") as mock_ip_task:
            mock_heavy_task.delay.return_value = "domain-celery-id"

            result = submit_task(
                self._build_task_data(
                    options={"port_scan": True, "port_scan_type": "all"},
                )
            )

        self.assertEqual(result["dispatch_queue"], "arlheavy")
        mock_heavy_task.delay.assert_called_once()
        mock_ip_task.delay.assert_not_called()
        mock_main_task.delay.assert_not_called()

    def test_submit_task_falls_back_to_main_queue_when_arlweb_unavailable(self):
        task_collection = self._build_task_collection("65f000000000000000000003")

        with patch("app.helpers.task.utils.conn_db", return_value=task_collection), \
                patch("app.helpers.task.is_dispatch_queue_available", return_value=False), \
                patch("app.celerytask.arl_task") as mock_main_task, \
                patch("app.celerytask.arl_task_web") as mock_web_task:
            mock_main_task.delay.return_value = "main-celery-id"

            result = submit_task(self._build_task_data(options={"nuclei_scan": True}))

        self.assertEqual(result["dispatch_queue"], "arltask")
        self.assertEqual(result["dispatch_queue_reason"], "fallback:web_queue_unavailable")
        mock_main_task.delay.assert_called_once()
        mock_web_task.delay.assert_not_called()

    def test_submit_task_routes_asset_site_update_to_arlweb(self):
        task_collection = self._build_task_collection("65f000000000000000000004")

        with patch("app.helpers.task.utils.conn_db", return_value=task_collection), \
                patch("app.helpers.task.is_dispatch_queue_available", side_effect=lambda name: name == "arlweb"), \
                patch("app.celerytask.arl_task") as mock_main_task, \
                patch("app.celerytask.arl_task_web") as mock_web_task:
            mock_web_task.delay.return_value = "asset-web-celery-id"

            result = submit_task(
                self._build_task_data(
                    task_type=TaskType.ASSET_SITE_UPDATE,
                    options={"scope_id": "scope-1", "scheduler_id": "scheduler-1"},
                )
            )

        self.assertEqual(result["dispatch_queue"], "arlweb")
        self.assertEqual(result["dispatch_queue_reason"], "asset_site_update")
        mock_web_task.delay.assert_called_once()
        mock_main_task.delay.assert_not_called()

    def test_submit_job_routes_monitor_web_heavy_task_to_arlweb(self):
        with patch("app.scheduler._should_dispatch_monitor_heavy_queue", return_value=(False, "")), \
                patch("app.scheduler._should_dispatch_monitor_web_queue", return_value=(True, "web_heavy=file_leak")), \
                patch("app.scheduler.celerytask.arl_task") as mock_main_task, \
                patch("app.scheduler.celerytask.arl_task_heavy") as mock_heavy_task, \
                patch("app.scheduler.celerytask.arl_task_web") as mock_web_task:
            mock_web_task.delay.return_value = "monitor-web-celery-id"

            submit_job(
                domain="example.com",
                job_id="job-1",
                scope_id="scope-1",
                options={"file_leak": True},
                name="monitor-web",
                scope_type=AssetScopeType.DOMAIN,
            )

        mock_web_task.delay.assert_called_once()
        mock_main_task.delay.assert_not_called()
        mock_heavy_task.delay.assert_not_called()

    def test_submit_job_routes_heavy_ip_monitor_to_arlip(self):
        with patch("app.scheduler._should_dispatch_monitor_heavy_queue", return_value=(True, "port_scan_type=all")), \
                patch("app.scheduler.celerytask.arl_task") as mock_main_task, \
                patch("app.scheduler.celerytask.arl_task_heavy") as mock_heavy_task, \
                patch("app.scheduler.celerytask.arl_task_ip") as mock_ip_task:
            mock_ip_task.delay.return_value = "monitor-ip-celery-id"

            submit_job(
                domain="198.51.100.1",
                job_id="job-ip-1",
                scope_id="scope-ip-1",
                options={"port_scan": True, "port_scan_type": "all"},
                name="monitor-ip-heavy",
                scope_type=AssetScopeType.IP,
            )

        mock_ip_task.delay.assert_called_once()
        mock_heavy_task.delay.assert_not_called()
        mock_main_task.delay.assert_not_called()

    def test_submit_job_falls_back_when_heavy_ip_consumer_is_unavailable(self):
        with patch("app.scheduler._should_dispatch_monitor_heavy_queue", return_value=(False, "ip_queue_unavailable")), \
                patch("app.scheduler.celerytask.arl_task") as mock_main_task, \
                patch("app.scheduler.celerytask.arl_task_ip") as mock_ip_task:
            mock_main_task.delay.return_value = "monitor-ip-fallback-celery-id"

            submit_job(
                domain="198.51.100.1",
                job_id="job-ip-fallback",
                scope_id="scope-ip-fallback",
                options={"port_scan": True, "port_scan_type": "all"},
                name="monitor-ip-heavy",
                scope_type=AssetScopeType.IP,
            )

        mock_main_task.delay.assert_called_once()
        mock_ip_task.delay.assert_not_called()

    def test_monitor_heavy_ip_requires_dedicated_consumer(self):
        with patch("app.scheduler.is_dispatch_queue_available", return_value=False):
            is_heavy, reason = _should_dispatch_monitor_heavy_queue(
                "198.51.100.1",
                {"port_scan": True, "port_scan_type": "all"},
                scope_type=AssetScopeType.IP,
            )

        self.assertFalse(is_heavy)
        self.assertEqual("ip_queue_unavailable", reason)

    def test_submit_job_keeps_heavy_domain_monitor_on_arlheavy(self):
        with patch("app.scheduler._should_dispatch_monitor_heavy_queue", return_value=(True, "port_scan_type=all")), \
                patch("app.scheduler.celerytask.arl_task") as mock_main_task, \
                patch("app.scheduler.celerytask.arl_task_heavy") as mock_heavy_task, \
                patch("app.scheduler.celerytask.arl_task_ip") as mock_ip_task:
            mock_heavy_task.delay.return_value = "monitor-domain-celery-id"

            submit_job(
                domain="",
                job_id="job-domain-1",
                scope_id="scope-domain-1",
                options={"port_scan": True, "port_scan_type": "all"},
                name="monitor-domain-heavy",
                scope_type=AssetScopeType.DOMAIN,
            )

        mock_heavy_task.delay.assert_called_once()
        mock_ip_task.delay.assert_not_called()
        mock_main_task.delay.assert_not_called()


if __name__ == "__main__":
    unittest.main()
