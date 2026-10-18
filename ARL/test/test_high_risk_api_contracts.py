"""任务与报告 API 的高风险权限和副作用合同测试。"""

import unittest
from unittest.mock import MagicMock, patch

from bson import ObjectId

from app.config import Config
from app.main import arl_app
from app.modules import ErrorMsg
from app.routes import export as export_route
from app.routes import api_console as api_console_route
from app.routes import assetSite as asset_site_route
from app.routes import assetScope as asset_scope_route
from app.routes import console as console_route
from app.routes import github_task as github_task_route
from app.routes import policy as policy_route
from app.routes import task_schedule as task_schedule_route
from app.routes import task as task_route
from app.routes import user as user_route
from app.routes import vuln as vuln_route
from app.utils import user as user_utils


TASK_ID = "65f000000000000000000001"
OWN_TASK_ID = "65f000000000000000000002"
ALICE = {"type": "login", "username": "alice"}
API_PRINCIPAL = {"type": "api", "username": "ARL-API"}


class _UserCollection(object):
    def __init__(self, user_count):
        self.user_count = user_count

    def count_documents(self, _query):
        return self.user_count


class HighRiskApiContractTest(unittest.TestCase):
    def setUp(self):
        self.app = arl_app
        original_testing = self.app.config.get("TESTING")
        self.app.config["TESTING"] = True
        self.addCleanup(self.app.config.__setitem__, "TESTING", original_testing)
        self.client = self.app.test_client()
        self.principal = ALICE

        auth_config = patch.object(Config, "AUTH", True)
        auth_config.start()
        self.addCleanup(auth_config.stop)

        self.login_patch = patch.object(
            user_utils, "user_login_header", side_effect=self._principal
        )
        self.user_principal_patch = patch.object(
            user_utils, "current_principal", side_effect=self._principal
        )
        self.route_principal_patch = patch(
            "app.utils.current_principal", side_effect=self._principal
        )
        self.login_mock = self.login_patch.start()
        self.user_principal_mock = self.user_principal_patch.start()
        self.route_principal_mock = self.route_principal_patch.start()
        self.addCleanup(self.route_principal_patch.stop)
        self.addCleanup(self.user_principal_patch.stop)
        self.addCleanup(self.login_patch.stop)

        self.user_collection = _UserCollection(user_count=2)
        conn_patch = patch.object(
            user_utils,
            "conn_db",
            side_effect=lambda name: self.user_collection if name == "user" else None,
        )
        conn_patch.start()
        self.addCleanup(conn_patch.stop)

    def _principal(self, *_args, **_kwargs):
        return self.principal

    def set_principal(self, principal):
        self.principal = principal

    def _headers(self):
        return {"Token": "test-token"}

    def test_task_create_uses_authenticated_owner_and_never_runs_scanner(self):
        created_task = {"_id": TASK_ID, "name": "fixture", "target": "example.test"}
        with patch.object(task_route, "submit_task_task", return_value=[created_task]) as submit:
            response = self.client.post(
                "/api/task/",
                json={
                    "name": "fixture",
                    "target": "example.test",
                    "owner_username": "bob",
                    "port_scan": False,
                },
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(200, response.get_json()["code"])
        self.assertEqual("alice", submit.call_args.kwargs["owner_username"])

    def test_task_create_rejects_empty_custom_port_range_before_enqueue(self):
        with patch.object(task_route, "submit_task_task") as submit:
            response = self.client.post(
                "/api/task/",
                json={
                    "name": "fixture",
                    "target": "example.test",
                    "port_scan_type": "custom",
                    "port_custom": "",
                },
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.PortCustomInvalid["code"], response.get_json()["code"])
        submit.assert_not_called()

    def test_policy_task_creation_uses_authenticated_owner_and_never_runs_scanner(self):
        with patch.object(
            task_route, "get_options_by_policy_id", return_value={"related_scope_id": "scope-fixture"}
        ), patch.object(
            task_route, "get_scope_by_scope_id", return_value={"scope_array": ["example.test"]}
        ), patch.object(task_route, "check_target_in_scope"), patch.object(
            task_route, "submit_task_task", return_value=[{"_id": TASK_ID}]
        ) as submit:
            response = self.client.post(
                "/api/task/policy/",
                json={
                    "name": "fixture",
                    "task_tag": "task",
                    "target": "example.test",
                    "policy_id": "policy-fixture",
                    "owner_username": "bob",
                },
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(200, response.get_json()["code"])
        self.assertEqual("alice", submit.call_args.kwargs["owner_username"])

    def test_task_list_is_scoped_to_login_owner(self):
        expected = {"items": [], "total": 0, "code": 200}
        with patch.object(task_route.ARLTask, "build_data", return_value=expected) as build:
            response = self.client.get(
                "/api/task/?size=5&name=fixture", headers=self._headers()
            )

        self.assertEqual(200, response.status_code)
        args = build.call_args.kwargs["args"]
        self.assertEqual(
            {"owner_username": "alice"},
            args["$and"][0],
        )
        self.assertEqual("fixture", args["name"])

    def test_task_list_includes_legacy_tasks_only_for_single_user_install(self):
        self.user_collection.user_count = 1
        with patch.object(
            task_route.ARLTask,
            "build_data",
            return_value={"items": [], "total": 0, "code": 200},
        ) as build:
            response = self.client.get("/api/task/", headers=self._headers())

        self.assertEqual(200, response.status_code)
        owner_filter = build.call_args.kwargs["args"]["$and"][0]["$or"]
        self.assertIn({"owner_username": "alice"}, owner_filter)
        self.assertIn({"owner_username": {"$exists": False}}, owner_filter)
        self.assertIn({"owner_username": None}, owner_filter)
        self.assertIn({"owner_username": ""}, owner_filter)

    def test_task_list_api_principal_remains_global(self):
        self.set_principal(API_PRINCIPAL)
        with patch.object(
            task_route.ARLTask,
            "build_data",
            return_value={"items": [], "total": 0, "code": 200},
        ) as build:
            response = self.client.get("/api/task/", headers=self._headers())

        self.assertEqual(200, response.status_code)
        args = build.call_args.kwargs["args"]
        self.assertNotIn("owner_username", args)
        self.assertNotIn("$or", args)

    def test_delete_cannot_remove_another_login_users_task(self):
        with patch.object(
            task_route.TaskRepository,
            "find_by_id",
            side_effect=[
                {"_id": OWN_TASK_ID, "owner_username": "alice", "status": "done"},
                {"_id": TASK_ID, "owner_username": "bob", "status": "done"},
            ],
        ), patch.object(task_route.TaskRepository, "delete_by_id") as delete_task, patch.object(
            task_route.TaskRepository, "delete_related_data"
        ) as delete_related:
            response = self.client.post(
                "/api/task/delete/",
                json={"task_id": [OWN_TASK_ID, TASK_ID], "del_task_data": True},
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.NotFoundTask["code"], response.get_json()["code"])
        delete_task.assert_not_called()
        delete_related.assert_not_called()

    def test_delete_allows_own_completed_task(self):
        with patch.object(
            task_route.TaskRepository,
            "find_by_id",
            return_value={"_id": TASK_ID, "owner_username": "alice", "status": "done"},
        ), patch.object(task_route.TaskRepository, "delete_by_id") as delete_task, patch.object(
            task_route.TaskRepository, "delete_related_data"
        ) as delete_related:
            response = self.client.post(
                "/api/task/delete/",
                json={"task_id": [TASK_ID], "del_task_data": False},
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(200, response.get_json()["code"])
        delete_task.assert_called_once_with(TASK_ID)
        delete_related.assert_called_once_with(TASK_ID, False)

    def test_invalid_task_id_is_hidden_as_not_found_without_database_lookup(self):
        with patch.object(task_route.TaskRepository, "find_by_id") as find_task:
            response = self.client.get(
                "/api/task/stop/not-an-object-id", headers=self._headers()
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.NotFoundTask["code"], response.get_json()["code"])
        find_task.assert_not_called()

    def test_stop_cannot_revoke_another_login_users_task(self):
        with patch.object(
            task_route.TaskRepository,
            "find_by_id",
            return_value={
                "_id": TASK_ID,
                "owner_username": "bob",
                "status": "running",
                "celery_id": "fixture-celery-id",
            },
        ), patch.object(task_route.celerytask.celery.control, "revoke") as revoke, patch.object(
            task_route.TaskRepository, "update_by_id"
        ) as update:
            response = self.client.get(
                "/api/task/stop/{}".format(TASK_ID), headers=self._headers()
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.NotFoundTask["code"], response.get_json()["code"])
        revoke.assert_not_called()
        update.assert_not_called()

    def test_batch_stop_cannot_revoke_another_login_users_task(self):
        with patch.object(
            task_route.TaskRepository,
            "find_by_id",
            return_value={
                "_id": TASK_ID,
                "owner_username": "bob",
                "status": "running",
                "celery_id": "fixture-celery-id",
            },
        ), patch.object(task_route.celerytask.celery.control, "revoke") as revoke, patch.object(
            task_route.TaskRepository, "update_by_id"
        ) as update:
            response = self.client.post(
                "/api/task/batch_stop/",
                json={"task_id": [TASK_ID]},
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        revoke.assert_not_called()
        update.assert_not_called()

    def test_sync_cannot_enqueue_another_login_users_task(self):
        with patch.object(
            task_route.TaskRepository,
            "find_by_id",
            return_value={"_id": TASK_ID, "owner_username": "bob", "status": "done", "type": "domain"},
        ), patch.object(task_route, "get_scope_by_scope_id") as get_scope, patch.object(
            task_route.celerytask.arl_task, "delay"
        ) as enqueue:
            response = self.client.post(
                "/api/task/sync/",
                json={"task_id": TASK_ID, "scope_id": "scope-fixture"},
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.NotFoundTask["code"], response.get_json()["code"])
        get_scope.assert_not_called()
        enqueue.assert_not_called()

    def test_restart_cannot_requeue_another_login_users_task(self):
        with patch.object(
            task_route.TaskRepository,
            "find_by_id",
            return_value={"_id": TASK_ID, "owner_username": "bob", "status": "done"},
        ), patch.object(task_route, "restart_task") as restart:
            response = self.client.post(
                "/api/task/restart/",
                json={"task_id": [TASK_ID]},
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.NotFoundTask["code"], response.get_json()["code"])
        restart.assert_not_called()

    def test_single_export_hides_foreign_task_and_does_not_generate_report(self):
        with patch.object(
            export_route, "get_task_data", return_value={
                "_id": TASK_ID,
                "owner_username": "bob",
                "target": "private.example.test",
            }
        ), patch.object(export_route, "export_arl") as build_report:
            response = self.client.get(
                "/api/export/{}".format(TASK_ID), headers=self._headers()
            )

        self.assertEqual(404, response.status_code)
        self.assertNotIn("private.example.test", response.get_data(as_text=True))
        build_report.assert_not_called()

    def test_batch_export_rejects_mixed_task_owners_before_generating_report(self):
        tasks = {
            "task-a": {"_id": "task-a", "owner_username": "alice", "name": "mine"},
            "task-b": {"_id": "task-b", "owner_username": "bob", "name": "theirs"},
        }
        with patch.object(export_route, "get_task_data", side_effect=tasks.get), patch.object(
            export_route, "export_merge_tasks"
        ) as build_report:
            response = self.client.post(
                "/api/export/batch",
                json={"task_ids": ["task-a", "task-b"]},
                headers=self._headers(),
            )

        self.assertEqual(404, response.status_code)
        self.assertNotIn("theirs", response.get_data(as_text=True))
        build_report.assert_not_called()

    def test_invalid_login_does_not_issue_authentication_token(self):
        with patch.object(user_route.utils, "user_login", return_value=None):
            response = self.client.post(
                "/api/user/login",
                json={"username": "alice", "password": "invalid"},
            )

        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual(401, payload["code"])
        self.assertIn("message", payload)
        self.assertIn("data", payload)
        self.assertNotIn("token", payload.get("data", {}))

    def test_password_confirmation_mismatch_does_not_change_or_revoke_credentials(self):
        with patch.object(user_route.utils, "change_pass") as change_pass, patch.object(
            user_route.utils, "user_logout"
        ) as logout:
            response = self.client.post(
                "/api/user/change_pass",
                json={
                    "old_password": "old-fixture",
                    "new_password": "new-fixture",
                    "check_password": "different-fixture",
                },
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(301, response.get_json()["code"])
        change_pass.assert_not_called()
        logout.assert_not_called()

    def test_successful_password_change_revokes_the_old_token(self):
        with patch.object(user_route.utils, "change_pass", return_value=True), patch.object(
            user_route.utils, "user_logout"
        ) as logout:
            response = self.client.post(
                "/api/user/change_pass",
                json={
                    "old_password": "old-fixture",
                    "new_password": "new-fixture",
                    "check_password": "new-fixture",
                },
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(200, response.get_json()["code"])
        logout.assert_called_once_with("test-token")

    def test_asset_site_delete_requires_authentication_before_database_side_effect(self):
        self.set_principal(None)
        with patch.object(asset_site_route.utils, "conn_db") as conn_db:
            response = self.client.post(
                "/api/asset_site/delete/",
                json={"_id": [TASK_ID]},
            )

        self.assertEqual(401, response.get_json()["code"])
        conn_db.assert_not_called()

    def test_asset_site_delete_targets_only_requested_record_ids(self):
        collection = MagicMock()
        with patch.object(asset_site_route.utils, "conn_db", return_value=collection):
            response = self.client.post(
                "/api/asset_site/delete/",
                json={"_id": [TASK_ID]},
                headers=self._headers(),
            )

        self.assertEqual(200, response.get_json()["code"])
        collection.delete_one.assert_called_once_with({"_id": ObjectId(TASK_ID)})

    def test_vulnerability_delete_targets_only_requested_record_ids(self):
        collection = MagicMock()
        with patch.object(vuln_route.utils, "conn_db", return_value=collection):
            response = self.client.post(
                "/api/vuln/delete/",
                json={"_id": [TASK_ID]},
                headers=self._headers(),
            )

        self.assertEqual(200, response.get_json()["code"])
        collection.delete_one.assert_called_once_with({"_id": ObjectId(TASK_ID)})

    def test_asset_scope_rejects_invalid_domain_before_database_write(self):
        with patch.object(asset_scope_route, "conn") as conn:
            response = self.client.post(
                "/api/asset_scope/",
                json={
                    "name": "fixture scope",
                    "scope": "not a valid host",
                    "black_scope": "",
                    "scope_type": "domain",
                },
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.DomainInvalid["code"], response.get_json()["code"])
        conn.assert_not_called()

    def test_github_task_rejects_blank_keyword_before_enqueue(self):
        with patch.object(github_task_route, "submit_github_task") as submit:
            response = self.client.post(
                "/api/github_task/",
                json={"name": "fixture", "keyword": "   "},
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.GithubKeywordEmpty["code"], response.get_json()["code"])
        submit.assert_not_called()

    def test_github_task_creation_uses_fixed_queue_adapter_without_external_request(self):
        queued_task = {"_id": TASK_ID, "name": "fixture", "keyword": "token"}
        with patch.object(
            github_task_route, "submit_github_task", return_value=queued_task
        ) as submit:
            response = self.client.post(
                "/api/github_task/",
                json={"name": "fixture", "keyword": " token "},
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(200, response.get_json()["code"])
        self.assertEqual("token", submit.call_args.kwargs["task_data"]["keyword"])

    def test_config_save_rejects_non_object_before_persisting(self):
        with patch.object(
            api_console_route, "_load_config_from_file", return_value={"existing": True}
        ), patch.object(api_console_route.CONFIG_DOMAIN_SERVICE, "save") as save:
            response = self.client.post(
                "/api/api_console/config/",
                json={"config": ["invalid"]},
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.Error["code"], response.get_json()["code"])
        save.assert_not_called()

    def test_config_save_preserves_redacted_secret_and_never_echoes_it(self):
        secret_value = "unit-test-secret-value"
        current = {"service": {"api_token": secret_value, "timeout": 10}}
        saved_configs = []

        def save(config_obj, validator):
            validator(config_obj)
            saved_configs.append(config_obj)
            return config_obj, {"backup_path": "fixture-backup"}

        with patch.object(api_console_route, "_load_config_from_file", return_value=current), patch.object(
            api_console_route.CONFIG_DOMAIN_SERVICE, "save", side_effect=save
        ):
            response = self.client.post(
                "/api/api_console/config/",
                json={"config": {"service": {"api_token": "<redacted>", "timeout": 20}}},
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(200, response.get_json()["code"])
        self.assertEqual(secret_value, saved_configs[0]["service"]["api_token"])
        self.assertNotIn(secret_value, response.get_data(as_text=True))

    def test_schedule_rejects_invalid_notification_policy_before_database_write(self):
        with patch.object(task_schedule_route.utils, "conn_db") as conn_db, patch.object(
            task_schedule_route.task, "get_ip_domain_list"
        ) as parse_targets:
            response = self.client.post(
                "/api/task_schedule/",
                json={
                    "name": "fixture schedule",
                    "target": "fixture.invalid",
                    "schedule_type": "recurrent_scan",
                    "policy_id": TASK_ID,
                    "cron": "0 0 * * *",
                    "task_tag": "task",
                    "notify_on": "unsupported",
                },
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.Error["code"], response.get_json()["code"])
        conn_db.assert_not_called()
        parse_targets.assert_not_called()

    def test_schedule_creation_persists_and_returns_the_same_id(self):
        policy_collection = MagicMock()
        policy_collection.find_one.return_value = {"name": "fixture policy"}
        schedule_collection = MagicMock()
        stored_documents = []

        def save_schedule(document):
            stored_documents.append(dict(document))

        schedule_collection.insert_one.side_effect = save_schedule

        def get_collection(name):
            return {
                "policy": policy_collection,
                "task_schedule": schedule_collection,
            }[name]

        with patch.object(
            task_schedule_route.utils, "conn_db", side_effect=get_collection
        ), patch.object(
            task_schedule_route.task,
            "get_ip_domain_list",
            return_value=([], ["fixture.invalid"]),
        ), patch.object(
            task_schedule_route.utils, "check_cron_interval", return_value=(True, "")
        ), patch.object(
            task_schedule_route.utils, "check_cron", return_value=(None, 60, None)
        ), patch.object(
            task_schedule_route.utils, "time2date", return_value="2030-01-01 00:01:00"
        ):
            response = self.client.post(
                "/api/task_schedule/",
                json={
                    "name": "fixture schedule",
                    "target": "fixture.invalid",
                    "schedule_type": "recurrent_scan",
                    "policy_id": TASK_ID,
                    "cron": "0 0 * * *",
                    "task_tag": "task",
                    "notify_on": "failed",
                },
                headers=self._headers(),
            )

        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual(200, payload["code"])
        saved = stored_documents[0]
        returned_id = payload["data"]["_id"]
        self.assertEqual(ObjectId(returned_id), saved["_id"])
        self.assertEqual("fixture policy", saved["policy_name"])
        self.assertEqual("failed", saved["notify_on"])

    def test_policy_create_returns_persisted_id_and_defaulted_contract(self):
        policy_id = ObjectId(TASK_ID)
        collection = MagicMock()
        collection.insert_one.return_value.inserted_id = policy_id
        payload = {
            "name": "contract fixture",
            "desc": "fixture",
            "policy": {
                "domain_config": {},
                "ip_config": {"port_scan_type": "test"},
                "site_config": {},
                "poc_config": [],
                "brute_config": [],
            },
        }

        with patch.object(policy_route.utils, "conn_db", return_value=collection), \
                patch.object(policy_route, "_update_plugin_config", side_effect=lambda value, **_kwargs: value):
            response = self.client.post(
                "/api/policy/add/", json=payload, headers=self._headers()
            )

        body = response.get_json()
        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.Success["code"], body["code"])
        self.assertEqual(str(policy_id), body["data"]["policy_id"])
        stored = collection.insert_one.call_args.args[0]
        self.assertEqual("contract fixture", stored["name"])
        self.assertEqual("test", stored["policy"]["ip_config"]["port_scan_type"])

    def test_policy_create_rejects_invalid_custom_ports_before_persisting(self):
        collection = MagicMock()
        payload = {
            "name": "invalid fixture",
            "policy": {
                "ip_config": {
                    "port_scan_type": "custom",
                    "port_custom": "not-a-port",
                }
            },
        }

        with patch.object(policy_route.utils, "conn_db", return_value=collection) as conn_db, \
                patch.object(policy_route.utils.arl, "build_port_custom", return_value="invalid port"):
            response = self.client.post(
                "/api/policy/add/", json=payload, headers=self._headers()
            )

        self.assertEqual(ErrorMsg.PortCustomInvalid["code"], response.get_json()["code"])
        conn_db.assert_not_called()
        collection.insert_one.assert_not_called()

    def test_policy_delete_only_targets_requested_policy_id(self):
        policy_id = ObjectId(TASK_ID)
        collection = MagicMock()
        collection.find_one.return_value = {"name": "fixture policy"}

        with patch.object(policy_route.utils, "conn_db", return_value=collection):
            response = self.client.post(
                "/api/policy/delete/",
                json={"policy_id": [str(policy_id)]},
                headers=self._headers(),
            )

        self.assertEqual(ErrorMsg.Success["code"], response.get_json()["code"])
        collection.delete_one.assert_called_once_with({"_id": policy_id})

    def test_system_monitor_returns_the_documented_success_contract(self):
        snapshot = ({"cpu_percent": 12.5, "process_count": 3}, [{"time": "12:00"}])
        with patch.object(
            console_route, "_collect_system_monitor_snapshot", return_value=snapshot
        ):
            response = self.client.get(
                "/api/console/system_monitor/", headers=self._headers()
            )

        body = response.get_json()
        self.assertEqual(200, response.status_code)
        self.assertEqual(ErrorMsg.Success["code"], body["code"])
        self.assertEqual(snapshot[0], body["data"]["resource"])
        self.assertEqual(snapshot[1], body["data"]["history_24h"])


if __name__ == "__main__":
    unittest.main()
