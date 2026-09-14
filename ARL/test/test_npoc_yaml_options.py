"""NPoC 总开关、插件选择和列表查询边界测试。"""

import pathlib
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ARL"))

from app.helpers import task as task_helper
from app.modules import TaskTag, TaskType
from app.services.collection_query_service import build_db_query


class _FakeCollection:
    def __init__(self, plugins):
        self.plugins = plugins

    def find_one(self, query):
        return next(
            (item for item in self.plugins if all(item.get(key) == value for key, value in query.items())),
            None,
        )


class NpocYamlOptionsTest(unittest.TestCase):
    def test_explicit_switch_overrides_legacy_selected_items(self):
        self.assertTrue(task_helper.npoc_poc_scan_enabled({"poc_config": [{"enable": True}]}))
        self.assertFalse(task_helper.npoc_poc_scan_enabled({"npoc_poc_scan": False, "poc_config": [{"enable": True}]}))
        self.assertTrue(task_helper.npoc_poc_scan_enabled({"npoc_poc_scan": True, "poc_config": []}))

    def test_new_task_defaults_off_and_explicit_empty_selection_is_preserved(self):
        with mock.patch.object(task_helper.utils, "conn_db", return_value=_FakeCollection([])):
            data = task_helper.build_task_data(
                "demo", ["example.test"], TaskType.RISK_CRUISING, TaskTag.RISK_CRUISING,
                {"poc_config": [], "npoc_poc_scan": None},
            )
        self.assertFalse(data["options"]["npoc_poc_scan"])
        self.assertEqual(data["options"]["poc_config"], [])

    def test_only_ready_poc_can_enter_task_config(self):
        plugins = [
            {"plugin_name": "ready", "plugin_type": "poc", "vul_name": "Ready", "status": "ready"},
            {"plugin_name": "quarantine", "plugin_type": "poc", "vul_name": "No", "status": "quarantine"},
        ]
        with mock.patch.object(task_helper.utils, "conn_db", return_value=_FakeCollection(plugins)):
            normalized = task_helper.normalize_task_poc_config([{"plugin_name": "ready", "enable": True}])
            with self.assertRaises(Exception):
                task_helper.normalize_task_poc_config([{"plugin_name": "quarantine", "enable": True}])
        self.assertEqual(normalized[0]["plugin_name"], "ready")

    def test_poc_keyword_query_covers_metadata_and_tags(self):
        query = build_db_query({"q": "grafana", "status": "ready", "plugin_type": "poc"})
        self.assertEqual(query["status"]["$regex"], "ready")
        self.assertEqual(query["plugin_type"]["$regex"], "poc")
        fields = {next(iter(item)) for item in query["$or"]}
        self.assertTrue({"plugin_name", "vul_name", "app_name", "finger", "tags"}.issubset(fields))


if __name__ == "__main__":
    unittest.main()
