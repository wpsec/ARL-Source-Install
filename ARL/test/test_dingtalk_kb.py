import unittest
from unittest.mock import MagicMock, patch

IMPORT_ERROR = None
try:
    from app.helpers.message_notify import (
        push_dingtalk_kb,
        push_task_finish_notify,
        _build_ssl_cert_warning_markdown,
    )
    from app.utils import dingtalk_openapi
except Exception as exc:
    push_dingtalk_kb = None
    push_task_finish_notify = None
    _build_ssl_cert_warning_markdown = None
    dingtalk_openapi = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires dingtalk test dependencies: {}".format(IMPORT_ERROR))
class TestDingtalkKnowledgeBase(unittest.TestCase):
    """钉钉知识库写入相关回归测试。"""

    @patch('app.utils.dingtalk_openapi.update_workbook_range')
    @patch('app.utils.dingtalk_openapi.list_workbook_sheets')
    def test_write_sheet_values_to_workbook_should_split_large_sheet(
        self,
        mock_list_workbook_sheets,
        mock_update_workbook_range,
    ):
        """大工作表应按块写入，避免单次请求过大。"""
        mock_list_workbook_sheets.return_value = (
            True,
            {
                "items": [
                    {
                        "name": "Sheet1",
                        "sheet_id": "sheet-1",
                    }
                ]
            },
        )
        mock_update_workbook_range.return_value = (True, {"status_code": 200})

        values = [["row-{}".format(idx), "value-{}".format(idx)] for idx in range(401)]
        success, result = dingtalk_openapi.write_sheet_values_to_workbook(
            workbook_id="workbook-1",
            values=values,
            operator_id="operator-1",
            sheet_name="Sheet1",
        )

        self.assertTrue(success)
        self.assertEqual(mock_update_workbook_range.call_count, 3)
        self.assertEqual(
            [call.kwargs.get("range_a1") for call in mock_update_workbook_range.call_args_list],
            ["A1:B200", "A201:B400", "A401:B401"],
        )
        self.assertEqual(result.get("write_chunk_result", {}).get("chunk_count"), 3)
        self.assertEqual(result.get("write_chunk_result", {}).get("chunk_success_count"), 3)
        self.assertEqual(result.get("write_chunk_result", {}).get("chunk_failed_count"), 0)

    @patch('app.utils.dingtalk_openapi.write_sheet_items_to_workbook')
    @patch('app.utils.dingtalk_openapi.rename_workbook_sheet')
    @patch('app.utils.dingtalk_openapi.write_sheet_values_to_workbook')
    @patch('app.utils.dingtalk_openapi.create_workbook')
    @patch('app.utils.dingtalk_openapi._load_workbook_sheet_items')
    @patch('app.routes.export.export_merge_tasks')
    @patch('app.utils.dingtalk_openapi._is_config_ready')
    def test_publish_task_export_to_kb_should_keep_partial_success(
        self,
        mock_is_config_ready,
        mock_export_merge_tasks,
        mock_load_workbook_sheet_items,
        mock_create_workbook,
        mock_write_sheet_values_to_workbook,
        mock_rename_workbook_sheet,
        mock_write_sheet_items_to_workbook,
    ):
        """部分工作表失败时，已创建的知识库报告应保留为部分成功。"""
        mock_is_config_ready.return_value = True
        mock_export_merge_tasks.return_value = b"excel-bytes"
        mock_load_workbook_sheet_items.return_value = (
            True,
            {
                "items": [
                    {"sheet_name": "站点", "values": [["site"]]},
                    {"sheet_name": "风险", "values": [["risk"]]},
                ],
                "truncated_sheets": False,
            },
        )
        mock_create_workbook.return_value = (
            True,
            {
                "dentry_uuid": "workbook-1",
                "doc_key": "doc-1",
                "node_id": "node-1",
                "node_url": "https://alidocs.example/report",
            },
        )
        mock_write_sheet_values_to_workbook.return_value = (
            True,
            {
                "workbook_id": "workbook-1",
                "sheet_name": "Sheet1",
                "sheet_id": "sheet-1",
            },
        )
        mock_rename_workbook_sheet.return_value = (True, {"sheet_name": "执行概览"})
        mock_write_sheet_items_to_workbook.return_value = (
            False,
            {
                "sheet_count": 2,
                "sheet_success_count": 1,
                "sheet_failed_count": 1,
                "items": [
                    {"index": 1, "sheet_name": "风险", "success": False, "result": {"error": "timeout"}}
                ],
                "workbook_id": "workbook-1",
                "last_error": {"error": "timeout"},
            },
        )

        success, result = dingtalk_openapi.publish_task_export_to_kb(
            title="demo",
            task_ids=["task-1"],
            overview_context={"schedule_name": "test"},
        )

        self.assertTrue(success)
        self.assertTrue(result.get("partial_success", False))
        self.assertTrue(result.get("sheet_write_result", {}).get("partial_success", False))
        self.assertEqual(result.get("sheet_write_result", {}).get("sheet_failed_count"), 1)
        self.assertEqual(result.get("node_url"), "https://alidocs.example/report")

    @patch('app.helpers.message_notify.utils.conn_db')
    @patch('app.helpers.message_notify.dingtalk_openapi.publish_task_export_to_kb')
    def test_push_dingtalk_kb_should_mark_partial_success(
        self,
        mock_publish_task_export_to_kb,
        mock_conn_db,
    ):
        """消息层应将部分成功写入状态显式标记出来。"""
        mock_publish_task_export_to_kb.return_value = (
            True,
            {
                "node_id": "node-1",
                "node_url": "https://alidocs.example/report",
                "workbook_id": "workbook-1",
                "sheet_count": 3,
                "partial_success": True,
                "sheet_write_result": {
                    "sheet_success_count": 2,
                    "sheet_failed_count": 1,
                },
            },
        )
        mock_conn_db.return_value = MagicMock()

        success, result = push_dingtalk_kb(
            report_title="demo",
            markdown_report="demo",
            task_ids=["task-1"],
        )

        self.assertTrue(success)
        self.assertEqual(result.get("status"), "partial_success")
        self.assertTrue(result.get("partial_success", False))
        self.assertEqual(result.get("sheet_success_count"), 2)
        self.assertEqual(result.get("sheet_failed_count"), 1)

    @patch('app.helpers.message_notify._push_ssl_cert_warning')
    @patch('app.helpers.message_notify.push_dingding')
    @patch('app.helpers.message_notify.utils.conn_db')
    @patch('app.helpers.message_notify.dingtalk_openapi.refresh_runtime_dingtalk_config_best_effort')
    @patch('app.helpers.message_notify.Config.DINGTALK_SSL_CERT_NOTIFY_ENABLE', True)
    def test_push_task_finish_notify_should_keep_ssl_warning_for_schedule_sub_task(
        self,
        mock_refresh_runtime,
        mock_conn_db,
        mock_push_dingding,
        mock_push_ssl_cert_warning,
    ):
        """计划任务子任务应跳过完成通知，但保留 SSL 临期提醒。"""
        mock_conn_db.return_value.find_one.return_value = {
            "_id": "65f1234567890abc12345678",
            "status": "done",
            "task_tag": "task",
            "options": {
                "from_task_schedule": True,
                "dingding_notify": False,
                "ssl_cert": True,
            },
        }

        push_task_finish_notify("65f1234567890abc12345678")

        mock_push_dingding.assert_not_called()
        mock_push_ssl_cert_warning.assert_called_once_with("65f1234567890abc12345678")

    def test_build_ssl_cert_warning_markdown_should_not_include_report_link(self):
        """SSL 证书提醒不应再展示报告链接占位。"""
        markdown = _build_ssl_cert_warning_markdown(
            {
                "domain": "policy.example.com",
                "start_time": "2025-01-01 00:00:00",
                "end_time": "2026-01-01 00:00:00",
                "validity_text": "剩余 7 天",
                "endpoints": ["1.1.1.1:443"],
                "cert_identity_text": "SHA256:demo",
            },
            report_link="https://example.com/report",
        )

        self.assertIn("SSL证书安全警告", markdown)
        self.assertNotIn("报告链接", markdown)


if __name__ == '__main__':
    unittest.main()
