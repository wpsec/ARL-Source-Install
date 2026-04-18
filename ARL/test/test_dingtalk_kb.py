import unittest
from unittest.mock import MagicMock, patch

IMPORT_ERROR = None
try:
    from app.helpers.message_notify import (
        push_dingtalk_kb,
        push_task_finish_notify,
        _build_ssl_cert_warning_markdown,
        _push_ssl_cert_warning,
    )
    from app.utils import dingtalk_openapi
except Exception as exc:
    push_dingtalk_kb = None
    push_task_finish_notify = None
    _build_ssl_cert_warning_markdown = None
    _push_ssl_cert_warning = None
    dingtalk_openapi = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, "requires dingtalk test dependencies: {}".format(IMPORT_ERROR))
class TestDingtalkKnowledgeBase(unittest.TestCase):
    """钉钉知识库写入相关回归测试。"""

    @patch('app.utils.dingtalk_openapi.request_openapi')
    def test_update_workbook_range_should_pad_values_to_match_range_width(
        self,
        mock_request_openapi,
    ):
        """写入分块时应按目标 range 列宽补齐尾部空列，避免钉钉报列数不匹配。"""
        mock_request_openapi.return_value = (True, {"status_code": 200})

        success, result = dingtalk_openapi.update_workbook_range(
            workbook_id="workbook-1",
            sheet_name="系统服务",
            range_a1="A201:E288",
            values=[
                ["1.1.1.1", "80", "http", "nginx"],
                ["2.2.2.2", "443", "https", ""],
            ],
            operator_id="operator-1",
        )

        self.assertTrue(success)
        payload = mock_request_openapi.call_args.kwargs.get("json_data", {})
        self.assertEqual(
            [
                ["1.1.1.1", "80", "http", "nginx", ""],
                ["2.2.2.2", "443", "https", "", ""],
            ],
            payload.get("values"),
        )
        self.assertEqual("A201:E288", result.get("range"))

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

    def test_build_ordered_export_sheet_items_should_keep_wih_endpoint_sheet(self):
        """钉钉知识库应保留 WIH 接口提取工作表。"""
        ordered_items, ignored_sheet_names = dingtalk_openapi._build_ordered_export_sheet_items(
            [
                {"sheet_name": "风险", "values": [["risk"]]},
                {"sheet_name": "WIH接口提取", "values": [["endpoint"]]},
                {"sheet_name": "WIH", "values": [["wih"]]},
            ]
        )

        self.assertEqual(
            ["WIH", "WIH接口提取", "风险"],
            [item.get("sheet_name") for item in ordered_items],
        )
        self.assertEqual([], ignored_sheet_names)

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

    @patch('app.helpers.message_notify.push_dingding')
    @patch('app.helpers.message_notify._collect_ssl_cert_warnings')
    def test_push_ssl_cert_warning_should_notify_all_deduplicated_items_per_task(
        self,
        mock_collect_ssl_cert_warnings,
        mock_push_dingding,
    ):
        """SSL 临期提醒应按当前任务去重后发送，不应被历史任务状态抑制。"""
        mock_collect_ssl_cert_warnings.return_value = [
            {
                "domain": "cube.eytax.com.cn",
                "start_time": "2025-05-16 00:00:00",
                "end_time": "2026-05-15 23:59:59",
                "remaining_days": 27,
                "validity_text": "剩余 27 天",
                "endpoints": ["1.1.1.1:443"],
                "cert_identity_text": "SHA256:cube-demo",
            },
            {
                "domain": "cube-uat.eytax.com.cn",
                "start_time": "2025-04-24 00:00:00",
                "end_time": "2026-04-23 23:59:59",
                "remaining_days": 5,
                "validity_text": "剩余 5 天",
                "endpoints": ["2.2.2.2:443"],
                "cert_identity_text": "SHA256:cube-uat-demo",
            },
        ]
        mock_push_dingding.return_value = True

        _push_ssl_cert_warning("65f1234567890abc12345678")

        self.assertEqual(2, mock_push_dingding.call_count)
        self.assertIn("cube.eytax.com.cn", mock_push_dingding.call_args_list[0].kwargs.get("markdown_report", ""))
        self.assertIn("cube-uat.eytax.com.cn", mock_push_dingding.call_args_list[1].kwargs.get("markdown_report", ""))


if __name__ == '__main__':
    unittest.main()
