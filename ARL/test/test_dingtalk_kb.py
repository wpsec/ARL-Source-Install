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
    from app.helpers import task_schedule as task_schedule_module
    from app.utils import dingtalk_openapi
except Exception as exc:
    push_dingtalk_kb = None
    push_task_finish_notify = None
    _build_ssl_cert_warning_markdown = None
    _push_ssl_cert_warning = None
    task_schedule_module = None
    dingtalk_openapi = None
    IMPORT_ERROR = exc


class _FakeCollection(object):
    def __init__(self, items=None):
        self.items = list(items or [])
        self.replaced_items = []

    def find(self, query=None, projection=None):
        return list(self.items)

    def find_one(self, query=None, projection=None, sort=None):
        return None

    def find_one_and_replace(self, query, item):
        self.replaced_items.append(dict(item))
        return item

    def insert_one(self, item):
        self.items.append(dict(item))
        return MagicMock()


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
            task_ids=["task-1", "task-2"],
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

    def test_deduplicate_task_export_sheet_items_should_prefer_analyzed_ai_result(self):
        """知识库写入前应按语义去重，并优先保留已分析 AI 结果。"""
        deduped_items, summary = dingtalk_openapi._deduplicate_task_export_sheet_items(
            [
                {
                    "sheet_name": "URL信息",
                    "values": [
                        ["URL", "站点", "标题", "状态码", "body长度", "来源", "AI分析"],
                        ["https://example.com/admin", "https://example.com", "Login", "200", "1024", "spider", "未分析"],
                        ["https://example.com/admin", "https://example.com", "Login", "200", "1024", "spider", "可疑（中）"],
                    ],
                },
                {
                    "sheet_name": "风险",
                    "values": [
                        ["来源", "风险名称", "严重级别", "目标", "风险URL", "凭证", "模板/插件", "风险类型", "详情", "AI分析"],
                        ["nuclei", "未授权访问", "high", "https://example.com", "https://example.com/api", "", "tpl-1", "auth", "detail", "未分析"],
                        ["nuclei", "未授权访问", "high", "https://example.com", "https://example.com/api", "", "tpl-1", "auth", "detail", "危险（高）"],
                    ],
                },
                {
                    "sheet_name": "WIH接口提取",
                    "values": [
                        ["序号", "目标", "页面URL", "方法", "状态码", "响应大小", "请求url", "请求报文", "AI填充参数", "回复报文", "AI分析"],
                        [1, "https://example.com", "/admin", "POST", "200", "80", "/api/export", "POST /api/export", "", "", "未分析"],
                        [2, "https://example.com", "/admin", "POST", "200", "80", "/api/export", "POST /api/export", "", "", "高价值"],
                    ],
                },
            ]
        )

        self.assertEqual(3, summary.get("removed_rows"))
        url_values = deduped_items[0].get("values")
        risk_values = deduped_items[1].get("values")
        wih_values = deduped_items[2].get("values")
        self.assertEqual(2, len(url_values))
        self.assertEqual("可疑（中）", url_values[1][-1])
        self.assertEqual("危险（高）", risk_values[1][-1])
        self.assertEqual(1, wih_values[1][0])
        self.assertEqual("高价值", wih_values[1][-1])

    @patch('app.utils.dingtalk_openapi.create_workbook')
    @patch('app.utils.dingtalk_openapi._load_workbook_sheet_items')
    @patch('app.routes.export.export_merge_tasks')
    @patch('app.routes.export.build_task_export_summary')
    @patch('app.utils.dingtalk_openapi._is_config_ready')
    @patch('app.utils.dingtalk_openapi.Config.DINGTALK_KB_DRY_RUN', True)
    def test_publish_task_export_to_kb_dry_run_should_return_dedup_summary(
        self,
        mock_is_config_ready,
        mock_build_task_export_summary,
        mock_export_merge_tasks,
        mock_load_workbook_sheet_items,
        mock_create_workbook,
    ):
        """dry_run 下仍应生成去重统计，但不调用钉钉创建接口。"""
        mock_is_config_ready.return_value = True
        mock_export_merge_tasks.return_value = b"excel-bytes"
        mock_build_task_export_summary.return_value = {}
        mock_load_workbook_sheet_items.return_value = (
            True,
            {
                "items": [
                    {
                        "sheet_name": "URL信息",
                        "values": [
                            ["URL", "站点", "标题", "状态码", "body长度", "来源", "AI分析"],
                            ["https://example.com/a", "https://example.com", "A", "200", "10", "spider", "未分析"],
                            ["https://example.com/a", "https://example.com", "A", "200", "10", "spider", "正常"],
                        ],
                    }
                ],
                "truncated_sheets": False,
            },
        )

        success, result = dingtalk_openapi.publish_task_export_to_kb(
            title="demo",
            task_ids=["task-1", "task-2"],
            overview_context={},
        )

        self.assertTrue(success)
        self.assertTrue(result.get("dry_run"))
        self.assertEqual(1, result.get("dedup_summary", {}).get("removed_rows"))
        mock_create_workbook.assert_not_called()

    @patch('app.helpers.task_schedule.push_dingtalk_kb')
    @patch('app.helpers.task_schedule.push_dingding')
    @patch('app.helpers.task_schedule.utils.conn_db')
    def test_process_task_schedule_runs_should_wait_for_running_ai_denoise(
        self,
        mock_conn_db,
        mock_push_dingding,
        mock_push_dingtalk_kb,
    ):
        """AI 去噪仍在运行时，不应生成知识库报告或聚合通知。"""
        task_id = task_schedule_module.bson.ObjectId()
        run_id = task_schedule_module.bson.ObjectId()
        run_collection = _FakeCollection(
            [
                {
                    "_id": run_id,
                    "status": task_schedule_module.RUN_STATUS_RUNNING,
                    "task_ids": [str(task_id)],
                    "summary": {},
                    "missing_retry_count": 0,
                    "notify_enable": True,
                    "notify_kb_enable": True,
                    "notify_channel": "dingding",
                    "notify_on": "finished",
                    "push_status": task_schedule_module.RUN_PUSH_PENDING,
                    "kb_push_status": task_schedule_module.RUN_PUSH_PENDING,
                    "start_time": 100,
                    "start_date": "2026-01-01 00:00:00",
                    "end_time": 0,
                    "end_date": "-",
                }
            ]
        )
        task_collection = _FakeCollection(
            [
                {
                    "_id": task_id,
                    "status": task_schedule_module.TaskStatus.DONE,
                    "name": "demo",
                    "target": "example.com",
                    "type": "domain",
                    "statistic": {},
                    "options": {"ai_denoise": True},
                    "ai_denoise_status": {"status": "running", "pending_modules": []},
                }
            ]
        )

        def _conn_db(name):
            return run_collection if name == task_schedule_module.TASK_SCHEDULE_RUN_COLLECTION else task_collection

        mock_conn_db.side_effect = _conn_db

        task_schedule_module.process_task_schedule_runs()

        mock_push_dingtalk_kb.assert_not_called()
        mock_push_dingding.assert_not_called()
        self.assertEqual(1, len(run_collection.replaced_items))
        saved_run = run_collection.replaced_items[-1]
        self.assertEqual(task_schedule_module.RUN_STATUS_RUNNING, saved_run.get("status"))
        self.assertEqual(task_schedule_module.RUN_PUSH_PENDING, saved_run.get("kb_push_status"))
        self.assertEqual(1, saved_run.get("ai_denoise_wait_summary", {}).get("waiting_task_count"))

    @patch('app.routes.export.build_task_export_summary')
    @patch('app.helpers.task_schedule.push_dingtalk_kb')
    @patch('app.helpers.task_schedule.push_dingding')
    @patch('app.helpers.task_schedule.utils.conn_db')
    def test_process_task_schedule_runs_should_push_after_ai_denoise_done(
        self,
        mock_conn_db,
        mock_push_dingding,
        mock_push_dingtalk_kb,
        mock_build_task_export_summary,
    ):
        """AI 去噪进入终态后，计划任务应正常写入知识库。"""
        task_id = task_schedule_module.bson.ObjectId()
        run_id = task_schedule_module.bson.ObjectId()
        mock_build_task_export_summary.return_value = {
            "site_cnt": 1,
            "domain_cnt": 1,
            "ip_cnt": 0,
            "url_cnt": 1,
            "vuln_cnt": 0,
            "task_summaries": {
                str(task_id): {
                    "site_cnt": 1,
                    "domain_cnt": 1,
                    "ip_cnt": 0,
                    "url_cnt": 1,
                    "vuln_cnt": 0,
                }
            },
        }
        mock_push_dingtalk_kb.return_value = (
            True,
            {
                "node_id": "node-1",
                "node_url": "https://alidocs.example/report",
                "partial_success": False,
                "sheet_success_count": 2,
                "sheet_failed_count": 0,
                "api_result": {},
            },
        )
        run_collection = _FakeCollection(
            [
                {
                    "_id": run_id,
                    "schedule_id": "schedule-1",
                    "schedule_name": "demo",
                    "run_number": 1,
                    "status": task_schedule_module.RUN_STATUS_RUNNING,
                    "task_ids": [str(task_id)],
                    "summary": {},
                    "missing_retry_count": 0,
                    "notify_enable": False,
                    "notify_kb_enable": True,
                    "notify_channel": "dingding",
                    "notify_on": "finished",
                    "push_status": task_schedule_module.RUN_PUSH_PENDING,
                    "kb_push_status": task_schedule_module.RUN_PUSH_PENDING,
                    "start_time": 100,
                    "start_date": "2026-01-01 00:00:00",
                    "end_time": 0,
                    "end_date": "-",
                }
            ]
        )
        task_collection = _FakeCollection(
            [
                {
                    "_id": task_id,
                    "status": task_schedule_module.TaskStatus.DONE,
                    "name": "demo",
                    "target": "example.com",
                    "type": "domain",
                    "statistic": {},
                    "options": {"ai_denoise": True},
                    "ai_denoise_status": {"status": "done", "pending_modules": []},
                }
            ]
        )

        def _conn_db(name):
            return run_collection if name == task_schedule_module.TASK_SCHEDULE_RUN_COLLECTION else task_collection

        mock_conn_db.side_effect = _conn_db

        task_schedule_module.process_task_schedule_runs()

        mock_push_dingtalk_kb.assert_called_once()
        self.assertEqual(1, len(run_collection.replaced_items))
        saved_run = run_collection.replaced_items[-1]
        self.assertEqual(task_schedule_module.RUN_STATUS_FINISHED, saved_run.get("status"))
        self.assertEqual(task_schedule_module.RUN_PUSH_SUCCESS, saved_run.get("kb_push_status"))
        self.assertEqual("https://alidocs.example/report", saved_run.get("kb_node_url"))

    @patch('app.helpers.task_schedule.time.time', return_value=2000)
    @patch('app.routes.export.build_task_export_summary')
    @patch('app.helpers.task_schedule.push_dingtalk_kb')
    @patch('app.helpers.task_schedule.push_dingding', return_value=True)
    @patch('app.helpers.task_schedule.utils.conn_db')
    def test_process_task_schedule_runs_should_force_finalize_after_ai_denoise_timeout(
        self,
        mock_conn_db,
        _mock_push_dingding,
        mock_push_dingtalk_kb,
        mock_build_task_export_summary,
        _mock_time,
    ):
        """AI 去噪等待超时后，应降级放行知识库与聚合通知。"""
        task_id = task_schedule_module.bson.ObjectId()
        run_id = task_schedule_module.bson.ObjectId()
        mock_build_task_export_summary.return_value = {
            "site_cnt": 1,
            "domain_cnt": 1,
            "ip_cnt": 0,
            "url_cnt": 2,
            "vuln_cnt": 0,
            "task_summaries": {
                str(task_id): {
                    "site_cnt": 1,
                    "domain_cnt": 1,
                    "ip_cnt": 0,
                    "url_cnt": 2,
                    "vuln_cnt": 0,
                }
            },
        }
        mock_push_dingtalk_kb.return_value = (
            True,
            {
                "node_id": "node-1",
                "node_url": "https://alidocs.example/degraded-report",
                "partial_success": False,
                "sheet_success_count": 2,
                "sheet_failed_count": 0,
                "api_result": {},
            },
        )
        run_collection = _FakeCollection(
            [
                {
                    "_id": run_id,
                    "schedule_id": "schedule-1",
                    "schedule_name": "demo",
                    "run_number": 1,
                    "status": task_schedule_module.RUN_STATUS_RUNNING,
                    "task_ids": [str(task_id)],
                    "summary": {},
                    "missing_retry_count": 0,
                    "notify_enable": True,
                    "notify_kb_enable": True,
                    "notify_channel": "dingding",
                    "notify_on": "finished",
                    "push_status": task_schedule_module.RUN_PUSH_PENDING,
                    "kb_push_status": task_schedule_module.RUN_PUSH_PENDING,
                    "start_time": 100,
                    "start_date": "2026-01-01 00:00:00",
                    "end_time": 0,
                    "end_date": "-",
                }
            ]
        )
        task_collection = _FakeCollection(
            [
                {
                    "_id": task_id,
                    "status": task_schedule_module.TaskStatus.DONE,
                    "name": "demo",
                    "target": "example.com",
                    "type": "domain",
                    "statistic": {},
                    "options": {"ai_denoise": True},
                    "ai_denoise_status": {
                        "status": "done",
                        "pending_modules": ["url"],
                        "updated_at": 1000,
                    },
                }
            ]
        )

        def _conn_db(name):
            return run_collection if name == task_schedule_module.TASK_SCHEDULE_RUN_COLLECTION else task_collection

        mock_conn_db.side_effect = _conn_db

        task_schedule_module.process_task_schedule_runs()

        mock_push_dingtalk_kb.assert_called_once()
        self.assertEqual(1, len(run_collection.replaced_items))
        saved_run = run_collection.replaced_items[-1]
        self.assertEqual(task_schedule_module.RUN_STATUS_FINISHED, saved_run.get("status"))
        self.assertEqual(task_schedule_module.RUN_PUSH_SUCCESS, saved_run.get("push_status"))
        self.assertEqual(task_schedule_module.RUN_PUSH_SUCCESS, saved_run.get("kb_push_status"))
        self.assertTrue(saved_run.get("ai_denoise_degrade", {}).get("enabled"))
        self.assertIn("example.com", saved_run.get("ai_denoise_degrade", {}).get("timed_out_targets", []))
        kb_extra_data = mock_push_dingtalk_kb.call_args.kwargs.get("extra_data", {})
        self.assertTrue(kb_extra_data.get("ai_denoise_degrade", {}).get("enabled"))

    def test_build_schedule_run_markdown_should_include_ai_degrade_note(self):
        """降级放行时，聚合通知应明确标记 AI 未完成。"""
        markdown = task_schedule_module.build_schedule_run_markdown(
            {
                "schedule_name": "demo",
                "run_number": 1,
                "status": task_schedule_module.RUN_STATUS_FINISHED,
                "start_date": "2026-01-01 00:00:00",
                "end_date": "2026-01-01 00:10:00",
                "summary": {
                    "done": 1,
                    "error": 0,
                    "stop": 0,
                    "site_cnt": 1,
                    "domain_cnt": 1,
                    "ip_cnt": 0,
                    "url_cnt": 2,
                    "vuln_cnt": 0,
                },
                "ai_denoise_degrade": {
                    "enabled": True,
                    "message": "AI 去噪等待超时，已按原始扫描结果继续生成知识库与通知。",
                    "timed_out_task_count": 1,
                    "timed_out_targets": ["example.com"],
                    "tasks": [
                        {
                            "task_id": "task-1",
                            "target": "example.com",
                            "status": "done",
                            "wait_elapsed_sec": 600,
                            "pending_modules": ["url", "fileleak"],
                        }
                    ],
                },
            }
        )

        self.assertIn("AI 降级说明", markdown)
        self.assertIn("example.com", markdown)
        self.assertIn("待处理模块", markdown)

    def test_build_task_overview_sheet_values_should_include_ai_degrade_summary(self):
        """知识库执行概览应展示 AI 降级放行说明。"""
        values = dingtalk_openapi._build_task_overview_sheet_values(
            title="demo",
            task_ids=[],
            overview_meta={
                "ai_denoise_degrade": {
                    "enabled": True,
                    "message": "AI 去噪等待超时，已按原始扫描结果继续生成知识库与通知。",
                    "timed_out_task_count": 2,
                    "timed_out_targets": ["example.com", "demo.example.com"],
                }
            },
        )

        self.assertIn(["AI去噪状态", "降级放行"], values)
        self.assertIn(["超时任务数", "2"], values)
        self.assertIn(["受影响目标", "example.com、demo.example.com"], values)

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
                "domain": "cube.example.com",
                "start_time": "2025-05-16 00:00:00",
                "end_time": "2026-05-15 23:59:59",
                "remaining_days": 27,
                "validity_text": "剩余 27 天",
                "endpoints": ["1.1.1.1:443"],
                "cert_identity_text": "SHA256:cube-demo",
            },
            {
                "domain": "cube-uat.example.com",
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
        self.assertIn("cube.example.com", mock_push_dingding.call_args_list[0].kwargs.get("markdown_report", ""))
        self.assertIn("cube-uat.example.com", mock_push_dingding.call_args_list[1].kwargs.get("markdown_report", ""))

    @patch('app.helpers.message_notify.push_dingding')
    @patch('app.helpers.message_notify._collect_ssl_cert_warnings')
    def test_push_ssl_cert_warning_should_notify_again_on_later_scan(
        self,
        mock_collect_ssl_cert_warnings,
        mock_push_dingding,
    ):
        """相同证书在后续扫描中仍应继续提醒，不应被历史通知状态抑制。"""
        mock_collect_ssl_cert_warnings.return_value = [
            {
                "domain": "cube.example.com",
                "start_time": "2025-05-16 00:00:00",
                "end_time": "2026-05-15 23:59:59",
                "remaining_days": 29,
                "validity_text": "剩余 29 天",
                "endpoints": ["1.1.1.1:443"],
                "cert_identity_text": "SHA256:cube-demo",
            }
        ]
        mock_push_dingding.return_value = True

        _push_ssl_cert_warning("65f1234567890abc12345678")
        _push_ssl_cert_warning("75f1234567890abc12345679")

        self.assertEqual(2, mock_push_dingding.call_count)
        first_markdown = mock_push_dingding.call_args_list[0].kwargs.get("markdown_report", "")
        second_markdown = mock_push_dingding.call_args_list[1].kwargs.get("markdown_report", "")
        self.assertIn("cube.example.com", first_markdown)
        self.assertIn("剩余 29 天", first_markdown)
        self.assertIn("cube.example.com", second_markdown)
        self.assertIn("剩余 29 天", second_markdown)


if __name__ == '__main__':
    unittest.main()
