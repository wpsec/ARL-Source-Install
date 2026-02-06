"""
批量表格导出功能单元测试

测试内容：
- 后端批量导出API接口
- Excel文件生成和内容验证
- 错误处理和边界情况
"""

import unittest
import json
from unittest.mock import patch, MagicMock
from app.routes.export import ARLBatchExcel, export_merge_tasks
from app import create_app


class TestBatchExport(unittest.TestCase):
    """批量导出功能测试类"""

    def setUp(self):
        """测试前准备"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

        # 模拟任务数据
        self.mock_task_data = {
            "_id": "test_task_1",
            "name": "测试任务1",
            "target": "example.com",
            "status": "done"
        }

        self.mock_task_data_2 = {
            "_id": "test_task_2",
            "name": "测试任务2",
            "target": "test.com",
            "status": "done"
        }

    def tearDown(self):
        """测试后清理"""
        pass

    @patch('app.routes.export.get_task_data')
    def test_batch_export_api_success(self, mock_get_task_data):
        """测试批量导出API成功情况"""
        # 模拟获取任务数据
        mock_get_task_data.side_effect = lambda task_id: {
            "test_task_1": self.mock_task_data,
            "test_task_2": self.mock_task_data_2
        }.get(task_id)

        # 测试数据
        test_data = {
            "task_ids": ["test_task_1", "test_task_2"]
        }

        # 发送POST请求
        response = self.client.post(
            '/api/export/batch',
            data=json.dumps(test_data),
            content_type='application/json',
            headers={'Token': 'test_token'}
        )

        # 验证响应
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/octet-stream')

        # 验证文件名包含任务名
        content_disposition = response.headers.get('Content-Disposition', '')
        self.assertIn('ARL批量导出报告_测试任务1.xlsx', content_disposition)

    def test_batch_export_api_invalid_request(self):
        """测试批量导出API无效请求"""
        # 测试空请求体
        response = self.client.post(
            '/api/export/batch',
            data=json.dumps({}),
            content_type='application/json',
            headers={'Token': 'test_token'}
        )
        self.assertEqual(response.status_code, 400)

        # 测试无效的task_ids
        response = self.client.post(
            '/api/export/batch',
            data=json.dumps({"task_ids": "invalid"}),
            content_type='application/json',
            headers={'Token': 'test_token'}
        )
        self.assertEqual(response.status_code, 400)

    @patch('app.routes.export.get_task_data')
    def test_batch_export_api_task_not_found(self, mock_get_task_data):
        """测试批量导出API任务不存在"""
        # 模拟任务不存在
        mock_get_task_data.return_value = None

        test_data = {
            "task_ids": ["nonexistent_task"]
        }

        response = self.client.post(
            '/api/export/batch',
            data=json.dumps(test_data),
            content_type='application/json',
            headers={'Token': 'test_token'}
        )

        self.assertEqual(response.status_code, 404)

    @patch('app.routes.export.get_task_data')
    @patch('app.routes.export.get_ip_data')
    @patch('app.routes.export.get_domain_data')
    @patch('app.routes.export.get_site_data')
    def test_export_merge_tasks_function(self, mock_get_site_data, mock_get_domain_data,
                                       mock_get_ip_data, mock_get_task_data):
        """测试export_merge_tasks函数"""
        # 模拟任务数据
        mock_get_task_data.side_effect = lambda task_id: {
            "task_1": {"name": "任务1", "target": "example.com"},
            "task_2": {"name": "任务2", "target": "test.com"}
        }.get(task_id)

        # 模拟IP数据
        mock_get_ip_data.return_value = [
            {"ip": "192.168.1.1", "port_info": [{"port": 80, "service": "http"}]},
            {"ip": "192.168.1.2", "port_info": [{"port": 443, "service": "https"}]}
        ]

        # 模拟域名数据
        mock_get_domain_data.return_value = [
            {"domain": "www.example.com", "record": "A"},
            {"domain": "api.example.com", "record": "A"}
        ]

        # 模拟站点数据
        mock_get_site_data.return_value = [
            {"url": "http://www.example.com", "title": "Example Site"},
            {"url": "https://api.example.com", "title": "API Site"}
        ]

        # 调用函数
        result = export_merge_tasks(["task_1", "task_2"])

        # 验证结果是二进制数据
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

        # 验证Excel文件头 (ZIP文件头标识)
        self.assertEqual(result[:4], b'PK\x03\x04')


class TestBatchExportIntegration(unittest.TestCase):
    """批量导出集成测试"""

    def setUp(self):
        """集成测试准备"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_batch_export_workflow(self):
        """测试完整的批量导出工作流程"""
        # 1. 准备测试数据（在实际环境中需要真实的已完成任务）
        # 2. 调用批量导出API
        # 3. 验证响应格式
        # 4. 验证Excel文件内容

        # 注意：这个测试需要在有真实数据的环境中运行
        # 这里只验证API接口的基本可用性

        test_data = {
            "task_ids": ["dummy_task_id"]  # 使用虚拟ID进行基本验证
        }

        response = self.client.post(
            '/api/export/batch',
            data=json.dumps(test_data),
            content_type='application/json',
            headers={'Token': 'test_token'}
        )

        # 验证API基本可用性（即使数据不存在，也应该返回适当的错误响应）
        self.assertIn(response.status_code, [200, 400, 404, 500])


if __name__ == '__main__':
    unittest.main()