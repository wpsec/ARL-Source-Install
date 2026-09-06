"""钉钉配置接口敏感字段脱敏回归（route 接入层纯函数）。

原为 pytest 风格文件，`unittest discover` 在容器（无 pytest）中收集即
ModuleNotFoundError（hygiene 容器重扫 load-fail 项）；统一为仓库既有的
unittest 框架，断言语义逐条保留。
"""
import unittest

try:
    import flask_restx  # noqa: F401  route 模块导入依赖
    from app.routes.dingtalk_api import (
        _fill_missing_sensitive_dingtalk_fields,
        _sanitize_dingtalk_config_for_client,
        _sanitize_dingtalk_runtime_status_for_client,
    )
    _IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - 轻依赖环境退化为 skip
    _IMPORT_ERROR = exc


@unittest.skipIf(
    _IMPORT_ERROR is not None,
    "需要 flask_restx/app.routes 依赖: {}".format(_IMPORT_ERROR),
)
class DingtalkSensitiveSanitizeTest(unittest.TestCase):
    def test_sanitize_dingtalk_config_for_client_hides_sensitive_values(self):
        raw_config = {
            "dingding_access_token": "token-demo",
            "dingding_secret": "secret-demo",
            "corp_id": "corp-demo",
            "app_key": "app-key-demo",
            "app_secret": "app-secret-demo",
            "operator_id": "operator-demo",
            "workspace_id": "workspace-demo",
            "parent_node_id": "parent-demo",
            "base_url": "https://api.dingtalk.com",
        }

        safe_config, sensitive_configured = _sanitize_dingtalk_config_for_client(raw_config)

        self.assertEqual(safe_config["base_url"], "https://api.dingtalk.com")
        self.assertEqual(safe_config["dingding_access_token"], "")
        self.assertEqual(safe_config["dingding_secret"], "")
        self.assertEqual(safe_config["corp_id"], "")
        self.assertEqual(safe_config["app_key"], "")
        self.assertEqual(safe_config["app_secret"], "")
        self.assertEqual(safe_config["operator_id"], "")
        self.assertEqual(safe_config["workspace_id"], "")
        self.assertEqual(safe_config["parent_node_id"], "")
        self.assertIs(sensitive_configured["dingding_access_token"], True)
        self.assertIs(sensitive_configured["app_secret"], True)
        self.assertIs(sensitive_configured["workspace_id"], True)

    def test_fill_missing_sensitive_dingtalk_fields_preserves_existing_values(self):
        current_config_obj = {
            "DINGDING": {
                "ACCESS_TOKEN": "old-token",
                "SECRET": "old-secret",
            },
            "DINGTALK_API": {
                "CORP_ID": "old-corp",
                "APP_KEY": "old-app-key",
                "APP_SECRET": "old-app-secret",
                "OPERATOR_ID": "old-operator",
                "WORKSPACE_ID": "old-workspace",
                "PARENT_NODE_ID": "old-parent",
                "BASE_URL": "https://api.dingtalk.com",
            },
        }

        merged = _fill_missing_sensitive_dingtalk_fields(
            {
                "base_url": "https://api.dingtalk.com",
                "title_prefix": "互联网资产自动化收集",
                "app_key": "new-app-key",
            },
            current_config_obj,
        )

        self.assertEqual(merged["dingding_access_token"], "old-token")
        self.assertEqual(merged["dingding_secret"], "old-secret")
        self.assertEqual(merged["corp_id"], "old-corp")
        self.assertEqual(merged["app_key"], "new-app-key")
        self.assertEqual(merged["app_secret"], "old-app-secret")
        self.assertEqual(merged["operator_id"], "old-operator")
        self.assertEqual(merged["workspace_id"], "old-workspace")
        self.assertEqual(merged["parent_node_id"], "old-parent")

    def test_sanitize_dingtalk_runtime_status_for_client_hides_sensitive_values(self):
        runtime_status = {
            "corp_id": "corp-demo",
            "app_key": "app-key-demo",
            "operator_id": "operator-demo",
            "workspace_id": "workspace-demo",
            "parent_node_id": "parent-demo",
            "app_secret_set": True,
            "missing_basic_fields": [],
        }

        safe_status = _sanitize_dingtalk_runtime_status_for_client(runtime_status)

        self.assertEqual(safe_status["corp_id"], "")
        self.assertEqual(safe_status["app_key"], "")
        self.assertEqual(safe_status["operator_id"], "")
        self.assertEqual(safe_status["workspace_id"], "")
        self.assertEqual(safe_status["parent_node_id"], "")
        self.assertIs(safe_status["app_secret_set"], True)


if __name__ == "__main__":
    unittest.main()
