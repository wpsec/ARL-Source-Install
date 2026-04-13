import pytest

pytest.importorskip("flask_restx")

from app.routes.dingtalk_api import (
    _fill_missing_sensitive_dingtalk_fields,
    _sanitize_dingtalk_config_for_client,
    _sanitize_dingtalk_runtime_status_for_client,
)


def test_sanitize_dingtalk_config_for_client_hides_sensitive_values():
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

    assert safe_config["base_url"] == "https://api.dingtalk.com"
    assert safe_config["dingding_access_token"] == ""
    assert safe_config["dingding_secret"] == ""
    assert safe_config["corp_id"] == ""
    assert safe_config["app_key"] == ""
    assert safe_config["app_secret"] == ""
    assert safe_config["operator_id"] == ""
    assert safe_config["workspace_id"] == ""
    assert safe_config["parent_node_id"] == ""
    assert sensitive_configured["dingding_access_token"] is True
    assert sensitive_configured["app_secret"] is True
    assert sensitive_configured["workspace_id"] is True


def test_fill_missing_sensitive_dingtalk_fields_preserves_existing_values():
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

    assert merged["dingding_access_token"] == "old-token"
    assert merged["dingding_secret"] == "old-secret"
    assert merged["corp_id"] == "old-corp"
    assert merged["app_key"] == "new-app-key"
    assert merged["app_secret"] == "old-app-secret"
    assert merged["operator_id"] == "old-operator"
    assert merged["workspace_id"] == "old-workspace"
    assert merged["parent_node_id"] == "old-parent"


def test_sanitize_dingtalk_runtime_status_for_client_hides_sensitive_values():
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

    assert safe_status["corp_id"] == ""
    assert safe_status["app_key"] == ""
    assert safe_status["operator_id"] == ""
    assert safe_status["workspace_id"] == ""
    assert safe_status["parent_node_id"] == ""
    assert safe_status["app_secret_set"] is True
