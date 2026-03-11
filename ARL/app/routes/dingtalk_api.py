"""
钉钉开放平台调试接口

用途：
- 测试钉钉开放平台配置是否可用
- 拉取知识库空间列表和目录节点列表
- 手动创建知识库表格（WORKBOOK）用于联调
"""
from datetime import datetime
from pathlib import Path
import errno
import os
import tempfile
import threading

import yaml
from flask import request
from flask_restx import fields, Namespace

from app import utils
from app.config import Config
from app.modules import ErrorMsg
from app.utils import auth, dingtalk_openapi
from . import ARLResource

ns = Namespace("dingtalk_api", description="钉钉开放平台调试")
logger = utils.get_logger()
DINGTALK_CONFIG_LOCK = threading.Lock()


test_dingtalk_fields = ns.model(
    "TestDingtalkApi",
    {
        "force_refresh_token": fields.Boolean(required=False, description="是否强制刷新access token", default=False),
    },
)

list_workspaces_fields = ns.model(
    "ListDingtalkWorkspaces",
    {
        "operator_id": fields.String(required=False, description="可选，覆盖配置中的 operator_id"),
    },
)

list_nodes_fields = ns.model(
    "ListDingtalkNodes",
    {
        "operator_id": fields.String(required=False, description="可选，覆盖配置中的 operator_id"),
        "parent_node_id": fields.String(required=False, description="可选，覆盖配置中的 parent_node_id"),
    },
)

create_workbook_fields = ns.model(
    "CreateDingtalkWorkbook",
    {
        "title": fields.String(required=False, description="表格标题，默认使用前缀+时间"),
        "operator_id": fields.String(required=False, description="可选，覆盖配置中的 operator_id"),
        "workspace_id": fields.String(required=False, description="可选，覆盖配置中的 workspace_id"),
        "parent_node_id": fields.String(required=False, description="可选，覆盖配置中的 parent_node_id"),
    },
)

list_sheets_fields = ns.model(
    "ListDingtalkWorkbookSheets",
    {
        "workbook_id": fields.String(required=True, description="workbookId（创建表格返回的 dentry_uuid）"),
        "operator_id": fields.String(required=False, description="可选，覆盖配置中的 operator_id"),
    },
)

write_markdown_fields = ns.model(
    "WriteDingtalkWorkbookMarkdown",
    {
        "workbook_id": fields.String(required=True, description="workbookId（创建表格返回的 dentry_uuid）"),
        "sheet_name": fields.String(required=False, description="工作表名，默认 Sheet1"),
        "markdown_content": fields.String(required=False, description="写入内容，支持 markdown 文本"),
        "operator_id": fields.String(required=False, description="可选，覆盖配置中的 operator_id"),
    },
)

save_dingtalk_config_fields = ns.model(
    "SaveDingtalkConfig",
    {
        "dingtalk_config": fields.Raw(required=True, description="钉钉集成配置对象"),
    },
)


def _resolve_config_path() -> Path:
    """
    解析配置文件路径，优先写入容器挂载的 config.yaml。
    """
    custom_path = os.environ.get("ARL_CONFIG_EDIT_PATH", "").strip()
    candidates = [
        Path(custom_path) if custom_path else None,
        Path("/code/app/config.yaml"),
        Path(__file__).resolve().parents[2] / "docker" / "config-docker.yaml",
    ]
    for item in candidates:
        if not item:
            continue
        if item.exists() and item.is_file():
            return item
    return Path(__file__).resolve().parents[2] / "docker" / "config-docker.yaml"


def _load_config_from_file(config_path: Path):
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8") as file_obj:
        loaded = yaml.safe_load(file_obj) or {}
    if not isinstance(loaded, dict):
        raise ValueError("配置文件根节点必须为对象")
    return loaded


def _atomic_write_yaml(config_path: Path, config_obj: dict):
    config_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_text = yaml.safe_dump(
        config_obj,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            dir=str(config_path.parent),
            suffix=".tmp",
            encoding="utf-8",
        ) as tmp_file:
            tmp_file.write(yaml_text)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            tmp_path = Path(tmp_file.name)
        tmp_path.replace(config_path)
    except OSError as exc:
        if exc.errno in (errno.EBUSY, errno.EXDEV, errno.EPERM):
            logger.warning("atomic replace failed on mounted config, fallback to direct write: %s", exc)
            with config_path.open("w", encoding="utf-8") as file_obj:
                file_obj.write(yaml_text)
                file_obj.flush()
                os.fsync(file_obj.fileno())
            return
        raise
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()


def _backup_config_file(config_path: Path) -> str:
    if not config_path.exists():
        return ""
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = config_path.with_name("{}.bak.{}".format(config_path.name, stamp))
    backup_path.write_text(config_path.read_text(encoding="utf-8"), encoding="utf-8")
    return str(backup_path)


def _safe_bool(value, default_value=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return bool(default_value)


def _safe_int(value, default_value, min_value=1):
    try:
        parsed = int(value)
    except Exception:
        return int(default_value)
    if parsed < min_value:
        return int(default_value)
    return parsed


def _extract_dingtalk_config(config_obj):
    dingding_conf = config_obj.get("DINGDING", {})
    if not isinstance(dingding_conf, dict):
        dingding_conf = {}

    dingtalk_api_conf = config_obj.get("DINGTALK_API", {})
    if not isinstance(dingtalk_api_conf, dict):
        dingtalk_api_conf = {}

    return {
        "dingding_access_token": str(dingding_conf.get("ACCESS_TOKEN", Config.DINGDING_ACCESS_TOKEN or "")),
        "dingding_secret": str(dingding_conf.get("SECRET", Config.DINGDING_SECRET or "")),
        "kb_enable": _safe_bool(dingtalk_api_conf.get("ENABLE"), Config.DINGTALK_KB_ENABLE),
        "base_url": str(dingtalk_api_conf.get("BASE_URL", Config.DINGTALK_API_BASE_URL or "https://api.dingtalk.com")),
        "corp_id": str(dingtalk_api_conf.get("CORP_ID", Config.DINGTALK_CORP_ID or "")),
        "app_key": str(dingtalk_api_conf.get("APP_KEY", Config.DINGTALK_APP_KEY or "")),
        "app_secret": str(dingtalk_api_conf.get("APP_SECRET", Config.DINGTALK_APP_SECRET or "")),
        "operator_id": str(dingtalk_api_conf.get("OPERATOR_ID", Config.DINGTALK_OPERATOR_ID or "")),
        "workspace_id": str(dingtalk_api_conf.get("WORKSPACE_ID", Config.DINGTALK_WORKSPACE_ID or "")),
        "parent_node_id": str(dingtalk_api_conf.get("PARENT_NODE_ID", Config.DINGTALK_PARENT_NODE_ID or "")),
        "create_node_path": str(
            dingtalk_api_conf.get("CREATE_NODE_PATH", Config.DINGTALK_KB_CREATE_NODE_PATH or "")
        ),
        "kb_timeout": _safe_int(dingtalk_api_conf.get("KB_TIMEOUT"), Config.DINGTALK_KB_TIMEOUT),
        "title_prefix": str(dingtalk_api_conf.get("TITLE_PREFIX", Config.DINGTALK_KB_TITLE_PREFIX or "")),
        "dry_run": _safe_bool(dingtalk_api_conf.get("DRY_RUN"), Config.DINGTALK_KB_DRY_RUN),
        "report_base_url": str(dingtalk_api_conf.get("REPORT_BASE_URL", Config.DINGTALK_REPORT_BASE_URL or "")),
        "ssl_cert_notify_enable": _safe_bool(
            dingtalk_api_conf.get("SSL_CERT_NOTIFY_ENABLE"), Config.DINGTALK_SSL_CERT_NOTIFY_ENABLE
        ),
    }


def _merge_dingtalk_config(config_obj, dingtalk_config):
    if not isinstance(dingtalk_config, dict):
        raise ValueError("dingtalk_config 必须为对象")

    if not isinstance(config_obj.get("DINGDING"), dict):
        config_obj["DINGDING"] = {}
    if not isinstance(config_obj.get("DINGTALK_API"), dict):
        config_obj["DINGTALK_API"] = {}

    dingding_conf = config_obj["DINGDING"]
    dingtalk_api_conf = config_obj["DINGTALK_API"]

    dingding_conf["ACCESS_TOKEN"] = str(dingtalk_config.get("dingding_access_token", "")).strip()
    dingding_conf["SECRET"] = str(dingtalk_config.get("dingding_secret", "")).strip()

    dingtalk_api_conf["ENABLE"] = _safe_bool(dingtalk_config.get("kb_enable"), False)
    dingtalk_api_conf["BASE_URL"] = str(dingtalk_config.get("base_url", "")).strip() or "https://api.dingtalk.com"
    dingtalk_api_conf["CORP_ID"] = str(dingtalk_config.get("corp_id", "")).strip()
    dingtalk_api_conf["APP_KEY"] = str(dingtalk_config.get("app_key", "")).strip()
    dingtalk_api_conf["APP_SECRET"] = str(dingtalk_config.get("app_secret", "")).strip()
    dingtalk_api_conf["OPERATOR_ID"] = str(dingtalk_config.get("operator_id", "")).strip()
    dingtalk_api_conf["WORKSPACE_ID"] = str(dingtalk_config.get("workspace_id", "")).strip()
    dingtalk_api_conf["PARENT_NODE_ID"] = str(dingtalk_config.get("parent_node_id", "")).strip()
    dingtalk_api_conf["CREATE_NODE_PATH"] = (
        str(dingtalk_config.get("create_node_path", "")).strip() or "/v1.0/doc/workspaces/{workspace_id}/docs"
    )
    dingtalk_api_conf["KB_TIMEOUT"] = _safe_int(dingtalk_config.get("kb_timeout"), 20)
    dingtalk_api_conf["TITLE_PREFIX"] = str(dingtalk_config.get("title_prefix", "")).strip()
    dingtalk_api_conf["DRY_RUN"] = _safe_bool(dingtalk_config.get("dry_run"), False)
    dingtalk_api_conf["REPORT_BASE_URL"] = str(dingtalk_config.get("report_base_url", "")).strip()
    dingtalk_api_conf["SSL_CERT_NOTIFY_ENABLE"] = _safe_bool(
        dingtalk_config.get("ssl_cert_notify_enable"), False
    )
    return config_obj


def _apply_runtime_dingtalk_config(dingtalk_config):
    """
    将保存后的钉钉配置同步到当前进程内存，便于立即测试。
    """
    Config.DINGDING_ACCESS_TOKEN = str(dingtalk_config.get("dingding_access_token", "")).strip()
    Config.DINGDING_SECRET = str(dingtalk_config.get("dingding_secret", "")).strip()
    Config.DINGTALK_KB_ENABLE = _safe_bool(dingtalk_config.get("kb_enable"), False)
    Config.DINGTALK_API_BASE_URL = str(dingtalk_config.get("base_url", "")).strip() or "https://api.dingtalk.com"
    Config.DINGTALK_CORP_ID = str(dingtalk_config.get("corp_id", "")).strip()
    Config.DINGTALK_APP_KEY = str(dingtalk_config.get("app_key", "")).strip()
    Config.DINGTALK_APP_SECRET = str(dingtalk_config.get("app_secret", "")).strip()
    Config.DINGTALK_OPERATOR_ID = str(dingtalk_config.get("operator_id", "")).strip()
    Config.DINGTALK_WORKSPACE_ID = str(dingtalk_config.get("workspace_id", "")).strip()
    Config.DINGTALK_PARENT_NODE_ID = str(dingtalk_config.get("parent_node_id", "")).strip()
    Config.DINGTALK_KB_CREATE_NODE_PATH = (
        str(dingtalk_config.get("create_node_path", "")).strip() or "/v1.0/doc/workspaces/{workspace_id}/docs"
    )
    Config.DINGTALK_KB_TIMEOUT = _safe_int(dingtalk_config.get("kb_timeout"), 20)
    Config.DINGTALK_KB_TITLE_PREFIX = str(dingtalk_config.get("title_prefix", "")).strip()
    Config.DINGTALK_KB_DRY_RUN = _safe_bool(dingtalk_config.get("dry_run"), False)
    Config.DINGTALK_REPORT_BASE_URL = str(dingtalk_config.get("report_base_url", "")).strip()
    Config.DINGTALK_SSL_CERT_NOTIFY_ENABLE = _safe_bool(
        dingtalk_config.get("ssl_cert_notify_enable"), False
    )


def _build_dingtalk_error(message, detail):
    """
    统一构建钉钉调试接口的错误返回
    """
    data = {
        "success": False,
        "error_message": message,
        "detail": detail,
    }
    if isinstance(detail, dict) and detail.get("missing_fields"):
        data["missing_fields"] = detail.get("missing_fields", [])
    return utils.build_ret(ErrorMsg.Error, data)


def _build_dingtalk_success(data):
    """
    统一构建钉钉调试接口成功返回
    """
    if not isinstance(data, dict):
        data = {"result": data}

    ret_data = {"success": True}
    ret_data.update(data)
    return utils.build_ret(ErrorMsg.Success, ret_data)


@ns.route("/config/")
class DingtalkApiConfig(ARLResource):
    """
    获取/保存钉钉集成配置
    """

    @auth
    def get(self):
        config_path = _resolve_config_path()
        try:
            config_obj = _load_config_from_file(config_path)
            dingtalk_config = _extract_dingtalk_config(config_obj)
            runtime_status = dingtalk_openapi.get_runtime_status()
            return _build_dingtalk_success(
                {
                    "config": dingtalk_config,
                    "runtime_status": runtime_status,
                    "config_path": str(config_path),
                    "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
        except Exception as exc:
            logger.exception("load dingtalk config failed: %s", exc)
            return _build_dingtalk_error(
                "load dingtalk config failed",
                {"error": str(exc), "config_path": str(config_path)},
            )

    @auth
    @ns.expect(save_dingtalk_config_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        dingtalk_config = payload.get("dingtalk_config")
        config_path = _resolve_config_path()

        with DINGTALK_CONFIG_LOCK:
            try:
                config_obj = _load_config_from_file(config_path)
                config_obj = _merge_dingtalk_config(config_obj, dingtalk_config)
                backup_path = _backup_config_file(config_path)
                _atomic_write_yaml(config_path, config_obj)
                saved_config = _extract_dingtalk_config(config_obj)
                _apply_runtime_dingtalk_config(saved_config)
            except Exception as exc:
                logger.exception("save dingtalk config failed: %s", exc)
                return _build_dingtalk_error(
                    "save dingtalk config failed",
                    {"error": str(exc), "config_path": str(config_path)},
                )

        return _build_dingtalk_success(
            {
                "saved": True,
                "config": saved_config,
                "runtime_status": dingtalk_openapi.get_runtime_status(),
                "config_path": str(config_path),
                "backup_path": backup_path,
                "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )


@ns.route("/test/")
class DingtalkApiTest(ARLResource):
    """
    测试钉钉开放平台连通性
    """

    @auth
    @ns.expect(test_dingtalk_fields)
    def post(self):
        args = self.parse_args(test_dingtalk_fields)
        success, result = dingtalk_openapi.test_connection(
            force_refresh_token=bool(args.get("force_refresh_token", False))
        )
        if not success:
            return _build_dingtalk_error("dingtalk test failed", result)
        return _build_dingtalk_success(result)


@ns.route("/workspaces/")
class DingtalkApiWorkspaces(ARLResource):
    """
    获取知识库空间列表
    """

    @auth
    @ns.expect(list_workspaces_fields)
    def post(self):
        args = self.parse_args(list_workspaces_fields)
        success, result = dingtalk_openapi.list_workspaces(operator_id=args.get("operator_id", ""))
        if not success:
            return _build_dingtalk_error("list dingtalk workspaces failed", result)
        return _build_dingtalk_success(result)


@ns.route("/nodes/")
class DingtalkApiNodes(ARLResource):
    """
    获取知识库目录节点列表
    """

    @auth
    @ns.expect(list_nodes_fields)
    def post(self):
        args = self.parse_args(list_nodes_fields)
        success, result = dingtalk_openapi.list_nodes(
            parent_node_id=args.get("parent_node_id", ""),
            operator_id=args.get("operator_id", ""),
        )
        if not success:
            return _build_dingtalk_error("list dingtalk nodes failed", result)
        return _build_dingtalk_success(result)


@ns.route("/create_workbook/")
class DingtalkApiCreateWorkbook(ARLResource):
    """
    手动创建知识库表格（WORKBOOK）
    """

    @auth
    @ns.expect(create_workbook_fields)
    def post(self):
        args = self.parse_args(create_workbook_fields)
        success, result = dingtalk_openapi.create_workbook(
            title=args.get("title", ""),
            workspace_id=args.get("workspace_id", ""),
            parent_node_id=args.get("parent_node_id", ""),
            operator_id=args.get("operator_id", ""),
            require_enable=False,
        )
        if not success:
            return _build_dingtalk_error("create dingtalk workbook failed", result)
        return _build_dingtalk_success(result)


@ns.route("/sheets/")
class DingtalkApiWorkbookSheets(ARLResource):
    """
    获取 workbook 下工作表列表
    """

    @auth
    @ns.expect(list_sheets_fields)
    def post(self):
        args = self.parse_args(list_sheets_fields)
        success, result = dingtalk_openapi.list_workbook_sheets(
            workbook_id=args.get("workbook_id", ""),
            operator_id=args.get("operator_id", ""),
            require_enable=False,
        )
        if not success:
            return _build_dingtalk_error("list dingtalk workbook sheets failed", result)
        return _build_dingtalk_success(result)


@ns.route("/write_markdown/")
class DingtalkApiWriteWorkbookMarkdown(ARLResource):
    """
    将 markdown 文本写入 workbook
    """

    @auth
    @ns.expect(write_markdown_fields)
    def post(self):
        args = self.parse_args(write_markdown_fields)
        markdown_content = args.get("markdown_content", "")
        if not markdown_content:
            markdown_content = "### 钉钉 API 联调测试\n\n- 时间：`{}`\n- 结果：`write markdown success`\n".format(
                utils.curr_date()
            )

        success, result = dingtalk_openapi.write_markdown_to_workbook(
            workbook_id=args.get("workbook_id", ""),
            markdown_content=markdown_content,
            operator_id=args.get("operator_id", ""),
            sheet_name=args.get("sheet_name", "Sheet1"),
            require_enable=False,
        )
        if not success:
            return _build_dingtalk_error("write workbook markdown failed", result)
        return _build_dingtalk_success(result)
