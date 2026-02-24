"""
钉钉开放平台调试接口

用途：
- 测试钉钉开放平台配置是否可用
- 拉取知识库空间列表和目录节点列表
- 手动创建知识库表格（WORKBOOK）用于联调
"""
from flask_restx import fields, Namespace

from app import utils
from app.modules import ErrorMsg
from app.utils import auth, dingtalk_openapi
from . import ARLResource

ns = Namespace("dingtalk_api", description="钉钉开放平台调试")


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
    return utils.build_ret(ErrorMsg.Success, data)


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
    获取当前钉钉开放平台配置状态（脱敏）
    """

    @auth
    def get(self):
        data = dingtalk_openapi.get_runtime_status()
        return _build_dingtalk_success(data)


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
