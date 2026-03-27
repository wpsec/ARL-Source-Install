"""
AI 渗透测试结果查询接口

说明：
- 展示任务执行阶段 `ai_pen_test` 产出的验证结果
- 用于任务详情页 `AI渗透` 标签页查询与筛选
"""
from flask_restx import fields, Namespace

from app.utils import auth
from . import base_query_fields, ARLResource, get_arl_parser


ns = Namespace("ai_pen_test", description="AI 渗透测试结果")

base_search_fields = {
    "task_id": fields.String(description="任务ID"),
    "source_collection": fields.String(description="来源集合(vuln/nuclei_result/wih/site/url)"),
    "risk_type": fields.String(description="风险类型"),
    "risk_name": fields.String(description="风险名称"),
    "target": fields.String(description="目标"),
    "vuln_url": fields.String(description="漏洞URL"),
    "decision": fields.String(description="结论(verified/likely_false_positive/needs_manual_review)"),
    "status": fields.String(description="执行状态(ok/error/skipped)"),
    "verification_step": fields.String(description="验证阶段(http_fetch_replay/mcp_http_probe/mcp_idor_probe/mcp_api_doc_probe/mcp_jwt_probe/mcp_websocket_probe)"),
    "payload_type": fields.String(description="探针类型(xss_probe/sqli_probe/idor_probe/api_doc_probe等)"),
    "reason": fields.String(description="验证说明"),
}
base_search_fields.update(base_query_fields)


@ns.route("/")
class ARLAiPenTest(ARLResource):
    """AI 渗透测试结果查询"""

    parser = get_arl_parser(base_search_fields, location="args")

    @auth
    @ns.expect(parser)
    def get(self):
        args = self.parser.parse_args()
        return self.build_data(args=args, collection="ai_pen_test_result")
