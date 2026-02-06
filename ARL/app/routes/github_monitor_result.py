"""
GitHub监控结果模块

功能说明：
- GitHub定期监控任务的结果存储和查询
- 记录监控任务发现的泄露信息
- 支持按监控任务、关键字查询
- 支持结果趋势分析

说明：
- 监控结果与一次性搜索任务结果的区别
- 监控任务定期执行，结果按时间序列保存
- 支持跨时间段的对比分析
- 可追踪泄露信息的发展变化

监控场景：
- 持续监控关键字泄露
- 定期检测企业代码泄露
- 追踪敏感信息的时间序列
"""
from flask_restx import fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser

ns = Namespace('github_monitor_result', description="Github 监控结果详情")

logger = get_logger()

base_search_fields = {
    'path': fields.String(required=False, description="路径名称"),
    'repo_full_name': fields.String(description="仓库名称"),
    'human_content': fields.String(description="内容"),
    'keyword': fields.String(description="关键字"),
    "github_scheduler_id": fields.String(description="Github 监控ID"),
    'github_task_id': fields.String(description="任务ID")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLGithubMonitorResult(ARLResource):
    """GitHub监控结果查询接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询GitHub监控任务的结果
        
        参数：
            - path: 文件路径
            - repo_full_name: 仓库名称
            - human_content: 内容关键字
            - keyword: 监控关键字
            - github_scheduler_id: 监控任务ID
            - page: 页码
            - size: 每页数量
        
        返回：
            分页的监控结果列表
        
        说明：
        - 返回的是定期监控任务发现的结果
        - 支持按时间和内容分类
        - 可用于趋势分析
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='github_monitor_result')

        return data


