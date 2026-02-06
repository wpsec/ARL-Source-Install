"""
GitHub泄露结果模块

功能说明：
- GitHub代码泄露搜索结果查询
- 显示搜索到的敏感信息和源代码
- 支持按仓库、内容等多维度查询
- 提供结果详情展示

说明：
- 存储GitHub搜索任务的结果
- 包含泄露内容的完整信息
- 支持标记和分类结果
- 支持导出结果数据

结果包含：
- 仓库名称和URL
- 泄露内容
- 发现时间
- 文件路径
- 代码行号

应用场景：
- 查看GitHub上发现的泄露信息
- 追踪泄露内容来源
- 风险评估和修复
"""
from flask_restx import fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser

ns = Namespace('github_result', description="Github 结果详情")

logger = get_logger()

base_search_fields = {
    'path': fields.String(required=False, description="路径名称"),
    'repo_full_name': fields.String(description="仓库名称"),
    'human_content': fields.String(description="内容"),
    'github_task_id': fields.String(description="任务ID")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLGithubResult(ARLResource):
    """GitHub泄露结果查询接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询GitHub泄露搜索结果
        
        参数：
            - path: 文件路径（模糊匹配）
            - repo_full_name: 仓库全名（格式: owner/repo）
            - human_content: 内容关键字
            - github_task_id: 所属GitHub任务ID
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [泄露结果列表],
                    "total": 总数
                }
            }
        
        结果字段说明：
            - repo_full_name: 仓库全名
            - path: 文件路径
            - human_content: 泄露内容
            - url: GitHub链接
            - match_line: 匹配行号
            - found_time: 发现时间
        
        应用场景：
        - 查看企业相关的泄露信息
        - 追踪源代码或密钥泄露
        - 汇总泄露统计分析
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='github_result')

        return data


