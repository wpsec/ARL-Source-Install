"""
指纹统计模块

功能说明：
- 指纹识别结果的统计汇总
- 按指纹类型统计数量
- 支持任务、指纹名称等多维度查询
- 用于展示资产指纹分布情况

说明：
- 统计每种指纹在扫描结果中出现的次数
- 支持按任务维度统计
- 用于快速定位最常见的应用类型
- 支持指纹排序和筛选

应用场景：
- 了解资产中最常见的Web框架
- 发现常见的Web服务器
- 快速定位特定应用类型的资产
"""
from flask_restx import fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser

ns = Namespace('stat_finger', description="指纹统计信息")

logger = get_logger()

base_search_fields = {
    'name': fields.String(required=False, description="指纹名称"),  # 字段名没搞好
    "task_id": fields.String(description="任务 ID"),
    "cnt": fields.Integer(description="数目"),
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLStatFingerprint(ARLResource):
    """指纹统计查询接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询指纹统计信息
        
        参数：
            - name: 指纹名称（模糊匹配）
            - task_id: 任务ID
            - cnt: 数量范围筛选
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [指纹统计列表],
                    "total": 总数
                }
            }
        
        统计字段说明：
            - name: 指纹名称（如WordPress、ThinkPHP）
            - cnt: 该指纹出现的次数
            - task_id: 所属任务ID
        
        应用场景：
        - 快速统计资产中使用的框架和组件
        - 按流行度排序应用类型
        - 发现资产中的技术栈分布
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='stat_finger')

        return data
