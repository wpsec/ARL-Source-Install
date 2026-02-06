"""
URL信息管理模块

功能：
- URL信息查询、导出
- URL批量删除

说明：
- URL数据来自站点爬虫和目录扫描
- 记录了URL的状态码、标题、内容长度等信息
- 支持按来源、站点、状态码等维度查询
"""
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser

ns = Namespace('url', description="URL信息")

logger = get_logger()

# URL查询字段
base_search_fields = {
    'fld': fields.String(required=False, description="IP"),
    'site': fields.String(description="域名"),
    'url': fields.String(required=False, description="URL"),
    'content_length': fields.Integer(description="body 长度"),
    'status_code': fields.Integer(description="状态码"),
    'title': fields.String(description="标题"),
    'source': fields.String(description="来源"),
    "task_id": fields.String(description="任务ID")
}

# 合并通用查询字段
base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLUrl(ARLResource):
    """URL信息查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询URL信息
        
        参数：
            - fld: 根域名
            - site: 站点（模糊匹配）
            - url: URL（模糊匹配）
            - content_length: 响应Body长度
            - status_code: HTTP状态码
            - title: 页面标题
            - source: 来源（如spider、scan）
            - task_id: 任务ID
            - page: 页码（默认1）
            - size: 每页数量（默认10）
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [URL信息列表],
                    "total": 总数
                }
            }
        
        URL字段说明：
            - url: 完整URL
            - site: 所属站点
            - title: 页面标题
            - status_code: HTTP状态码
            - content_length: 响应内容长度
            - source: 来源（spider/scan/brute）
            - task_id: 关联的任务ID
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='url')

        return data


@ns.route('/export/')
class ARLUrlExport(ARLResource):
    """URL信息导出接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        导出URL信息到Excel文件
        
        参数：
            与查询接口相同
        
        返回：
            Excel文件下载
        
        说明：
        - 导出字段：URL、标题、状态码、内容长度、来源等
        - 文件名：url_export_时间戳.xlsx
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="url")

        return response

