"""
服务信息管理模块

功能：
- 服务信息查询、导出
- 端口和服务识别结果管理

说明：
- 服务数据来自端口扫描和服务识别
- 包含端口、协议、产品、版本等信息
- 支持按IP、端口、服务名称等维度查询
"""
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser

ns = Namespace('service', description="系统服务信息")

logger = get_logger()

# 服务查询字段
base_search_fields = {
    'service_name': fields.String(description="系统服务名称"),
    'service_info.ip': fields.String(required=False, description="IP"),
    'service_info.port_id': fields.Integer(description="端口号"),
    'service_info.version': fields.String(description="系统服务版本"),
    'service_info.product': fields.String(description="产品"),
    "task_id": fields.String(description="任务ID")
}

# 合并通用查询字段
base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLService(ARLResource):
    """服务信息查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询服务信息
        
        参数：
            - service_name: 服务名称（如 http、mysql、ssh）
            - service_info.ip: IP地址
            - service_info.port_id: 端口号
            - service_info.version: 服务版本
            - service_info.product: 产品名称（如 nginx、Apache）
            - task_id: 任务ID
            - page: 页码（默认1）
            - size: 每页数量（默认10）
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [服务信息列表],
                    "total": 总数
                }
            }
        
        服务字段说明：
            - service_name: 服务名称（如 http、ssh、mysql）
            - service_info: {
                - ip: IP地址
                - port_id: 端口号
                - protocol: 协议类型（tcp/udp）
                - product: 产品名称
                - version: 版本号
                - banner: 服务Banner信息
              }
            - task_id: 关联的任务ID
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='service')

        return data

