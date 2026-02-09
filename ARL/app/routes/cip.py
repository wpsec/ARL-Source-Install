"""
C段IP统计模块

功能说明：
- C段IP信息查询
- C段范围内的IP和域名统计
- 支持任务ID筛选

说明：
- C段指 IP 地址的前三个八位组（如 192.168.1.0/24）
- 统计每个 C 段内的 IP 数量、域名数量等
- 支持按任务、C段等多维度查询
- 用于快速定位资产分布情况
"""
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser

ns = Namespace('cip', description="C段 ip 统计信息")

logger = get_logger()

base_search_fields = {
    'cidr_ip': fields.String(required=False, description="C段"),
    "task_id": fields.String(description="任务 ID"),
    "ip_count": fields.Integer(description="IP 个数"),
    "domain_count": fields.Integer(description="解析到该 C 段域名个数")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLCIPList(ARLResource):
    """C段IP统计查询接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询C段IP统计信息
        
        参数：
            - cidr_ip: C段地址（如 192.168.1.0/24）
            - task_id: 任务ID
            - ip_count: IP数量范围筛选
            - domain_count: 域名数量范围筛选
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [C段统计信息],
                    "total": 总数
                }
            }
        
        C段统计字段：
            - cidr_ip: C段地址
            - ip_count: 该C段内IP总数
            - domain_count: 解析到该C段的域名总数
            - task_id: 所属任务ID
        
        应用场景：
        - 快速查看资产IP分布
        - 定位大规模IP段
        - 对比不同时期的IP分布
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='cip')

        return data


@ns.route('/export/')
class ARLCIPExport(ARLResource):
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        C 段 IP 导出
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="cip")

        return response
