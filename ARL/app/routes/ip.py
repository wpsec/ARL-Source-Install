"""
IP 资产管理 API
================================================

该模块提供 IP 资产的查询、导出和删除功能

主要功能：
1. 查询 IP 信息（支持多种查询条件）
2. 导出 IP:端口数据
3. 从 IP 记录中导出域名列表
4. 导出纯 IP 列表
5. 批量删除 IP 记录

IP 信息包括：
- IP 地址
- 关联的域名
- 开放端口信息（端口号、服务名、版本、产品）
- 操作系统信息
- CDN 厂商信息
- GeoIP 地理位置信息（国家、城市、地区）
- ASN 信息（自治系统号、组织）
- IP 类型（公网/内网）

端口信息包括：
- port_id: 端口号
- service_name: 服务名称（如 http、ssh）
- version: 服务版本
- product: 产品名称（如 Apache、Nginx）
- protocol: 协议类型（tcp/udp）
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from app import utils
from app.modules import ErrorMsg
from . import base_query_fields, ARLResource, get_arl_parser

# 创建 IP 信息命名空间
ns = Namespace('ip', description="IP信息")

logger = get_logger()

# IP 查询字段定义
base_search_fields = {
    'ip': fields.String(required=False, description="IP 地址"),
    'domain': fields.String(description="关联的域名"),
    'port_info.port_id': fields.Integer(description="开放的端口号"),
    'port_info.service_name': fields.String(description="服务名称（如 http、ssh、mysql）"),
    'port_info.version': fields.String(description="服务版本号"),
    'port_info.product': fields.String(description="产品名称（如 Apache、Nginx）"),
    'os_info.name': fields.String(description="操作系统名称"),
    "task_id": fields.String(description="关联的任务ID"),
    "ip_type": fields.String(description="IP类型：PUBLIC（公网）或 PRIVATE（内网）"),
    "cdn_name": fields.String(description="CDN 厂商名称（如 Cloudflare、阿里云CDN）"),
    "geo_asn.number": fields.Integer(description="ASN 自治系统号"),
    "geo_asn.organization": fields.String(description="ASN 组织名称"),
    "geo_city.region_name": fields.String(description="地理位置区域名称")
}

# 合并基础查询字段
base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLIP(ARLResource):
    """IP 信息查询接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询 IP 信息
        
        支持的查询条件：
        - ip: IP地址（模糊匹配）
        - domain: 关联域名
        - port_info.port_id: 端口号
        - port_info.service_name: 服务名称
        - os_info.name: 操作系统
        - ip_type: IP类型（PUBLIC/PRIVATE）
        - cdn_name: CDN厂商
        - geo_asn.*: ASN信息
        - geo_city.*: 地理位置信息
        
        返回：
            分页的 IP 信息列表
        
        应用场景：
        - 查询开放特定端口的主机
        - 查询使用特定服务的主机
        - 按地理位置筛选IP
        - 查询内网IP或公网IP
        - 查询使用CDN的站点
        """
        args = self.parser.parse_args()
        # 从 ip 集合查询数据
        data = self.build_data(args=args, collection='ip')

        return data


@ns.route('/export/')
class ARLIPExport(ARLResource):
    """IP:端口导出接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        导出 IP:端口数据
        
        导出格式：
            192.168.1.1:80
            192.168.1.1:443
            192.168.1.2:22
        
        返回：
            文本文件下载
            文件名格式：ip_数量_时间戳.txt
        
        应用场景：
        - 导出端口列表用于其他工具扫描
        - 导出目标主机清单
        - 批量导出资产
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="ip")

        return response


@ns.route('/export_domain/')
class ARLIPExportDomain(ARLResource):
    """从 IP 记录中导出域名接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        从 IP 记录中导出关联的域名
        
        导出 IP 记录中 domain 字段的所有域名
        每行一个域名
        
        返回：
            文本文件下载
        
        应用场景：
        - 导出解析到特定IP的域名
        - 批量导出域名资产
        """
        args = self.parser.parse_args()
        response = self.send_export_file_attr(args=args, collection="ip", field="domain")

        return response


@ns.route('/export_ip/')
class ARLIPExportIp(ARLResource):
    """纯 IP 导出接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        导出纯 IP 地址列表
        
        导出格式（不包含端口）：
            192.168.1.1
            192.168.1.2
            192.168.1.3
        
        返回：
            文本文件下载
        
        应用场景：
        - 导出 IP 列表用于其他工具
        - 生成主机清单
        - 批量导出 IP 资产
        """
        args = self.parser.parse_args()
        response = self.send_export_file_attr(args=args, collection="ip", field="ip")

        return response


# 删除 IP 请求模型定义
delete_ip_fields = ns.model('deleteIpFields', {
    '_id': fields.List(fields.String(required=True, description="要删除的 IP 记录 ID 列表"))
})


@ns.route('/delete/')
class DeleteARLIP(ARLResource):
    """IP 信息删除接口"""
    
    @auth
    @ns.expect(delete_ip_fields)
    def post(self):
        """
        批量删除 IP 记录
        
        请求体：
            {
                "_id": ["IP记录ID1", "IP记录ID2", ...]
            }
        
        返回：
            删除成功的 IP 记录 ID 列表
        
        注意：
        - 支持批量删除
        - 删除操作不可恢复
        - 只删除 IP 记录，不影响关联的其他资产
        - 需要管理员权限
        """
        args = self.parse_args(delete_ip_fields)
        id_list = args.pop('_id', [])
        
        # 遍历删除每个 IP 记录
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('ip').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})
