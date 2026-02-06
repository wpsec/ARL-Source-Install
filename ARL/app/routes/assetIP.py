"""
资产IP管理模块

功能说明：
- 管理资产组中的IP信息
- 支持IP及关联端口服务的查询、导出和删除
- 提供IP和域名的单独导出功能
- 支持按多种维度过滤（IP类型、端口、服务、操作系统、CDN等）

主要数据字段：
- IP地址：支持IPv4/IPv6
- 端口信息：端口号、服务名称、版本、产品等
- 操作系统：识别的系统信息
- 域名：关联解析的域名
- IP类型：公网(PUBLIC)/内网(PRIVATE)
- CDN信息：CDN厂商识别
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app.modules import ErrorMsg
from app import utils

ns = Namespace('asset_ip', description="资产组IP信息")

logger = get_logger()

# IP查询字段定义
base_search_fields = {
    'ip': fields.String(required=False, description="IP地址"),
    'domain': fields.String(description="关联域名"),
    'port_info.port_id': fields.Integer(description="端口号"),
    'port_info.service_name': fields.String(description="系统服务名称（如http, ssh等）"),
    'port_info.version': fields.String(description="服务版本号"),
    'port_info.product': fields.String(description="产品名称（如nginx, apache等）"),
    'os_info.name': fields.String(description="操作系统名称"),
    "task_id": fields.String(description="任务ID"),
    "update_date__dgt": fields.String(description="更新时间大于（格式：YYYY-MM-DD HH:mm:ss）"),
    "update_date__dlt": fields.String(description="更新时间小于（格式：YYYY-MM-DD HH:mm:ss）"),
    "scope_id": fields.String(description="所属资产组ID"),
    "ip_type": fields.String(description="IP类型，公网(PUBLIC)和内网(PRIVATE)"),
    "cdn_name": fields.String(description="CDN厂商名称（如cloudflare, akamai等）")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLAssetIP(ARLResource):
    """资产IP查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询资产组中的IP信息
        
        参数：
            - ip: IP地址过滤
            - domain: 关联域名过滤
            - port_info.port_id: 端口号过滤
            - port_info.service_name: 服务名称过滤
            - port_info.product: 产品名称过滤
            - os_info.name: 操作系统名称过滤
            - scope_id: 资产组ID过滤
            - ip_type: IP类型(PUBLIC/PRIVATE)
            - cdn_name: CDN厂商过滤
            - update_date__dgt/dlt: 更新时间范围
            - page: 页码
            - size: 每页数量
            - order: 排序字段
        
        返回：
            {
                "code": 200,
                "items": [
                    {
                        "_id": "数据ID",
                        "ip": "IP地址",
                        "domain": ["域名1", "域名2"],
                        "port_info": [
                            {
                                "port_id": 端口号,
                                "service_name": "服务名",
                                "version": "版本",
                                "product": "产品"
                            }
                        ],
                        "os_info": {"name": "操作系统"},
                        "geo_info": {"country": "国家", "province": "省份", "city": "城市"},
                        "ip_type": "PUBLIC/PRIVATE",
                        "cdn_name": "CDN厂商",
                        "scope_id": "资产组ID",
                        "update_date": "更新时间"
                    }
                ],
                "total": 总数
            }
        
        说明：
        - 返回IP及其关联的端口、服务、操作系统等完整信息
        - 支持按多种维度组合查询
        - 端口信息以数组形式返回，一个IP可能包含多个开放端口
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='asset_ip')

        return data


@ns.route('/export/')
class ARLAssetIPExport(ARLResource):
    """资产IP详细信息导出接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        导出资产组中的IP完整信息到Excel
        
        参数：
            与查询接口相同
        
        返回：
            Excel文件下载
        
        说明：
        - 导出IP、端口、服务、操作系统等完整信息
        - 文件名：asset_ip_export_时间戳.xlsx
        - 端口信息会展开到多行
        """
        args = self.parser.parse_args()
        response = self.send_export_file(args=args, _type="asset_ip")

        return response


@ns.route('/export_ip/')
class ARLIPExportIp(ARLResource):
    """IP地址单独导出接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        从资产组IP中单独导出IP地址列表
        
        参数：
            与查询接口相同
        
        返回：
            纯文本文件，每行一个IP地址
        
        说明：
        - 只导出IP地址字段，不包含其他信息
        - 自动去重
        - 适合批量扫描工具使用
        """
        args = self.parser.parse_args()
        response = self.send_export_file_attr(args=args, collection="asset_ip", field="ip")

        return response


@ns.route('/export_domain/')
class ARLIPExportIp(ARLResource):
    """域名单独导出接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        从资产组IP中单独导出关联域名列表
        
        参数：
            与查询接口相同
        
        返回：
            纯文本文件，每行一个域名
        
        说明：
        - 导出IP关联的所有解析域名
        - 自动去重
        - 适合域名批量管理
        """
        args = self.parser.parse_args()
        response = self.send_export_file_attr(args=args, collection="asset_ip", field="domain")

        return response


# 删除IP请求模型
delete_ip_fields = ns.model('deleteAssetIP',  {
    '_id': fields.List(fields.String(required=True, description="IP数据_id列表"))
})


@ns.route('/delete/')
class DeleteARLAssetIP(ARLResource):
    """删除资产IP接口"""
    
    @auth
    @ns.expect(delete_ip_fields)
    def post(self):
        """
        批量删除资产组中的IP记录
        
        请求体：
            {
                "_id": ["IP数据ID1", "IP数据ID2", ...]
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "_id": ["已删除的ID列表"]
            }
        
        说明：
        - 支持批量删除多个IP记录
        - 删除操作不可逆
        - 只删除资产组中的IP信息，不影响任务数据
        - 会同时删除IP的所有关联信息（端口、服务等）
        """
        args = self.parse_args(delete_ip_fields)
        id_list = args.pop('_id', "")
        
        # 遍历删除每个IP记录
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('asset_ip').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})
