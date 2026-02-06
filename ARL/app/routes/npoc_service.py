"""
NPoC服务识别模块

功能说明：
- Python实现的服务识别（NPoC）
- 识别常见网络服务
- 提供服务版本检测
- 支持自定义服务指纹

说明：
- NPoC: Network Probe of Concept（网络探测概念验证）
- 基于Python实现的轻量级服务识别
- 支持 HTTP、FTP、SSH、SMTP 等常见协议
- 可识别服务版本和配置信息
- 支持按任务、端口、服务类型等多维度查询

识别场景：
- Web服务器识别
- FTP、SSH等远程服务识别
- 邮件服务器识别
- 数据库服务识别
"""
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser

ns = Namespace('npoc_service', description="系统服务(python)信息")

logger = get_logger()

base_search_fields = {
    'scheme': fields.String(description="系统服务名称"),
    'host': fields.String(required=False, description="host"),
    'port': fields.String(description="端口号"),
    'target': fields.String(description="目标"),
    "task_id": fields.String(description="任务ID")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class NpocService(ARLResource):
    """NPoC服务识别查询接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询NPoC服务识别结果
        
        参数：
            - scheme: 服务类型（http、ftp、ssh等）
            - host: 主机地址
            - port: 服务端口
            - target: 扫描目标
            - task_id: 任务ID
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [服务列表],
                    "total": 总数
                }
            }
        
        服务字段说明：
            - scheme: 服务协议类型
            - host: 主机地址
            - port: 端口号
            - target: 目标地址
            - version: 版本信息
            - info: 服务详情
        
        应用场景：
        - 快速识别目标资产的服务类型
        - 发现未知服务和隐藏服务
        - 版本探测和漏洞检测
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='npoc_service')

        return data
