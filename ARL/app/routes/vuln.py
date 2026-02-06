"""
漏洞信息管理模块

功能说明：
- 管理扫描发现的漏洞信息
- 支持漏洞的查询和删除
- 漏洞来源：PoC扫描、Nuclei扫描等

主要数据字段：
- plg_name: 插件ID（识别漏洞的插件）
- plg_type: 漏洞类别（如SQL注入、XSS、敏感信息泄露等）
- vul_name: 漏洞名称
- app_name: 应用名称（受影响的应用）
- target: 漏洞目标（URL或IP）
- severity: 严重级别
- description: 漏洞描述
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app import utils
from app.modules import ErrorMsg

ns = Namespace('vuln', description="漏洞信息")

logger = get_logger()

# 漏洞查询字段定义
base_search_fields = {
    'plg_name': fields.String(required=False, description="插件ID（识别漏洞的插件名）"),
    'plg_type': fields.String(description="漏洞类别（如sqli, xss, info-leak等）"),
    'vul_name': fields.String(description="漏洞名称"),
    'app_name': fields.String(description="应用名称（受影响的应用）"),
    'target': fields.String(description="漏洞目标（URL或IP）"),
    "task_id": fields.String(description="任务ID")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLUrl(ARLResource):
    """漏洞查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询漏洞信息
        
        参数：
            - plg_name: 插件ID过滤
            - plg_type: 漏洞类别过滤
            - vul_name: 漏洞名称过滤
            - app_name: 应用名称过滤
            - target: 目标过滤
            - task_id: 任务ID过滤
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "items": [
                    {
                        "_id": "漏洞ID",
                        "plg_name": "插件ID",
                        "plg_type": "漏洞类别",
                        "vul_name": "漏洞名称",
                        "app_name": "应用名称",
                        "target": "漏洞目标",
                        "severity": "严重级别",
                        "description": "漏洞描述",
                        "detail": "详细信息",
                        "task_id": "任务ID",
                        "save_date": "保存时间"
                    }
                ],
                "total": 总数
            }
        
        说明：
        - 漏洞信息来自PoC扫描、Nuclei扫描等
        - 严重级别：critical（严重）、high（高危）、medium（中危）、low（低危）、info（信息）
        - 用于安全评估和漏洞管理
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='vuln')

        return data


# 删除漏洞请求模型
delete_vuln_fields = ns.model('deleteVulnFields',  {
    '_id': fields.List(fields.String(required=True, description="漏洞信息_id列表"))
})


@ns.route('/delete/')
class DeleteARLVuln(ARLResource):
    """删除漏洞信息接口"""
    
    @auth
    @ns.expect(delete_vuln_fields)
    def post(self):
        """
        批量删除漏洞信息
        
        请求体：
            {
                "_id": ["漏洞ID1", "漏洞ID2", ...]
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "_id": ["已删除的漏洞ID列表"]
            }
        
        说明：
        - 支持批量删除多个漏洞记录
        - 删除操作不可逆
        - 通常用于清理误报或已修复的漏洞
        """
        args = self.parse_args(delete_vuln_fields)
        id_list = args.pop('_id', [])
        
        # 遍历删除每个漏洞记录
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('vuln').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})


