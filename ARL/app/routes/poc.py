"""
PoC（Proof of Concept）管理模块

功能说明：
- 管理漏洞验证插件（PoC插件）
- 支持PoC的查询、同步和清空
- PoC用于验证漏洞是否真实存在

PoC类型：
1. poc：漏洞验证插件（如CVE漏洞检测）
2. brute：暴力破解插件（如弱口令检测）

主要功能：
- 查询可用的PoC插件
- 从NPoC项目同步最新PoC
- 清空PoC数据库
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app.services.npoc import NPoC
from app import utils, celerytask
from app.modules import ErrorMsg, TaskStatus, CeleryAction
import copy

ns = Namespace('poc', description="PoC信息")

logger = get_logger()

# PoC查询字段定义
base_search_fields = {
    'plugin_name': fields.String(description="PoC插件名称/ID"),
    'app_name': fields.String(description="应用名称（目标应用）"),
    'scheme': fields.String(description="支持的协议（http、https等）"),
    'vul_name': fields.String(description="漏洞名称"),
    'plugin_type': fields.String(description="插件类别", enum=['poc', 'brute']),
    'update_date': fields.String(description="更新时间"),
    'category': fields.String(description="PoC分类（如CMS、框架、中间件等）")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLPoC(ARLResource):
    """PoC查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询PoC插件信息
        
        参数：
            - plugin_name: PoC插件名称过滤
            - app_name: 应用名称过滤
            - scheme: 协议过滤
            - vul_name: 漏洞名称过滤
            - plugin_type: 插件类别过滤（poc/brute）
            - category: PoC分类过滤
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "items": [
                    {
                        "_id": "插件ID",
                        "plugin_name": "插件名称",
                        "app_name": "应用名称",
                        "vul_name": "漏洞名称",
                        "scheme": "协议",
                        "plugin_type": "插件类型",
                        "category": "分类",
                        "description": "描述",
                        "severity": "严重级别",
                        "update_date": "更新时间"
                    }
                ],
                "total": 总数
            }
        
        说明：
        - PoC插件用于漏洞验证和暴力破解
        - 可在任务配置中选择要使用的PoC
        - 支持HTTP、HTTPS等多种协议
        - 插件来自ARL-NPoC项目
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args,  collection='poc')

        return data


@ns.route('/sync/')
class ARLPoCSync(ARLResource):
    """PoC同步接口"""

    @auth
    def get(self):
        """
        同步更新PoC插件信息
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "plugin_cnt": 插件总数
            }
        
        说明：
        - 从ARL-NPoC项目同步最新的PoC插件
        - 会更新现有插件并删除已废弃的插件
        - 建议定期执行以获取最新漏洞检测能力
        - 同步过程可能需要几秒钟
        
        操作流程：
        1. 读取NPoC插件列表
        2. 同步到数据库（更新或新增）
        3. 删除已废弃的插件
        """
        n = NPoC()
        plugin_cnt = len(n.plugin_name_list)
        # 同步插件到数据库
        n.sync_to_db()
        # 删除废弃的插件
        n.delete_db()

        return utils.build_ret(ErrorMsg.Success, {"plugin_cnt": plugin_cnt})


@ns.route('/delete/')
class ARLPoCDelete(ARLResource):
    """PoC清空接口"""

    @auth
    def get(self):
        """
        清空所有PoC插件信息
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "delete_cnt": 删除数量
            }
        
        说明：
        - 清空PoC数据库中的所有插件
        - 删除操作不可逆
        - 清空后需要重新同步才能使用PoC功能
        - 通常在重新初始化或排查问题时使用
        """
        result = utils.conn_db('poc').delete_many({})

        delete_cnt = result.deleted_count

        return utils.build_ret(ErrorMsg.Success, {"delete_cnt": delete_cnt})



