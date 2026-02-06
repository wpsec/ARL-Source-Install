"""
Nuclei扫描结果管理模块

功能说明：
- 管理Nuclei漏洞扫描工具的扫描结果
- 支持扫描结果的查询和删除

Nuclei简介：
- Nuclei是一款基于模板的快速漏洞扫描工具
- 使用YAML模板定义漏洞检测规则
- 覆盖CVE漏洞、错误配置、敏感信息泄露等
- 社区维护了数千个高质量模板

主要数据字段：
- template_id: 使用的模板ID
- template_url: 模板文件URL
- vuln_name: 漏洞名称
- vuln_severity: 漏洞严重级别（critical/high/medium/low/info）
- vuln_url: 漏洞URL
- target: 扫描目标
- curl_command: 复现漏洞的curl命令
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app import utils
from app.modules import ErrorMsg

ns = Namespace('nuclei_result', description="nuclei 扫描结果")

logger = get_logger()

# Nuclei扫描结果查询字段定义
base_search_fields = {
    'template_url': fields.String(required=False, description="模板文件URL"),
    'template_id': fields.String(description="模板ID（如CVE-2021-xxxx）"),
    'vuln_name': fields.String(description="漏洞名称"),
    'vuln_severity': fields.String(description="漏洞严重级别（critical/high/medium/low/info）"),
    'vuln_url': fields.String(description="漏洞URL"),
    'curl_command': fields.String(description="复现漏洞的curl命令"),
    'target': fields.String(description="扫描目标"),
    "task_id": fields.String(description="任务ID")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLUrl(ARLResource):
    """Nuclei扫描结果查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询Nuclei扫描结果
        
        参数：
            - template_id: 模板ID过滤
            - template_url: 模板文件URL过滤
            - vuln_name: 漏洞名称过滤
            - vuln_severity: 漏洞级别过滤
            - vuln_url: 漏洞URL过滤
            - target: 目标过滤
            - task_id: 任务ID过滤
            - page: 页码
            - size: 每页数量
        
        返回：
            {
                "code": 200,
                "items": [
                    {
                        "_id": "数据ID",
                        "template_id": "模板ID",
                        "template_url": "模板URL",
                        "vuln_name": "漏洞名称",
                        "vuln_severity": "严重级别",
                        "vuln_url": "漏洞URL",
                        "target": "扫描目标",
                        "curl_command": "curl命令",
                        "matched_at": "匹配位置",
                        "extracted_results": "提取的结果",
                        "task_id": "任务ID",
                        "save_date": "保存时间"
                    }
                ],
                "total": 总数
            }
        
        说明：
        - Nuclei是基于模板的漏洞扫描工具
        - 严重级别：
          * critical: 严重（如RCE、SQL注入等）
          * high: 高危
          * medium: 中危
          * low: 低危
          * info: 信息类
        - curl_command可用于手动复现漏洞
        - 模板来自nuclei-templates项目
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='nuclei_result')

        return data


# 删除Nuclei结果请求模型
delete_nuclei_result_fields = ns.model('deleteNucleiResultFields',  {
    '_id': fields.List(fields.String(required=True, description="Nuclei扫描结果_id列表"))
})


@ns.route('/delete/')
class DeleteNucleiResult(ARLResource):
    """删除Nuclei扫描结果接口"""
    
    @auth
    @ns.expect(delete_nuclei_result_fields)
    def post(self):
        """
        批量删除Nuclei扫描结果
        
        请求体：
            {
                "_id": ["结果ID1", "结果ID2", ...]
            }
        
        返回：
            {
                "code": 200,
                "message": "成功",
                "_id": ["已删除的ID列表"]
            }
        
        说明：
        - 支持批量删除多个扫描结果
        - 删除操作不可逆
        - 通常用于清理误报或已修复的漏洞
        """
        args = self.parse_args(delete_nuclei_result_fields)
        id_list = args.pop('_id', [])
        
        # 遍历删除每个扫描结果
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('nuclei_result').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})


