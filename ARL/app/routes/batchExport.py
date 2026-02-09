"""
批量导出模块

功能说明：
- 支持批量导出多个任务或资产组的数据
- 提供两种导出模式：
  1. 按任务ID批量导出：导出多个任务的扫描结果
  2. 按资产组ID批量导出：导出多个资产组的持久化数据

导出类型：
- 任务数据：站点、域名、IP、URL、IP端口、C段等
- 资产组数据：asset_ip、asset_domain、asset_site、asset_wih

导出格式：
- 站点/域名/IP/URL：纯文本格式（每行一条）
- IP端口：IP:Port格式
- C段：IP段格式
"""
import time
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import auth
from app import utils
from . import ARLResource

ns = Namespace('batch_export', description="批量导出")


# 批量导出请求模型（按任务ID）
batch_export_fields = ns.model('BatchExport',  {
    "task_id": fields.List(fields.String(description="任务ID列表"), required=True),
})


@ns.route('/site/')
class BatchExportSite(ARLResource):
    """批量导出站点接口"""

    @auth
    @ns.expect(batch_export_fields)
    def post(self):
        """
        批量导出多个任务的站点数据
        
        请求体：
            {
                "task_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            纯文本文件下载（每行一个站点URL）
        
        说明：
        - 合并多个任务的站点数据
        - 自动去重
        - 适合批量分析和归档
        """
        args = self.parse_args(batch_export_fields)
        task_id_list = args.pop("task_id", [])
        response = self.send_batch_export_file(task_id_list, "site")

        return response


@ns.route('/domain/')
class BatchExportDomain(ARLResource):
    """批量导出域名接口"""

    @auth
    @ns.expect(batch_export_fields)
    def post(self):
        """
        批量导出多个任务的域名数据
        
        请求体：
            {
                "task_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            纯文本文件下载（每行一个域名）
        
        说明：
        - 合并多个任务的域名数据
        - 自动去重
        - 包括子域名和主域名
        """
        args = self.parse_args(batch_export_fields)
        task_id_list = args.get("task_id", [])

        response = self.send_batch_export_file(task_id_list, "domain")

        return response


@ns.route('/ip/')
class BatchExportIP(ARLResource):
    """批量导出IP接口"""

    @auth
    @ns.expect(batch_export_fields)
    def post(self):
        """
        批量导出多个任务的IP地址
        
        请求体：
            {
                "task_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            纯文本文件下载（每行一个IP地址）
        
        说明：
        - 合并多个任务的IP数据
        - 自动去重
        - 适合后续批量扫描使用
        """
        args = self.parse_args(batch_export_fields)
        task_id_list = args.get("task_id", [])

        response = self.send_batch_export_file(task_id_list, "ip")

        return response


@ns.route('/url/')
class BatchExportURL(ARLResource):
    """批量导出URL接口"""

    @auth
    @ns.expect(batch_export_fields)
    def post(self):
        """
        批量导出多个任务的URL数据
        
        请求体：
            {
                "task_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            纯文本文件下载（每行一个URL）
        
        说明：
        - 合并多个任务的URL数据
        - 自动去重
        - 包括爬虫和WIH提取的URL
        """
        args = self.parse_args(batch_export_fields)
        task_id_list = args.get("task_id", [])

        response = self.send_batch_export_file(task_id_list, "url")

        return response


@ns.route('/ip_port/')
class BatchExportIpPort(ARLResource):
    """批量导出IP端口接口"""

    @auth
    @ns.expect(batch_export_fields)
    def post(self):
        """
        批量导出多个任务的IP端口数据
        
        请求体：
            {
                "task_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            纯文本文件下载（每行一个IP:Port）
        
        说明：
        - 合并多个任务的开放端口数据
        - 格式：IP:Port（如192.168.1.1:80）
        - 自动去重
        - 适合后续服务识别和漏洞扫描
        """
        args = self.parse_args(batch_export_fields)
        task_id_list = args.get("task_id", [])

        # 收集所有IP端口组合
        items_set = set()
        for task_id in task_id_list:
            if not task_id:
                continue

            query = {"task_id": task_id}
            items = list(utils.conn_db('ip').find(query, {"ip": 1, "port_info": 1}))

            # 遍历每个IP的端口信息
            for item in items:
                curr_ip = item["ip"]
                for port_info in item.get("port_info", []):
                    items_set.add("{}:{}".format(curr_ip, port_info["port_id"]))

        response = self.send_file(items_set, "ip_port")

        return response


@ns.route('/cip/')
class BatchExportCIP(ARLResource):
    """批量导出C段接口"""

    @auth
    @ns.expect(batch_export_fields)
    def post(self):
        """
        批量导出多个任务的C段数据
        
        请求体：
            {
                "task_id": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            纯文本文件下载（每行一个C段）
        
        说明：
        - 合并多个任务的C段数据
        - C段格式：192.168.1.0/24
        - 自动去重
        - 用于发现同一网段的其他资产
        """
        args = self.parse_args(batch_export_fields)
        task_id_list = args.get("task_id", [])

        response = self.send_batch_export_file(task_id_list, "cip")

        return response


# 批量导出请求模型（按资产组ID）
scope_batch_export_fields = ns.model('ScopeBatchExport',  {
    "scope_id": fields.List(fields.String(description="资产组ID列表"), required=True),
})


@ns.route('/asset_ip/')
class BatchExportAssetIP(ARLResource):
    """批量导出资产组IP接口"""

    @auth
    @ns.expect(scope_batch_export_fields)
    def post(self):
        """
        批量导出多个资产组的IP数据
        
        请求体：
            {
                "scope_id": ["资产组ID1", "资产组ID2", ...]
            }
        
        返回：
            Excel文件下载（包含IP及端口服务等完整信息）
        
        说明：
        - 合并多个资产组的IP数据
        - 包含端口、服务、操作系统等详细信息
        - 自动去重
        """
        args = self.parse_args(scope_batch_export_fields)
        scope_id_list = args.get("scope_id", [])

        response = self.send_scope_batch_export_file(scope_id_list, "asset_ip")

        return response


@ns.route('/asset_domain/')
class BatchExportAssetIP(ARLResource):
    """批量导出资产组域名接口"""

    @auth
    @ns.expect(scope_batch_export_fields)
    def post(self):
        """
        批量导出多个资产组的域名数据
        
        请求体：
            {
                "scope_id": ["资产组ID1", "资产组ID2", ...]
            }
        
        返回：
            Excel文件下载（包含域名及解析记录等完整信息）
        
        说明：
        - 合并多个资产组的域名数据
        - 包含IP、DNS记录类型、解析值等详细信息
        - 自动去重
        """
        args = self.parse_args(scope_batch_export_fields)
        scope_id_list = args.get("scope_id", [])

        response = self.send_scope_batch_export_file(scope_id_list, "asset_domain")

        return response


@ns.route('/asset_site/')
class BatchExportAssetIP(ARLResource):
    """批量导出资产组站点接口"""

    @auth
    @ns.expect(scope_batch_export_fields)
    def post(self):
        """
        批量导出多个资产组的站点数据
        
        请求体：
            {
                "scope_id": ["资产组ID1", "资产组ID2", ...]
            }
        
        返回：
            Excel文件下载（包含站点URL、标题、指纹等完整信息）
        
        说明：
        - 合并多个资产组的站点数据
        - 包含标题、服务器、状态码、指纹等详细信息
        - 自动去重
        """
        args = self.parse_args(scope_batch_export_fields)
        scope_id_list = args.get("scope_id", [])

        response = self.send_scope_batch_export_file(scope_id_list, "asset_site")

        return response


@ns.route('/asset_wih/')
class BatchExportAssetWIH(ARLResource):
    """批量导出资产组WIH接口"""

    @auth
    @ns.expect(scope_batch_export_fields)
    def post(self):
        """
        批量导出多个资产组的WIH数据
        
        请求体：
            {
                "scope_id": ["资产组ID1", "资产组ID2", ...]
            }
        
        返回：
            Excel文件下载（包含WIH记录类型、内容等完整信息）
        
        说明：
        - 合并多个资产组的WIH（Web Info Hunter）数据
        - 包含记录类型、内容、来源等详细信息
        - 自动去重
        - 用于批量分析JS中提取的敏感信息
        """
        args = self.parse_args(scope_batch_export_fields)
        scope_id_list = args.get("scope_id", [])

        response = self.send_scope_batch_export_file(scope_id_list, "asset_wih")

        return response

