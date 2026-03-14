"""
SSL 证书信息管理 API
================================================

该模块提供 SSL/TLS 证书信息的查询和管理功能

主要功能：
1. 查询 SSL 证书信息
2. 删除 SSL 证书记录

证书信息包括：
- IP 和端口
- 证书主题和签发者
- 序列号
- 有效期
- 指纹（SHA-256、SHA-1、MD5）
- 备用名称（subjectAltName）

这些证书信息在端口扫描时自动收集
"""
from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app import utils
from app.modules import ErrorMsg

# 创建证书信息命名空间
ns = Namespace('cert', description="证书信息")

logger = get_logger()


def _build_sort_doc(orderby_list):
    """
    将 [(field, direction)] 转为 MongoDB sort 文档。
    """
    sort_doc = {}
    for item in orderby_list or []:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue

        field, direction = item
        field = str(field or "").strip()
        if not field:
            continue

        try:
            direction = int(direction)
        except Exception:
            direction = -1

        sort_doc[field] = -1 if direction < 0 else 1

    if "_id" not in sort_doc:
        sort_doc["_id"] = -1

    return sort_doc


# 证书查询字段定义
# 支持按照证书的各个属性进行查询
base_search_fields = {
    'ip': fields.String(description="IP地址"),
    'port': fields.Integer(description="端口号"),
    'scan_mode': fields.String(description="证书扫描模式（default/sni）"),
    'sni_domain': fields.String(description="SNI 域名（仅 scan_mode=sni 时有值）"),
    'cert.subject_dn': fields.String(description="证书主题名称（Subject DN）"),
    'cert.issuer_dn': fields.String(description="证书签发者名称（Issuer DN）"),
    'cert.serial_number ': fields.String(description="证书序列号"),
    'cert.validity.start': fields.String(description="证书有效期开始时间"),
    'cert.validity.end': fields.String(description="证书有效期结束时间"),
    'cert.fingerprint.sha256': fields.String(description="证书SHA-256指纹"),
    'cert.fingerprint.sha1': fields.String(description="证书SHA-1指纹"),
    'cert.fingerprint.md5': fields.String(description="证书MD5指纹"),
    'cert.extensions.subjectAltName': fields.String(description="证书备用名称（SAN），包含额外的域名"),
    'task_id': fields.String(description="关联的任务ID"),
}

# 合并基础查询字段（分页、排序等）
base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLCert(ARLResource):
    """SSL 证书信息查询接口"""
    parser = get_arl_parser(base_search_fields, location='args')

    def _build_data_prefer_domain_cert(self, args):
        """
        任务维度证书查询：
        - 同一 task_id + ip + port 仅保留一条“最优证书”记录
        - 优先级：sni > default，且优先带 sni_domain/domain 的记录
        """
        default_field = self.get_default_field(args)
        page = default_field.get("page", 1)
        size = default_field.get("size", 10)
        orderby_list = default_field.get("order", [("_id", -1)])
        sort_doc = _build_sort_doc(orderby_list)
        query = self.build_db_query(args)

        base_pipeline = [
            {"$match": query},
            {
                "$addFields": {
                    "_rank_mode": {
                        "$cond": [{"$eq": ["$scan_mode", "sni"]}, 0, 1]
                    },
                    "_rank_sni_domain": {
                        "$cond": [
                            {"$gt": [{"$strLenCP": {"$ifNull": ["$sni_domain", ""]}}, 0]},
                            0,
                            1,
                        ]
                    },
                    "_rank_domain": {
                        "$cond": [
                            {"$gt": [{"$strLenCP": {"$ifNull": ["$domain", ""]}}, 0]},
                            0,
                            1,
                        ]
                    },
                }
            },
            {
                "$sort": {
                    "task_id": 1,
                    "ip": 1,
                    "port": 1,
                    "_rank_mode": 1,
                    "_rank_sni_domain": 1,
                    "_rank_domain": 1,
                    "_id": -1,
                }
            },
            {
                "$group": {
                    "_id": {"task_id": "$task_id", "ip": "$ip", "port": "$port"},
                    "doc": {"$first": "$$ROOT"},
                }
            },
            {"$replaceRoot": {"newRoot": "$doc"}},
        ]

        result_pipeline = base_pipeline + [
            {"$sort": sort_doc},
            {"$skip": size * (page - 1)},
            {"$limit": size},
        ]
        count_pipeline = base_pipeline + [{"$count": "total"}]

        result_items = list(utils.conn_db('cert').aggregate(result_pipeline, allowDiskUse=True))
        count_items = list(utils.conn_db('cert').aggregate(count_pipeline, allowDiskUse=True))
        total = 0
        if count_items and isinstance(count_items[0], dict):
            total = int(count_items[0].get("total", 0) or 0)

        return {
            "page": page,
            "size": size,
            "total": total,
            "items": self.build_return_items(result_items),
            "query": query,
            "code": 200,
        }

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询 SSL 证书信息
        
        支持的查询条件：
        - IP地址和端口
        - 证书主题、签发者
        - 证书序列号、指纹
        - 证书有效期
        - 备用名称（SAN）
        - 任务ID
        
        返回：
            分页的证书信息列表
        
        应用场景：
        - 查找使用特定 CA 签发的证书
        - 查找特定域名的证书
        - 查找即将过期的证书
        - 审计证书配置
        """
        args = self.parser.parse_args()
        task_id = str(args.get("task_id", "") or "").strip()
        scan_mode = str(args.get("scan_mode", "") or "").strip().lower()

        # 任务视图默认返回“端点优先证书”，避免 default 默认证书覆盖业务域名证书；
        # 若显式指定 scan_mode，则按原始明细返回，便于排障。
        if task_id and not scan_mode:
            return self._build_data_prefer_domain_cert(args)

        # 从 cert 集合查询原始数据
        return self.build_data(args=args, collection='cert')


# 删除证书请求模型定义
delete_cert_fields = ns.model('deleteCertFields', {
    '_id': fields.List(fields.String(required=True, description="要删除的证书ID列表"))
})


@ns.route('/delete/')
class DeleteARLCert(ARLResource):
    """SSL 证书信息删除接口"""
    
    @auth
    @ns.expect(delete_cert_fields)
    def post(self):
        """
        批量删除 SSL 证书信息
        
        请求体：
            {
                "_id": ["证书ID1", "证书ID2", ...]
            }
        
        返回：
            删除成功的证书ID列表
        
        注意：
        - 支持批量删除
        - 删除操作不可恢复
        - 需要管理员权限
        """
        args = self.parse_args(delete_cert_fields)
        id_list = args.pop('_id', [])
        
        # 遍历删除每个证书
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('cert').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})
