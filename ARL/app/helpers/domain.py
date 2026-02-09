"""
域名辅助函数模块

功能说明：
- 提供从任务ID查询域名和IP的辅助函数
- 支持查询私有域名、公网IP、域名列表
- 用于任务结果聚合和数据提取
"""
from app import utils
from app.utils.cache import build_cache_key, cached_call


def find_private_domain_by_task_id(task_id):
    """
    根据任务ID查找私有域名
    
    参数：
        task_id: 任务ID
    
    返回：
        list: 去重后的私有域名列表
    
    说明：
    - 查询ip表中ip_type为PRIVATE的记录
    - 提取domain字段中的所有域名
    - 去重后返回
    - 私有域名通常解析到内网IP
    """
    key = build_cache_key("helper:find_private_domain_by_task_id", task_id)

    def _loader():
        query = {
            "task_id": task_id,
            "ip_type": "PRIVATE"
        }
        domains = []
        items = utils.conn_db('ip').find(query)
        for item in list(items):
            if not item.get("domain"):
                continue
            domains.extend(item["domain"])
        return list(set(domains))

    return cached_call(key, _loader, expire=120)


def find_public_ip_by_task_id(task_id):
    """
    根据任务ID查找公网IP
    
    参数：
        task_id: 任务ID
    
    返回：
        list: 公网IP列表
    
    说明：
    - 查询ip表中ip_type为PUBLIC的记录
    - 使用distinct去重获取所有公网IP
    """
    key = build_cache_key("helper:find_public_ip_by_task_id", task_id)

    def _loader():
        query = {
            "task_id": task_id,
            "ip_type": "PUBLIC"
        }
        items = utils.conn_db('ip').distinct("ip", query)
        return list(items)

    return cached_call(key, _loader, expire=120)


def find_domain_by_task_id(task_id):
    """
    根据任务ID查找所有域名
    
    参数：
        task_id: 任务ID
    
    返回：
        list: 去重后的域名列表
    
    说明：
    - 查询domain表中该任务的所有域名
    - 使用distinct去重
    """
    key = build_cache_key("helper:find_domain_by_task_id", task_id)

    def _loader():
        query = {
            "task_id": task_id
        }
        items = utils.conn_db('domain').distinct("domain", query)
        return list(items)

    return cached_call(key, _loader, expire=120)

