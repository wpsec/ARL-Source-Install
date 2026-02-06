"""
资产域名辅助函数模块

功能说明：
- 提供资产域名查询功能
- 根据范围ID查询域名资产
"""
from app import utils
from app.utils.cache import build_cache_key, cached_call


def find_domain_by_scope_id(scope_id):
    """
    根据范围ID查找域名资产
    
    参数：
        scope_id: 资产范围ID
    
    返回：
        list: 去重后的域名列表
    
    说明：
    - 查询asset_domain表中指定范围的域名
    - 使用distinct去重
    - 用于资产监控和统计
    """
    key = build_cache_key("helper:find_domain_by_scope_id", scope_id)

    def _loader():
        query = {
            "scope_id": scope_id
        }
        items = utils.conn_db('asset_domain').distinct("domain", query)
        return list(items)

    return cached_call(key, _loader, expire=120)




