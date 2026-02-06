"""
WIH资产辅助函数模块

功能说明：
- 获取WIH (Web Info Hunter) 记录的去重信息
- 用于WIH资产监控和去重
"""
from app import utils
from app.utils.cache import build_cache_key, cached_call


def get_wih_record_fnv_hash(scope_id):
    """
    获取WIH记录的FNV哈希值列表
    
    参数：
        scope_id: 资产范围ID
    
    返回：
        list: 去重后的FNV哈希值列表
    
    说明：
    - 查询asset_wih表中指定范围的记录
    - 使用distinct获取去重后的fnv_hash
    - fnv_hash用于去重WIH记录
    - WIH从JavaScript中提取域名、URL、API等信息
    """
    key = build_cache_key("helper:get_wih_record_fnv_hash", scope_id)

    def _loader():
        query = {
            "scope_id": scope_id
        }
        items = utils.conn_db('asset_wih').distinct("fnv_hash", query)
        return list(items)

    return cached_call(key, _loader, expire=120)
