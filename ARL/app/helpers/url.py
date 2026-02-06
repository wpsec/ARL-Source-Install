"""
URL辅助函数模块

功能说明：
- 根据任务ID查询URL资产
- 用于任务结果提取
"""
from app import utils
from app.utils.cache import build_cache_key, cached_call


def get_url_by_task_id(task_id):
    """
    根据任务ID获取URL列表
    
    参数：
        task_id: 任务ID
    
    返回：
        list: 去重后的URL列表
    
    说明：
    - 查询url表中该任务的所有URL
    - 使用distinct去重
    - 包含爬虫发现的URL和站点路径
    """
    key = build_cache_key("helper:get_url_by_task_id", task_id)

    def _loader():
        query = {
            "task_id": task_id
        }
        items = utils.conn_db('url').distinct("url", query)
        return list(items)

    return cached_call(key, _loader, expire=120)
