"""
策略配置辅助函数模块

功能说明：
- 根据策略ID获取任务扫描选项
- 合并域名、IP、站点配置
- 区分任务类型返回不同配置
"""
import bson
from app import utils
from app.modules import TaskTag


def get_options_by_policy_id(policy_id, task_tag):
    """
    根据策略ID获取任务配置选项
    
    参数：
        policy_id: 策略ID
        task_tag: 任务标签（TASK/MONITOR/RISK_CRUISING）
    
    返回：
        dict: 任务配置选项
        None: 策略不存在
    
    说明：
    - 从policy表查询策略配置
    - 提取domain_config、ip_config、site_config
    - 如果有scope_config，添加关联资产范围ID
    - 仅资产发现任务(TASK)需要域名和IP配置
    - 所有任务都需要站点配置
    - 合并其他策略字段返回
    """
    query = {
        "_id": bson.ObjectId(policy_id)
    }
    data = utils.conn_db("policy").find_one(query)
    if not data:
        return

    policy = data["policy"]
    options = {
        "policy_name": data["name"]
    }
    domain_config = policy.pop("domain_config")
    ip_config = policy.pop("ip_config")
    site_config = policy.pop("site_config")

    if "scope_config" in policy:
        scope_config = policy.pop("scope_config")
        options["related_scope_id"] = scope_config["scope_id"]

    # 仅仅资产发现任务需要这些
    if task_tag == TaskTag.TASK:
        options.update(domain_config)
        options.update(ip_config)

    options.update(site_config)

    options.update(policy)
    return options

