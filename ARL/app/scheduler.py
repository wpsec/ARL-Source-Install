"""
定时任务调度器模块
用于管理资产监控的定时任务调度

主要功能：
- 添加域名/IP监控定时任务
- 添加资产站点更新监控任务
- 添加资产WebInfoHunter(WIH)更新监控任务
- 启动/停止/恢复/删除定时任务
- 执行到期的定时任务
- 监控任务执行状态

定时任务类型：
1. 域名监控任务（DOMAIN）：定期扫描域名资产
2. IP监控任务（IP）：定期扫描IP资产
3. 站点更新监控（site_update_monitor）：监控资产站点变化
4. WIH更新监控（wih_update_monitor）：监控Web指纹变化
"""
import sys
from bson import ObjectId
from app.utils import conn_db as conn
from app import utils
from app import celerytask
import time
from app.modules import CeleryAction, SchedulerStatus, AssetScopeType
from app.helpers import task_schedule, asset_site_monitor, asset_wih_monitor

# 获取日志记录器
logger = utils.get_logger()

# 域名监控任务的默认选项配置
domain_monitor_options = {
    'domain_brute': True,  # 启用域名爆破
    'domain_brute_type': 'big',  # 使用大字典爆破
    'alt_dns': False,  # 禁用域名变异生成
    'arl_search': True,  # 启用ARL搜索引擎
    'port_scan_type': 'test',  # 端口扫描类型（test/top100/top1000/all）
    'port_scan': True,  # 启用端口扫描
    'dns_query_plugin': True,  # 启用DNS查询插件
    'site_identify': False  # 禁用站点识别
}

# IP监控任务的默认选项配置
ip_monitor_options = {
    'port_scan_type': 'test',  # 端口扫描类型
    'port_scan': True,  # 启用端口扫描
    'site_identify': False  # 禁用站点识别
}


def add_job(domain, scope_id, options=None, interval=60 * 1, name="", scope_type=AssetScopeType.DOMAIN):
    """
    添加定时监控任务
    
    参数：
        domain: 监控目标（域名或IP）
        scope_id: 资产范围ID
        options: 监控选项配置（如果为None则使用默认配置）
        interval: 执行间隔（秒），默认60秒
        name: 任务名称
        scope_type: 资产范围类型（DOMAIN或IP）
    
    返回：
        任务ID（字符串格式的ObjectId）
    """
    logger.info("add {} job {} {} {}".format(scope_type, interval, domain, scope_id))
    
    # 如果未指定监控选项，使用默认配置
    if options is None:
        if scope_type == AssetScopeType.DOMAIN:
            options = domain_monitor_options
        if scope_type == AssetScopeType.IP:
            options = ip_monitor_options

    # 对IP任务禁用域名相关的监控选项
    # IP地址不需要进行域名爆破、变异、查询等操作
    disable_options = {
        "domain_brute": False,  # 禁用域名爆破
        "alt_dns": False,  # 禁用域名变异
        "dns_query_plugin": False,  # 禁用DNS查询插件
        "arl_search": False  # 禁用ARL搜索
    }

    if scope_type == AssetScopeType.IP:
        options.update(disable_options)

    # 设置首次运行时间为30秒后
    current_time = int(time.time()) + 30
    item = {
        "domain": domain,  # 监控目标
        "scope_id": scope_id,  # 资产范围ID
        "interval": interval,  # 执行间隔（秒）
        "next_run_time": current_time,  # 下次运行时间戳
        "next_run_date": utils.time2date(current_time),  # 下次运行时间（可读格式）
        "last_run_time": 0,  # 上次运行时间戳
        "last_run_date": "-",  # 上次运行时间（可读格式）
        "run_number": 0,  # 已运行次数
        "status": SchedulerStatus.RUNNING,  # 任务状态（运行中）
        "monitor_options": options,  # 监控选项
        "name": name,  # 任务名称
        "scope_type": scope_type  # 资产范围类型
    }
    
    # 插入到scheduler集合
    conn('scheduler').insert(item)

    return str(item["_id"])


def add_asset_site_monitor_job(scope_id, name, interval=60 * 1):
    """
    添加资产站点更新监控任务
    定期检查资产范围内站点的更新情况
    
    参数：
        scope_id: 资产范围ID
        name: 任务名称
        interval: 执行间隔（秒），默认60秒
    
    返回：
        任务ID（字符串格式的ObjectId）
    """
    current_time = int(time.time()) + 30

    item = {
        "domain": "资产站点更新",  # 任务描述
        "scope_id": scope_id,
        "interval": interval,
        "next_run_time": current_time,
        "next_run_date": utils.time2date(current_time),
        "last_run_time": 0,
        "last_run_date": "-",
        "run_number": 0,
        "status": SchedulerStatus.RUNNING,
        "monitor_options": {},  # 站点监控无需额外选项
        "name": name,
        "scope_type": "site_update_monitor"  # 特殊类型：站点更新监控
    }
    conn('scheduler').insert(item)

    return str(item["_id"])


def add_asset_wih_monitor_job(scope_id, name, interval=60 * 1):
    """
    添加资产WebInfoHunter(WIH)更新监控任务
    定期更新资产范围内站点的Web指纹信息
    
    参数：
        scope_id: 资产范围ID
        name: 任务名称
        interval: 执行间隔（秒），默认60秒
    
    返回：
        任务ID（字符串格式的ObjectId）
    """
    current_time = int(time.time()) + 30

    item = {
        "domain": "资产分组 WIH 更新",  # 任务描述
        "scope_id": scope_id,
        "interval": interval,
        "next_run_time": current_time,
        "next_run_date": utils.time2date(current_time),
        "last_run_time": 0,
        "last_run_date": "-",
        "run_number": 0,
        "status": SchedulerStatus.RUNNING,
        "monitor_options": {},  # WIH监控无需额外选项
        "name": name,
        "scope_type": "wih_update_monitor"  # 特殊类型：WIH更新监控
    }
    conn('scheduler').insert(item)

    return str(item["_id"])


def delete_job(job_id):
    """
    删除定时任务
    
    参数：
        job_id: 任务ID
    
    返回：
        删除操作的结果
    """
    ret = conn("scheduler").delete_one({"_id": ObjectId(job_id)})
    return ret


def stop_job(job_id):
    """
    停止定时任务
    将任务状态设置为停止，并将下次运行时间设置为最大值
    
    参数：
        job_id: 任务ID
    
    返回：
        更新操作的结果
    """
    item = find_job(job_id)
    item["next_run_date"] = "-"
    item["next_run_time"] = sys.maxsize  # 设置为最大整数，表示永不运行
    item["status"] = SchedulerStatus.STOP  # 状态改为停止
    query = {"_id": ObjectId(job_id)}
    ret = conn('scheduler').find_one_and_replace(query, item)
    return ret


def recover_job(job_id):
    """
    恢复已停止的定时任务
    重新设置下次运行时间，并将状态改为运行中
    
    参数：
        job_id: 任务ID
    
    返回：
        更新操作的结果
    """
    current_time = int(time.time()) + 30
    item = find_job(job_id)

    # 计算下次运行时间
    next_run_time = current_time + item["interval"]
    item["next_run_date"] = utils.time2date(next_run_time)
    item["next_run_time"] = next_run_time
    item["status"] = SchedulerStatus.RUNNING  # 状态改为运行中
    query = {"_id": ObjectId(job_id)}
    ret = conn('scheduler').find_one_and_replace(query, item)
    return ret


def find_job(job_id):
    """
    查找指定的定时任务
    
    参数：
        job_id: 任务ID
    
    返回：
        任务信息字典
    """
    query = {"_id": ObjectId(job_id)}
    item = conn('scheduler').find_one(query)
    return item


def all_job():
    """
    获取所有定时任务
    
    返回：
        任务列表
    """
    items = []
    for item in conn('scheduler').find():
        items.append(item)
    return items


def submit_job(domain, job_id, scope_id, options=None, name="", scope_type=AssetScopeType.DOMAIN):
    """
    提交监控任务到Celery队列执行
    根据资产类型（域名或IP）选择相应的任务处理器
    
    参数：
        domain: 监控目标（域名或IP）
        job_id: 任务ID
        scope_id: 资产范围ID
        options: 监控选项配置
        name: 任务名称
        scope_type: 资产范围类型（DOMAIN或IP）
    
    说明：
        - 域名任务会触发域名扫描、子域名爆破、端口扫描等操作
        - IP任务会触发端口扫描、服务识别等操作
        - 任务通过Celery异步队列分发给Worker节点执行
    """
    # 根据资产类型选择默认监控选项
    monitor_options = domain_monitor_options.copy()
    if scope_type == AssetScopeType.IP:
        monitor_options = ip_monitor_options.copy()

    # 如果没有指定选项，使用空字典
    if options is None:
        options = {}

    # 合并用户自定义选项（用户选项会覆盖默认选项）
    monitor_options.update(options)

    # 构造任务数据
    task_data = {
        "domain": domain,  # 监控目标
        "scope_id": scope_id,  # 资产范围ID
        "job_id": job_id,  # 定时任务ID
        "type": scope_type,  # 任务类型
        "monitor_options": monitor_options,  # 监控选项
        "name": name  # 任务名称
    }

    # 如果是域名类型任务
    if scope_type == AssetScopeType.DOMAIN:
        task_options = {
            "celery_action": CeleryAction.DOMAIN_EXEC_TASK,  # 指定为域名执行任务
            "data": task_data
        }
        # 提交到Celery队列，返回任务ID
        celery_id = celerytask.arl_task.delay(options=task_options)
        logger.info("submit domain job {} {} {}".format(celery_id, domain, scope_id))

    # 如果是IP类型任务
    if scope_type == AssetScopeType.IP:
        task_options = {
            "celery_action": CeleryAction.IP_EXEC_TASK,  # 指定为IP执行任务
            "data": task_data
        }
        # 提交到Celery队列，返回任务ID
        celery_id = celerytask.arl_task.delay(options=task_options)
        logger.info("submit ip job {} {} {}".format(celery_id, domain, scope_id))


def update_job_run(job_id):
    """
    更新定时任务的运行状态
    在任务执行完成后调用，更新上次/下次运行时间和运行次数
    
    参数：
        job_id: 任务ID
    
    说明：
        - 记录上次运行时间
        - 计算下次运行时间（当前时间 + 间隔时间）
        - 增加运行次数计数器
    """
    curr_time = int(time.time())
    item = find_job(job_id)
    if not item:
        return
    
    # 计算下次运行时间（当前时间 + 执行间隔）
    item["next_run_time"] = curr_time + item["interval"]
    item["next_run_date"] = utils.time2date(item["next_run_time"])
    
    # 记录上次运行时间
    item["last_run_time"] = curr_time
    item["last_run_date"] = utils.time2date(curr_time)
    
    # 运行次数加1
    item["run_number"] += 1
    
    # 更新数据库记录
    query = {"_id": item["_id"]}
    conn('scheduler').find_one_and_replace(query, item)


def asset_monitor_scheduler():
    """
    资产监控定时任务调度器主函数
    遍历所有定时任务，检查是否到期需要执行
    
    工作流程：
        1. 获取当前时间戳
        2. 遍历所有定时任务
        3. 跳过已停止的任务
        4. 检查任务是否到期（next_run_time <= 当前时间）
        5. 根据任务类型提交到相应的执行队列
        6. 更新任务的下次运行时间
    
    支持的任务类型：
        - DOMAIN: 域名监控任务
        - IP: IP监控任务
        - site_update_monitor: 站点更新监控
        - wih_update_monitor: Web指纹更新监控
    """
    curr_time = int(time.time())
    
    # 遍历所有定时任务
    for item in all_job():
        try:
            # 跳过已停止的任务
            if item.get("status") == SchedulerStatus.STOP:
                continue
            
            # 检查任务是否到期需要执行
            if item["next_run_time"] <= curr_time:
                # 提取任务参数
                domain = item["domain"]
                scope_id = item["scope_id"]
                options = item["monitor_options"]
                name = item["name"]
                scope_type = item.get("scope_type")

                # 如果没有指定类型，默认为域名类型
                if not scope_type:
                    scope_type = AssetScopeType.DOMAIN

                # 根据任务类型提交到不同的执行队列
                
                # 站点更新监控任务
                if scope_type == "site_update_monitor":
                    asset_site_monitor.submit_asset_site_monitor_job(scope_id=scope_id,
                                                                     name=name,
                                                                     scheduler_id=str(item["_id"]))

                # WIH（Web指纹）更新监控任务
                if scope_type == "wih_update_monitor":
                    asset_wih_monitor.submit_asset_wih_monitor_job(scope_id=scope_id,
                                                                   name=name,
                                                                   scheduler_id=str(item["_id"]))

                # 域名或IP监控任务
                else:
                    submit_job(domain=domain, job_id=str(item["_id"]),
                               scope_id=scope_id, options=options,
                               name=name, scope_type=scope_type)

                # 更新下次运行时间
                item["next_run_time"] = curr_time + item["interval"]
                item["next_run_date"] = utils.time2date(item["next_run_time"])
                query = {"_id": item["_id"]}
                conn('scheduler').find_one_and_replace(query, item)

        except Exception as e:
            # 记录异常但不中断调度器运行
            logger.exception(e)


def run_forever():
    """
    调度器主循环，持续运行各类定时任务调度器
    
    调度器类型：
        1. 资产监控任务调度器（asset_monitor_scheduler）
           - 处理域名/IP监控定时任务
           - 处理站点更新监控任务
           - 处理WIH更新监控任务
        
        2. GitHub监控任务调度器（github_task_scheduler）
           - 监控GitHub上的代码泄露、敏感信息等
        
        3. 计划任务调度器（task_scheduler）
           - 处理用户创建的一次性或周期性扫描任务
    
    注意事项：
        - 每个循环周期为58秒
        - sleep时间不能超过60秒，否则GitHub任务可能无法及时执行
        - 所有异常都在各自的调度器内部处理，不会影响主循环
        - 此函数会在单独的容器（arl_scheduler）中运行
    """
    from app.utils.github_task import github_task_scheduler
    
    logger.info("start scheduler server ")
    
    # 无限循环，持续调度各类任务
    while True:
        # 资产监控任务调度
        # 处理域名/IP的定期扫描、站点更新监控、WIH更新监控
        asset_monitor_scheduler()

        # Github 监控任务调度
        # 监控GitHub代码仓库，查找敏感信息泄露
        github_task_scheduler()

        # 计划任务调度
        # 处理用户通过Web界面创建的扫描任务
        task_schedule.task_scheduler()

        # logger.debug(time.time())
        # sleep 时间不能超过60S，Github 里的任务可能运行不了。
        # 休眠58秒后继续下一轮调度检查
        time.sleep(58)


if __name__ == '__main__':
    # 直接运行此文件时，启动调度器主循环
    run_forever()
