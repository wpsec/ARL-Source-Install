"""
任务辅助函数模块

功能说明：
- 任务创建和参数验证
- 目标解析和校验
- 任务数据构建

主要功能：
1. 目标解析：解析IP、域名、URL等目标
2. 黑名单检查：检查IP和域名黑名单
3. 任务数据构建：构建任务配置数据
4. 任务提交：提交Celery任务

主要函数：
- target2list(): 解析目标字符串为列表
- get_ip_domain_list(): 分离IP和域名列表
- build_task_data(): 构建任务数据
- submit_task(): 提交任务到Celery
"""
import bson
import re
from app import utils
from app.modules import TaskStatus, TaskTag, TaskType, CeleryAction
from app import celerytask

logger = utils.get_logger()


def target2list(target):
    """
    解析目标字符串为列表
    
    参数：
        target: 目标字符串（逗号或空格分隔）
    
    返回：
        list: 目标列表（去重后）
    
    示例：
        "1.1.1.1 2.2.2.2,3.3.3.3" -> ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    """
    target = target.strip().lower()
    # 使用逗号或空格分割
    target_lists = re.split(r",|\s", target)
    # 清除空白符
    target_lists = list(filter(None, target_lists))
    # 去重
    target_lists = list(set(target_lists))

    return target_lists


def get_ip_domain_list(target):
    """
    分离IP和域名列表
    
    参数：
        target: 目标字符串
    
    返回：
        tuple: (ip_list, domain_list)
    
    说明：
    - 自动识别IP、IP段、域名
    - 检查IP黑名单
    - 检查域名黑名单和禁止域名
    - 支持泛域名(*.example.com)
    
    异常：
        Exception: 目标无效或在黑名单中
    """
    target_lists = target2list(target)
    ip_list = set()
    domain_list = set()
    
    for item in target_lists:
        if not item:
            continue

        # IP目标（包括IP段）
        if utils.is_vaild_ip_target(item):
            if not utils.not_in_black_ips(item):
                raise Exception("{} 在黑名单IP中".format(item))
            ip_list.add(item)

        # 禁止域名检查
        elif utils.domain.is_forbidden_domain(item):
            raise Exception("{} 包含在禁止域名内".format(item))

        # 普通域名
        elif utils.is_valid_domain(item):
            if utils.check_domain_black(item):
                raise Exception("{} 包含在系统黑名单中".format(item))

            domain_list.add(item)

        # 泛域名（*.example.com）
        elif utils.is_valid_fuzz_domain(item):
            domain_list.add(item)
        else:
            raise Exception("{} 无效的目标".format(item))

    return ip_list, domain_list


def build_task_data(task_name, task_target, task_type, task_tag, options):
    """
    构建任务数据
    
    参数：
        task_name: 任务名称
        task_target: 扫描目标
        task_type: 任务类型（ip/domain/risk_cruising）
        task_tag: 任务标签（task/monitor/risk_cruising）
        options: 扫描选项字典
    
    返回：
        dict: 任务数据
    
    说明：
    - 验证任务类型和标签
    - 针对IP任务禁用域名相关选项
    - 构建完整的任务配置
    
    异常：
        Exception: 参数无效
    """

    # 检查任务类型
    avail_task_type = [TaskType.IP, TaskType.DOMAIN, TaskType.RISK_CRUISING]
    if task_type not in avail_task_type:
        raise Exception("{} 无效的 task_type".format(task_type))

    # 检查任务标签
    avail_task_tag = [TaskTag.RISK_CRUISING, TaskTag.MONITOR, TaskTag.TASK]
    if task_tag not in avail_task_tag:
        raise Exception("{} 无效的 task_tag".format(task_type))

    if not isinstance(options, dict):
        raise Exception("{} 不是 dict".format(options))

    options_cp = options.copy()

    # 针对IP任务关闭域名相关选项
    if task_type == TaskType.IP:
        disable_options = {
            "domain_brute": False,
            "alt_dns": False,
            "dns_query_plugin": False,
            "arl_search": False
        }
        options_cp.update(disable_options)

    task_data = {
        'name': task_name,
        'target': task_target,
        'start_time': '-',
        'status': TaskStatus.WAITING,
        'type': task_type,
        "task_tag": task_tag,
        'options': options_cp,
        "end_time": "-",
        "service": [],
        "celery_id": ""
    }

    # 单独对风险巡航任务处理
    if task_tag == TaskType.RISK_CRUISING:
        poc_config = options.get("poc_config", [])

        if options.get("result_set_id"):
            result_set_id = options.pop("result_set_id")
            result_set_len = options.pop("result_set_len")
            target_field = "目标：{}， PoC：{}".format(result_set_len, len(poc_config))
            task_data["result_set_id"] = result_set_id
        else:
            target_field = "目标：{}， PoC：{}".format(len(task_target), len(poc_config))
            task_data["cruising_target"] = task_target

        task_data["target"] = target_field

    return task_data


def submit_task(task_data):
    """
    提交任务到Celery
    
    参数：
        task_data: 任务数据字典
    
    返回：
        dict: 更新后的任务数据（包含task_id和celery_id）
    
    说明：
    - 保存任务到数据库
    - 根据任务类型映射到对应的Celery action
    - 调用Celery异步执行任务
    - 更新celery_id到数据库
    - 失败则删除任务记录
    
    异常：
        Exception: 任务提交失败
    """
    target = task_data["target"]
    utils.conn_db('task').insert_one(task_data)
    task_id = str(task_data.pop("_id"))
    task_data["task_id"] = task_id

    # 任务类型映射到Celery action
    celery_action = ""
    type_map_action = {
        TaskType.DOMAIN: CeleryAction.DOMAIN_TASK,
        TaskType.IP: CeleryAction.IP_TASK,
        TaskType.RISK_CRUISING: CeleryAction.RUN_RISK_CRUISING,
        TaskType.ASSET_SITE_UPDATE: CeleryAction.ASSET_SITE_UPDATE,
        TaskType.FOFA: CeleryAction.FOFA_TASK,
        TaskType.ASSET_SITE_ADD: CeleryAction.ADD_ASSET_SITE_TASK,
        TaskType.ASSET_WIH_UPDATE: CeleryAction.ASSET_WIH_UPDATE,
    }

    task_type = task_data["type"]
    if task_type in type_map_action:
        celery_action = type_map_action[task_type]

    assert celery_action

    task_options = {
        "celery_action": celery_action,
        "data": task_data
    }

    try:
        # 提交到Celery
        celery_id = celerytask.arl_task.delay(options=task_options)
        logger.info("target:{} task_id:{} celery_id:{}".format(target, task_id, celery_id))

        # 更新celery_id
        values = {"$set": {"celery_id": str(celery_id)}}
        task_data["celery_id"] = str(celery_id)
        utils.conn_db('task').update_one({"_id": bson.ObjectId(task_id)}, values)

    except Exception as e:
        # 失败删除任务记录
        utils.conn_db('task').delete_one({"_id": bson.ObjectId(task_id), "status": TaskStatus.WAITING})
        logger.info("下发失败 {}".format(target))
        raise e

    return task_data


def submit_task_task(target, name, options):
    """
    根据目标自动创建并提交任务
    
    参数：
        target: 目标字符串（可包含IP和域名）
        name: 任务名称
        options: 扫描选项
    
    返回：
        list: 任务数据列表
    
    说明：
    - 自动分离IP和域名
    - IP创建IP任务
    - 每个域名创建单独的域名任务
    - 返回所有创建的任务信息
    """
    task_data_list = []

    # 分离IP和域名
    ip_list, domain_list = get_ip_domain_list(target)

    # 创建IP任务
    if ip_list:
        ip_target = " ".join(ip_list)
        task_data = build_task_data(task_name=name, task_target=ip_target,
                                    task_type=TaskType.IP, task_tag=TaskTag.TASK,
                                    options=options)

        task_data = submit_task(task_data)
        task_data_list.append(task_data)

    # 创建域名任务（每个域名一个任务）
    if domain_list:
        for domain_target in domain_list:
            task_data = build_task_data(task_name=name, task_target=domain_target,
                                        task_type=TaskType.DOMAIN, task_tag=TaskTag.TASK,
                                        options=options)
            task_data = submit_task(task_data)
            task_data_list.append(task_data)

    return task_data_list



# 风险巡航任务下发
def submit_risk_cruising(target, name, options):
    target_lists = target2list(target)
    task_data_list = []
    task_data = build_task_data(task_name=name, task_target=target_lists,
                                task_type=TaskType.RISK_CRUISING, task_tag=TaskTag.RISK_CRUISING,
                                options=options)

    task_data = submit_task(task_data)
    task_data_list.append(task_data)

    return task_data_list


def submit_add_asset_site_task(task_name: str, target: list, options: dict) -> dict:
    task_data = {
        'name': task_name,
        'target': "站点：{}".format(len(target)),
        'start_time': '-',
        'status': TaskStatus.WAITING,
        'type': TaskType.ASSET_SITE_ADD,
        "task_tag": TaskTag.RISK_CRUISING,
        'options': options,
        "end_time": "-",
        "service": [],
        "cruising_target": target,
        "celery_id": ""
    }
    task_data = submit_task(task_data)
    return task_data


def get_task_data(task_id):
    task_data = utils.conn_db('task').find_one({'_id': bson.ObjectId(task_id)})
    return task_data


def restart_task(task_id):
    name_pre = "重新运行-"
    task_data = get_task_data(task_id)
    if not task_data:
        raise Exception("没有找到 task_id : {}".format(task_id))

    # 把一些基础字段初始化
    task_data.pop("_id")
    task_data["start_time"] = "-"
    task_data["status"] = TaskStatus.WAITING
    task_data["end_time"] = "-"
    task_data["service"] = []
    task_data["celery_id"] = ""
    if "statistic" in task_data:
        task_data.pop("statistic")

    name = task_data["name"]
    if name_pre not in name:
        task_data["name"] = name_pre + name

    task_type = task_data["type"]
    task_tag = task_data.get("task_tag", "")

    # 特殊情况单独判断
    if task_type == TaskType.RISK_CRUISING and task_tag == TaskTag.RISK_CRUISING:
        if task_data.get("result_set_id"):
            raise Exception("task_id : {}, 不支持该任务重新运行".format(task_id))

    # 监控任务的重新下发有点麻烦
    if task_type == TaskType.DOMAIN and task_tag == TaskTag.MONITOR:
        raise Exception("task_id : {}, 不支持该任务重新运行".format(task_id))

    elif task_type == TaskType.IP and task_data["options"].get("scope_id"):
        raise Exception("task_id : {}, 不支持该任务重新运行".format(task_id))

    submit_task(task_data)

    return task_data
