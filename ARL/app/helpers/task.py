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
import time
from app import utils
from app.modules import TaskStatus, TaskTag, TaskType, CeleryAction
from app.config import Config

logger = utils.get_logger()
_QUEUE_AVAILABILITY_CACHE = {}
_QUEUE_AVAILABILITY_CACHE_TTL_SEC = 15
_WEB_HEAVY_OPTION_KEYS = (
    "site_capture",
    "site_spider",
    "file_leak",
    "nuclei_scan",
    "afrog_scan",
    "web_info_hunter",
)
def apply_arch_compat_options(options):
    """
    保留任务选项，架构差异由镜像构建阶段提供对应的工具实现。

    生产镜像会按目标架构编译 MassDNS，因此 ARM64 不应再静默关闭域名能力；
    若工具构建或运行失败，应由具体阶段记录失败并按既有策略处理。
    """
    options_cp = options.copy()
    return options_cp, []


def _refresh_dispatch_queue_cache(timeout_sec=1.5):
    """
    通过 Celery inspect 查询当前活跃消费者队列，并做短时缓存。

    说明：
    - 仅在任务下发时使用，避免把任务投递到“代码支持但部署未启动”的队列
    - 任何异常都按“未知”处理，调用方应保守回退到 arltask
    """
    now = time.time()
    available = set()

    try:
        from app import celerytask

        inspect = celerytask.celery.control.inspect(timeout=timeout_sec)
        active_queues = inspect.active_queues() or {}
        for _, queue_items in active_queues.items():
            if not isinstance(queue_items, list):
                continue
            for item in queue_items:
                if not isinstance(item, dict):
                    continue
                queue_name = str(item.get("name", "") or "").strip()
                if queue_name:
                    available.add(queue_name)
    except Exception as e:
        logger.warning("inspect active_queues failed error:{}".format(e))

    for queue_name in ["arltask", "arlheavy", "arlweb", "arlgithub"]:
        _QUEUE_AVAILABILITY_CACHE[queue_name] = {
            "available": queue_name in available,
            "check_time": now,
        }

    return available


def is_dispatch_queue_available(queue_name, cache_ttl_sec=_QUEUE_AVAILABILITY_CACHE_TTL_SEC):
    """
    判断指定队列当前是否存在活跃 Celery 消费者。
    """
    queue_name = str(queue_name or "").strip()
    if not queue_name:
        return False

    cached = _QUEUE_AVAILABILITY_CACHE.get(queue_name)
    now = time.time()
    if cached and (now - float(cached.get("check_time", 0) or 0)) < max(float(cache_ttl_sec or 0), 1.0):
        return bool(cached.get("available"))

    available = _refresh_dispatch_queue_cache()
    return queue_name in available


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
        item = str(item or "").strip()
        if not item:
            continue

        # IP目标（包括IP段）
        if utils.is_vaild_ip_target(item):
            if not utils.not_in_black_ips(item):
                raise Exception("{} 在黑名单IP中".format(item))
            ip_list.add(item)
            continue

        normalized_domain = utils.normalize_domain(item)
        normalized_fuzz_domain = utils.normalize_fuzz_domain(item) if "{fuzz}" in item else ""

        # 禁止域名检查
        check_item = normalized_domain or normalized_fuzz_domain or item
        if utils.domain.is_forbidden_domain(check_item):
            raise Exception("{} 包含在禁止域名内".format(item))

        # 普通域名
        if normalized_domain and utils.is_valid_domain(normalized_domain):
            if utils.check_domain_black(normalized_domain):
                raise Exception("{} 包含在系统黑名单中".format(item))

            domain_list.add(normalized_domain)
            continue

        # 泛域名（*.example.com）
        if normalized_fuzz_domain and utils.is_valid_fuzz_domain(normalized_fuzz_domain):
            domain_list.add(normalized_fuzz_domain)
            continue

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
    arch_compat_notices = []

    if task_type in [TaskType.IP, TaskType.DOMAIN]:
        options_cp, arch_compat_notices = apply_arch_compat_options(options_cp)

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

    if arch_compat_notices:
        task_data["compat_notice"] = {
            "arch": utils.get_runtime_arch(),
            "message": "当前为非 x86_64 环境，已自动关闭部分 x86_64 专有功能",
            "disabled_options": arch_compat_notices
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


def _estimate_port_count(ports):
    """
    估算端口字符串对应的端口数量。
    """
    ports = str(ports or "").strip()
    if not ports:
        return 0

    if ports == "0-65535":
        return 65535

    total = 0
    for token in ports.split(","):
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            start, end = token.split("-", 1)
            try:
                start_i = int(start)
                end_i = int(end)
                if end_i >= start_i:
                    total += end_i - start_i + 1
            except Exception:
                continue
        else:
            try:
                int(token)
                total += 1
            except Exception:
                continue

    return total


def _estimate_target_count(task_data):
    """
    估算任务目标数量（粗略值，用于队列分流）。
    """
    task_type = task_data.get("type")
    target = task_data.get("target")
    if task_type == TaskType.IP:
        target_text = str(target or "").strip()
        if not target_text:
            return 0
        target_items = [x for x in re.split(r",|\s", target_text) if str(x).strip()]
        return len(target_items)

    if task_type == TaskType.DOMAIN:
        return 1

    return 0


def _estimate_task_port_count(options):
    """
    根据任务选项推断端口数量。
    """
    if not isinstance(options, dict):
        return 0

    scan_port_type = str(options.get("port_scan_type", "test") or "test").strip().lower()
    scan_port_map = {
        "test": Config.TOP_10,
        "top100": Config.TOP_100,
        "top1000": Config.TOP_1000,
        "all": "0-65535",
        "custom": str(options.get("port_custom", "") or ""),
    }
    return _estimate_port_count(scan_port_map.get(scan_port_type, Config.TOP_10))


def _resolve_queue_task(queue_name):
    """
    根据队列名返回对应的 Celery 任务入口。
    """
    from app import celerytask

    queue_name = str(queue_name or "").strip().lower()
    if queue_name == "arlheavy":
        return celerytask.arl_task_heavy
    if queue_name == "arlweb":
        return celerytask.arl_task_web
    if queue_name == "arlgithub":
        return celerytask.arl_github
    return celerytask.arl_task


def _collect_enabled_web_heavy_options(options):
    """
    收集会显著拉长 Web 阶段的功能开关。
    """
    enabled = []
    if not isinstance(options, dict):
        return enabled

    for option_key in _WEB_HEAVY_OPTION_KEYS:
        if bool(options.get(option_key)):
            enabled.append(option_key)

    return enabled


def should_dispatch_web_queue_by_options(options):
    """
    判断是否应分流到 Web 重任务队列 arlweb。
    """
    enabled_options = _collect_enabled_web_heavy_options(options)
    if not enabled_options:
        return False, ""

    if not is_dispatch_queue_available("arlweb"):
        return False, "web_queue_unavailable"

    return True, "web_heavy={}".format(",".join(enabled_options[:3]))


def _should_dispatch_heavy_queue(task_data, celery_action):
    """
    判断任务是否应分流到重任务队列 arlheavy。
    """
    if celery_action not in [CeleryAction.DOMAIN_TASK, CeleryAction.IP_TASK]:
        return False, ""

    options = task_data.get("options", {})
    if not isinstance(options, dict):
        return False, ""

    if not options.get("port_scan"):
        return False, ""

    scan_port_type = str(options.get("port_scan_type", "test") or "test").strip().lower()
    service_detection = bool(options.get("service_detection"))
    os_detection = bool(options.get("os_detection"))
    target_count = _estimate_target_count(task_data)
    port_count = _estimate_task_port_count(options)

    heavy_port_threshold = max(int(getattr(Config, "TASK_HEAVY_PORT_THRESHOLD", 1000) or 1000), 1)
    heavy_service_port_threshold = max(
        int(getattr(Config, "TASK_HEAVY_SERVICE_PORT_THRESHOLD", 500) or 500), 1
    )
    heavy_target_threshold = max(int(getattr(Config, "TASK_HEAVY_TARGET_THRESHOLD", 24) or 24), 1)

    heavy_reason = ""
    if scan_port_type == "all":
        heavy_reason = "port_scan_type=all"
    elif task_data.get("type") == TaskType.DOMAIN and scan_port_type == "top1000":
        heavy_reason = "domain_port_scan_type=top1000"
    elif os_detection:
        heavy_reason = "os_detection=true"
    elif service_detection and port_count >= heavy_service_port_threshold:
        heavy_reason = "service_detection=true,port_count={}".format(port_count)
    elif target_count >= heavy_target_threshold and port_count >= heavy_port_threshold:
        heavy_reason = "target_count={},port_count={}".format(target_count, port_count)

    if not heavy_reason:
        return False, ""

    if not bool(getattr(Config, "TASK_HEAVY_QUEUE_ENABLE", True)):
        return False, "heavy_queue_disabled"

    if not is_dispatch_queue_available("arlheavy"):
        return False, "heavy_queue_unavailable"

    return True, heavy_reason


def _should_dispatch_web_queue(task_data, celery_action):
    """
    判断任务是否应分流到 Web 重任务队列 arlweb。
    """
    action_reason_map = {
        CeleryAction.ASSET_SITE_UPDATE: "asset_site_update",
        CeleryAction.ASSET_WIH_UPDATE: "asset_wih_update",
    }
    action_reason = action_reason_map.get(celery_action, "")
    if action_reason:
        if not is_dispatch_queue_available("arlweb"):
            return False, "web_queue_unavailable"
        return True, action_reason

    if celery_action not in [CeleryAction.DOMAIN_TASK, CeleryAction.IP_TASK]:
        return False, ""

    options = task_data.get("options", {})
    return should_dispatch_web_queue_by_options(options)


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
    force_queue_name = str(task_data.pop("_dispatch_queue", "") or "").strip().lower()
    force_queue_reason = str(task_data.pop("_dispatch_queue_reason", "") or "").strip()
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
        from app import celerytask

        queue_name = "arltask"
        queue_reason = ""
        queue_task = celerytask.arl_task

        # 重启任务允许显式指定回主队列，兼容仅监听 arltask 的历史 worker 部署。
        if force_queue_name == "arlheavy":
            queue_name = "arlheavy"
            queue_reason = force_queue_reason or "force_queue=arlheavy"
            queue_task = _resolve_queue_task(queue_name)
        elif force_queue_name == "arlweb":
            queue_name = "arlweb"
            queue_reason = force_queue_reason or "force_queue=arlweb"
            queue_task = _resolve_queue_task(queue_name)
        elif force_queue_name == "arltask":
            queue_name = "arltask"
            queue_reason = force_queue_reason or "force_queue=arltask"
            queue_task = _resolve_queue_task(queue_name)
        else:
            # 将重任务分流到独立队列，避免阻塞普通任务。
            is_heavy, heavy_reason = _should_dispatch_heavy_queue(task_data, celery_action)
            if is_heavy:
                queue_name = "arlheavy"
                queue_reason = heavy_reason
                queue_task = _resolve_queue_task(queue_name)
            elif heavy_reason:
                queue_reason = "fallback:{}".format(heavy_reason)
            else:
                is_web_heavy, web_reason = _should_dispatch_web_queue(task_data, celery_action)
                if is_web_heavy:
                    queue_name = "arlweb"
                    queue_reason = web_reason
                    queue_task = _resolve_queue_task(queue_name)
                elif web_reason:
                    queue_reason = "fallback:{}".format(web_reason)

        if force_queue_name:
            logger.info(
                "submit_task force queue task_id:{} type:{} queue:{} reason:{}".format(
                    task_id, task_type, queue_name, queue_reason or "-"
                )
            )

        # 提交到 Celery
        celery_id = queue_task.delay(options=task_options)
        logger.info(
            "target:{} task_id:{} queue:{} queue_reason:{} celery_id:{}".format(
                target,
                task_id,
                queue_name,
                queue_reason or "-",
                celery_id
            )
        )

        # 更新 celery_id 与派发队列信息，便于排查“waiting”问题。
        dispatch_now = utils.curr_date()
        dispatch_ts = int(time.time())
        values = {
            "$set": {
                "celery_id": str(celery_id),
                "dispatch_queue": queue_name,
                "dispatch_time": dispatch_now,
                "dispatch_ts": dispatch_ts,
            }
        }
        if queue_reason:
            values["$set"]["dispatch_queue_reason"] = queue_reason
        else:
            values["$unset"] = {"dispatch_queue_reason": ""}

        task_data["celery_id"] = str(celery_id)
        task_data["dispatch_queue"] = queue_name
        task_data["dispatch_time"] = dispatch_now
        task_data["dispatch_ts"] = dispatch_ts
        if queue_reason:
            task_data["dispatch_queue_reason"] = queue_reason
        else:
            task_data.pop("dispatch_queue_reason", None)
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

    old_status = str(task_data.get("status", "") or "")
    old_name = str(task_data.get("name", "") or "")

    # 把一些基础字段初始化
    task_data.pop("_id")
    task_data["start_time"] = "-"
    task_data["status"] = TaskStatus.WAITING
    task_data["end_time"] = "-"
    task_data["service"] = []
    task_data["celery_id"] = ""
    reset_fields = [
        "statistic",
        "sync_status",
        "stop_reason",
        "interrupted",
        "last_error",
        "error_logs",
        "waf_skip_summary",
        "dispatch_queue",
        "dispatch_queue_reason",
        "dispatch_time",
        "dispatch_ts",
    ]
    for field in reset_fields:
        task_data.pop(field, None)

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

    # 历史部署可能仅监听 arltask，重启任务优先回主队列，避免落到 arlheavy 后长期 waiting。
    task_data["_dispatch_queue"] = "arltask"
    task_data["_dispatch_queue_reason"] = "restart_force_main_queue"
    logger.info(
        "restart task old_task_id:{} old_status:{} old_name:{} new_name:{} target:{} queue:{}".format(
            task_id,
            old_status or "-",
            old_name or "-",
            task_data.get("name", "-"),
            task_data.get("target", "-"),
            task_data["_dispatch_queue"],
        )
    )

    submit_task(task_data)

    return task_data
