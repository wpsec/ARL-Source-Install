"""
Celery 异步任务调度模块
================================================

该模块负责管理所有的异步任务，包括：
- 域名扫描任务
- IP 扫描任务
- GitHub 泄露监控任务
- 资产同步和更新任务
- FOFA 查询任务

使用 Celery 分布式任务队列实现任务的异步执行和负载均衡
"""
import signal
import time
import traceback
from bson import ObjectId
from app.config import Config, refresh_runtime_config_best_effort
from celery import Celery, platforms
from app import utils
from app import tasks as wrap_tasks
from app.modules import CeleryAction, TaskSyncStatus, TaskStatus

# 获取日志记录器
logger = utils.get_logger()

# 初始化 Celery 应用
# broker: 消息队列地址（RabbitMQ）
celery = Celery('task', broker=Config.CELERY_BROKER_URL)

# Celery 配置
celery.conf.update(
    # ARL 的扫描任务经常是“单条消息运行几十分钟”的长任务。
    # 若使用 late ack，则 RabbitMQ 会一直看不到 ACK，容易撞上 consumer_timeout
    # 触发 PRECONDITION_FAILED 并直接关闭 worker 通道。这里改为“消费后尽早 ACK”，
    # 再配合运行中状态落库与中断恢复逻辑，降低 MQ 侧长任务超时风险。
    task_acks_late=False,
    # 保持默认语义：手动 stop/terminate 的任务不自动重新入队，避免被用户停止后再次跑起来。
    task_reject_on_worker_lost=False,
    worker_prefetch_multiplier=Config.CELERY_PREFETCH_MULTIPLIER,  # Worker 每次只预取较少任务
    # 显式设置 broker heartbeat，减少对默认协商值的依赖，降低宿主机短时卡顿导致的误判断链。
    broker_heartbeat=Config.CELERY_BROKER_HEARTBEAT,
    broker_heartbeat_checkrate=Config.CELERY_BROKER_HEARTBEAT_CHECKRATE,
    # 定期回收 worker 子进程，减少长时间运行导致的内存膨胀
    worker_max_tasks_per_child=Config.CELERY_MAX_TASKS_PER_CHILD,
    worker_max_memory_per_child=Config.CELERY_MAX_MEMORY_PER_CHILD,
    # Broker 连接稳定性配置：断连自动重连
    broker_connection_retry=True,
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=None,  # None 表示无限重试，避免短暂重启导致 worker 退出
    # Broker 连接重试配置
    broker_transport_options={
        "max_retries": 3,  # 最大重试次数
        "interval_start": 0,  # 重试间隔起始时间
        "interval_step": 0.2,  # 重试间隔递增步长
        "interval_max": 0.5  # 最大重试间隔
    },
)
# 允许 root 用户运行 Celery（容器环境需要）
platforms.C_FORCE_ROOT = True

_WAITING_ORPHAN_QUEUE_SET = ("arltask", "arlheavy", "arlweb", "arlgithub")
_WAITING_ORPHAN_GRACE_SEC = 90


def _extract_live_task_ids(task_items):
    """
    从 inspect 返回的任务列表中提取 celery task id。
    """
    task_id_set = set()
    if not isinstance(task_items, list):
        return task_id_set

    for item in task_items:
        if not isinstance(item, dict):
            continue

        task_id = str(item.get("id", "") or "").strip()
        if not task_id:
            request = item.get("request")
            if isinstance(request, dict):
                task_id = str(request.get("id", "") or "").strip()

        if task_id:
            task_id_set.add(task_id)

    return task_id_set


def _collect_live_celery_task_ids(timeout_sec=1.5):
    """
    收集当前 worker 已知的 active/reserved/scheduled 任务 id。
    """
    inspect = celery.control.inspect(timeout=timeout_sec)
    live_task_id_set = set()

    try:
        result_list = [
            inspect.active() or {},
            inspect.reserved() or {},
            inspect.scheduled() or {},
        ]
    except Exception as e:
        logger.warning("collect live celery task ids failed error:{}".format(e))
        return live_task_id_set, False

    for result in result_list:
        if not isinstance(result, dict):
            continue
        for _, task_items in result.items():
            live_task_id_set |= _extract_live_task_ids(task_items)

    return live_task_id_set, True


def _get_broker_queue_message_counts(queue_names):
    """
    使用 broker 被动声明读取队列消息数，不修改队列状态。
    """
    from kombu import Queue

    count_map = {}
    try:
        with celery.connection_or_acquire() as conn:
            channel = conn.channel()
            try:
                for queue_name in queue_names:
                    try:
                        queue = Queue(queue_name, channel=channel)
                        declared = queue.queue_declare(passive=True, channel=channel)
                        count_map[queue_name] = int((declared or ("", 0, 0))[1] or 0)
                    except Exception as e:
                        logger.warning(
                            "get broker queue message count failed queue:{} error:{}".format(
                                queue_name, e
                            )
                        )
                        return count_map, False
            finally:
                try:
                    channel.close()
                except Exception:
                    pass
    except Exception as e:
        logger.warning("connect broker for queue count failed error:{}".format(e))
        return count_map, False

    return count_map, True


def _guess_waiting_task_dispatch_ts(item):
    """
    推断 waiting 任务的派发时间戳，优先使用 dispatch_ts，兼容历史数据回退 ObjectId 时间。
    """
    dispatch_ts = item.get("dispatch_ts")
    try:
        dispatch_ts = int(dispatch_ts or 0)
    except Exception:
        dispatch_ts = 0

    if dispatch_ts > 0:
        return dispatch_ts

    try:
        object_id = item.get("_id")
        if isinstance(object_id, ObjectId):
            return int(object_id.generation_time.timestamp())
    except Exception:
        pass

    return 0


def recover_orphan_waiting_tasks_on_worker_start(
    reason="worker restarted before waiting task status update",
    grace_sec=_WAITING_ORPHAN_GRACE_SEC,
    inspect_timeout_sec=1.5,
):
    """
    回收“高置信孤儿 waiting 任务”。

    仅在同时满足以下条件时才标记为 error：
    - 任务状态为 waiting，且已有 celery_id
    - broker 对应队列当前消息数为 0
    - 当前没有 worker 将该 celery_id 视为 active/reserved/scheduled
    - 距离派发时间超过 grace_sec
    """
    now_ts = int(time.time())
    now_text = utils.curr_date()
    safe_grace_sec = max(int(grace_sec or 0), 10)

    live_task_id_set, live_ok = _collect_live_celery_task_ids(timeout_sec=inspect_timeout_sec)
    queue_count_map, queue_ok = _get_broker_queue_message_counts(_WAITING_ORPHAN_QUEUE_SET)
    if not live_ok or not queue_ok:
        logger.warning(
            "skip orphan waiting task recovery live_ok:{} queue_ok:{}".format(
                live_ok, queue_ok
            )
        )
        return {"task": 0, "github_task": 0}

    detail = {
        "time": now_text,
        "stage": "worker_bootstrap",
        "message": reason,
    }
    update = {
        "$set": {
            "status": "error",
            "end_time": now_text,
            "stop_reason": reason,
            "interrupted": True,
            "last_error": detail,
        },
        "$push": {
            "error_logs": {
                "$each": [detail],
                "$slice": -20,
            }
        }
    }

    collection_queue_map = {
        "task": "arltask",
        "github_task": "arlgithub",
    }
    recovered_count_map = {
        "task": 0,
        "github_task": 0,
    }

    for collection, default_queue in collection_queue_map.items():
        query = {
            "status": "waiting",
            "start_time": {"$in": ["", "-"]},
            "celery_id": {"$nin": ["", None]},
        }

        try:
            item_list = list(
                utils.conn_db(collection).find(
                    query,
                    {
                        "_id": 1,
                        "celery_id": 1,
                        "dispatch_queue": 1,
                        "dispatch_ts": 1,
                    },
                )
            )
        except Exception as e:
            logger.warning(
                "query waiting task for orphan recovery failed collection:{} error:{}".format(
                    collection, e
                )
            )
            continue

        orphan_id_list = []
        for item in item_list:
            celery_id = str(item.get("celery_id", "") or "").strip()
            if not celery_id:
                continue

            dispatch_ts = _guess_waiting_task_dispatch_ts(item)
            if dispatch_ts <= 0 or (now_ts - dispatch_ts) < safe_grace_sec:
                continue

            if celery_id in live_task_id_set:
                continue

            queue_name = str(item.get("dispatch_queue", "") or "").strip() or default_queue
            if int(queue_count_map.get(queue_name, 0) or 0) > 0:
                continue

            orphan_id_list.append(item["_id"])

        if not orphan_id_list:
            continue

        try:
            result = utils.conn_db(collection).update_many(
                {
                    "_id": {"$in": orphan_id_list},
                    "status": "waiting",
                },
                update,
            )
            recovered_count_map[collection] = int(result.modified_count or 0)
        except Exception as e:
            logger.warning(
                "update orphan waiting task failed collection:{} error:{}".format(
                    collection, e
                )
            )

    if recovered_count_map["task"] or recovered_count_map["github_task"]:
        logger.warning(
            "recover orphan waiting tasks on worker start task:{} github_task:{} reason:{}".format(
                recovered_count_map["task"],
                recovered_count_map["github_task"],
                reason,
            )
        )
    else:
        logger.info("recover orphan waiting tasks on worker start no stale waiting task found")

    return recovered_count_map


@celery.task(queue='arltask')
def arl_task(options):
    """
    主任务队列入口
    所有非 GitHub 相关的任务都通过此入口执行
    
    参数：
        options: 任务选项字典，包含：
            - celery_action: 任务类型
            - data: 任务数据
    """
    # 这里不检验 celery_action， 调用的时候区分
    run_task(options)


@celery.task(queue='arlheavy')
def arl_task_heavy(options):
    """
    重任务队列入口
    仅承接高负载扫描任务（如全端口/深度探测），与常规任务隔离执行。

    参数：
        options: 任务选项字典
    """
    run_task(options)


@celery.task(queue='arlweb')
def arl_task_web(options):
    """
    Web 重任务队列入口
    主要承接目录扫描、PoC、截图、站点爬虫等 Web 重阶段任务。

    参数：
        options: 任务选项字典
    """
    run_task(options)


def _mark_task_started_best_effort(action, data):
    """
    任务刚被 Celery 消费时，尽早从 waiting 切换为 running。

    背景：
    - task_acks_late=True 只能保证 broker 侧不提前丢消息，但 DB 状态仍可能短暂停留在 waiting。
    - 先标记 running 后，UI 能更快反映“已被 worker 接手”，后续中断恢复也更准确。
    """
    if not isinstance(data, dict):
        return

    task_id = str(data.get("task_id", "") or "").strip()
    if not task_id:
        return

    # GitHub 任务单独落库到 github_task，其它任务落在 task。
    collection = "task"
    if action in [CeleryAction.GITHUB_TASK_TASK, CeleryAction.GITHUB_TASK_MONITOR]:
        collection = "github_task"

    try:
        query = {"_id": ObjectId(task_id), "status": "waiting"}
        update = {"$set": {"status": "running", "start_time": utils.curr_date()}}
        result = utils.conn_db(collection).update_one(query, update)
        if int(result.modified_count or 0) > 0:
            logger.info(
                "mark task started collection:{} task_id:{} action:{}".format(
                    collection, task_id, action
                )
            )
    except Exception as e:
        logger.warning(
            "mark task started failed collection:{} task_id:{} action:{} error:{}".format(
                collection, task_id, action, e
            )
        )


def _should_skip_stale_task_message(action, data):
    """
    跳过数据库已终态或已删除的历史队列消息，避免 broker 残留消息被重新执行。

    说明：
    - RabbitMQ 队列中的消息与 task 表状态并非强一致
    - waiting 阶段若消息长期积压在无人消费的队列中，后续即使任务被 stop/delete，broker 里仍可能残留旧消息
    - 这些旧消息一旦被后续 worker 捞到，必须先校验数据库状态再决定是否执行
    """
    if not isinstance(data, dict):
        return False

    task_id = str(data.get("task_id", "") or "").strip()
    if not task_id:
        return False

    collection = ""
    if action in [
        CeleryAction.DOMAIN_TASK,
        CeleryAction.IP_TASK,
        CeleryAction.RUN_RISK_CRUISING,
        CeleryAction.FOFA_TASK,
        CeleryAction.ASSET_SITE_UPDATE,
        CeleryAction.ADD_ASSET_SITE_TASK,
        CeleryAction.ASSET_WIH_UPDATE,
        CeleryAction.DOMAIN_TASK_SYNC_TASK,
    ]:
        collection = "task"
    elif action in [CeleryAction.GITHUB_TASK_TASK, CeleryAction.GITHUB_TASK_MONITOR]:
        collection = "github_task"

    if not collection:
        return False

    try:
        item = utils.conn_db(collection).find_one({"_id": ObjectId(task_id)}, {"status": 1})
    except Exception as e:
        logger.warning(
            "check stale task message failed collection:{} task_id:{} action:{} error:{}".format(
                collection, task_id, action, e
            )
        )
        return False

    if not item:
        logger.warning(
            "skip stale queued task message collection:{} task_id:{} action:{} reason:not_found".format(
                collection, task_id, action
            )
        )
        return True

    status = str(item.get("status", "") or "").strip().lower()
    if status in {TaskStatus.DONE, TaskStatus.STOP, TaskStatus.ERROR}:
        logger.warning(
            "skip stale queued task message collection:{} task_id:{} action:{} status:{}".format(
                collection, task_id, action, status
            )
        )
        return True

    return False


def run_task(options):
    """
    任务执行核心函数
    根据 celery_action 分发到不同的处理函数
    
    参数：
        options: 任务选项字典
    
    支持的任务类型：
        - DOMAIN_TASK_SYNC_TASK: 域名任务同步
        - DOMAIN_EXEC_TASK: 域名监控任务执行
        - IP_EXEC_TASK: IP 监控任务执行
        - DOMAIN_TASK: 常规域名扫描任务
        - IP_TASK: 常规 IP 扫描任务
        - RUN_RISK_CRUISING: 风险巡航任务
        - FOFA_TASK: FOFA 查询任务
        - GITHUB_TASK_TASK: GitHub 搜索任务
        - GITHUB_TASK_MONITOR: GitHub 监控任务
        - ASSET_SITE_UPDATE: 资产站点更新
        - ADD_ASSET_SITE_TASK: 添加资产站点任务
        - ASSET_WIH_UPDATE: 资产 WIH 更新
    """
    # 注册 SIGTERM 信号处理器，优雅退出
    signal.signal(signal.SIGTERM, utils.exit_gracefully)

    action = options.get("celery_action")
    data = options.get("data")

    # 任务执行前按配置文件 mtime 轻量热刷新，保证保存后的配置尽快生效。
    refresh_runtime_config_best_effort()
    
    # 任务类型到处理函数的映射
    action_map = {
        CeleryAction.DOMAIN_TASK_SYNC_TASK: domain_task_sync,
        CeleryAction.DOMAIN_EXEC_TASK: domain_exec,
        CeleryAction.IP_EXEC_TASK: ip_exec,
        CeleryAction.DOMAIN_TASK: domain_task,
        CeleryAction.IP_TASK: ip_task,
        CeleryAction.RUN_RISK_CRUISING: run_risk_cruising_task,
        CeleryAction.FOFA_TASK: fofa_task,
        CeleryAction.GITHUB_TASK_TASK: github_task_task,
        CeleryAction.GITHUB_TASK_MONITOR: github_task_monitor,
        CeleryAction.ASSET_SITE_UPDATE: asset_site_update,
        CeleryAction.ADD_ASSET_SITE_TASK: asset_site_add_task,
        CeleryAction.ASSET_WIH_UPDATE: asset_wih_update_task,
    }
    
    start_time = time.time()
    # 这里监控任务 task_id 和 target 是空的
    logger.info("run_task action:{} time:{} acks_late:{}".format(
        action, start_time, celery.conf.task_acks_late
    ))
    logger.info(
        "name:{}, target:{}, task_id:{}, dispatch_queue:{}, dispatch_queue_reason:{}".format(
            data.get("name"),
            data.get("target"),
            data.get("task_id"),
            data.get("dispatch_queue", "-"),
            data.get("dispatch_queue_reason", "-"),
        )
    )

    if _should_skip_stale_task_message(action=action, data=data):
        return

    # 任务被 worker 实际消费后，先做一次“waiting -> running”兜底状态切换。
    _mark_task_started_best_effort(action=action, data=data)
    
    try:
        # 根据 action 获取对应的处理函数
        fun = action_map.get(action)
        if fun:
            fun(data)
        else:
            logger.warning("not found {} action".format(action))
    except Exception as e:
        logger.exception(e)
        task_id = str(data.get("task_id", "") or "").strip() if isinstance(data, dict) else ""
        utils.append_task_error(
            task_id=task_id,
            error=e,
            stage="celery_action:{}".format(action),
            traceback_text=traceback.format_exc(),
        )

    elapsed = time.time() - start_time
    logger.info("end {} elapsed: {}".format(action, elapsed))


@celery.task(queue='arlgithub')
def arl_github(options):
    """
    GitHub 任务队列入口
    所有 GitHub 相关的任务通过此队列执行，独立队列避免影响主任务
    
    参数：
        options: 任务选项字典
    """
    # 这里不检验 celery_action， 调用的时候区分
    run_task(options)


def domain_exec(options):
    """
    域名监测任务执行器
    用于定期监控域名资产的变化
    
    参数：
        options: 包含以下字段：
            - scope_id: 资产范围ID
            - domain: 监控的域名
            - job_id: 定时任务ID
            - monitor_options: 监控选项配置
            - name: 任务名称
    
    功能：
        - 子域名爆破
        - DNS 解析
        - 端口扫描
        - 服务识别
        - 站点指纹识别
    """
    scope_id = options.get("scope_id")
    domain = options.get("domain")
    job_id = options.get("job_id")
    monitor_options = options.get("monitor_options")
    name = options.get("name")
    wrap_tasks.domain_executors(base_domain=domain, job_id=job_id,
                                scope_id=scope_id, options=monitor_options, name=name)


def domain_task_sync(options):
    """
    域名同步任务
    将扫描任务的结果同步到资产范围
    
    参数：
        options: 包含以下字段：
            - scope_id: 资产范围ID
            - task_id: 任务ID
    
    流程：
        1. 更新任务同步状态为运行中
        2. 执行资产同步
        3. 更新同步状态为完成或错误
    """
    from app.services.syncAsset import sync_asset
    scope_id = options.get("scope_id")
    task_id = options.get("task_id")
    query = {"_id": ObjectId(task_id)}
    try:
        # 更新状态为同步中
        update = {"$set": {"sync_status": TaskSyncStatus.RUNNING}}
        utils.conn_db('task').update_one(query, update)

        # 执行资产同步
        sync_asset(task_id, scope_id, update_flag=False)

        # 更新状态为默认（同步完成）
        update = {"$set": {"sync_status": TaskSyncStatus.DEFAULT}}
        utils.conn_db('task').update_one(query, update)
    except Exception as e:
        # 同步失败，更新状态为错误
        update = {"$set": {"sync_status": TaskSyncStatus.ERROR}}
        utils.conn_db('task').update_one(query, update)
        logger.exception(e)


def domain_task(options):
    """
    常规域名扫描任务
    用户通过 Web 界面手动创建的一次性域名扫描任务
    
    参数：
        options: 包含以下字段：
            - target: 目标域名
            - options: 扫描选项配置
            - task_id: 任务ID
    
    功能：
        与 domain_exec 类似，但是一次性任务，不会定期执行
    """
    target = options["target"]
    task_options = options["options"]
    task_id = options["task_id"]
    
    # 验证任务是否存在
    item = utils.conn_db('task').find_one({"_id": ObjectId(task_id)})
    if not item:
        logger.info("domain_task not found {} {}".format(target, item))
        return
    
    # 执行域名扫描任务
    wrap_tasks.domain_task(target, task_id, task_options)


def ip_task(options):
    """
    常规 IP 扫描任务
    用户通过 Web 界面手动创建的一次性 IP 扫描任务
    
    参数：
        options: 包含以下字段：
            - target: 目标 IP 或 IP 段
            - options: 扫描选项配置
            - task_id: 任务ID
    
    功能：
        - 端口扫描
        - 服务识别
        - 站点探测
    """
    target = options["target"]
    task_options = options["options"]
    task_id = options["task_id"]
    wrap_tasks.ip_task(target, task_id, task_options)


def run_risk_cruising_task(options):
    """
    风险巡航任务
    对资产进行安全风险扫描和评估
    
    参数：
        options: 包含以下字段：
            - task_id: 任务ID
    """
    task_id = options["task_id"]
    wrap_tasks.run_risk_cruising_task(task_id)


def fofa_task(options):
    """
    FOFA 查询任务
    通过 FOFA 搜索引擎获取 IP 资产，然后进行扫描
    
    参数：
        options: 包含以下字段：
            - task_id: 任务ID
            - options: 扫描选项配置
            - fofa_ip: FOFA 查询得到的 IP 列表
    
    说明：
        FOFA 是一个网络空间资产搜索引擎
        可以通过关键词搜索全网的资产
    """
    task_id = options["task_id"]
    task_options = options["options"]
    target = " ".join(options["fofa_ip"])  # 将 IP 列表拼接成字符串
    wrap_tasks.ip_task(target, task_id, task_options)


def ip_exec(options):
    """
    IP 监测任务执行器
    用于定期监控 IP 资产的变化
    
    参数：
        options: 包含以下字段：
            - scope_id: 资产范围ID
            - domain: 目标 IP（这里虽然叫 domain，实际是 IP）
            - job_id: 定时任务ID
            - monitor_options: 监控选项配置
            - name: 任务名称
    
    功能：
        - 端口扫描
        - 服务识别
        - 站点探测
        - 变化对比
    """
    scope_id = options.get("scope_id")
    target = options.get("domain")
    job_id = options.get("job_id")
    monitor_options = options.get("monitor_options")
    name = options.get("name")
    wrap_tasks.ip_executor(target=target, scope_id=scope_id,
                           task_name=name, job_id=job_id,
                           options=monitor_options)


def github_task_task(options):
    """
    GitHub 搜索任务
    在 GitHub 上搜索敏感信息泄露
    
    参数：
        options: 包含以下字段：
            - task_id: 任务ID
            - keyword: 搜索关键词
    
    功能：
        搜索包含关键词的代码仓库、代码文件等
        常用于发现 API Key、密码、数据库连接等敏感信息泄露
    """
    task_id = options["task_id"]
    keyword = options["keyword"]
    wrap_tasks.github_task_task(task_id=task_id, keyword=keyword)


def github_task_monitor(options):
    """
    GitHub 监控任务
    定期监控 GitHub 上的敏感信息泄露
    
    参数：
        options: 包含以下字段：
            - task_id: 任务ID
            - keyword: 监控关键词
            - github_scheduler_id: GitHub 调度器ID
    
    说明：
        与 github_task_task 的区别是这是定期执行的监控任务
    """
    task_id = options["task_id"]
    keyword = options["keyword"]
    scheduler_id = options["github_scheduler_id"]
    wrap_tasks.github_task_monitor(task_id=task_id, keyword=keyword, scheduler_id=scheduler_id)


def asset_site_update(options):
    """
    资产站点更新任务
    监控资产范围内站点的变化
    
    参数：
        options: 包含以下字段：
            - task_id: 任务ID
            - options: 包含 scope_id 和 scheduler_id
    
    功能：
        定期检查站点是否有变化（标题、状态码、内容等）
        及时发现资产变化和异常
    """
    task_id = options["task_id"]
    task_options = options["options"]
    scope_id = task_options["scope_id"]
    scheduler_id = task_options["scheduler_id"]
    wrap_tasks.asset_site_update_task(task_id=task_id,
                                      scope_id=scope_id, scheduler_id=scheduler_id)


def asset_wih_update_task(options):
    """
    资产 WIH (Web Information Hunter) 更新任务
    更新站点的 Web 指纹信息
    
    参数：
        options: 包含以下字段：
            - task_id: 任务ID
            - options: 包含 scope_id 和 scheduler_id
    
    功能：
        使用 WIH 工具重新识别站点的技术栈、框架、中间件等信息
        保持指纹信息的准确性和时效性
    """
    task_id = options["task_id"]
    task_options = options["options"]
    scope_id = task_options["scope_id"]
    scheduler_id = task_options["scheduler_id"]
    wrap_tasks.asset_wih_update_task(task_id=task_id,
                                     scope_id=scope_id, scheduler_id=scheduler_id)


def asset_site_add_task(options):
    """
    添加资产站点任务
    将新发现的站点添加到资产库
    
    参数：
        options: 包含以下字段：
            - task_id: 任务ID
    """
    task_id = options["task_id"]
    wrap_tasks.run_add_asset_site_task(task_id)
