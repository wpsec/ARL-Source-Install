"""
任务计划调度模块

功能说明：
- 管理定时任务和周期任务
- 支持cron表达式的周期任务
- 支持指定时间的定时任务
- 自动触发任务执行
"""
import bson
from app import utils
from app.modules import TaskScheduleStatus, TaskTag, TaskStatus
from crontab import CronTab
import time

from .policy import get_options_by_policy_id
from .message_notify import push_dingding


logger = utils.get_logger()
TASK_SCHEDULE_RUN_COLLECTION = "task_schedule_run"
RUN_STATUS_RUNNING = "running"
RUN_STATUS_FINISHED = "finished"
RUN_STATUS_ERROR = "error"
RUN_PUSH_PENDING = "pending"
RUN_PUSH_SUCCESS = "success"
RUN_PUSH_ERROR = "error"
RUN_PUSH_SKIP = "skip"


def task_scheduler():
    """
    计划任务调度主函数
    
    说明：
    - 轮询所有SCHEDULED状态的计划任务
    - 检查周期任务的cron表达式，到达执行时间则触发
    - 检查定时任务的start_time，到达时间则触发
    - 支持任务类型：资产发现任务(TASK)、风险巡航任务(RISK_CRUISING)
    - 周期任务需间隔3分钟以上才能再次执行
    """
    items = list(utils.conn_db('task_schedule').find())
    for item in items:
        try:
            if item["status"] != TaskScheduleStatus.SCHEDULED:
                continue

            task_tag = item["task_tag"]
            should_scheduler_tag = [TaskTag.TASK, TaskTag.RISK_CRUISING]
            if task_tag not in should_scheduler_tag:
                logger.warning("非资产发现任务或风险巡航任务, {} {}", item["task_tag"], str(item["_id"]))
                continue

            # 周期任务检查
            if item["schedule_type"] == "recurrent_scan":
                entry = CronTab(item["cron"])
                next_sec = entry.next(default_utc=False)
                # 距离下次执行不足60秒，且上次执行超过3分钟
                if next_sec < 60 and abs(time.time() - item.get("last_run_time", 0)) > 60*3:
                    logger.info("run_recurrent_scan {} {}".format(item["target"], str(item["_id"])))
                    run_recurrent_scan(item)

            # 定时任务检查
            elif item["schedule_type"] == "future_scan":
                start_time = item["start_time"]
                if 0 < start_time <= time.time():
                    logger.info("run_future_scan {} {}".format(item["target"], str(item["_id"])))
                    run_future_scan(item)

        except Exception as e:
            logger.exception(e)

    # 在调度周期中统一处理计划任务执行实例，触发完成态通知
    try:
        process_task_schedule_runs()
    except Exception as e:
        logger.exception(e)


def submit_task_schedule(item):
    """
    提交计划任务
    
    参数：
        item: 计划任务数据
    
    异常：
        Exception: 策略不存在或任务提交失败
    
    说明：
    - 根据policy_id获取扫描配置
    - 根据task_tag区分任务类型
    - TASK类型：调用submit_task_task创建任务
    - RISK_CRUISING类型：调用submit_risk_cruising创建风险巡航任务
    - 周期任务会在名称中添加运行次数
    """
    from .task import submit_risk_cruising
    from .task import submit_task_task
    target = item["target"]
    task_tag = item["task_tag"]
    task_schedule_name = item["name"]
    policy_id = item["policy_id"]
    options = get_options_by_policy_id(policy_id, task_tag=task_tag)

    if not options:
        change_task_schedule_status(item["_id"], TaskScheduleStatus.ERROR)
        raise Exception("not found policy_id {}".format(policy_id))

    # 标记来源为计划任务，避免普通任务完成通知重复推送
    options["from_task_schedule"] = True

    name = "定时任务-{}".format(task_schedule_name[:15])

    if item["schedule_type"] == "recurrent_scan":
        run_number = item.get("run_number", 0) + 1
        name = "周期任务-{}-{}".format(task_schedule_name[:15], run_number)

    task_data_list = []
    if task_tag == TaskTag.TASK:
        task_data_list = submit_task_task(target=target, name=name, options=options)
    if task_tag == TaskTag.RISK_CRUISING:
        task_data_list = submit_risk_cruising(target=target, name=name, options=options)
    if not task_data_list:
        raise Exception("not found task_data {}".format(target))

    return task_data_list


def create_task_schedule_run(item, task_data_list):
    """
    记录一次计划任务执行实例

    说明：
    - 一个计划任务触发后，可能会拆分成多个 task_id
    - 通过 run 记录统一跟踪完成态和推送状态
    """
    task_ids = []
    for task_data in task_data_list:
        task_id = task_data.get("task_id", "")
        if task_id:
            task_ids.append(task_id)

    notify_enable_value = item.get("notify_enable", None)
    if notify_enable_value is None:
        notify_enable = True
    else:
        notify_enable = bool(notify_enable_value)

    run_item = {
        "schedule_id": str(item["_id"]),
        "schedule_name": item.get("name", ""),
        "schedule_type": item.get("schedule_type", ""),
        "task_tag": item.get("task_tag", ""),
        "run_number": item.get("run_number", 0),
        "task_ids": task_ids,
        "status": RUN_STATUS_RUNNING,
        "summary": {},
        # 兼容历史计划任务记录（无 notify_enable 字段时默认开启）
        "notify_enable": notify_enable,
        "notify_channel": str(item.get("notify_channel", "dingding") or "dingding").lower(),
        "notify_on": str(item.get("notify_on", "finished") or "finished").lower(),
        "push_status": RUN_PUSH_PENDING,
        "start_time": int(time.time()),
        "start_date": utils.curr_date(),
        "end_time": 0,
        "end_date": "-",
    }
    utils.conn_db(TASK_SCHEDULE_RUN_COLLECTION).insert_one(run_item)
    return run_item


def build_schedule_run_summary(task_ids):
    """
    统计一轮计划任务中的子任务状态
    """
    summary = {
        "total": len(task_ids),
        "done": 0,
        "error": 0,
        "stop": 0,
        "waiting": 0,
        "running": 0,
        "missing": 0,
        "site_cnt": 0,
        "domain_cnt": 0,
        "ip_cnt": 0,
        "url_cnt": 0,
        "vuln_cnt": 0,
        "task_details": [],
    }
    if not task_ids:
        return summary

    object_ids = []
    for task_id in task_ids:
        try:
            object_ids.append(bson.ObjectId(task_id))
        except Exception:
            summary["missing"] += 1

    if not object_ids:
        return summary

    items = list(
        utils.conn_db("task").find(
            {"_id": {"$in": object_ids}},
            {"status": 1, "name": 1, "target": 1, "type": 1, "statistic": 1},
        )
    )
    summary["missing"] += max(len(object_ids) - len(items), 0)

    for item in items:
        status = item.get("status", "")
        if status == TaskStatus.DONE:
            summary["done"] += 1
        elif status == TaskStatus.ERROR:
            summary["error"] += 1
        elif status == TaskStatus.STOP:
            summary["stop"] += 1
        elif status == TaskStatus.WAITING:
            summary["waiting"] += 1
        else:
            summary["running"] += 1

        statistic = item.get("statistic", {})
        if isinstance(statistic, dict):
            summary["site_cnt"] += int(statistic.get("site_cnt", 0) or 0)
            summary["domain_cnt"] += int(statistic.get("domain_cnt", 0) or 0)
            summary["ip_cnt"] += int(statistic.get("ip_cnt", 0) or 0)
            summary["url_cnt"] += int(statistic.get("url_cnt", 0) or 0)
            summary["vuln_cnt"] += int(statistic.get("vuln_cnt", 0) or 0)

        summary["task_details"].append(
            {
                "id": str(item.get("_id", "")),
                "name": str(item.get("name", "")),
                "target": str(item.get("target", "")),
                "type": str(item.get("type", "")),
                "status": status,
                "site_cnt": int(statistic.get("site_cnt", 0) or 0) if isinstance(statistic, dict) else 0,
                "domain_cnt": int(statistic.get("domain_cnt", 0) or 0) if isinstance(statistic, dict) else 0,
                "ip_cnt": int(statistic.get("ip_cnt", 0) or 0) if isinstance(statistic, dict) else 0,
                "url_cnt": int(statistic.get("url_cnt", 0) or 0) if isinstance(statistic, dict) else 0,
                "vuln_cnt": int(statistic.get("vuln_cnt", 0) or 0) if isinstance(statistic, dict) else 0,
            }
        )

    return summary


def should_push_schedule_run(notify_on, run_status):
    """
    判断当前执行实例是否需要触发推送
    """
    notify_on = str(notify_on or "finished").lower()
    if notify_on == "always":
        return True
    if notify_on in ["failed", "error"]:
        return run_status == RUN_STATUS_ERROR
    return run_status == RUN_STATUS_FINISHED


def build_schedule_run_markdown(run_item):
    """
    构建计划任务执行结果的钉钉 Markdown 摘要
    """
    summary = run_item.get("summary", {})
    total = summary.get("total", 0)
    done = summary.get("done", 0)
    error = summary.get("error", 0)
    stop = summary.get("stop", 0)
    waiting = summary.get("waiting", 0)
    running = summary.get("running", 0)
    missing = summary.get("missing", 0)
    site_cnt = summary.get("site_cnt", 0)
    domain_cnt = summary.get("domain_cnt", 0)
    ip_cnt = summary.get("ip_cnt", 0)
    url_cnt = summary.get("url_cnt", 0)
    vuln_cnt = summary.get("vuln_cnt", 0)
    task_details = summary.get("task_details", [])
    start_date = run_item.get("start_date", "-")
    end_date = run_item.get("end_date", "-")
    schedule_name = run_item.get("schedule_name", "")
    schedule_id = run_item.get("schedule_id", "")
    run_number = run_item.get("run_number", 0)
    run_status = run_item.get("status", "")
    status_map = {
        RUN_STATUS_FINISHED: "已完成",
        RUN_STATUS_ERROR: "执行异常",
        RUN_STATUS_RUNNING: "运行中",
    }
    run_status_text = status_map.get(run_status, run_status)

    markdown = "### 计划任务执行结果\n\n"
    markdown += "本轮计划任务`{}`，子任务：完成 `{}` / 失败 `{}` / 停止 `{}`。\n\n".format(
        run_status_text, done, error, stop
    )
    markdown += "#### 执行信息\n\n"
    markdown += "- 名称：`{}`\n".format(schedule_name)
    markdown += "- 计划ID：`{}`\n".format(schedule_id)
    markdown += "- 执行轮次：`{}`\n".format(run_number)
    markdown += "- 执行状态：`{}`\n".format(run_status_text)
    markdown += "- 开始时间：`{}`\n".format(start_date)
    markdown += "- 结束时间：`{}`\n\n".format(end_date)

    markdown += "#### 子任务统计\n\n"
    markdown += "- 总任务数：`{}`\n".format(total)
    markdown += "- 已完成：`{}`\n".format(done)
    markdown += "- 执行异常：`{}`\n".format(error)
    markdown += "- 已停止：`{}`\n".format(stop)
    markdown += "- 等待：`{}`\n".format(waiting)
    markdown += "- 运行中：`{}`\n".format(running)
    markdown += "- 状态丢失：`{}`\n".format(missing)

    markdown += "\n#### 资产结果汇总\n\n"
    markdown += "- 站点总数：`{}`\n".format(site_cnt)
    markdown += "- 域名总数：`{}`\n".format(domain_cnt)
    markdown += "- IP总数：`{}`\n".format(ip_cnt)
    markdown += "- URL总数：`{}`\n".format(url_cnt)
    markdown += "- 漏洞总数：`{}`\n".format(vuln_cnt)

    if isinstance(task_details, list) and task_details:
        status_text_map = {
            TaskStatus.DONE: "已完成",
            TaskStatus.ERROR: "执行异常",
            TaskStatus.STOP: "已停止",
            TaskStatus.WAITING: "等待中",
        }
        markdown += "\n#### 子任务明细（最多5条）\n\n"
        for idx, detail in enumerate(task_details[:5], 1):
            detail_status = status_text_map.get(detail.get("status", ""), detail.get("status", "运行中"))
            detail_name = detail.get("name", "") or "-"
            detail_target = (detail.get("target", "") or "-")[:100]
            detail_type = detail.get("type", "") or "-"
            markdown += "{}. `{}`（{}）\n".format(idx, detail_name, detail_status)
            markdown += "   - 类型：`{}`\n".format(detail_type)
            markdown += "   - 目标：`{}`\n".format(detail_target)
            markdown += "   - 结果：站点 `{}` / 域名 `{}` / IP `{}` / URL `{}` / 漏洞 `{}`\n".format(
                detail.get("site_cnt", 0),
                detail.get("domain_cnt", 0),
                detail.get("ip_cnt", 0),
                detail.get("url_cnt", 0),
                detail.get("vuln_cnt", 0),
            )

    return markdown


def process_task_schedule_runs():
    """
    处理处于运行中的计划任务执行实例

    说明：
    - 轮询 task_ids 状态
    - 全部完成后按配置触发钉钉推送
    - 将推送结果回写到 run 记录，避免重复推送
    """
    query = {"status": RUN_STATUS_RUNNING}
    run_items = list(utils.conn_db(TASK_SCHEDULE_RUN_COLLECTION).find(query))
    for run_item in run_items:
        task_ids = run_item.get("task_ids", [])
        summary = build_schedule_run_summary(task_ids)
        run_item["summary"] = summary

        # 任务仍在执行中，先只更新统计信息
        if summary.get("waiting", 0) > 0 or summary.get("running", 0) > 0:
            utils.conn_db(TASK_SCHEDULE_RUN_COLLECTION).find_one_and_replace({"_id": run_item["_id"]}, run_item)
            continue

        # 所有子任务已结束，判定执行实例状态
        failed_count = summary.get("error", 0) + summary.get("stop", 0) + summary.get("missing", 0)
        run_item["status"] = RUN_STATUS_FINISHED if failed_count == 0 else RUN_STATUS_ERROR
        run_item["end_time"] = int(time.time())
        run_item["end_date"] = utils.curr_date()

        # 默认不推送或推送条件不满足时，标记为 skip
        run_item["push_status"] = RUN_PUSH_SKIP
        notify_enable = bool(run_item.get("notify_enable", False))
        notify_channel = str(run_item.get("notify_channel", "dingding") or "dingding").lower()
        notify_on = run_item.get("notify_on", "finished")

        if notify_enable and should_push_schedule_run(notify_on, run_item["status"]):
            run_item["push_status"] = RUN_PUSH_ERROR
            if notify_channel == "dingding":
                markdown_report = build_schedule_run_markdown(run_item)
                if push_dingding(markdown_report=markdown_report):
                    run_item["push_status"] = RUN_PUSH_SUCCESS
            else:
                logger.warning("unsupported notify channel {} on run {}".format(notify_channel, str(run_item["_id"])))
            run_item["push_date"] = utils.curr_date()

        utils.conn_db(TASK_SCHEDULE_RUN_COLLECTION).find_one_and_replace({"_id": run_item["_id"]}, run_item)


def get_next_run_date(cron):
    """
    根据cron表达式生成下一次运行时间
    
    参数：
        cron: cron表达式
    
    返回：
        str: 下一次运行的日期时间字符串
    
    说明：
    - 使用CronTab解析cron表达式
    - 从当前时间+61秒开始计算下一次执行时间
    - 返回格式化的日期时间字符串
    """
    entry = CronTab(cron)
    now_time = time.time() + 61
    next_sec = entry.next(now=now_time, default_utc=False)
    return utils.time2date(now_time + next_sec - 60)


def run_recurrent_scan(item):
    """
    触发周期任务执行
    
    参数：
        item: 周期任务数据
    
    说明：
    - 更新下一次运行时间（根据cron表达式）
    - 增加运行次数计数
    - 记录最后运行时间和日期
    - 保存到数据库
    - 提交任务到Celery
    - 先更新数据库后提交任务，防止重复运行
    """

    # 记录运行时间和次数
    item["next_run_date"] = get_next_run_date(item["cron"])
    item["run_number"] = item.get("run_number", 0) + 1
    item["last_run_time"] = int(time.time())
    item["last_run_date"] = utils.curr_date()

    query = {
        "_id": item["_id"]
    }
    utils.conn_db('task_schedule').find_one_and_replace(query, item)

    # 为了防止多次运行，后提交任务
    task_data_list = submit_task_schedule(item)
    create_task_schedule_run(item, task_data_list)


def run_future_scan(item):
    """
    触发定时任务执行
    
    参数：
        item: 定时任务数据
    
    说明：
    - 增加运行次数计数
    - 修改状态为DONE（定时任务只执行一次）
    - 保存到数据库
    - 提交任务到Celery
    - 先更新数据库后提交任务，防止重复运行
    """
    query = {
        "_id": item["_id"]
    }
    item["run_number"] = item.get("run_number", 0) + 1
    item["status"] = TaskScheduleStatus.DONE
    utils.conn_db('task_schedule').find_one_and_replace(query, item)

    # 为了防止多次运行，后提交任务
    task_data_list = submit_task_schedule(item)
    create_task_schedule_run(item, task_data_list)


def find_task_schedule(_id):
    """
    查找计划任务
    
    参数：
        _id: 计划任务ID
    
    返回：
        dict: 计划任务数据
        None: 任务不存在
    """
    query = {'_id': bson.ObjectId(_id)}
    item = utils.conn_db('task_schedule').find_one(query)
    return item


def remove_task_schedule(_id):
    """
    删除计划任务
    
    参数：
        _id: 计划任务ID
    
    返回：
        int: 删除的数量（0或1）
    """
    query = {'_id': bson.ObjectId(_id)}
    result = utils.conn_db('task_schedule').delete_one(query)
    return result.deleted_count


def change_task_schedule_status(_id, status):
    """
    改变计划任务状态
    
    参数：
        _id: 计划任务ID
        status: 新状态
    
    返回：
        dict: 更新后的任务数据
        str: 错误信息
        None: 任务不存在
    
    说明：
    - ERROR状态不可改变
    - 相同状态不重复设置
    - 终止状态（DONE/ERROR/STOP）会清空下次运行时间
    - SCHEDULED状态会重新计算下次运行时间
    - 周期任务根据cron表达式计算，定时任务使用start_date
    """
    query = {'_id': bson.ObjectId(_id)}
    item = find_task_schedule(_id)
    if not item:
        return

    old_status = item["status"]

    if old_status == TaskScheduleStatus.ERROR:
        return "{} 不可改变状态".format(item["name"])

    if old_status == status:
        return "{} 已经处于 {} ".format(item["name"], status)

    item["status"] = status

    done_status_list = [TaskScheduleStatus.DONE,
                        TaskScheduleStatus.ERROR,
                        TaskScheduleStatus.STOP]

    if status in done_status_list:
        item["next_run_date"] = "-"

    elif status == TaskScheduleStatus.SCHEDULED:
        if item["schedule_type"] == "recurrent_scan":
            item["next_run_date"] = get_next_run_date(item["cron"])

        else:
            item["next_run_date"] = item["start_date"]

    utils.conn_db('task_schedule').find_one_and_replace(query, item)

    return item
