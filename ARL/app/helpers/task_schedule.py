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
from app.modules import TaskScheduleStatus, TaskTag
from crontab import CronTab
import time

from .policy import get_options_by_policy_id


logger = utils.get_logger()


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

    name = "定时任务-{}".format(task_schedule_name[:15])

    if item["schedule_type"] == "recurrent_scan":
        run_number = item.get("run_number", 0) + 1
        name = "周期任务-{}-{}".format(task_schedule_name[:15], run_number)

    if task_tag == TaskTag.TASK:
        submit_task_task(target=target, name=name, options=options)
    if task_tag == TaskTag.RISK_CRUISING:
        task_data_list = submit_risk_cruising(target=target, name=name, options=options)
        if not task_data_list:
            raise Exception("not found task_data {}".format(target))


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
    submit_task_schedule(item)


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
    submit_task_schedule(item)


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

