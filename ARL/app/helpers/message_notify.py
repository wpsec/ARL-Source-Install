"""
消息推送通知模块

功能说明：
- 支持邮件推送
- 支持钉钉推送
- 用于任务结果通知和监控告警
"""
<<<<<<< HEAD
from bson import ObjectId
=======
>>>>>>> 2206ccf2c4fd7a50bd4600ba24497329f627c06b
from app.config import Config
from app.utils import get_logger, push
from app import utils
from app.modules import TaskTag, TaskStatus

logger = get_logger()


def push_email(title, html_report):
    """
    发送邮件通知
    
    参数：
        title: 邮件标题
        html_report: HTML格式的报告内容
    
    返回：
        bool: True-发送成功，None-发送失败
    
    说明：
    - 需要在配置中设置EMAIL_HOST、EMAIL_USERNAME、EMAIL_PASSWORD
    - 收件人地址在EMAIL_TO中配置
    - 支持HTML格式的富文本邮件
    - 用于GitHub搜索、资产监控等结果通知
    """
    try:
        if Config.EMAIL_HOST and Config.EMAIL_USERNAME and Config.EMAIL_PASSWORD:
            push.send_email(host=Config.EMAIL_HOST, port=Config.EMAIL_PORT, mail=Config.EMAIL_USERNAME,
                            password=Config.EMAIL_PASSWORD, to=Config.EMAIL_TO,
                            title=title, html=html_report)
            logger.info("send email succ")
            return True
    except Exception as e:
        logger.info("error on send email {}".format(title))
        logger.warning(e)


def push_dingding(markdown_report):
    """
    发送钉钉通知
    
    参数：
        markdown_report: Markdown格式的报告内容
    
    返回：
        bool: True-发送成功，None-发送失败
    
    说明：
    - 需要在配置中设置DINGDING_ACCESS_TOKEN和DINGDING_SECRET
    - 使用钉钉机器人Webhook推送
    - 支持Markdown格式的消息
    - 返回errcode为0表示成功
    - 适合移动端查看
    """
    try:
        if Config.DINGDING_ACCESS_TOKEN and Config.DINGDING_SECRET:
            data = push.dingding_send(access_token=Config.DINGDING_ACCESS_TOKEN,
                                      secret=Config.DINGDING_SECRET, msgtype="markdown",
                                      msg=markdown_report)
            if data.get("errcode", -1) == 0:
                logger.info("push dingding succ")
                return True
            else:
                logger.info("{}".format(data))

    except Exception as e:
        logger.info("error on send dingding {}".format(markdown_report[:15]))
        logger.warning(e)


<<<<<<< HEAD
def build_task_finish_markdown(task_data):
    """
    构建普通任务完成后的钉钉摘要
    """
    task_id = str(task_data.get("_id", ""))
    name = str(task_data.get("name", ""))
    task_type = str(task_data.get("type", ""))
    task_tag = str(task_data.get("task_tag", ""))
    status = str(task_data.get("status", ""))
    target = str(task_data.get("target", ""))
    start_time = str(task_data.get("start_time", "-"))
    end_time = str(task_data.get("end_time", "-"))
    statistic = task_data.get("statistic", {})

    task_type_map = {
        "domain": "域名资产扫描",
        "ip": "IP资产扫描",
        "risk_cruising": "风险巡航",
        "fofa": "FOFA资产扫描",
        "asset_site_update": "站点监控更新",
        "asset_wih_update": "WIH监控更新",
    }
    task_tag_map = {
        "task": "资产发现任务",
        "monitor": "资产监控任务",
        "risk_cruising": "风险巡航任务",
    }
    status_map = {
        "done": "已完成",
        "error": "执行异常",
        "stop": "已停止",
        "waiting": "等待中",
    }

    task_type_text = task_type_map.get(task_type, task_type)
    task_tag_text = task_tag_map.get(task_tag, task_tag)
    status_text = status_map.get(status, status)

    site_cnt = 0
    domain_cnt = 0
    ip_cnt = 0
    url_cnt = 0
    vuln_cnt = 0
    if isinstance(statistic, dict) and statistic:
        site_cnt = statistic.get("site_cnt", 0)
        domain_cnt = statistic.get("domain_cnt", 0)
        ip_cnt = statistic.get("ip_cnt", 0)
        url_cnt = statistic.get("url_cnt", 0)
        vuln_cnt = statistic.get("vuln_cnt", 0)

    markdown = "### 任务执行完成通知\n\n"
    markdown += "本次任务`{}`，共发现：站点 `{}` / 域名 `{}` / IP `{}`。\n\n".format(
        status_text, site_cnt, domain_cnt, ip_cnt
    )
    markdown += "#### 基础信息\n\n"
    markdown += "- 任务ID：`{}`\n".format(task_id)
    markdown += "- 任务名称：`{}`\n".format(name)
    markdown += "- 任务类型：`{}`\n".format(task_type_text)
    markdown += "- 任务类别：`{}`\n".format(task_tag_text)
    markdown += "- 执行状态：`{}`\n".format(status_text)
    markdown += "- 开始时间：`{}`\n".format(start_time)
    markdown += "- 结束时间：`{}`\n".format(end_time)
    markdown += "- 扫描目标：`{}`\n\n".format(target[:180])

    if isinstance(statistic, dict) and statistic:
        markdown += "\n#### 结果统计\n\n"
        markdown += "- 站点数（可访问地址）：`{}`\n".format(site_cnt)
        markdown += "- 域名数：`{}`\n".format(domain_cnt)
        markdown += "- IP数：`{}`\n".format(ip_cnt)
        markdown += "- URL数：`{}`\n".format(url_cnt)
        markdown += "- 漏洞数：`{}`\n".format(vuln_cnt)

    return markdown


def push_task_finish_notify(task_id):
    """
    普通任务完成后的钉钉推送

    说明：
    - 仅对普通任务和风险巡航任务生效
    - 计划任务子任务会标记 from_task_schedule，避免和计划任务推送重复
    """
    try:
        if not task_id or len(task_id) != 24:
            return

        query = {"_id": ObjectId(task_id)}
        task_data = utils.conn_db("task").find_one(query)
        if not task_data:
            return

        if task_data.get("status") != TaskStatus.DONE:
            return

        task_tag = task_data.get("task_tag", "")
        if task_tag not in [TaskTag.TASK, TaskTag.RISK_CRUISING]:
            return

        options = task_data.get("options", {})
        if not (isinstance(options, dict) and options.get("dingding_notify")):
            return

        if isinstance(options, dict) and options.get("from_task_schedule"):
            return

        markdown_report = build_task_finish_markdown(task_data)
        push_dingding(markdown_report=markdown_report)

    except Exception as e:
        logger.warning("push task finish notify error {}".format(task_id))
        logger.warning(e)
=======

>>>>>>> 2206ccf2c4fd7a50bd4600ba24497329f627c06b
