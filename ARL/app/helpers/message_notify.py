"""
消息推送通知模块

功能说明：
- 支持邮件推送
- 支持钉钉推送
- 用于任务结果通知和监控告警
"""
from datetime import datetime
from bson import ObjectId
from app.config import Config
from app.utils import get_logger, push
from app.utils import dingtalk_openapi
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
    - 需要设置 DINGDING_ACCESS_TOKEN
    - DINGDING_SECRET 仅在机器人开启加签时需要
    - 使用钉钉机器人Webhook推送
    - 支持Markdown格式的消息
    - 返回errcode为0表示成功
    - 适合移动端查看
    """
    try:
        if Config.DINGDING_ACCESS_TOKEN:
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


def push_dingtalk_kb(
    report_title,
    markdown_report,
    source_type="",
    source_id="",
    extra_data=None,
    task_ids=None,
    github_result_items=None,
):
    """
    推送 Markdown 报告到钉钉知识库（开放平台 API）

    返回：
        (success: bool, result: dict)
    """
    result = {
        "title": report_title,
        "source_type": source_type,
        "source_id": source_id,
        "status": "error",
        "push_date": utils.curr_date(),
        "markdown_len": len(markdown_report or ""),
    }

    if isinstance(extra_data, dict):
        result["extra_data"] = extra_data

    normalized_task_ids = []
    if isinstance(task_ids, list):
        for item in task_ids:
            task_id = str(item or "").strip()
            if not task_id:
                continue
            normalized_task_ids.append(task_id)

    if normalized_task_ids:
        overview_context = extra_data if isinstance(extra_data, dict) else {}
        result["task_count"] = len(normalized_task_ids)
        success, api_result = dingtalk_openapi.publish_task_export_to_kb(
            title=report_title,
            task_ids=normalized_task_ids,
            overview_context=overview_context,
        )
    elif source_type == "github_scheduler" and isinstance(github_result_items, list):
        keyword = ""
        overview_context = {}
        if isinstance(extra_data, dict):
            keyword = str(extra_data.get("keyword", "") or "")
            overview_context.update(extra_data)
        if source_id and "source_id" not in overview_context:
            overview_context["source_id"] = str(source_id)
        success, api_result = dingtalk_openapi.publish_github_monitor_to_kb(
            title=report_title,
            keyword=keyword,
            result_items=github_result_items,
            overview_context=overview_context,
        )
    else:
        success, api_result = dingtalk_openapi.publish_markdown_to_kb(
            title=report_title,
            markdown_content=markdown_report,
        )
    result["api_result"] = api_result
    result["status"] = "success" if success else "error"
    result["node_id"] = api_result.get("node_id", "") if isinstance(api_result, dict) else ""
    result["node_url"] = api_result.get("node_url", "") if isinstance(api_result, dict) else ""
    result["workbook_id"] = api_result.get("workbook_id", "") if isinstance(api_result, dict) else ""
    result["sheet_count"] = api_result.get("sheet_count", 0) if isinstance(api_result, dict) else 0
    if isinstance(api_result, dict) and isinstance(api_result.get("write_result"), dict):
        result["sheet_name"] = api_result["write_result"].get("sheet_name", "")
        result["sheet_range"] = api_result["write_result"].get("range", "")
    if isinstance(api_result, dict) and isinstance(api_result.get("sheet_write_result"), dict):
        result["sheet_success_count"] = api_result["sheet_write_result"].get("sheet_success_count", 0)
        result["sheet_failed_count"] = api_result["sheet_write_result"].get("sheet_failed_count", 0)

    try:
        utils.conn_db("dingtalk_kb_push_log").insert_one(result)
    except Exception as e:
        logger.warning("save dingtalk kb push log error {}".format(e))

    if success:
        logger.info("push dingtalk knowledge base succ title:{}".format(report_title))
        return True, result

    logger.warning("push dingtalk knowledge base fail title:{} result:{}".format(report_title, api_result))
    return False, result


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
        vuln_cnt = int(statistic.get("vuln_cnt", 0) or 0) + int(statistic.get("nuclei_result_cnt", 0) or 0)

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


def _parse_cert_datetime(value):
    """
    兼容解析证书有效期时间字符串。
    """
    text = str(value or "").strip()
    if not text:
        return None

    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]:
        try:
            return datetime.strptime(text, fmt)
        except Exception:
            continue

    return None


def _extract_alert_domain(cert_obj, ip, port):
    """
    优先使用证书域名信息作为告警展示域名。
    """
    if not isinstance(cert_obj, dict):
        return "{}:{}".format(ip, port) if ip and port else (ip or "")

    subject = cert_obj.get("subject", {})
    if isinstance(subject, dict):
        common_name = str(subject.get("common_name", "")).strip()
        if common_name:
            return common_name

    extensions = cert_obj.get("extensions", {})
    if isinstance(extensions, dict):
        san_text = str(extensions.get("subjectAltName", "")).strip()
        if san_text:
            for raw_item in san_text.split(","):
                item = raw_item.strip()
                if not item:
                    continue
                if ":" in item:
                    left, right = item.split(":", 1)
                    if left.strip().lower() == "dns" and right.strip():
                        return right.strip()
                elif item:
                    return item

    return "{}:{}".format(ip, port) if ip and port else (ip or "")


def _collect_ssl_cert_warnings(task_id, alert_days=30, max_items=10):
    """
    收集任务中临期/过期证书列表。
    """
    warnings = []
    now_dt = datetime.utcnow()

    for item in utils.conn_db("cert").find({"task_id": task_id}):
        cert_obj = item.get("cert", {}) if isinstance(item.get("cert"), dict) else {}
        validity = cert_obj.get("validity", {}) if isinstance(cert_obj.get("validity"), dict) else {}
        end_time = str(validity.get("end", "")).strip()
        if not end_time:
            continue

        end_dt = _parse_cert_datetime(end_time)
        if not end_dt:
            continue

        remaining_days = (end_dt - now_dt).days
        if remaining_days > alert_days:
            continue

        ip = str(item.get("ip", "")).strip()
        port = str(item.get("port", "")).strip()
        domain = _extract_alert_domain(cert_obj, ip, port)
        warnings.append(
            {
                "domain": domain,
                "ip": ip,
                "port": port,
                "end_time": end_time,
                "remaining_days": remaining_days,
            }
        )

    warnings.sort(key=lambda row: row.get("remaining_days", 999999))
    if len(warnings) > max_items:
        warnings = warnings[:max_items]
    return warnings


def _build_report_link_fallback(task_id):
    """
    当钉钉知识库链接不可用时，回退到平台报告链接。
    """
    base_url = str(Config.DINGTALK_REPORT_BASE_URL or "").strip().rstrip("/")
    if not base_url:
        return ""
    return "{}/?task_id={}".format(base_url, task_id)


def _build_ssl_cert_warning_markdown(warn_item, report_link):
    """
    构建 SSL 证书告警消息模板。
    """
    remaining_days = int(warn_item.get("remaining_days", 0))
    if remaining_days >= 0:
        remain_text = "{} 天".format(remaining_days)
    else:
        remain_text = "已过期 {} 天".format(abs(remaining_days))

    markdown = "### SSL证书安全警告\n\n"
    markdown += "- 检测域名：`{}`\n".format(str(warn_item.get("domain", "") or "-"))
    markdown += "- 检测时间：`{}`\n".format(utils.curr_date())
    markdown += "- 证书有效期剩余：`{}`\n".format(remain_text)
    markdown += "- 请在有效期内及时更新！\n"
    if report_link:
        markdown += "- 报告链接：[点击查看]({})\n".format(report_link)
    else:
        markdown += "- 报告链接：`未生成`\n"
    return markdown


def _push_ssl_cert_warning(task_id, task_data):
    """
    推送 SSL 证书临期告警，并尽可能附带钉钉知识库报告链接。
    """
    warnings = _collect_ssl_cert_warnings(task_id=task_id, alert_days=30, max_items=10)
    if not warnings:
        return

    report_link = ""
    if Config.DINGTALK_KB_ENABLE:
        task_name = str(task_data.get("name", "")).strip()
        report_title = "{}-SSL证书扫描报告-{}".format(task_name or "任务", utils.curr_date())
        summary_markdown = "### SSL证书扫描报告\n\n- 任务ID：`{}`\n- 告警证书数量：`{}`".format(
            task_id, len(warnings)
        )
        kb_success, kb_result = push_dingtalk_kb(
            report_title=report_title,
            markdown_report=summary_markdown,
            source_type="ssl_cert_warning",
            source_id=task_id,
            extra_data={"task_id": task_id, "warning_count": len(warnings)},
            task_ids=[task_id],
        )
        if kb_success and isinstance(kb_result, dict):
            report_link = str(kb_result.get("node_url", "")).strip()

    if not report_link:
        report_link = _build_report_link_fallback(task_id)

    for warn_item in warnings:
        markdown_report = _build_ssl_cert_warning_markdown(warn_item, report_link=report_link)
        push_dingding(markdown_report=markdown_report)


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
        if not isinstance(options, dict):
            options = {}

        if options.get("from_task_schedule"):
            return

        finish_notify_enabled = bool(options.get("dingding_notify"))
        ssl_cert_notify_enabled = bool(Config.DINGTALK_SSL_CERT_NOTIFY_ENABLE and options.get("ssl_cert"))
        if not finish_notify_enabled and not ssl_cert_notify_enabled:
            return

        if finish_notify_enabled:
            markdown_report = build_task_finish_markdown(task_data)
            push_dingding(markdown_report=markdown_report)

        if ssl_cert_notify_enabled:
            _push_ssl_cert_warning(task_id, task_data)

    except Exception as e:
        logger.warning("push task finish notify error {}".format(task_id))
        logger.warning(e)
