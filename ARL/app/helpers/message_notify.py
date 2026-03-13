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
        # 统一在发送前刷新一次运行时配置，避免常驻进程持有旧 token。
        dingtalk_openapi.refresh_runtime_dingtalk_config_best_effort()

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


def _normalize_alert_domain(value):
    """
    规范化告警域名候选，非法域名返回空字符串。
    """
    domain = str(value or "").strip().lower().rstrip(".")
    if not domain:
        return ""
    if domain.startswith("*."):
        domain = domain[2:]
    if ":" in domain and domain.count(":") == 1:
        domain = domain.split(":", 1)[0].strip()
    if not domain:
        return ""
    if not utils.is_valid_domain(domain):
        return ""
    return domain


def _extract_san_domains(cert_obj):
    """
    从证书 SAN 中提取域名候选。
    """
    output = []
    if not isinstance(cert_obj, dict):
        return output

    extensions = cert_obj.get("extensions", {})
    if not isinstance(extensions, dict):
        return output

    san_text = str(extensions.get("subjectAltName", "")).strip()
    if not san_text:
        return output

    for raw_item in san_text.split(","):
        item = raw_item.strip()
        if not item:
            continue
        if ":" in item:
            left, right = item.split(":", 1)
            if left.strip().lower() != "dns":
                continue
            domain = _normalize_alert_domain(right)
        else:
            domain = _normalize_alert_domain(item)

        if domain and domain not in output:
            output.append(domain)

    return output


def _normalize_cert_identity_value(value):
    """
    归一化证书身份值（指纹/序列号），用于稳定去重键。
    """
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return text.replace(":", "").replace(" ", "")


def _extract_cert_identity(cert_obj):
    """
    提取证书身份信息：
    - 优先 sha256，再 sha1，再 serial_number
    - 返回 (identity_key, identity_text)
    """
    if not isinstance(cert_obj, dict):
        return "", ""

    fingerprint = cert_obj.get("fingerprint", {})
    if isinstance(fingerprint, dict):
        sha256 = _normalize_cert_identity_value(fingerprint.get("sha256", ""))
        if sha256:
            return "sha256:{}".format(sha256), "SHA256:{}".format(sha256)

        sha1 = _normalize_cert_identity_value(fingerprint.get("sha1", ""))
        if sha1:
            return "sha1:{}".format(sha1), "SHA1:{}".format(sha1)

    serial_number = _normalize_cert_identity_value(cert_obj.get("serial_number", ""))
    if serial_number:
        return "serial:{}".format(serial_number), "SERIAL:{}".format(serial_number)

    return "", ""


def _build_ssl_alert_context(task_id):
    """
    构建 SSL 告警所需上下文：
    - IP 类型（用于过滤内网）
    - IP 对应域名（优先展示任务内真实域名）
    - 任务域名集合（用于约束证书域名候选）
    """
    ip_type_map = {}
    ip_domain_map = {}
    task_domain_set = set()

    for item in utils.conn_db("domain").find({"task_id": task_id}, {"domain": 1, "ips": 1}):
        domain = _normalize_alert_domain(item.get("domain", ""))
        if domain:
            task_domain_set.add(domain)

        raw_ips = item.get("ips", [])
        if isinstance(raw_ips, str):
            raw_ips = [x.strip() for x in raw_ips.split(",") if x.strip()]
        if not isinstance(raw_ips, list):
            raw_ips = []

        for raw_ip in raw_ips:
            ip = str(raw_ip or "").strip()
            if not ip:
                continue
            if not domain:
                continue
            ip_domain_map.setdefault(ip, []).append(domain)

    for item in utils.conn_db("ip").find({"task_id": task_id}, {"ip": 1, "ip_type": 1, "domain": 1}):
        ip = str(item.get("ip", "")).strip()
        if not ip:
            continue

        ip_type = str(item.get("ip_type", "")).strip().upper()
        if ip_type:
            ip_type_map[ip] = ip_type

        raw_domains = item.get("domain", [])
        if isinstance(raw_domains, str):
            raw_domains = [raw_domains]
        if not isinstance(raw_domains, list):
            raw_domains = []

        for raw_domain in raw_domains:
            domain = _normalize_alert_domain(raw_domain)
            if not domain:
                continue
            task_domain_set.add(domain)
            ip_domain_map.setdefault(ip, []).append(domain)

    for ip, domains in list(ip_domain_map.items()):
        ordered = []
        seen = set()
        for domain in domains:
            if domain in seen:
                continue
            ordered.append(domain)
            seen.add(domain)
        ip_domain_map[ip] = ordered

    return {
        "ip_type_map": ip_type_map,
        "ip_domain_map": ip_domain_map,
        "task_domain_set": task_domain_set,
    }


def _is_private_alert_ip(ip, ip_type_map):
    """
    判断证书告警 IP 是否属于内网/保留类型。
    """
    ip_text = str(ip or "").strip()
    if not ip_text:
        return False

    if str(ip_type_map.get(ip_text, "")).upper() == "PRIVATE":
        return True

    try:
        ip_type = str(utils.get_ip_type(ip_text) or "").upper()
    except Exception:
        ip_type = ""
    return ip_type == "PRIVATE"


def _extract_alert_domain(cert_obj, ip, port, ip_domain_map=None, task_domain_set=None):
    """
    告警域名优先级：
    1) 任务内 IP 关联域名
    2) SAN 域名（优先命中任务域名）
    3) CN（仅合法域名）
    4) ip:port 回退
    """
    ip_text = str(ip or "").strip()
    port_text = str(port or "").strip()
    ip_domain_map = ip_domain_map if isinstance(ip_domain_map, dict) else {}
    task_domain_set = task_domain_set if isinstance(task_domain_set, set) else set()

    mapped_domains = ip_domain_map.get(ip_text, [])
    if isinstance(mapped_domains, list):
        for domain in mapped_domains:
            if domain:
                return domain

    san_domains = _extract_san_domains(cert_obj)
    if task_domain_set:
        for domain in san_domains:
            if domain in task_domain_set:
                return domain
    if san_domains:
        return san_domains[0]

    subject = cert_obj.get("subject", {}) if isinstance(cert_obj, dict) else {}
    if isinstance(subject, dict):
        common_name = _normalize_alert_domain(subject.get("common_name", ""))
        if common_name:
            return common_name

    return "{}:{}".format(ip_text, port_text) if ip_text and port_text else (ip_text or "-")


def _format_cert_validity_text(remaining_days):
    """
    将剩余天数格式化为可读文本。
    """
    try:
        days = int(remaining_days)
    except Exception:
        return "-"

    if days < 0:
        return "已过期 {} 天".format(abs(days))
    if days == 0:
        return "今日到期"
    return "剩余 {} 天".format(days)


def _collect_ssl_cert_warnings(task_id, alert_days=30, max_items=10):
    """
    收集任务中临期/过期证书列表，并在任务内按 域名+证书身份+到期时间 聚合去重。
    """
    alert_days = max(int(alert_days or 30), 1)
    warning_map = {}
    now_dt = datetime.utcnow()
    alert_context = _build_ssl_alert_context(task_id)
    ip_type_map = alert_context.get("ip_type_map", {})
    ip_domain_map = alert_context.get("ip_domain_map", {})
    task_domain_set = alert_context.get("task_domain_set", set())

    for item in utils.conn_db("cert").find({"task_id": task_id}):
        cert_obj = item.get("cert", {}) if isinstance(item.get("cert"), dict) else {}
        validity = cert_obj.get("validity", {}) if isinstance(cert_obj.get("validity"), dict) else {}
        start_time = str(validity.get("start", "")).strip()
        end_time = str(validity.get("end", "")).strip()
        if not end_time:
            continue

        ip = str(item.get("ip", "")).strip()
        if _is_private_alert_ip(ip, ip_type_map):
            continue

        end_dt = _parse_cert_datetime(end_time)
        if not end_dt:
            continue

        remaining_days = (end_dt - now_dt).days
        if remaining_days > alert_days:
            continue

        port = str(item.get("port", "")).strip()
        domain = _extract_alert_domain(
            cert_obj=cert_obj,
            ip=ip,
            port=port,
            ip_domain_map=ip_domain_map,
            task_domain_set=task_domain_set,
        )
        endpoint = "{}:{}".format(ip, port) if ip and port else (ip or "-")
        identity_key, identity_text = _extract_cert_identity(cert_obj)
        # 同域名同证书同到期时间视为同一告警，合并端点避免重复通知。
        dedup_key = "{}|{}|{}".format(
            str(domain or "-").strip().lower(),
            identity_key or endpoint,
            end_time,
        )
        warn_item = warning_map.get(dedup_key)
        if warn_item is None:
            warn_item = {
                "domain": domain,
                "ip": ip,
                "port": port,
                "endpoints": [],
                "start_time": start_time,
                "end_time": end_time,
                "remaining_days": remaining_days,
                "validity_text": _format_cert_validity_text(remaining_days),
                "cert_identity_key": identity_key,
                "cert_identity_text": identity_text,
            }
            warning_map[dedup_key] = warn_item

        if endpoint and endpoint not in warn_item["endpoints"]:
            warn_item["endpoints"].append(endpoint)

    warnings = list(warning_map.values())
    for warn_item in warnings:
        warn_item["endpoints"] = sorted(warn_item.get("endpoints", []))
    warnings.sort(key=lambda row: (row.get("remaining_days", 999999), str(row.get("domain", ""))))
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
    markdown = "### SSL证书安全警告\n\n"
    markdown += "- 检测域名：`{}`\n".format(str(warn_item.get("domain", "") or "-"))
    markdown += "- 检测时间：`{}`\n".format(utils.curr_date())
    markdown += "- 生效时间：`{}`\n".format(str(warn_item.get("start_time", "") or "-"))
    markdown += "- 失效时间：`{}`\n".format(str(warn_item.get("end_time", "") or "-"))
    markdown += "- 证书有效期：`{}`\n".format(str(warn_item.get("validity_text", "") or "-"))
    endpoint_text = ", ".join(warn_item.get("endpoints", [])) or "-"
    markdown += "- 告警端点：`{}`\n".format(endpoint_text)
    cert_identity_text = str(warn_item.get("cert_identity_text", "") or "-")
    markdown += "- 证书标识：`{}`\n".format(cert_identity_text)
    markdown += "- 请在有效期内及时更新！\n"
    if report_link:
        markdown += "- 报告链接：[点击查看]({})\n".format(report_link)
    else:
        markdown += "- 报告链接：`未生成`\n"
    return markdown


def _build_ssl_warning_level(remaining_days, alert_days):
    """
    告警分级（数值越大表示越紧急），用于跨任务抑制重复通知。
    """
    alert_days = max(int(alert_days or 30), 1)
    try:
        days = int(remaining_days)
    except Exception:
        return -1

    if days < 0:
        return 6
    if days == 0:
        return 5
    if days <= 1:
        return 4
    if days <= 3:
        return 3
    if days <= 7:
        return 2
    if days <= 15:
        return 1
    if days <= alert_days:
        return 0
    return -1


def _build_ssl_notify_state_key(warn_item):
    """
    生成跨任务通知去重键：域名 + 证书身份 + 到期时间。
    """
    domain = str(warn_item.get("domain", "") or "-").strip().lower()
    cert_identity = str(warn_item.get("cert_identity_key", "") or "").strip().lower()
    if not cert_identity:
        # 兜底使用端点，避免无指纹证书导致状态键缺失。
        cert_identity = ",".join(warn_item.get("endpoints", [])) or "-"
    end_time = str(warn_item.get("end_time", "") or "-").strip()
    return "{}|{}|{}".format(domain, cert_identity, end_time)


def _load_ssl_notify_state_level(state_key):
    """
    读取历史通知等级；不存在返回 -1。
    """
    if not state_key:
        return -1

    item = utils.conn_db("ssl_cert_notify_state").find_one(
        {"state_key": state_key},
        {"last_level": 1},
    )
    if not item:
        return -1

    try:
        return int(item.get("last_level", -1))
    except Exception:
        return -1


def _save_ssl_notify_state(state_key, warn_item, level, task_id):
    """
    保存通知状态（仅在发送成功后调用），避免重复推送。
    """
    if not state_key:
        return

    update_doc = {
        "state_key": state_key,
        "domain": str(warn_item.get("domain", "") or "-").strip().lower(),
        "cert_identity_key": str(warn_item.get("cert_identity_key", "") or "").strip().lower(),
        "end_time": str(warn_item.get("end_time", "") or "").strip(),
        "remaining_days": int(warn_item.get("remaining_days", 0) or 0),
        "last_level": int(level),
        "last_task_id": str(task_id or ""),
        "last_notify_date": utils.curr_date(),
        "update_date": utils.curr_date(),
    }
    utils.conn_db("ssl_cert_notify_state").update_one(
        {"state_key": state_key},
        {
            "$set": update_doc,
            "$setOnInsert": {"create_date": utils.curr_date()},
        },
        upsert=True,
    )


def _push_ssl_cert_warning(task_id, task_data):
    """
    推送 SSL 证书临期告警，并尽可能附带钉钉知识库报告链接。
    """
    alert_days = int(Config.DINGTALK_SSL_CERT_NOTIFY_DAYS or 30)
    if alert_days <= 0:
        alert_days = 30

    warnings = _collect_ssl_cert_warnings(task_id=task_id, alert_days=alert_days, max_items=20)
    if not warnings:
        return

    # 跨任务告警降噪：仅首次出现或告警等级升级时发送。
    pending_warnings = []
    for warn_item in warnings:
        level = _build_ssl_warning_level(warn_item.get("remaining_days", 0), alert_days=alert_days)
        if level < 0:
            continue
        state_key = _build_ssl_notify_state_key(warn_item)
        history_level = _load_ssl_notify_state_level(state_key)
        if level <= history_level:
            continue
        pending_warnings.append(
            {
                "warn_item": warn_item,
                "state_key": state_key,
                "level": level,
            }
        )

    if not pending_warnings:
        logger.info("skip ssl cert warning notify task_id:%s reason:no level upgrade", task_id)
        return

    report_link = ""
    if Config.DINGTALK_KB_ENABLE:
        task_name = str(task_data.get("name", "")).strip()
        report_title = "{}-SSL证书过期报告-{}".format(task_name or "任务", utils.curr_date())
        summary_markdown = (
            "### SSL证书过期提醒报告\n\n"
            "- 告警证书数量：`{}`\n"
            "- 提醒阈值：`<= {} 天`\n"
        ).format(len(pending_warnings), alert_days)
        kb_success, kb_result = push_dingtalk_kb(
            report_title=report_title,
            markdown_report=summary_markdown,
            source_type="ssl_cert_warning",
            source_id=task_id,
            extra_data={"task_id": task_id, "warning_count": len(pending_warnings), "alert_days": alert_days},
            task_ids=[task_id],
        )
        if kb_success and isinstance(kb_result, dict):
            report_link = str(kb_result.get("node_url", "")).strip()

    if not report_link:
        report_link = _build_report_link_fallback(task_id)

    for item in pending_warnings:
        warn_item = item["warn_item"]
        markdown_report = _build_ssl_cert_warning_markdown(warn_item, report_link=report_link)
        if push_dingding(markdown_report=markdown_report):
            _save_ssl_notify_state(
                state_key=item["state_key"],
                warn_item=warn_item,
                level=item["level"],
                task_id=task_id,
            )


def push_task_finish_notify(task_id):
    """
    普通任务完成后的钉钉推送

    说明：
    - 仅对普通任务和风险巡航任务生效
    - 计划任务子任务会标记 from_task_schedule，避免和计划任务推送重复
    """
    try:
        # Worker 进程常驻，任务完成回调前做一次配置热刷新，避免修改配置后必须重启容器。
        dingtalk_openapi.refresh_runtime_dingtalk_config_best_effort()

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
            logger.info(
                "skip task finish notify task_id:%s dingding_notify:%s ssl_cert:%s ssl_cert_notify_enable:%s",
                task_id,
                finish_notify_enabled,
                bool(options.get("ssl_cert")),
                bool(Config.DINGTALK_SSL_CERT_NOTIFY_ENABLE),
            )
            return

        if finish_notify_enabled:
            markdown_report = build_task_finish_markdown(task_data)
            push_dingding(markdown_report=markdown_report)

        if ssl_cert_notify_enabled:
            _push_ssl_cert_warning(task_id, task_data)

    except Exception as e:
        logger.warning("push task finish notify error {}".format(task_id))
        logger.warning(e)
