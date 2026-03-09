"""
控制台信息管理模块

功能说明：
- 获取系统设备信息
- 提供仪表盘聚合数据
- 用于系统监控和健康检查
"""
from collections import deque
from datetime import datetime, timedelta
import threading
import time

import psutil
from flask import request
from flask_restx import Namespace
from app.utils import get_logger, auth
from app.utils.device import human_size
from app import utils
from app.modules import ErrorMsg
from . import ARLResource, conn

ns = Namespace('console', description="控制台信息")

logger = get_logger()
SYSTEM_MONITOR_LOCK = threading.Lock()
SYSTEM_MONITOR_HISTORY = deque(maxlen=360)
LAST_NET_IO_SAMPLE = {
    "timestamp": 0.0,
    "bytes_sent": 0,
    "bytes_recv": 0,
}
LOG_LINE_MAX_LENGTH = 320
DEFAULT_RECENT_LOG_LIMIT = 24
MAX_RECENT_LOG_LIMIT = 100

TASK_STATUS_TEXT_MAP = {
    "waiting": "等待中",
    "running": "运行中",
    "done": "已完成",
    "stop": "已停止",
    "error": "执行异常",
}

TASK_TYPE_TEXT_MAP = {
    "domain": "域名任务",
    "ip": "IP任务",
    "risk_cruising": "风险巡航任务",
    "fofa": "FOFA任务",
    "asset_site_add": "站点添加任务",
    "asset_site_update": "站点更新任务",
    "asset_wih_update": "WIH更新任务",
}

TASK_STAGE_TEXT_MAP = {
    "domain_brute": "域名爆破",
    "dns_query_plugin": "域名查询插件",
    "arl_search": "ARL历史查询",
    "alt_dns": "DNS字典智能生成",
    "port_scan": "端口扫描",
    "ssl_cert": "SSL证书获取",
    "cert_query_plugin": "证书查询插件",
    "find_site": "站点识别",
    "npoc_service_detection": "服务识别",
    "poc_run": "PoC扫描",
    "weak_brute": "弱口令爆破",
    "findvhost": "Host碰撞",
    "search_engines": "搜索引擎调用",
    "ip_query_plugin": "IP查询插件",
    "fetch site": "站点采集",
    "domain site monitor": "站点监控",
    "send notify": "发送通知",
}


def _count_documents(collection: str, query=None) -> int:
    """
    统计集合文档数量（异常时返回 0）
    """
    try:
        return conn(collection).count_documents(query or {})
    except Exception as e:
        logger.debug("count %s failed: %s", collection, e)
        return 0


def _safe_float(value, default=0.0) -> float:
    """
    安全转 float，避免异常中断监控聚合。
    """
    try:
        if value is None:
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def _build_risk_distribution():
    """
    构建漏洞风险分布（高危/中危/低危/信息）
    """
    risk_map = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    try:
        pipeline = [
            {"$project": {"severity": {"$toLower": {"$ifNull": ["$severity", "info"]}}}},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
        ]
        for item in conn("vuln").aggregate(pipeline):
            level = str(item.get("_id", "")).strip().lower()
            count = int(item.get("count", 0))
            if level in risk_map:
                risk_map[level] += count
            else:
                risk_map["info"] += count
    except Exception as e:
        logger.debug("build risk distribution failed: %s", e)

    return [
        {"name": "高危", "value": risk_map["critical"] + risk_map["high"], "color": "#ef4444"},
        {"name": "中危", "value": risk_map["medium"], "color": "#f59e0b"},
        {"name": "低危", "value": risk_map["low"], "color": "#3b82f6"},
        {"name": "信息", "value": risk_map["info"], "color": "#64748b"},
    ]


def _build_asset_trend_7d():
    """
    构建最近 7 天资产与漏洞趋势
    """
    now = datetime.now()
    start = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
    day_keys = [(start + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
    asset_map = {k: 0 for k in day_keys}
    vuln_map = {k: 0 for k in day_keys}

    try:
        asset_pipeline = [
            {"$match": {"save_date": {"$gte": start}}},
            {"$project": {"day": {"$dateToString": {"format": "%Y-%m-%d", "date": "$save_date"}}}},
            {"$group": {"_id": "$day", "count": {"$sum": 1}}}
        ]
        for item in conn("asset_site").aggregate(asset_pipeline):
            day = str(item.get("_id", ""))
            if day in asset_map:
                asset_map[day] = int(item.get("count", 0))
    except Exception as e:
        logger.debug("build asset trend failed: %s", e)

    try:
        vuln_pipeline = [
            {"$match": {"save_date": {"$gte": start}}},
            {"$project": {"day": {"$dateToString": {"format": "%Y-%m-%d", "date": "$save_date"}}}},
            {"$group": {"_id": "$day", "count": {"$sum": 1}}}
        ]
        for item in conn("vuln").aggregate(vuln_pipeline):
            day = str(item.get("_id", ""))
            if day in vuln_map:
                vuln_map[day] = int(item.get("count", 0))
    except Exception as e:
        logger.debug("build vuln trend failed: %s", e)

    return [{
        "name": day[-5:],
        "assets": asset_map[day],
        "vulns": vuln_map[day]
    } for day in day_keys]


def _build_network_trend_6h():
    """
    构建最近 6 小时任务流量趋势（用于仪表盘折线）
    """
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=5)
    hour_keys = [(start + timedelta(hours=i)).strftime("%Y-%m-%d %H:00") for i in range(6)]
    hour_count_map = {k: 0 for k in hour_keys}

    try:
        pipeline = [
            {"$match": {"save_date": {"$gte": start}}},
            {"$project": {"hour": {"$dateToString": {"format": "%Y-%m-%d %H:00", "date": "$save_date"}}}},
            {"$group": {"_id": "$hour", "count": {"$sum": 1}}}
        ]
        for item in conn("task").aggregate(pipeline):
            hour_key = str(item.get("_id", ""))
            if hour_key in hour_count_map:
                hour_count_map[hour_key] = int(item.get("count", 0))
    except Exception as e:
        logger.debug("build network trend failed: %s", e)

    trend = []
    for hour_key in hour_keys:
        count = hour_count_map[hour_key]
        in_value = max(60, count * 180)
        out_value = max(30, int(in_value * 0.55))
        trend.append({
            "time": hour_key[-5:],
            "in": in_value,
            "out": out_value
        })

    return trend


def _truncate_text(value, max_len=LOG_LINE_MAX_LENGTH):
    text = str(value or "").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _parse_time_value(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S"), value.timestamp()

    text = str(value or "").strip()
    if not text or text == "-":
        now = datetime.now()
        return now.strftime("%Y-%m-%d %H:%M:%S"), now.timestamp()

    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ]
    for fmt in formats:
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.strftime("%Y-%m-%d %H:%M:%S"), parsed.timestamp()
        except Exception:
            continue

    now = datetime.now()
    return text, now.timestamp()


def _get_task_log_level(status):
    value = str(status or "").strip().lower()
    if value in ["error", "fail", "failed"]:
        return "ERROR"
    if value in ["stop", "stopped"]:
        return "WARN"
    if value in ["done", "success", "finished"]:
        return "INFO"
    if value in ["waiting"]:
        return "WARN"
    return "INFO"


def _human_task_type(task_type):
    key = str(task_type or "").strip().lower()
    return TASK_TYPE_TEXT_MAP.get(key, key or "任务")


def _human_task_status(status):
    key = str(status or "").strip().lower()
    return TASK_STATUS_TEXT_MAP.get(key, key or "未知")


def _human_task_stage(stage):
    text = str(stage or "").strip()
    if not text:
        return "-"
    normalized = text.lower()
    if normalized in TASK_STATUS_TEXT_MAP:
        return TASK_STATUS_TEXT_MAP[normalized]
    if normalized in TASK_STAGE_TEXT_MAP:
        return TASK_STAGE_TEXT_MAP[normalized]
    return text


def _build_recent_task_summary_logs(limit=DEFAULT_RECENT_LOG_LIMIT):
    """
    构建最近扫描日志：展示扫描中阶段、最近完成情况与步骤耗时。
    """
    safe_limit = max(1, min(int(limit or DEFAULT_RECENT_LOG_LIMIT), MAX_RECENT_LOG_LIMIT))
    records = []
    seq = 0

    projection = {
        "_id": 1,
        "name": 1,
        "target": 1,
        "status": 1,
        "type": 1,
        "start_time": 1,
        "end_time": 1,
        "save_date": 1,
        "service": 1,
        "statistic": 1,
    }

    try:
        task_limit = max(24, safe_limit * 3)
        for task in conn("task").find({}, projection).sort("_id", -1).limit(task_limit):
            task_name = _truncate_text(task.get("name", "未命名任务"), max_len=36)
            task_type_text = _human_task_type(task.get("type", ""))
            task_status = str(task.get("status", "")).strip()
            task_status_lower = task_status.lower()
            status_text = _human_task_status(task_status)
            stage_text = _human_task_stage(task_status)
            target_preview = _truncate_text(task.get("target", "-"), max_len=56)

            if task_status_lower in ["done", "stop", "error"]:
                time_value = task.get("end_time") or task.get("save_date") or task.get("start_time")
            else:
                time_value = task.get("start_time") or task.get("save_date") or task.get("end_time")
            if str(time_value or "").strip() in ["", "-"]:
                try:
                    time_value = task.get("_id").generation_time
                except Exception:
                    pass

            display_time, ts_value = _parse_time_value(time_value)
            level = _get_task_log_level(task_status)

            if task_status_lower == "done":
                stat = task.get("statistic") or {}
                msg = "任务[{}]({}) 扫描完成，站点:{} 域名:{} IP:{} 漏洞:{}".format(
                    task_name,
                    task_type_text,
                    int(stat.get("site_cnt", 0) or 0),
                    int(stat.get("domain_cnt", 0) or 0),
                    int(stat.get("ip_cnt", 0) or 0),
                    int(stat.get("vuln_cnt", 0) or 0),
                )
            elif task_status_lower in ["error", "stop"]:
                msg = "任务[{}]({}) {}，最后阶段:{}，目标:{}".format(
                    task_name,
                    task_type_text,
                    status_text,
                    stage_text,
                    target_preview,
                )
            elif task_status_lower == "waiting":
                msg = "任务[{}]({}) 等待调度，目标:{}".format(task_name, task_type_text, target_preview)
            else:
                msg = "任务[{}]({}) 扫描中，当前阶段:{}，目标:{}".format(
                    task_name,
                    task_type_text,
                    stage_text,
                    target_preview,
                )

            records.append({
                "_seq": seq,
                "_ts": ts_value,
                "time": display_time,
                "level": level,
                "source": "SCAN",
                "msg": _truncate_text(msg),
            })
            seq += 1

            service_items = task.get("service", [])
            if isinstance(service_items, list) and service_items:
                for service_item in service_items[-2:]:
                    service_name = _human_task_stage(service_item.get("name"))
                    elapsed = _safe_float(service_item.get("elapsed", 0), 0.0)
                    if elapsed > 0:
                        msg = "任务[{}] 阶段完成: {} (耗时 {:.2f}s)".format(task_name, service_name, elapsed)
                    else:
                        msg = "任务[{}] 阶段完成: {}".format(task_name, service_name)
                    records.append({
                        "_seq": seq,
                        "_ts": ts_value,
                        "time": display_time,
                        "level": "INFO",
                        "source": "STEP",
                        "msg": _truncate_text(msg),
                    })
                    seq += 1
    except Exception as e:
        logger.debug("build recent scan logs failed: %s", e)

    if not records:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return [{
            "time": now,
            "level": "INFO",
            "source": "SCAN",
            "msg": "暂无扫描日志，创建任务后会在此实时展示扫描阶段",
        }]

    records.sort(key=lambda item: (item.get("_ts", 0), item.get("_seq", 0)), reverse=True)
    return [{
        "time": item.get("time", ""),
        "level": item.get("level", "INFO"),
        "source": item.get("source", "SCAN"),
        "msg": item.get("msg", ""),
    } for item in records[:safe_limit]]


def _build_recent_logs(limit=DEFAULT_RECENT_LOG_LIMIT):
    """
    构建实时扫描日志（仅任务扫描过程，不读取系统运行日志）。
    """
    return _build_recent_task_summary_logs(limit=limit)


def _build_engine_status(device_info, running_tasks: int, waiting_tasks: int):
    """
    构建单机引擎状态摘要
    """
    cpu_percent = _safe_float((device_info.get("cpu") or {}).get("percent", 0), 0.0)
    memory_info = device_info.get("memory") or device_info.get("virtual_memory") or {}
    disk_info = device_info.get("disk") or device_info.get("disk_usage") or {}
    memory_percent = _safe_float(memory_info.get("percent", 0), 0.0)
    disk_percent = _safe_float(disk_info.get("percent", 0), 0.0)

    # 资源评分仅用于趋势观察，不代表精确容量评估
    resource_score = max(
        0.0,
        min(100.0, 100.0 - (cpu_percent * 0.35 + memory_percent * 0.35 + disk_percent * 0.30))
    )

    return {
        "version": "ARL Engine",
        "deploy_mode": "single",
        "deploy_mode_text": "单机部署",
        "pending_tasks": int(waiting_tasks),
        "running_tasks": int(running_tasks),
        "resource_score": round(resource_score, 1),
        "resource_score_desc": "估算值，仅供参考",
        # 兼容旧前端字段
        "cluster_online": 1,
        "cluster_total": 1,
        "queue_pending": int(waiting_tasks),
        "health_score": round(resource_score, 1),
    }


def _collect_system_monitor_snapshot():
    """
    采集系统监控实时快照，并维护历史趋势缓存。
    """
    device_info = utils.device_info()
    cpu_info = device_info.get("cpu", {})
    memory_info = device_info.get("memory") or device_info.get("virtual_memory") or {}
    disk_info = device_info.get("disk") or device_info.get("disk_usage") or {}

    cpu_percent = _safe_float(cpu_info.get("percent", 0), 0.0)
    memory_percent = _safe_float(memory_info.get("percent", 0), 0.0)
    disk_percent = _safe_float(disk_info.get("percent", 0), 0.0)

    net_io = psutil.net_io_counters()
    now_ts = time.time()
    now_label = datetime.now().strftime("%H:%M")

    with SYSTEM_MONITOR_LOCK:
        last_ts = _safe_float(LAST_NET_IO_SAMPLE.get("timestamp", 0), 0.0)
        last_sent = int(LAST_NET_IO_SAMPLE.get("bytes_sent", 0) or 0)
        last_recv = int(LAST_NET_IO_SAMPLE.get("bytes_recv", 0) or 0)

        interval = max(0.0, now_ts - last_ts)
        sent_delta = max(0, int(net_io.bytes_sent) - last_sent)
        recv_delta = max(0, int(net_io.bytes_recv) - last_recv)

        if interval > 0:
            net_out_bps = sent_delta / interval
            net_in_bps = recv_delta / interval
        else:
            net_out_bps = 0.0
            net_in_bps = 0.0

        LAST_NET_IO_SAMPLE["timestamp"] = now_ts
        LAST_NET_IO_SAMPLE["bytes_sent"] = int(net_io.bytes_sent)
        LAST_NET_IO_SAMPLE["bytes_recv"] = int(net_io.bytes_recv)

        sample = {
            "time": now_label,
            "cpu": round(cpu_percent, 2),
            "ram": round(memory_percent, 2),
            "disk": round(disk_percent, 2),
            "net_in": round(net_in_bps / 1024.0, 2),      # KB/s
            "net_out": round(net_out_bps / 1024.0, 2),    # KB/s
            "net": round((net_in_bps + net_out_bps) / 1024.0, 2),
        }
        SYSTEM_MONITOR_HISTORY.append(sample)

        history = list(SYSTEM_MONITOR_HISTORY)
        if not history:
            history = [sample]

        # 对历史点位降采样，前端最多展示 24 个点，避免图表拥挤
        step = max(1, len(history) // 24)
        history_24h = history[::step][-24:]

    boot_time = "-"
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        logger.debug("parse boot time failed: %s", e)

    process_count = 0
    try:
        process_count = len(psutil.pids())
    except Exception as e:
        logger.debug("count process failed: %s", e)

    resource = {
        "cpu_percent": round(cpu_percent, 2),
        "cpu_count": int(cpu_info.get("count", 0) or 0),
        "memory_percent": round(memory_percent, 2),
        "memory_used": memory_info.get("used", "-"),
        "memory_total": memory_info.get("total", "-"),
        "disk_percent": round(disk_percent, 2),
        "disk_used": disk_info.get("used", "-"),
        "disk_total": disk_info.get("total", "-"),
        "network_total_sent": human_size(net_io.bytes_sent),
        "network_total_recv": human_size(net_io.bytes_recv),
        "network_rate_in_kbps": round(history_24h[-1]["net_in"], 2),
        "network_rate_out_kbps": round(history_24h[-1]["net_out"], 2),
        "network_rate_total_kbps": round(history_24h[-1]["net"], 2),
        "process_count": process_count,
        "boot_time": boot_time,
    }
    return resource, history_24h


@ns.route('/info')
class ARLConsole(ARLResource):
    """系统信息查询接口"""

    @auth
    def get(self):
        """
        获取系统控制台信息
        """
        data = {
            "device_info": utils.device_info()   # 包含 CPU 内存和磁盘信息
        }
        return utils.build_ret(ErrorMsg.Success, data)


@ns.route('/dashboard')
class ARLConsoleDashboard(ARLResource):
    """仪表盘聚合数据接口"""

    @auth
    def get(self):
        """
        获取仪表盘聚合数据

        返回：
            - stats: 核心统计数据
            - device_info: 主机资源信息
            - risk_distribution: 风险分布
            - asset_trend_7d: 最近 7 天趋势
            - network_trend: 最近 6 小时流量趋势
            - recent_logs: 最近扫描日志
            - engine: 引擎状态
        """
        device_info = utils.device_info()
        running_tasks = _count_documents("task", {"status": "running"})
        waiting_tasks = _count_documents("task", {"status": "waiting"})

        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        stats = {
            "task_total": _count_documents("task"),
            "running_tasks": running_tasks,
            "waiting_tasks": waiting_tasks,
            "scheduler_total": _count_documents("scheduler"),
            "asset_scope_total": _count_documents("asset_scope"),
            "asset_site_total": _count_documents("asset_site"),
            "vuln_total": _count_documents("vuln"),
            "github_task_total": _count_documents("github_task"),
            "new_assets_today": _count_documents("asset_site", {"save_date": {"$gte": today_start}})
        }

        data = {
            "stats": stats,
            "device_info": device_info,
            "risk_distribution": _build_risk_distribution(),
            "asset_trend_7d": _build_asset_trend_7d(),
            "network_trend": _build_network_trend_6h(),
            "recent_logs": _build_recent_logs(limit=DEFAULT_RECENT_LOG_LIMIT),
            "engine": _build_engine_status(device_info, running_tasks, waiting_tasks),
            "last_updated": str(datetime.now())
        }
        return utils.build_ret(ErrorMsg.Success, data)


@ns.route('/recent_logs')
class ARLConsoleRecentLogs(ARLResource):
    """仪表盘实时扫描日志接口"""

    @auth
    def get(self):
        """
        获取最近扫描日志
        Query:
            - limit: 条数，默认 24，最大 100
        """
        limit = request.args.get("limit", DEFAULT_RECENT_LOG_LIMIT, type=int)
        logs = _build_recent_logs(limit=limit)
        data = {
            "recent_logs": logs,
            "last_updated": str(datetime.now())
        }
        return utils.build_ret(ErrorMsg.Success, data)


@ns.route('/system_monitor/')
class ARLConsoleSystemMonitor(ARLResource):
    """
    系统监控接口
    """

    @auth
    def get(self):
        """
        获取系统监控实时数据与历史趋势
        """
        try:
            resource, history_24h = _collect_system_monitor_snapshot()
            data = {
                "resource": resource,
                "history_24h": history_24h,
                "updated_at": str(datetime.now()),
            }
            return utils.build_ret(ErrorMsg.Success, data)
        except Exception as e:
            logger.exception("load system monitor failed: %s", e)
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    "error": str(e),
                },
            )
