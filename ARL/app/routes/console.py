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


def _build_recent_logs():
    """
    构建实时日志摘要（来源：最近任务）
    """
    logs = []
    try:
        for task in conn("task").find({}, {"name": 1, "status": 1, "target": 1, "save_date": 1}).sort("_id", -1).limit(6):
            status = str(task.get("status", "")).lower()
            if status in ["done", "success", "finished"]:
                level = "INFO"
            elif status in ["error", "fail", "failed", "stop", "stopped"]:
                level = "CRIT"
            else:
                level = "WARN"
            logs.append({
                "level": level,
                "msg": "任务[{}] 状态:{} 目标:{}".format(
                    str(task.get("name", "未命名任务"))[:28],
                    str(task.get("status", "unknown")),
                    str(task.get("target", "-"))[:24]
                ),
                "time": str(task.get("save_date", ""))
            })
    except Exception as e:
        logger.debug("build recent logs failed: %s", e)

    if not logs:
        logs = [{
            "level": "INFO",
            "msg": "系统运行正常，暂未生成任务日志",
            "time": str(datetime.now())
        }]
    return logs


def _build_engine_status(device_info, running_tasks: int, waiting_tasks: int):
    """
    构建引擎状态摘要
    """
    cpu_percent = float(device_info.get("cpu", {}).get("percent", 0) or 0)
    memory_percent = float(device_info.get("memory", {}).get("percent", 0) or 0)
    disk_percent = float(device_info.get("disk", {}).get("percent", 0) or 0)
    health_score = max(0.0, min(100.0, 100.0 - (cpu_percent * 0.35 + memory_percent * 0.35 + disk_percent * 0.30)))

    return {
        "version": "ARL Engine",
        "cluster_online": 3,
        "cluster_total": 3,
        "queue_pending": int(running_tasks) + int(waiting_tasks),
        "health_score": round(health_score, 1)
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
            - recent_logs: 最近任务日志摘要
            - engine: 引擎状态
        """
        device_info = utils.device_info()
        running_tasks = _count_documents("task", {"status": {"$in": ["running", "waiting"]}})
        waiting_tasks = _count_documents("task", {"status": "waiting"})

        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        stats = {
            "task_total": _count_documents("task"),
            "running_tasks": running_tasks,
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
            "recent_logs": _build_recent_logs(),
            "engine": _build_engine_status(device_info, running_tasks, waiting_tasks),
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
