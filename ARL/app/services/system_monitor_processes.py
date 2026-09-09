"""ARL 应用容器进程数上报与汇总。"""

import json
import logging
import os
import re
import tempfile
import time
from typing import Dict, Iterable, Optional, Tuple

import psutil


logger = logging.getLogger("arlv2")

DEFAULT_MONITOR_DIR = "/run/arl-process-monitor"
DEFAULT_STALE_AFTER_SEC = 15.0
DEFAULT_INSTANCES = ("web", "worker_1", "worker_2", "scheduler")
INSTANCE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def get_monitor_dir() -> str:
    """返回共享进程监控目录。"""
    return str(os.environ.get("ARL_PROCESS_MONITOR_DIR", DEFAULT_MONITOR_DIR) or DEFAULT_MONITOR_DIR).strip()


def get_monitor_instance() -> str:
    """返回当前应用容器的稳定实例名。"""
    configured = str(os.environ.get("ARL_PROCESS_MONITOR_INSTANCE", "") or "").strip()
    instance = configured or str(os.environ.get("HOSTNAME", "unknown") or "unknown").strip()
    safe_instance = INSTANCE_NAME_RE.sub("_", instance).strip("._")
    return safe_instance or "unknown"


def get_expected_instances() -> Tuple[str, ...]:
    """返回需要汇总的 ARL 应用容器实例。"""
    configured = str(os.environ.get("ARL_PROCESS_MONITOR_INSTANCES", "") or "").strip()
    if not configured:
        return DEFAULT_INSTANCES

    instances = []
    for item in configured.split(","):
        safe_instance = INSTANCE_NAME_RE.sub("_", item.strip()).strip("._")
        if safe_instance and safe_instance not in instances:
            instances.append(safe_instance)
    return tuple(instances) or DEFAULT_INSTANCES


def get_stale_after_sec() -> float:
    """返回心跳失效时间，避免把已停止容器的最后一次数据继续累加。"""
    configured = str(os.environ.get("ARL_PROCESS_MONITOR_STALE_AFTER_SEC", "") or "").strip()
    try:
        value = float(configured) if configured else DEFAULT_STALE_AFTER_SEC
    except (TypeError, ValueError):
        value = DEFAULT_STALE_AFTER_SEC
    return max(3.0, value)


def collect_process_count() -> int:
    """读取当前容器进程数。"""
    try:
        return max(0, len(psutil.pids()))
    except (OSError, psutil.Error) as exc:
        logger.warning("count container processes failed: %s", exc)
        return 0


def _snapshot_path(monitor_dir: str, instance: str) -> str:
    safe_instance = INSTANCE_NAME_RE.sub("_", str(instance or "unknown")).strip("._") or "unknown"
    return os.path.join(monitor_dir, "{}.json".format(safe_instance))


def write_process_snapshot(
    process_count: Optional[int] = None,
    instance: Optional[str] = None,
    monitor_dir: Optional[str] = None,
    updated_at: Optional[float] = None,
) -> bool:
    """原子写入一个容器的进程数心跳。"""
    target_dir = str(monitor_dir or get_monitor_dir()).strip() or DEFAULT_MONITOR_DIR
    target_instance = instance or get_monitor_instance()
    payload = {
        "instance": target_instance,
        "process_count": max(0, int(process_count if process_count is not None else collect_process_count())),
        "updated_at": float(updated_at if updated_at is not None else time.time()),
    }
    temp_path = ""
    try:
        os.makedirs(target_dir, mode=0o755, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(
            prefix=".{}.".format(payload["instance"]),
            suffix=".tmp",
            dir=target_dir,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, _snapshot_path(target_dir, target_instance))
        temp_path = ""
        return True
    except (OSError, TypeError, ValueError) as exc:
        logger.warning("write process monitor snapshot failed instance=%s: %s", target_instance, exc)
        return False
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError as exc:
                logger.debug("remove process monitor temp file failed path=%s: %s", temp_path, exc)


def read_process_snapshots(
    expected_instances: Optional[Iterable[str]] = None,
    monitor_dir: Optional[str] = None,
    now: Optional[float] = None,
    stale_after_sec: Optional[float] = None,
) -> Dict[str, Dict[str, float]]:
    """读取仍在有效期内的容器心跳。"""
    target_dir = str(monitor_dir or get_monitor_dir()).strip() or DEFAULT_MONITOR_DIR
    current_time = float(now if now is not None else time.time())
    stale_after = max(3.0, float(stale_after_sec if stale_after_sec is not None else get_stale_after_sec()))
    snapshots: Dict[str, Dict[str, float]] = {}

    for instance in expected_instances or get_expected_instances():
        path = _snapshot_path(target_dir, instance)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            process_count = int(payload.get("process_count", -1))
            updated_at = float(payload.get("updated_at", 0))
            age = max(0.0, current_time - updated_at)
            if process_count < 0 or updated_at <= 0 or age > stale_after:
                continue
            snapshots[str(instance)] = {
                "process_count": process_count,
                "updated_at": updated_at,
                "age_sec": round(age, 3),
            }
        except FileNotFoundError:
            continue
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            logger.debug("read process monitor snapshot failed path=%s: %s", path, exc)

    return snapshots


def aggregate_process_counts(
    expected_instances: Optional[Iterable[str]] = None,
    monitor_dir: Optional[str] = None,
    now: Optional[float] = None,
    stale_after_sec: Optional[float] = None,
) -> Tuple[int, Dict[str, Dict[str, float]]]:
    """汇总有效应用容器进程数，并返回各容器明细。"""
    snapshots = read_process_snapshots(
        expected_instances=expected_instances,
        monitor_dir=monitor_dir,
        now=now,
        stale_after_sec=stale_after_sec,
    )
    total = sum(int(item.get("process_count", 0) or 0) for item in snapshots.values())
    return total, snapshots


def run_reporter(interval_sec: float = 3.0) -> None:
    """持续上报当前容器进程数，供 web 汇总。"""
    interval = max(1.0, float(interval_sec))
    instance = get_monitor_instance()
    while True:
        write_process_snapshot(instance=instance)
        time.sleep(interval)


def main() -> None:
    configured_interval = str(os.environ.get("ARL_PROCESS_MONITOR_INTERVAL_SEC", "3") or "3").strip()
    try:
        interval = float(configured_interval)
    except (TypeError, ValueError):
        interval = 3.0
    try:
        run_reporter(interval)
    except KeyboardInterrupt:
        logger.info("process monitor reporter stopped instance=%s", get_monitor_instance())


if __name__ == "__main__":
    main()
