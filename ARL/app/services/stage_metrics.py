"""阶段指标事件的统一格式。"""

import json
import time


_COUNT_FIELDS = (
    "target_count",
    "port_count",
    "input_count",
    "dedup_count",
    "filtered_count",
    "output_count",
    "queued_count",
    "pending_count",
    "success_count",
    "timeout_count",
    "retry_count",
    "failed_count",
    "degraded_count",
    "rust_execution_count",
    "fallback_count",
)


class StageMetric(object):
    """生成单个阶段或批次的独立指标事件，不依赖全局计数器。"""

    VERSION = 1

    def __init__(
        self,
        task_id,
        stage,
        batch=None,
        target_count=0,
        port_count=0,
        provider="",
        started_at=None,
        started_monotonic=None,
        cpu_started_sec=None,
    ):
        self.task_id = str(task_id or "")
        self.stage = str(stage or "")
        self.batch = str(batch or "")
        self.target_count = self._safe_count(target_count)
        self.port_count = self._safe_count(port_count)
        self.provider = str(provider or "")
        self.started_at = float(started_at if started_at is not None else time.time())
        self.started_monotonic = float(
            started_monotonic if started_monotonic is not None else time.monotonic()
        )
        self.cpu_started_sec = cpu_started_sec

    @staticmethod
    def _safe_count(value):
        try:
            return max(int(value or 0), 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _safe_float(value, default=0.0):
        try:
            return max(float(value or 0.0), 0.0)
        except (TypeError, ValueError):
            return default

    def finish(
        self,
        status="success",
        end_reason="completed",
        input_count=None,
        output_count=None,
        metrics=None,
        finished_at=None,
        finished_monotonic=None,
        cpu_finished_sec=None,
    ):
        raw_metrics = dict(metrics or {}) if isinstance(metrics, dict) else {}
        finished_at = float(finished_at if finished_at is not None else time.time())
        finished_monotonic = float(
            finished_monotonic
            if finished_monotonic is not None
            else time.monotonic()
        )
        wall_clock_sec = self._safe_float(
            finished_monotonic - self.started_monotonic
        )

        cpu_time_sec = raw_metrics.get("cpu_time_sec")
        if cpu_time_sec is None and self.cpu_started_sec is not None and cpu_finished_sec is not None:
            cpu_time_sec = self._safe_float(cpu_finished_sec - self.cpu_started_sec)
        elif cpu_time_sec is None:
            cpu_time_sec = 0.0

        event = {
            "metric_version": self.VERSION,
            "task_id": self.task_id,
            "stage": self.stage,
            "batch": self.batch,
            "provider": self.provider,
            "started_at": round(self.started_at, 3),
            "finished_at": round(finished_at, 3),
            "wall_clock_sec": round(wall_clock_sec, 6),
            "cpu_time_sec": round(self._safe_float(cpu_time_sec), 6),
            "network_wait_sec": round(
                self._safe_float(raw_metrics.get("network_wait_sec")), 6
            ),
            "status": str(status or "success").strip().lower() or "success",
            "end_reason": str(end_reason or "completed").strip().lower() or "completed",
            "target_count": self.target_count,
            "port_count": self.port_count,
            "input_count": self._safe_count(
                input_count if input_count is not None else raw_metrics.get("input_count")
            ),
            "dedup_count": self._safe_count(raw_metrics.get("dedup_count")),
            "filtered_count": self._safe_count(raw_metrics.get("filtered_count")),
            "output_count": self._safe_count(
                output_count if output_count is not None else raw_metrics.get("output_count")
            ),
            "queued_count": self._safe_count(raw_metrics.get("queued_count")),
            "pending_count": self._safe_count(raw_metrics.get("pending_count")),
            "success_count": self._safe_count(raw_metrics.get("success_count")),
            "timeout_count": self._safe_count(raw_metrics.get("timeout_count")),
            "retry_count": self._safe_count(raw_metrics.get("retry_count")),
            "failed_count": self._safe_count(raw_metrics.get("failed_count")),
            "degraded_count": self._safe_count(raw_metrics.get("degraded_count")),
            "rust_execution_count": self._safe_count(
                raw_metrics.get("rust_execution_count")
            ),
            "fallback_count": self._safe_count(raw_metrics.get("fallback_count")),
        }

        # 保留 provider、Rust 和批次实现的扩展字段，便于定位问题而不改变结果字段。
        for key, value in raw_metrics.items():
            if key not in event and key not in _COUNT_FIELDS:
                event[key] = value
        return event

    @staticmethod
    def service_metrics(event):
        """将事件转换为任务 service 记录中的可查询 metrics。"""
        if not isinstance(event, dict):
            return {}
        return {
            key: value
            for key, value in event.items()
            if key not in {"task_id", "stage", "started_at", "finished_at"}
        }

    @staticmethod
    def log(logger, event):
        """写入单行 JSON，避免并发阶段依赖全局计数差值。"""
        if not logger or not isinstance(event, dict):
            return
        try:
            logger.info("stage_metric %s", json.dumps(event, ensure_ascii=False, sort_keys=True))
        except Exception as exc:
            logger.warning("stage metric log failed error:%s", exc)
