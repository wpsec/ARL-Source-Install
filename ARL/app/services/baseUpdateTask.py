"""
任务更新处理基类
"""
import sys
import time

try:
    import resource
except ImportError:
    resource = None

from bson import ObjectId
from app import utils
from app.config import Config
from app.services.stage_metrics import StageMetric
from app.utils.log_safety import safe_error_text


# 用于更新任务状态
class BaseUpdateTask(object):
    UPDATE_RETRY_COUNT = 3
    UPDATE_RETRY_SLEEP_SEC = 0.6

    @staticmethod
    def _process_cpu_seconds():
        if resource is None:
            return None
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return max(0.0, float(usage.ru_utime or 0.0) + float(usage.ru_stime or 0.0))

    @staticmethod
    def _process_rss_mb():
        if resource is None:
            return None
        rss = max(0.0, float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss or 0.0))
        # ru_maxrss 的单位由平台决定，不能用数值大小猜测，否则 Linux 超过 1 GiB 会被低估。
        if sys.platform == "darwin":
            return rss / (1024 * 1024)
        return rss / 1024

    @staticmethod
    def _service_stage_status(metrics):
        if not isinstance(metrics, dict):
            return "success"

        raw_status = str(metrics.get("status", "") or "").strip().lower()
        status_map = {
            "ok": "success",
            "success": "success",
            "empty": "success",
            "partial": "partial",
            "degraded": "partial",
            "warning": "partial",
            "pending": "pending",
            "failed": "error",
            "error": "error",
            "timeout": "timeout",
            "skipped": "skipped",
        }
        if raw_status in status_map:
            return status_map[raw_status]
        try:
            timeout_count = int(metrics.get("timeout_count", 0) or 0)
        except (TypeError, ValueError):
            timeout_count = 0
        try:
            failed_count = int(metrics.get("failed_count", 0) or 0)
        except (TypeError, ValueError):
            failed_count = 0
        try:
            degraded_count = int(metrics.get("degraded_count", 0) or 0)
        except (TypeError, ValueError):
            degraded_count = 0
        if metrics.get("timeout_hit") or timeout_count > 0:
            return "partial"
        if failed_count > 0 or degraded_count > 0:
            return "partial"
        return "success"

    @staticmethod
    def _service_stage_budget(service_name):
        budget_map = {
            "search_engines": "SEARCH_PROVIDER_STAGE_TIMEOUT_SEC",
            "port_scan": "PORT_SCAN_STAGE_TIMEOUT_SEC",
            "dns_query_plugin": "DNS_QUERY_PLUGIN_STAGE_TIMEOUT_SEC",
            "nuclei_scan": "NUCLEI_STAGE_TIMEOUT_SEC",
            "nuclei_scan_retry": "NUCLEI_STAGE_TIMEOUT_SEC",
            "afrog_scan": "AFROG_STAGE_TIMEOUT_SEC",
        }
        config_name = budget_map.get(str(service_name or "").strip().lower())
        if not config_name:
            return None
        try:
            return max(0.0, float(getattr(Config, config_name)))
        except (AttributeError, TypeError, ValueError):
            return None

    def __init__(self, task_id: str):
        self.task_id = task_id
        self.logger = utils.get_logger()

    def _safe_update_task(self, query, update, action: str):
        """
        任务状态更新兜底：
        - Mongo 短暂抖动时重试，避免直接中断主扫描流程
        - 重试后仍失败则记录告警并跳过本次状态更新
        """
        last_error = None
        for attempt in range(1, self.UPDATE_RETRY_COUNT + 1):
            try:
                utils.conn_db('task').update_one(query, update)
                return True
            except Exception as e:
                last_error = e
                self.logger.warning(
                    "task status update failed task_id={} action={} attempt={}/{} error={}".format(
                        self.task_id, action, attempt, self.UPDATE_RETRY_COUNT, safe_error_text(e)
                    )
                )
                if attempt < self.UPDATE_RETRY_COUNT:
                    time.sleep(self.UPDATE_RETRY_SLEEP_SEC * attempt)

        self.logger.error(
            "task status update skipped task_id={} action={} error={}".format(
                self.task_id, action, safe_error_text(last_error)
            )
        )
        return False

    def update_services(self, service_name: str, elapsed: float, metrics: dict = None):
        self.update_task_field("status", service_name)
        elapsed_seconds = max(0.0, float(elapsed or 0.0))
        finished_at = time.time()
        service_status = self._service_stage_status(metrics)
        end_reason = "completed"
        if isinstance(metrics, dict):
            end_reason = str(
                metrics.get("end_reason") or metrics.get("reason") or end_reason
            ).strip()[:64] or end_reason
        stage_metric = StageMetric(
            task_id=self.task_id,
            stage=service_name,
            started_at=finished_at - elapsed_seconds,
            started_monotonic=time.monotonic() - elapsed_seconds,
        )
        stage_event = stage_metric.finish(
            finished_at=finished_at,
            finished_monotonic=time.monotonic(),
            status=service_status,
            end_reason=end_reason,
            metrics=metrics or {"output_count": 0},
        )
        StageMetric.log(self.logger, stage_event)
        self.append_service(
            service_name=service_name,
            elapsed=elapsed_seconds,
            metadata={
                "started_at": max(0.0, finished_at - elapsed_seconds),
                "finished_at": finished_at,
                "status": service_status,
                "end_reason": end_reason,
                "stage_kind": "execution",
                "budget_sec": self._service_stage_budget(service_name),
                "metrics": StageMetric.service_metrics(stage_event),
            },
            trigger_ai=True,
        )

    def append_service(
        self,
        service_name: str,
        elapsed: float,
        detail: str = "",
        trigger_ai: bool = False,
        metadata: dict = None,
    ):
        try:
            elapsed_seconds = max(0.0, float(elapsed or 0.0))
        except (TypeError, ValueError):
            elapsed_seconds = 0.0
        query = {"_id": ObjectId(self.task_id)}
        payload = {"name": service_name, "elapsed": round(elapsed_seconds, 3)}
        detail_text = str(detail or "").strip()
        if detail_text:
            payload["detail"] = detail_text
        self._apply_stage_metadata(payload, metadata)
        update = {"$push": {"service": payload}}
        self._safe_update_task(query, update, action="push_service")
        if trigger_ai:
            self.trigger_ai_denoise_stage(stage_name=service_name)

    @staticmethod
    def _apply_stage_metadata(payload: dict, metadata: dict = None):
        if not isinstance(metadata, dict):
            return

        for key in ("started_at", "finished_at", "budget_sec"):
            if metadata.get(key) is None:
                continue
            try:
                payload[key] = round(max(0.0, float(metadata[key])), 3)
            except (TypeError, ValueError):
                continue

        for key in ("input_count", "output_count"):
            if metadata.get(key) is None:
                continue
            try:
                payload[key] = max(0, int(metadata[key]))
            except (TypeError, ValueError):
                continue

        status = str(metadata.get("status", "") or "").strip().lower()
        if status in {"success", "partial", "error", "skipped", "timeout"}:
            payload["status"] = status

        end_reason = str(metadata.get("end_reason", "") or "").strip().lower()
        if end_reason:
            payload["end_reason"] = end_reason[:64]

        stage_kind = str(metadata.get("stage_kind", "") or "").strip().lower()
        if stage_kind in {"execution", "aggregate", "observation"}:
            payload["stage_kind"] = stage_kind

        metrics = metadata.get("metrics")
        if isinstance(metrics, dict):
            payload["metrics"] = metrics

    def start_stage(
        self,
        stage_name: str,
        input_count: int = None,
        budget_sec: float = None,
        stage_kind: str = "execution",
    ):
        started_at = time.time()
        started_monotonic = time.monotonic()
        cpu_started_sec = self._process_cpu_seconds()
        return {
            "name": str(stage_name or "").strip(),
            "started_at": started_at,
            "started_monotonic": started_monotonic,
            "cpu_started_sec": cpu_started_sec,
            "rss_started_mb": self._process_rss_mb(),
            "input_count": input_count,
            "budget_sec": budget_sec,
            "stage_kind": stage_kind,
            "stage_metric": StageMetric(
                task_id=self.task_id,
                stage=stage_name,
                started_at=started_at,
                started_monotonic=started_monotonic,
                cpu_started_sec=cpu_started_sec,
            ),
        }

    def finish_stage(
        self,
        context: dict,
        status: str = "success",
        end_reason: str = "completed",
        output_count: int = None,
        detail: str = "",
        metrics: dict = None,
        trigger_ai: bool = False,
    ):
        context = context if isinstance(context, dict) else {}
        started_monotonic = context.get("started_monotonic")
        try:
            elapsed = max(0.0, time.monotonic() - float(started_monotonic))
        except (TypeError, ValueError):
            elapsed = 0.0

        finished_at = time.time()
        cpu_started = context.get("cpu_started_sec")
        cpu_finished = self._process_cpu_seconds()
        resource_metrics = dict(metrics or {}) if isinstance(metrics, dict) else {}
        if cpu_started is not None and cpu_finished is not None:
            cpu_elapsed = max(0.0, cpu_finished - float(cpu_started))
        elif cpu_finished is not None:
            cpu_elapsed = 0.0
        else:
            cpu_elapsed = None
        if cpu_elapsed is not None:
            resource_metrics.setdefault("cpu_elapsed_sec", round(cpu_elapsed, 6))
            resource_metrics.setdefault(
                "non_cpu_elapsed_sec",
                round(max(0.0, elapsed - cpu_elapsed), 6),
            )
        rss_peak = self._process_rss_mb()
        if rss_peak is not None:
            resource_metrics.setdefault("rss_peak_mb", round(rss_peak, 3))
            resource_metrics.setdefault("rss_scope", "process_lifetime_max")
        stage_metric = context.get("stage_metric")
        if not isinstance(stage_metric, StageMetric):
            stage_metric = StageMetric(
                task_id=self.task_id,
                stage=context.get("name", "stage"),
                started_at=context.get("started_at", finished_at - elapsed),
                started_monotonic=context.get("started_monotonic", time.monotonic() - elapsed),
                cpu_started_sec=cpu_started,
            )
        stage_event = stage_metric.finish(
            status=status,
            end_reason=end_reason,
            input_count=context.get("input_count"),
            output_count=output_count,
            metrics=resource_metrics,
            finished_at=finished_at,
            finished_monotonic=time.monotonic(),
            cpu_finished_sec=cpu_finished,
        )
        resource_metrics.update(StageMetric.service_metrics(stage_event))
        StageMetric.log(self.logger, stage_event)
        metadata = {
            "started_at": context.get("started_at", finished_at - elapsed),
            "finished_at": finished_at,
            "status": status,
            "end_reason": end_reason,
            "input_count": context.get("input_count"),
            "output_count": output_count,
            "budget_sec": context.get("budget_sec"),
            "stage_kind": context.get("stage_kind", "execution"),
            "metrics": resource_metrics,
        }
        self.append_service(
            service_name=context.get("name", "stage"),
            elapsed=elapsed,
            detail=detail,
            metadata=metadata,
            trigger_ai=trigger_ai,
        )
        return metadata

    def update_task_field(self, field=None, value=None):
        query = {"_id": ObjectId(self.task_id)}
        update = {"$set": {field: value}}
        self._safe_update_task(query, update, action="set_{}".format(field))

    def trigger_ai_denoise_stage(self, stage_name: str, task_options=None):
        stage = str(stage_name or "").strip()
        if not stage:
            return

        try:
            # 延迟导入，避免 services 与 celerytask 初始化时出现循环依赖。
            from app import celerytask as celerytask_module
            enqueue_func = getattr(celerytask_module, "enqueue_ai_denoise_for_stage", None)
            if callable(enqueue_func):
                enqueue_func(task_id=self.task_id, stage_name=stage, task_options=task_options)
        except Exception as e:
            self.logger.warning(
                "trigger ai denoise stage failed task_id:{} stage:{} err:{}".format(
                    self.task_id, stage, e
                )
            )
