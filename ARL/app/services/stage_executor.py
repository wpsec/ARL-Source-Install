"""
任务阶段执行器。

阶段执行器只处理生命周期和观测数据；具体扫描逻辑仍由调用方提供，避免把网络、
数据库或外部程序策略混入通用执行框架。
"""

import time

from app.utils.provider_http import stage_execution_context
from app.utils.log_safety import safe_error_text


class StageExecutor(object):
    def __init__(
        self,
        task_id,
        base_update_task,
        logger,
        input_count_provider=None,
        budget_provider=None,
        result_metadata_provider=None,
        failure_reason_provider=None,
        detail_provider=None,
        description_provider=None,
    ):
        self.task_id = task_id
        self.base_update_task = base_update_task
        self.logger = logger
        self.input_count_provider = input_count_provider
        self.budget_provider = budget_provider
        self.result_metadata_provider = result_metadata_provider
        self.failure_reason_provider = failure_reason_provider
        self.detail_provider = detail_provider
        self.description_provider = description_provider

    def _input_count(self, name):
        if not callable(self.input_count_provider):
            return None
        return self.input_count_provider(name)

    def _budget(self, name):
        if not callable(self.budget_provider):
            return None
        return self.budget_provider(name)

    def _result_metadata(self, result):
        if not callable(self.result_metadata_provider):
            return None, {}
        output_count, metrics = self.result_metadata_provider(result)
        return output_count, metrics if isinstance(metrics, dict) else {}

    def _failure_reason(self, exc):
        if callable(self.failure_reason_provider):
            return self.failure_reason_provider(exc)
        return "exception"

    def _detail(self, name, detail, detail_provider=None):
        provider = detail_provider if callable(detail_provider) else self.detail_provider
        if callable(provider):
            return provider(name, detail)
        return str(detail or "").strip()

    def _description(self):
        if callable(self.description_provider):
            return self.description_provider()
        return ""

    @staticmethod
    def _result_status(metrics):
        """把批次返回的状态映射为任务阶段状态，避免失败被记录成成功。"""
        if not isinstance(metrics, dict):
            return "success"

        def count(name):
            try:
                return max(int(metrics.get(name, 0) or 0), 0)
            except (TypeError, ValueError):
                return 0

        raw_status = str(metrics.get("status", "") or "").strip().lower()
        status_map = {
            "ok": "success",
            "success": "success",
            "empty": "success",
            "running": "success",
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

        if metrics.get("timeout_hit") or count("timeout_count") > 0:
            return "partial"
        if (
            count("failed_count") > 0
            or count("degraded_count") > 0
            or count("pending_count") > 0
        ):
            return "partial"
        return "success"

    @staticmethod
    def _result_end_reason(metrics, status):
        if not isinstance(metrics, dict):
            return "completed"
        reason = str(metrics.get("end_reason", "") or metrics.get("reason", "")).strip()
        if reason:
            return reason[:64]
        if status == "timeout":
            return "budget_exhausted"
        if status in {"partial", "pending"}:
            return "partial_result"
        if status == "error":
            return "stage_failed"
        if status == "skipped":
            return "stage_skipped"
        return "completed"

    def execute(
        self,
        name,
        func,
        detail="",
        detail_provider=None,
        input_count=None,
        budget_sec=None,
        trigger_ai=False,
        stage_kind="execution",
        log_kind="stage",
    ):
        stage_name = str(name or "").strip()
        stage_detail = str(detail or "").strip()
        if log_kind == "substage":
            self.logger.info(
                "start substage {} task_id:{} detail:{}".format(
                    stage_name,
                    self.task_id,
                    stage_detail or "-",
                )
            )
        elif log_kind == "internal":
            self.logger.info(
                "start internal stage {} task_id:{} detail:{}".format(
                    stage_name,
                    self.task_id,
                    stage_detail or "-",
                )
            )
        else:
            description = self._description()
            self.logger.info(
                "start run {}, {}".format(stage_name, description)
                if description
                else "start run {}".format(stage_name)
            )

        if self.base_update_task:
            self.base_update_task.update_task_field("status", stage_name)

        if input_count is None:
            input_count = self._input_count(stage_name)
        if budget_sec is None:
            budget_sec = self._budget(stage_name)

        stage_context = None
        if self.base_update_task and callable(
            getattr(self.base_update_task, "start_stage", None)
        ):
            stage_context = self.base_update_task.start_stage(
                stage_name,
                input_count=input_count,
                budget_sec=budget_sec,
                stage_kind=stage_kind,
            )

        started_at = time.time()
        try:
            with stage_execution_context(stage_name, budget_sec):
                result = func()
            elapsed = max(0.0, time.time() - started_at)
            service_detail = self._detail(stage_name, stage_detail, detail_provider)
            output_count, metrics = self._result_metadata(result)
            metrics = dict(metrics or {})
            if budget_sec and elapsed > float(budget_sec):
                # 超预算即事实降级：业务返回 success 也必须覆盖为 partial，
                # 只有已更差的 error 保持不变；end_reason 同理仅在 completed/缺省时改写。
                current_status = str(metrics.get("status") or "").strip().lower()
                if current_status not in {"error", "partial", "pending"}:
                    metrics["status"] = "partial"
                current_reason = str(metrics.get("end_reason") or "").strip().lower()
                if current_reason in ("", "completed"):
                    metrics["end_reason"] = "budget_exceeded"
                metrics["budget_exceeded"] = True
                metrics["budget_sec"] = float(budget_sec)
                metrics["elapsed_sec"] = round(elapsed, 6)
                self.logger.warning(
                    "stage budget exceeded task_id:{} stage:{} elapsed:{:.3f}s budget:{:.3f}s".format(
                        self.task_id,
                        stage_name,
                        elapsed,
                        float(budget_sec),
                    )
                )
        except Exception as exc:
            elapsed = max(0.0, time.time() - started_at)
            reason = self._failure_reason(exc)
            service_detail = self._detail(stage_name, stage_detail, detail_provider)
            failure_metrics = {}
            if budget_sec and elapsed > float(budget_sec):
                # 失败路径同样必须留超预算证据：deadline 收敛正是让 provider
                # 在预算窗口内抛超时类异常；不记录则"拖满预算倒下"与
                # "秒级普通报错"在观测数据里无法区分。
                failure_metrics = {
                    "budget_exceeded": True,
                    "budget_sec": float(budget_sec),
                    "elapsed_sec": round(elapsed, 6),
                }
            if self.base_update_task and stage_context is not None:
                self.base_update_task.finish_stage(
                    stage_context,
                    status="timeout" if reason == "timeout" else "error",
                    end_reason=reason,
                    detail=service_detail,
                    metrics=failure_metrics or None,
                    trigger_ai=trigger_ai,
                )
            elif self.base_update_task:
                self.base_update_task.append_service(
                    stage_name,
                    elapsed,
                    detail=service_detail,
                    trigger_ai=trigger_ai,
                )

            log_prefix = "internal stage" if log_kind == "internal" else "stage"
            if log_kind == "substage":
                log_prefix = "substage"
            self.logger.warning(
                "{} failed task_id:{} stage:{} elapsed:{:.3f}s reason:{} error:{}{}".format(
                    log_prefix,
                    self.task_id,
                    stage_name,
                    elapsed,
                    reason,
                    safe_error_text(exc),
                    " budget_exceeded:True" if failure_metrics else "",
                )
            )
            raise

        if self.base_update_task and stage_context is not None:
            result_status = self._result_status(metrics)
            self.base_update_task.finish_stage(
                stage_context,
                status=result_status,
                end_reason=self._result_end_reason(metrics, result_status),
                output_count=output_count,
                detail=service_detail,
                metrics=metrics,
                trigger_ai=trigger_ai,
            )
        elif self.base_update_task:
            self.base_update_task.append_service(
                stage_name,
                elapsed,
                detail=service_detail,
                trigger_ai=trigger_ai,
            )

        if log_kind == "substage":
            self.logger.info(
                "end substage {} ({:.2f}s) task_id:{}".format(
                    stage_name,
                    elapsed,
                    self.task_id,
                )
            )
        elif log_kind == "internal":
            self.logger.info(
                "end internal stage {} ({:.2f}s) task_id:{}".format(
                    stage_name,
                    elapsed,
                    self.task_id,
                )
            )
        else:
            description = self._description()
            self.logger.info(
                "end run {} ({:.2f}s), {}".format(stage_name, elapsed, description)
                if description
                else "end run {} ({:.2f}s)".format(stage_name, elapsed)
            )
        return result
