"""单扫描阶段服务和显式回退边界。

阶段执行器负责记录失败；本模块只在调用方明确提供 fallback 时继续后续阶段，
并把异常原因写入任务已有的阶段 detail，避免“捕获后当作空结果”的静默降级。
"""

from app.services.task_pipeline import TaskPipeline
from app.utils.log_safety import safe_error_text


_NO_FALLBACK = object()


class SingleScanStageService(object):
    """执行一个阶段，并提供可选、显式的当前阶段回退。"""

    def __init__(self, task, runner=None, logger=None):
        self.task = task
        self.runner = runner
        self.logger = logger

    def _execute(self, name, func, fallback=_NO_FALLBACK, fallback_note=""):
        runner = self.runner
        if not callable(runner):
            runner = getattr(self.task, "run_func", None)
        if not callable(runner):
            runner = TaskPipeline(self.task).run_stage

        try:
            return runner(name, func)
        except Exception as exc:
            if fallback is _NO_FALLBACK:
                raise

            stage_name = str(name or "stage").strip() or "stage"
            error_text = safe_error_text(exc, max_length=220) or "unknown_error"
            note_text = safe_error_text(fallback_note, max_length=220)
            detail = "degraded=true | stage={} | error={}".format(stage_name, error_text)
            if note_text:
                detail += " | fallback={}".format(note_text)

            marker = getattr(self.task, "_mark_service_detail_override", None)
            if callable(marker):
                marker(stage_name, detail[:1200])
            if self.logger:
                self.logger.warning(
                    "task_id:{} scan stage degraded stage:{} error:{} fallback:{}".format(
                        getattr(self.task, "task_id", ""),
                        stage_name,
                        error_text,
                        note_text or "explicit",
                    )
                )
            if callable(fallback):
                return fallback()
            return fallback


class WebSiteSingleStageService(SingleScanStageService):
    """WebSiteFetch 的单阶段入口，任务类方法仍是兼容实现。"""

    def run(self, stage_name, func, fallback=_NO_FALLBACK, fallback_note=""):
        return self._execute(stage_name, func, fallback, fallback_note)


class IPSingleStageService(SingleScanStageService):
    """IPTask 的单阶段入口，使用 TaskPipeline 保持指标和预算语义。"""

    def __init__(self, task, logger=None):
        super(IPSingleStageService, self).__init__(
            task,
            runner=TaskPipeline(task).run_stage,
            logger=logger,
        )

    def run(self, stage_name, func, enabled=True, fallback=_NO_FALLBACK, fallback_note=""):
        if not enabled:
            return None
        return self._execute(stage_name, func, fallback, fallback_note)
