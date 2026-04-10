"""
任务更新处理基类
"""
import time

from bson import ObjectId
from app import utils


# 用于更新任务状态
class BaseUpdateTask(object):
    UPDATE_RETRY_COUNT = 3
    UPDATE_RETRY_SLEEP_SEC = 0.6

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
                        self.task_id, action, attempt, self.UPDATE_RETRY_COUNT, e
                    )
                )
                if attempt < self.UPDATE_RETRY_COUNT:
                    time.sleep(self.UPDATE_RETRY_SLEEP_SEC * attempt)

        self.logger.error(
            "task status update skipped task_id={} action={} error={}".format(
                self.task_id, action, last_error
            )
        )
        return False

    def update_services(self, service_name: str, elapsed: float):
        self.update_task_field("status", service_name)
        self.append_service(service_name=service_name, elapsed=elapsed, trigger_ai=True)

    def append_service(self, service_name: str, elapsed: float, detail: str = "", trigger_ai: bool = False):
        elapsed = "{:.2f}".format(elapsed)
        query = {"_id": ObjectId(self.task_id)}
        payload = {"name": service_name, "elapsed": float(elapsed)}
        detail_text = str(detail or "").strip()
        if detail_text:
            payload["detail"] = detail_text
        update = {"$push": {"service": payload}}
        self._safe_update_task(query, update, action="push_service")
        if trigger_ai:
            self.trigger_ai_denoise_stage(stage_name=service_name)

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
