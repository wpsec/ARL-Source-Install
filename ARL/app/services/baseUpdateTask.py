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
        elapsed = "{:.2f}".format(elapsed)
        self.update_task_field("status", service_name)
        query = {"_id": ObjectId(self.task_id)}
        update = {"$push": {"service": {"name": service_name, "elapsed": float(elapsed)}}}
        self._safe_update_task(query, update, action="push_service")

    def update_task_field(self, field=None, value=None):
        query = {"_id": ObjectId(self.task_id)}
        update = {"$set": {field: value}}
        self._safe_update_task(query, update, action="set_{}".format(field))
