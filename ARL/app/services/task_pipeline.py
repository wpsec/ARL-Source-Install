"""任务阶段流水线。

任务类型保留各自的扫描业务方法；本模块只统一阶段生命周期，避免每个任务
重复实现状态更新、计时和阶段指标回写。
"""


class TaskPipeline(object):
    def __init__(self, task):
        self.task = task

    def run_stage(self, name, func, enabled=True, detail=""):
        if not enabled:
            return None

        executor = getattr(self.task, "_get_stage_executor", None)
        if not callable(executor):
            raise RuntimeError("task does not provide stage executor")

        return executor().execute(
            name,
            func,
            detail=detail,
            detail_provider=getattr(self.task, "_consume_service_detail_override", None),
            trigger_ai=True,
            stage_kind="execution",
            log_kind="stage",
        )

    def run_many(self, stages):
        results = {}
        for stage in stages or []:
            if not isinstance(stage, dict):
                raise ValueError("stage definition must be an object")

            name = str(stage.get("name") or "").strip()
            func = stage.get("func")
            if not name or not callable(func):
                raise ValueError("stage definition requires name and callable func")

            results[name] = self.run_stage(
                name=name,
                func=func,
                enabled=stage.get("enabled", True),
                detail=stage.get("detail", ""),
            )
        return results
