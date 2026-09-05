"""统一任务收尾器（计划2/3 前置收口：报告 §4 重要项）。

任务标记 DONE 前必须回答三个问题，此前散落在各编排器、无统一保证：
1. 动态候选是否已在本任务内消费？——对新子域队列做有界 drain（复用
   WihOrchestrator 幂等入口：账本 covered 跳过、队列 take 一次性）。
2. 仍有积压时是否伪装成"干净完成"？——残余主机显式写入账本
   `pending_backlog|wih|<host>`(status=pending)，供监控/下轮识别。
3. 收尾证据在哪里？——经 StageExecutor 输出独立 stage metric
   （drain 轮数、各类积压计数），不新增 Mongo 任务字段、不改 API 面。

本模块只读任务上已存在的共享发现资产（web_site_fetch.discovery_context
或 task.discovery_context）；没有任何发现上下文的任务直接跳过，
异常一律收敛为 partial 证据，绝不阻断 DONE 主链路。
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from app import utils
from app.config import Config
from app.services.discovery_context import LedgerEntry

logger = utils.get_logger()

# 收尾时作为"任务尚未干净完成"证据显影的上下文指标键。
_BACKLOG_METRIC_KEYS = (
    "waf_block_count",
    "pending_count",
    "over_limit_request_count",
    "failed_count",
    "new_host_queue_dropped_count",
    "candidate_evicted_count",
    "api_shadow_error_total",
)


def _resolve_holder(task: Any) -> Optional[Any]:
    """持有共享发现上下文的任务对象：域名/IP 任务在站点阶段实例上。"""

    web_task = getattr(task, "web_site_fetch", None)
    if web_task is not None and getattr(web_task, "discovery_context", None) is not None:
        return web_task
    if getattr(task, "discovery_context", None) is not None:
        return task
    return None


class TaskFinalizer(object):
    def __init__(self, task: Any):
        self.task = task

    # -- drain ------------------------------------------------------------

    def _drain_enabled(self) -> bool:
        return bool(getattr(Config, "TASK_FINALIZER_ENABLE", True))

    def _drain_rounds(self) -> int:
        try:
            return max(0, int(getattr(Config, "TASK_FINALIZER_DRAIN_ROUNDS", 1) or 0))
        except (TypeError, ValueError):
            return 1

    def drain_new_hosts(self, holder: Any) -> Dict[str, int]:
        """有界同任务 drain：队列仍有未取用主机时重入 WIH 编排入口。"""

        queue = getattr(holder, "new_host_queue", None)
        rounds_run = 0
        if queue is None or not getattr(queue, "enabled", False):
            return {"drain_rounds": 0, "hosts_before": 0, "hosts_after": 0}

        before = len(queue.untaken_hosts())
        try:
            while rounds_run < self._drain_rounds() and queue.has_untaken():
                rounds_run += 1
                # 与主扫描完全同入口：take_for_wih 一次性取用、账本 covered 跳过、
                # WAF 类别熔断沿用任务级状态，不另起第二套 WIH 语义。
                holder.web_info_hunter()
        except Exception as exc:
            logger.warning(
                "task_id:{} finalizer drain failed round:{} error_type:{}".format(
                    getattr(self.task, "task_id", ""), rounds_run, type(exc).__name__
                )
            )
        after = len(queue.untaken_hosts())
        return {
            "drain_rounds": rounds_run,
            "hosts_before": before,
            "hosts_after": after,
        }

    # -- backlog evidence -------------------------------------------------

    def collect_backlog(self, holder: Any) -> Dict[str, Any]:
        context = getattr(holder, "discovery_context", None)
        queue = getattr(holder, "new_host_queue", None)
        backlog: Dict[str, Any] = {
            "queue_pending_hosts": 0,
            "candidate_discovered": 0,
            "candidate_queued": 0,
            "metrics": {},
        }
        if queue is not None:
            # 残余口径 = 未被 WIH 取用的主机；pending_hosts 是含已取用的观测镜像。
            backlog["queue_pending_hosts"] = len(queue.untaken_hosts())
        if context is None:
            return backlog
        try:
            backlog["candidate_discovered"] = sum(
                1 for _ in context.iter_candidates(status="discovered")
            )
            backlog["candidate_queued"] = sum(
                1 for _ in context.iter_candidates(status="queued")
            )
        except Exception as exc:
            logger.debug(
                "task_id:{} finalizer candidate count failed error_type:{}".format(
                    getattr(self.task, "task_id", ""), type(exc).__name__
                )
            )
        snapshot = {}
        try:
            snapshot = context.metrics_snapshot()
        except Exception:
            snapshot = {}
        backlog["metrics"] = {
            key: int(snapshot.get(key, 0) or 0) for key in _BACKLOG_METRIC_KEYS
        }
        return backlog

    def persist_pending_hosts(self, holder: Any) -> int:
        """队列残余主机显式记账为 pending，禁止表现为无声丢失。"""

        queue = getattr(holder, "new_host_queue", None)
        context = getattr(holder, "discovery_context", None)
        ledger = getattr(context, "ledger", None)
        if queue is None or ledger is None:
            return 0
        written = 0
        task_id = str(getattr(self.task, "task_id", "") or "")
        for host in queue.untaken_hosts():
            try:
                if getattr(ledger, "get", lambda _k: None)("pending_backlog|wih|{}".format(host)) is not None:
                    # 已记账（含历史 pending/covered）不重复覆盖状态。
                    continue
                ledger.upsert(
                    LedgerEntry(
                        idempotency_key="pending_backlog|wih|{}".format(host),
                        status="pending",
                        payload={"host": host, "task_id": task_id, "reason": "finalizer_backlog"},
                    )
                )
                written += 1
            except Exception as exc:
                logger.debug(
                    "task_id:{} finalizer pending persist failed host:{} error_type:{}".format(
                        task_id, str(host)[:120], type(exc).__name__
                    )
                )
        return written

    # -- entry ------------------------------------------------------------

    def _core(self) -> Dict[str, Any]:
        started_at = time.time()
        holder = _resolve_holder(self.task)
        if holder is None or not self._drain_enabled():
            return {
                "output_count": 0,
                "metrics": {
                    "status": "skipped",
                    "end_reason": "no_discovery_context" if holder is None else "disabled_by_config",
                },
            }

        drain = self.drain_new_hosts(holder)
        backlog = self.collect_backlog(holder)
        pending_written = self.persist_pending_hosts(holder)

        residual = (
            drain["hosts_after"]
            + backlog["queue_pending_hosts"]
            + backlog["candidate_discovered"]
            + backlog["candidate_queued"]
        )
        metrics = {
            # StageExecutor 的 result provider 只认嵌套 metrics 键作为状态来源。
            "status": "partial" if residual > 0 else "ok",
            "drain_rounds": drain["drain_rounds"],
            "drain_hosts_before": drain["hosts_before"],
            "drain_hosts_after": drain["hosts_after"],
            "backlog_queue_pending": backlog["queue_pending_hosts"],
            "backlog_candidate_discovered": backlog["candidate_discovered"],
            "backlog_candidate_queued": backlog["candidate_queued"],
            "pending_recorded": pending_written,
            "residual_total": residual,
            "elapsed_sec": round(time.time() - started_at, 6),
        }
        metrics.update({"ctx_" + key: value for key, value in backlog["metrics"].items()})
        logger.info(
            "task_id:{} finalization evidence:{}".format(
                getattr(self.task, "task_id", ""), metrics
            )
        )
        return {"output_count": drain["drain_rounds"], "metrics": metrics}

    def run(self) -> Dict[str, Any]:
        """收尾入口：优先经任务 StageExecutor 输出独立指标，异常只降级不抛出。"""

        runner = getattr(self.task, "_run_internal_stage", None)
        try:
            if callable(runner):
                return runner("task_finalization", self._core) or {}
            return self._core()
        except Exception as exc:
            logger.warning(
                "task_id:{} finalizer degraded error_type:{}".format(
                    getattr(self.task, "task_id", ""), type(exc).__name__
                )
            )
            return {"status": "degraded", "error_type": type(exc).__name__}


__all__ = ["TaskFinalizer"]
