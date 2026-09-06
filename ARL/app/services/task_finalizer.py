"""统一任务收尾器（计划2/3；Review 20260905 §4 重要项1/2、一般项3）。

任务标记 DONE 前必须回答三个问题：
1. 动态候选是否已在本任务内消费？——对新子域队列做有界 drain（复用
   WihOrchestrator 幂等入口：账本 covered 跳过、队列 take 一次性）。
   WIH 队列是渐进式发现的核心契约：drain 后仍有残余时，终态决策为
   done_pending，编排器不得再写裸 done。
2. WIH 之外的晚到候选是否伪装成"干净完成"？——策略级消费显影：
   目录扫描(directory)、URL 探测(url_probe)、API 端点(api)、
   队列容量溢出主机(wih_overflow)按"下一轮周期"语义写
   `pending_backlog|<policy>|<value>` 账本并输出分策略 pending 指标；
   不阻断 done（契约只承诺队列清空），但必须显式可见，
   不得静默丢失（Review §4 重要项2 的第二口径）。
3. 收尾证据在哪里？——经 StageExecutor 输出独立 stage metric
   （drain 轮数、分策略 pending、external_network 边界计数），
   不新增 Mongo 任务字段、不改 API 面；同时给出编排器可消费的
   terminal_status 决策。

终态兼容映射：done / done_pending / done_degraded 同属 done 家族终态，
后端守卫以 TaskStatus.TERMINAL 判定，前端按 "done" 子串归为完成。

外部边界（Review §4 一般项）：Go WIH、TruffleHog、fileLeak 子进程在
共享响应缓存之外发起真实网络，各自以 `external_network_*` 上下文指标
记账；收尾器把非空计数透出到 stage metrics，不计入"全链路一次请求"门禁。

本模块只读任务上已存在的共享发现资产（web_site_fetch.discovery_context
或 task.discovery_context）；没有任何发现上下文的任务直接跳过
（skipped→done：渐进式发现契约不适用）。异常一律收敛为 degraded
决策（done_degraded），绝不抛出阻断主链路。
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from app import utils
from app.config import Config
from app.services.discovery_context import LedgerEntry, url_host

logger = utils.get_logger()

# 收尾器返回给编排器的终态决策值，与 app.modules.TaskStatus 保持一致。
TERMINAL_DONE = "done"
TERMINAL_DONE_PENDING = "done_pending"
TERMINAL_DONE_DEGRADED = "done_degraded"

# 唯一阻断策略：WIH 队列残余决定 done/done_pending。
_BLOCKING_POLICY = "wih"
# 显影策略（下一轮周期语义）：记 pending 账本与指标，但不阻断 done。
# wih_overflow：容量/开关导致从未入队的主机（自查轮补口径），同样非阻断。
_DISPLAY_POLICIES = ("directory", "url_probe", "api", "wih_overflow")

# 候选状态仍在"未消费"集合中的取值；covered/fetched/skipped/failed 为消费终态。
_OPEN_STATUSES = ("discovered", "queued")

# 目录扫描消费证据：file_leak 服务按目标写 covered 账本
# （键 = task|file_leak|target|profile|dict_signature，逐目标成功才落账）。
_DIRECTORY_LEDGER_STAGE = "file_leak"

# 作为"任务尚未干净完成"证据显影的上下文指标键。
_BACKLOG_METRIC_KEYS = (
    "waf_block_count",
    "pending_count",
    "over_limit_request_count",
    "failed_count",
    "new_host_queue_dropped_count",
    "candidate_evicted_count",
    "api_shadow_error_total",
    # A5：账本 fail-open 累计计数（阈值判定与降级见 _core/_ledger_degraded）。
    "ledger_unavailable_total",
    "ledger_dedup_degraded_total",
)

_EXTERNAL_METRIC_PREFIX = "external_network_"


def _resolve_holder(task: Any) -> Optional[Any]:
    """持有共享发现上下文的任务对象：域名/IP 任务在站点阶段实例上。"""

    web_task = getattr(task, "web_site_fetch", None)
    if web_task is not None and getattr(web_task, "discovery_context", None) is not None:
        return web_task
    if getattr(task, "discovery_context", None) is not None:
        return task
    return None


def _resolve_hunter(holder: Any):
    """WIH 重入口：生产实现是 run_web_info_hunter，兼容测试/旧入口命名。"""

    for name in ("run_web_info_hunter", "web_info_hunter"):
        entry = getattr(holder, name, None)
        if callable(entry):
            return entry
    return None


class TaskFinalizer(object):
    def __init__(self, task: Any):
        self.task = task
        # run() 后可被编排器消费的终态决策；未运行前默认按 done 兼容。
        self.decision: Optional[Dict[str, Any]] = None

    def terminal_status(self) -> str:
        decision = self.decision or {}
        return str(decision.get("terminal_status") or TERMINAL_DONE)

    # -- drain ------------------------------------------------------------

    def _drain_enabled(self) -> bool:
        return bool(getattr(Config, "TASK_FINALIZER_ENABLE", True))

    def _drain_rounds(self) -> int:
        try:
            return max(0, int(getattr(Config, "TASK_FINALIZER_DRAIN_ROUNDS", 1) or 0))
        except (TypeError, ValueError):
            return 1

    def _pending_write_max(self) -> int:
        try:
            return max(0, int(getattr(Config, "TASK_FINALIZER_PENDING_MAX", 200) or 0))
        except (TypeError, ValueError):
            return 200

    def drain_new_hosts(self, holder: Any) -> Dict[str, int]:
        """有界同任务 drain：队列仍有未取用主机时重入 WIH 编排入口。"""

        queue = getattr(holder, "new_host_queue", None)
        rounds_run = 0
        if queue is None or not getattr(queue, "enabled", False):
            return {"drain_rounds": 0, "hosts_before": 0, "hosts_after": 0}

        before = len(queue.untaken_hosts())
        hunter = _resolve_hunter(holder)
        if hunter is None:
            logger.warning(
                "task_id:{} finalizer drain skipped round:0 reason:no_wih_entry".format(
                    getattr(self.task, "task_id", "")
                )
            )
            return {"drain_rounds": 0, "hosts_before": before, "hosts_after": before}
        try:
            while rounds_run < self._drain_rounds() and queue.has_untaken():
                rounds_run += 1
                # 与主扫描完全同入口：take_for_wih 一次性取用、账本 covered 跳过、
                # WAF 类别熔断沿用任务级状态，不另起第二套 WIH 语义。
                hunter()
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

    # -- policy-level pending ----------------------------------------------

    def _directory_policy_active(self, holder: Any) -> bool:
        """目录扫描契约仅在 file_leak 选项启用时成立；未启用不产生 pending 显影。"""

        if not bool(getattr(Config, "FILE_LEAK_NEW_HOST_ENABLE", True)):
            return False
        options = getattr(holder, "options", None)
        if isinstance(options, dict):
            return bool(options.get("file_leak"))
        return False

    def _host_in_scope(self, holder: Any, host: str) -> bool:
        checker = getattr(holder, "_host_in_task_scope", None)
        if not callable(checker):
            return True
        try:
            return bool(checker(host))
        except Exception:
            return False

    def _url_in_scope(self, holder: Any, url: str) -> bool:
        checker = getattr(holder, "_url_in_task_scope", None)
        if not callable(checker):
            return True
        try:
            return bool(checker(url))
        except Exception:
            return False

    def _directory_consumed_hosts(self, context: Any, ledger: Any) -> set:
        """目录消费证据 = file_leak 账本 covered 目标的主机集合。"""

        hosts = set()
        if ledger is None or not hasattr(ledger, "list_by_prefix"):
            return hosts
        prefix = "{}|{}|".format(
            str(getattr(context, "task_id", "") or ""), _DIRECTORY_LEDGER_STAGE
        )
        try:
            rows = ledger.list_by_prefix(prefix, statuses=("covered",), limit=5000)
        except Exception as exc:
            logger.debug(
                "task_id:{} finalizer directory ledger read failed error_type:{}".format(
                    getattr(self.task, "task_id", ""), type(exc).__name__
                )
            )
            return hosts
        for key, _payload in rows or []:
            parts = str(key or "").split("|")
            if len(parts) < 5 or parts[1] != _DIRECTORY_LEDGER_STAGE:
                continue
            target = parts[2].strip().lower()
            if not target:
                continue
            hosts.add(url_host(target) or target.split("/")[0].split(":")[0])
        return hosts

    def collect_pending_by_policy(self, holder: Any) -> Dict[str, Any]:
        """按策略枚举收尾时仍未消费的候选（不含 WIH 队列，队列单独记账）。

        返回 {"pending": {policy: [候选]}, "other_open": n, "consumed_skipped": n}。
        任何上下文读取异常收敛为空集，不影响主链路。
        """

        context = getattr(holder, "discovery_context", None)
        result: Dict[str, Any] = {
            "pending": {policy: [] for policy in _DISPLAY_POLICIES},
            "other_open": 0,
            "consumed_skipped": 0,
        }
        if context is None:
            return result
        ledger = getattr(context, "ledger", None)
        directory_active = self._directory_policy_active(holder)
        consumed_hosts = (
            self._directory_consumed_hosts(context, ledger) if directory_active else set()
        )
        try:
            candidates = list(context.iter_candidates())
        except Exception as exc:
            logger.debug(
                "task_id:{} finalizer candidate scan failed error_type:{}".format(
                    getattr(self.task, "task_id", ""), type(exc).__name__
                )
            )
            return result
        for candidate in candidates:
            try:
                status = str(getattr(candidate, "status", "") or "").strip().lower()
                if status not in _OPEN_STATUSES:
                    continue
                candidate_type = str(getattr(candidate, "candidate_type", "") or "").strip().lower()
                value = str(getattr(candidate, "candidate", "") or "").strip().lower()
            except Exception:
                continue
            if not value:
                continue
            if candidate_type == "host":
                if not self._host_in_scope(holder, value):
                    continue
                if not directory_active:
                    # 目录契约未启用时，主机只有一条任务内消费路径（WIH 队列）；
                    # 因容量上限/队列关闭从未入队的主机显影为 wih_overflow，
                    # 非阻断（阻断口径仍严格以队列未取用为唯一事实源）。
                    queue = getattr(holder, "new_host_queue", None)
                    if queue is None:
                        result["pending"]["wih_overflow"].append(value)
                    elif not getattr(queue, "is_queued", lambda _h: True)(value):
                        result["pending"]["wih_overflow"].append(value)
                    continue
                if value in consumed_hosts:
                    result["consumed_skipped"] += 1
                    continue
                result["pending"]["directory"].append(value)
            elif candidate_type in ("url", "page"):
                if not self._url_in_scope(holder, value):
                    continue
                result["pending"]["url_probe"].append(value)
            elif candidate_type == "endpoint":
                if not self._url_in_scope(holder, value):
                    continue
                result["pending"]["api"].append(value)
            else:
                # js/path/site 等由后续计划（计划6 第3批 ApiCandidateRegistry 等）
                # 立消费协议；本轮只做观测计数，不冒充 pending。
                result["other_open"] += 1
        return result

    def persist_pending_candidates(self, holder: Any, pending_by_policy: Dict[str, Any]) -> Dict[str, int]:
        """显影策略的晚到候选按下一轮周期语义记 pending，禁止表现为无声丢失。"""

        context = getattr(holder, "discovery_context", None)
        ledger = getattr(context, "ledger", None) if context is not None else None
        written: Dict[str, int] = {}
        if ledger is None:
            return written
        cap = self._pending_write_max()
        task_id = str(getattr(self.task, "task_id", "") or "")
        for policy in _DISPLAY_POLICIES:
            values = list((pending_by_policy or {}).get("pending", {}).get(policy, []))
            count = 0
            for value in values[:cap]:
                try:
                    if getattr(ledger, "get", lambda _k: None)(
                        "pending_backlog|{}|{}".format(policy, value)
                    ) is not None:
                        continue
                    ledger.upsert(
                        LedgerEntry(
                            idempotency_key="pending_backlog|{}|{}".format(policy, value),
                            status="pending",
                            payload={
                                "value": value,
                                "policy": policy,
                                "task_id": task_id,
                                "reason": "finalizer_next_cycle",
                            },
                        )
                    )
                    count += 1
                except Exception as exc:
                    logger.debug(
                        "task_id:{} finalizer pending persist failed policy:{} error_type:{}".format(
                            task_id, policy, type(exc).__name__
                        )
                    )
            written[policy] = count
        return written

    # -- backlog evidence -------------------------------------------------

    def collect_backlog(self, holder: Any) -> Dict[str, Any]:
        context = getattr(holder, "discovery_context", None)
        queue = getattr(holder, "new_host_queue", None)
        backlog: Dict[str, Any] = {
            "queue_pending_hosts": 0,
            "candidate_discovered": 0,
            "candidate_queued": 0,
            "metrics": {},
            "external": {},
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
        backlog["external"] = {
            key: int(value or 0)
            for key, value in snapshot.items()
            if str(key).startswith(_EXTERNAL_METRIC_PREFIX) and int(value or 0) > 0
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
        cap = self._pending_write_max()
        for host in queue.untaken_hosts()[:cap]:
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

    # -- A5 账本 fail-open 阈值门禁 ------------------------------------------

    def _ledger_degraded(self, holder: Any) -> Dict[str, Any]:
        """账本降级判定：unavailable+dedup_degraded 累计达到阈值即数据一致性降级。

        计数首选 context.metrics（后端经 attach_metrics_sink 汇入）；context
        缺失或未绑汇时回退读 backend.failure_totals()。
        """
        try:
            threshold = int(getattr(Config, "LEDGER_DEGRADED_THRESHOLD", 10) or 0)
        except (TypeError, ValueError):
            threshold = 10
        threshold = max(0, threshold)
        unavailable = 0
        dedup = 0
        context = getattr(holder, "discovery_context", None)
        snapshot: Dict[str, Any] = {}
        try:
            snapshot = dict(context.metrics_snapshot() or {}) if context is not None else {}
        except Exception as exc:
            logger.debug(
                "task_id:{} ledger metrics read failed error_type:{}".format(
                    getattr(self.task, "task_id", ""), type(exc).__name__)
            )
        unavailable = int(snapshot.get("ledger_unavailable_total") or 0)
        dedup = int(snapshot.get("ledger_dedup_degraded_total") or 0)
        if unavailable == 0 and dedup == 0:
            backend = getattr(getattr(context, "ledger", None), "backend", None)
            totals_getter = getattr(backend, "failure_totals", None)
            if callable(totals_getter):
                try:
                    totals = totals_getter() or {}
                    unavailable = int(totals.get("ledger_unavailable_total") or 0)
                    dedup = int(totals.get("ledger_dedup_degraded_total") or 0)
                except Exception as exc:
                    logger.debug(
                        "task_id:{} ledger failure_totals failed error_type:{}".format(
                            getattr(self.task, "task_id", ""), type(exc).__name__)
                    )
        degraded = threshold > 0 and (unavailable + dedup) >= threshold
        return {
            "degraded": degraded,
            "unavailable": unavailable,
            "dedup_degraded": dedup,
            "threshold": threshold,
        }

    def _persist_ledger_degradation(self, holder: Any, health: Dict[str, Any]) -> int:
        """恢复范围证据：降级任务落 pending_backlog|ledger 账本（每任务一条，幂等）。"""
        context = getattr(holder, "discovery_context", None)
        ledger = getattr(context, "ledger", None)
        if ledger is None:
            return 0
        task_id = str(getattr(self.task, "task_id", "") or "")
        key = "pending_backlog|ledger|{}".format(task_id)
        try:
            if getattr(ledger, "get", lambda _k: None)(key) is not None:
                return 0
            ledger.upsert(
                LedgerEntry(
                    idempotency_key=key,
                    status="pending",
                    payload={
                        "task_id": task_id,
                        "reason": "ledger_degraded",
                        "ledger_unavailable_total": health["unavailable"],
                        "ledger_dedup_degraded_total": health["dedup_degraded"],
                        "ledger_degraded_threshold": health["threshold"],
                    },
                )
            )
            return 1
        except Exception as exc:
            logger.debug(
                "task_id:{} ledger degradation persist failed error_type:{}".format(
                    task_id, type(exc).__name__)
            )
            return 0

    # -- entry ------------------------------------------------------------

    def _core(self) -> Dict[str, Any]:
        started_at = time.time()
        holder = _resolve_holder(self.task)
        if holder is None or not self._drain_enabled():
            end_reason = "no_discovery_context" if holder is None else "disabled_by_config"
            self.decision = {
                "terminal_status": TERMINAL_DONE,
                "verdict": "skipped",
                "blocking_residual": 0,
                "residual_total": 0,
                "pending_by_policy": {},
                "reason": end_reason,
            }
            return {
                "output_count": 0,
                "metrics": {
                    "status": "skipped",
                    "end_reason": end_reason,
                    "terminal_status": TERMINAL_DONE,
                },
            }

        drain = self.drain_new_hosts(holder)
        backlog = self.collect_backlog(holder)
        pending_by_policy = self.collect_pending_by_policy(holder)
        pending_written = self.persist_pending_hosts(holder)
        pending_written_other = self.persist_pending_candidates(holder, pending_by_policy)

        # 队列残余以未取用主机为唯一口径：drain hosts_after 与 queue_pending
        # 是同一事实的两次读取，取大者，不再相加造成重复计数。
        pending_wih = max(drain["hosts_after"], backlog["queue_pending_hosts"])
        pending_directory = len(pending_by_policy["pending"]["directory"])
        pending_url_probe = len(pending_by_policy["pending"]["url_probe"])
        pending_api = len(pending_by_policy["pending"]["api"])
        pending_wih_overflow = len(pending_by_policy["pending"]["wih_overflow"])

        # 阻断口径：只有 WIH 队列残余否决裸 done（渐进式队列核心契约）。
        blocking_residual = pending_wih
        # 证据口径：全策略未消费候选合计。同一主机可在多个策略口径下重复
        # 显影（如 wih 与 directory），分策略计数才是精确事实源；
        # residual_total 只做"是否存在积压"的证据总量。
        residual_total = (
            pending_wih
            + pending_directory
            + pending_url_probe
            + pending_api
            + pending_wih_overflow
        )

        # A5：账本 fail-open 超阈值 = 数据一致性降级。阻断口径不变
        # （WIH 残余仍优先决定 done_pending），降级只把"裸 done"升为
        # done_degraded，并把恢复证据落 pending_backlog|ledger 账本。
        ledger_health = self._ledger_degraded(holder)
        ledger_degraded_written = 0
        if ledger_health["degraded"]:
            ledger_degraded_written = self._persist_ledger_degradation(holder, ledger_health)
            logger.warning(
                "task_id:{} ledger fail-open degraded unavailable:{} dedup_degraded:{} threshold:{}".format(
                    getattr(self.task, "task_id", ""),
                    ledger_health["unavailable"],
                    ledger_health["dedup_degraded"],
                    ledger_health["threshold"],
                )
            )

        terminal_status = TERMINAL_DONE_PENDING if blocking_residual > 0 else TERMINAL_DONE
        if ledger_health["degraded"] and blocking_residual == 0:
            terminal_status = TERMINAL_DONE_DEGRADED
        self.decision = {
            "terminal_status": terminal_status,
            "verdict": "pending" if residual_total > 0 else ("degraded" if ledger_health["degraded"] else "clean"),
            "blocking_residual": blocking_residual,
            "residual_total": residual_total,
            "ledger_degraded": bool(ledger_health["degraded"]),
            "pending_by_policy": {
                "wih": pending_wih,
                "directory": pending_directory,
                "url_probe": pending_url_probe,
                "api": pending_api,
                "wih_overflow": pending_wih_overflow,
            },
            "other_open_candidates": pending_by_policy["other_open"],
            "reason": "queue_residual" if blocking_residual > 0 else (
                "ledger_degraded" if ledger_health["degraded"] else ""),
        }

        metrics = {
            # StageExecutor 的 result provider 只认嵌套 metrics 键作为状态来源。
            # A5：账本一致性降级优先于 partial——收尾阶段本身标 degraded。
            "status": (
                "degraded"
                if ledger_health["degraded"]
                else ("partial" if residual_total > 0 else "ok")
            ),
            "terminal_status": terminal_status,
            "drain_rounds": drain["drain_rounds"],
            "drain_hosts_before": drain["hosts_before"],
            "drain_hosts_after": drain["hosts_after"],
            "backlog_queue_pending": backlog["queue_pending_hosts"],
            "backlog_candidate_discovered": backlog["candidate_discovered"],
            "backlog_candidate_queued": backlog["candidate_queued"],
            "pending_wih": pending_wih,
            "pending_directory": pending_directory,
            "pending_url_probe": pending_url_probe,
            "pending_api": pending_api,
            "pending_wih_overflow": pending_wih_overflow,
            "pending_recorded": (
                pending_written
                + sum(pending_written_other.values())
                + ledger_degraded_written
            ),
            "pending_recorded_wih": pending_written,
            # 计数单一事实源为 ctx_ledger_*（context 透传），此处只落判定结果。
            "ledger_degraded": 1 if ledger_health["degraded"] else 0,
            "ledger_degraded_threshold": ledger_health["threshold"],
            "open_other_candidates": pending_by_policy["other_open"],
            "residual_total": residual_total,
            "blocking_residual": blocking_residual,
            "elapsed_sec": round(time.time() - started_at, 6),
        }
        metrics.update({"ctx_" + key: value for key, value in backlog["metrics"].items()})
        # 外部网络边界计数透出：Go WIH/TruffleHog/fileLeak 子进程请求发生在
        # 统一响应缓存之外，不计入"全链路一次请求"门禁。
        metrics.update(backlog["external"])
        logger.info(
            "task_id:{} finalization evidence:{}".format(
                getattr(self.task, "task_id", ""), metrics
            )
        )
        return {"output_count": drain["drain_rounds"], "metrics": metrics}

    def run(self) -> Dict[str, Any]:
        """收尾入口：优先经任务 StageExecutor 输出独立指标，异常只降级不抛出。

        降级即终态证据缺失：决策为 done_degraded，编排器不得写裸 done。
        """

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
            self.decision = {
                "terminal_status": TERMINAL_DONE_DEGRADED,
                "verdict": "degraded",
                "blocking_residual": 0,
                "residual_total": 0,
                "pending_by_policy": {},
                "reason": type(exc).__name__,
            }
            return {
                "status": "degraded",
                "error_type": type(exc).__name__,
                "terminal_status": TERMINAL_DONE_DEGRADED,
            }


__all__ = [
    "TaskFinalizer",
    "TERMINAL_DONE",
    "TERMINAL_DONE_PENDING",
    "TERMINAL_DONE_DEGRADED",
]
