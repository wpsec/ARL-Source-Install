"""DiscoveryLedger 的 Mongo 持久化后端。

设计边界（docs/00 统一发现上下文）：
- 账本只保存"可恢复状态与结果元数据"，不是业务结果事实源；
  任何后端异常一律 fail-open（返回可继续执行的安全默认），
  最坏情况退化为重复执行，绝不因账本故障阻断扫描。
- claim 使用单次原子 find_and_update + owner token + 租约过期：
  仅 pending/终态或租期已过的 claiming 可被接管，并发双抢只有一个成功；
  covered 永不可抢占。
"""

import os
import re
import time
import uuid

from app import utils

from .discovery_context import LedgerEntry


logger = utils.get_logger()

LEDGER_COLLECTION = "task_stage_ledger"

# 单阶段最坏时长量级；过期后视为 worker 已丢失，允许被接管。
LEDGER_CLAIM_TTL_SEC = 6 * 60 * 60

# 可被 claim 接管的历史状态（非进行中、非已完成）。
_CLAIMABLE_STATUSES = ("pending", "failed")

try:
    from pymongo import ReturnDocument as _ReturnDocument

    _RETURN_AFTER = _ReturnDocument.AFTER
except Exception:  # pragma: no cover - 依赖缺失时退化为协议字符串
    _ReturnDocument = None
    _RETURN_AFTER = "after"


class MongoLedgerBackend(object):
    """按 task_id 隔离的带租约账本后端。

    文档状态机: pending -> claiming(租约内) -> done类(covered/failed/...)；
    过期 claiming 视为可重入，由新 owner 原子接管。
    """

    def __init__(self, task_id, utils_module=None, metrics_sink=None):
        self.task_id = str(task_id or "").strip()
        self.utils = utils_module or utils
        # 每个实例（进程/任务）唯一，用于 CAS 归属确认与抢占仲裁。
        self.owner = "{}-{}".format(os.getpid(), uuid.uuid4().hex[:12])
        # A5（系统框架 Review 轮 2）：fail-open 必须可观测。metrics_sink 为
        # callable(name, amount)，由宿主在 DiscoveryContext 构造后绑定
        # （attach_metrics_sink）；观测失败绝不反向影响账本主路径。
        self._metrics_sink = metrics_sink
        self._unavailable_total = 0
        self._dedup_degraded_total = 0

    def attach_metrics_sink(self, sink):
        """晚绑定观测汇（DiscoveryContext 构造完成后注入 record_metric）。"""
        if callable(sink):
            self._metrics_sink = sink

    def _record_failure(self, name, dedup_degraded=False):
        # unavailable=后端操作异常；dedup_degraded=在 covered 状态不可确认时
        # 仍放行执行（宁可重扫不漏扫的代价面），是重复请求/重复扫描的直接证据。
        self._unavailable_total += 1
        if dedup_degraded:
            self._dedup_degraded_total += 1
        sink = self._metrics_sink
        if sink is None:
            return
        try:
            sink(name, 1)
            sink("ledger_unavailable_total", 1)
            if dedup_degraded:
                sink("ledger_dedup_degraded_total", 1)
        except Exception:
            # 观测汇故障不得成为扫描的新失败源（降级为本地计数已足够定阈）。
            pass

    def failure_totals(self):
        return {
            "ledger_unavailable_total": self._unavailable_total,
            "ledger_dedup_degraded_total": self._dedup_degraded_total,
        }

    def _db(self):
        return self.utils.conn_db(LEDGER_COLLECTION)

    def get(self, idempotency_key):
        key = str(idempotency_key or "")
        if not key:
            return None
        try:
            doc = self._db().find_one({"key": key})
        except Exception as exc:
            self._record_failure("ledger_get_failed")
            logger.warning(
                "ledger get failed task_id:{} error_type:{}".format(
                    self.task_id, type(exc).__name__)
            )
            return None
        if not isinstance(doc, dict):
            return None
        return self._entry_from_doc(key, doc)

    def _entry_from_doc(self, key, doc):
        return LedgerEntry(
            idempotency_key=str(doc.get("key") or key),
            status=str(doc.get("status") or "pending"),
            input_count=int(doc.get("input_count") or 0),
            output_count=int(doc.get("output_count") or 0),
            error_type=str(doc.get("error_type") or ""),
            updated_at=float(doc.get("updated_at") or 0.0),
            owner=str(doc.get("owner") or ""),
            lease_expires_at=float(doc.get("lease_expires_at") or 0.0),
        )

    def upsert(self, entry):
        """整条覆盖写（finish/失败落账用）；claim 走 CAS，不走本方法。"""
        now = time.time()
        try:
            self._db().replace_one(
                {"key": entry.idempotency_key},
                {
                    "key": entry.idempotency_key,
                    "task_id": self.task_id,
                    "status": entry.status,
                    "input_count": entry.input_count,
                    "output_count": entry.output_count,
                    "error_type": entry.error_type,
                    "updated_at": entry.updated_at or now,
                    "payload": dict(getattr(entry, "payload", {}) or {}),
                    # 终态不再占租约。
                    "owner": "",
                    "lease_expires_at": 0.0,
                },
                upsert=True,
            )
        except Exception as exc:
            self._record_failure("ledger_upsert_failed")
            logger.warning(
                "ledger upsert failed task_id:{} key:{} error_type:{}".format(
                    self.task_id, str(entry.idempotency_key)[:120],
                    type(exc).__name__))
        return entry

    def _claim_filter(self, key, now):
        """可 claim 条件：不存在（靠 upsert 建），或 pending/failed/
        已过期的 claiming。covered 与其他进行中一律不可夺。"""
        return {
            "$and": [
                {"key": key},
                {
                    "$or": [
                        {"status": {"$in": list(_CLAIMABLE_STATUSES)}},
                        {"status": "claiming",
                         "lease_expires_at": {"$lt": now}},
                    ]
                },
            ]
        }

    def claim(self, idempotency_key, input_count=0, owner=None,
              lease_sec=None):
        """原子占用：成功返回 True。仅两种情况成功：

        1) 首次占位（无记录，原子 upsert 插入，撞唯一键即判负）；
        2) 抢占 pending/终态/租约过期的 claiming，find_and_update 单次原子。
        """
        key = str(idempotency_key or "")
        if not key:
            return False
        owner = str(owner or self.owner)
        ttl = float(lease_sec or LEDGER_CLAIM_TTL_SEC)
        now = time.time()
        set_fields = {
            "task_id": self.task_id,
            "status": "claiming",
            "owner": owner,
            "lease_expires_at": now + ttl,
            "input_count": max(0, int(input_count or 0)),
            "updated_at": now,
        }
        try:
            doc = self._db().find_one_and_update(
                self._claim_filter(key, now),
                {"$set": dict(set_fields, key=key),
                 "$setOnInsert": {"output_count": 0, "error_type": ""}},
                return_document=_RETURN_AFTER,
                upsert=True,
            )
        except Exception as exc:
            # DuplicateKey = 并发下已被别的工作者占位/落库，本路径判负；
            # 其余后端故障 fail-open，宁可重跑不可漏跑。
            if self.is_duplicate_key_error(exc):
                owner_now = self._owner_of(key)
                status_now = self._status_of(key)
                return bool(
                    owner_now == owner
                    and status_now == "claiming")
            logger.warning(
                "ledger claim degraded task_id:{} key:{} error_type:{}".format(
                    self.task_id, key[:120], type(exc).__name__))
            existing = self.get(key)
            proceed = not (existing is not None and existing.status == "covered")
            # 放行即"covered 不可确认仍执行"：dedup 降级证据（重复扫描面）。
            self._record_failure("ledger_claim_failed", dedup_degraded=proceed)
            return proceed
        if not isinstance(doc, dict):
            return False
        # CAS 回执核验：必须是本 owner 的 claiming 才算真正拿到。
        if str(doc.get("status") or "") != "claiming":
            return False
        return str(doc.get("owner") or "") == owner

    def _owner_of(self, key):
        entry_doc = None
        try:
            entry_doc = self._db().find_one(
                {"key": key}, {"owner": 1})
        except Exception:
            self._record_failure("ledger_owner_probe_failed")
            return ""
        if isinstance(entry_doc, dict):
            return str(entry_doc.get("owner") or "")
        return ""

    @staticmethod
    def is_duplicate_key_error(exc):
        name = type(exc).__name__
        if "Duplicate" in name:
            return True
        text = str(exc) or ""
        return "E11000" in text or "duplicate key" in text.lower()

    def _status_of(self, key):
        try:
            entry_doc = self._db().find_one(
                {"key": key}, {"status": 1})
        except Exception:
            self._record_failure("ledger_status_probe_failed")
            return ""
        if isinstance(entry_doc, dict):
            return str(entry_doc.get("status") or "")
        return ""

    # claiming 之外的可回写状态（claim 前的 pending 或直接 finish 的场景）
    _FINISH_OWNABLE_STATUSES = ("claiming", "pending", "failed")

    def finish(self, idempotency_key, status, input_count=0,
               output_count=0, error=None, owner=None):
        """owner/lease fencing 的终态回写。

        仅持有当前 claiming(未过期由 claim 维护)或尚无记录时可写；
        记录已被其他 owner 接管则拒写并计数，covered 重复写为幂等 no-op。

        后端异常时的归属确认优先级高于 fail-open 覆盖写：无法确认归属
        则拒写（拒写不阻断扫描），绝不把"拒写"升级成整体覆盖他人文档。
        """
        key = str(idempotency_key or "")
        owner = str(owner or self.owner)
        now = time.time()
        entry = LedgerEntry(
            idempotency_key=key,
            status=str(status or "pending"),
            input_count=max(0, int(input_count or 0)),
            output_count=max(0, int(output_count or 0)),
            error_type=(
                type(error).__name__ if error is not None else ""),
            owner=owner,
        )
        if not key:
            return entry
        doc = {
            "key": key,
            "task_id": self.task_id,
            "status": entry.status,
            "input_count": entry.input_count,
            "output_count": entry.output_count,
            "error_type": entry.error_type,
            "updated_at": now,
            "payload": dict(getattr(entry, "payload", {}) or {}),
            # 终态不再占租约。
            "owner": "" if status == "covered" else owner,
            "lease_expires_at": 0.0,
        }
        update_failed = False
        try:
            result = self._db().update_one(
                {
                    "key": key,
                    "owner": owner,
                    "status": {"$in": list(self._FINISH_OWNABLE_STATUSES)},
                },
                {"$set": doc},
            )
            if int(getattr(result, "matched_count", 0) or 0) > 0:
                return entry
        except Exception as exc:
            self._record_failure("ledger_finish_failed")
            logger.warning(
                "ledger finish degraded task_id:{} key:{} error_type:{}".format(
                    self.task_id, key[:120], type(exc).__name__))
            update_failed = True

        try:
            existing = self._db().find_one({"key": key})
        except Exception as exc:
            self._record_failure("ledger_confirm_failed")
            # 确认查询与更新分离容错：fencing 已判负或归属未知时，
            # 确认失败不得升级为无条件覆盖写。
            logger.warning(
                "ledger finish confirm failed task_id:{} key:{} error_type:{}".format(
                    self.task_id, key[:120], type(exc).__name__))
            self.record_finish_rejected()
            return entry

        if not isinstance(existing, dict):
            # 无记录（未 claim 直接 finish）：安全 upsert。
            return self.upsert(entry)
        if str(existing.get("status") or "") == "covered":
            # 幂等 no-op：已有完成态，保留先写者。
            return self._entry_from_doc(key, existing)
        holder = str(existing.get("owner") or "")
        if (update_failed and holder == owner
                and str(existing.get("status") or "")
                in self._FINISH_OWNABLE_STATUSES):
            # update_one 误报异常但确认归属仍是自己：整条覆盖写保结果。
            return self.upsert(entry)
        # 被他人接管或状态不可回写：拒写并留观测计数。
        self.record_finish_rejected()
        logger.warning(
            "ledger finish fenced task_id:{} key:{} holder:{}".format(
                self.task_id, key[:120], holder[:64]))
        return self._entry_from_doc(key, existing)

    _finish_rejected_count = 0

    def record_finish_rejected(self):
        type(self)._finish_rejected_count = getattr(type(self), "_finish_rejected_count", 0) + 1
        # fencing 拒写是并发仲裁的正常结果，不计 unavailable，但必须可见
        # （连续大量 rejected 提示租约/接管异常）。
        sink = self._metrics_sink
        if sink is not None:
            try:
                sink("ledger_finish_rejected_total", 1)
            except Exception:
                pass

    def list_by_prefix(self, key_prefix, statuses=("pending",), limit=2000):
        """按前缀+状态读取 [(key, payload)]，不改变状态（overflow 回读/WAF 回灌共用）。"""
        prefix = str(key_prefix or "")
        if not prefix:
            return []
        status_list = [str(item or "") for item in (statuses or ())] or ["pending"]
        try:
            cursor = self._db().find(
                {
                    "key": {"$regex": "^" + re.escape(prefix)},
                    "status": {"$in": status_list},
                    "task_id": self.task_id,
                },
                {"key": 1, "payload": 1},
            )
            items = []
            for doc in cursor:
                if len(items) >= max(1, int(limit or 2000)):
                    break
                if not isinstance(doc, dict):
                    continue
                items.append((str(doc.get("key") or ""), dict(doc.get("payload") or {})))
            return items
        except Exception as exc:
            self._record_failure("ledger_list_failed")
            logger.warning(
                "ledger list_pending degraded task_id:{} prefix:{} error_type:{}".format(
                    self.task_id, prefix[:64], type(exc).__name__))
            return []

    def list_pending(self, key_prefix, limit=2000):
        """overflow 回读旧入口：pending 状态的 list_by_prefix 别名。"""
        return self.list_by_prefix(key_prefix, statuses=("pending",), limit=limit)

    def is_covered(self, idempotency_key):
        entry = self.get(idempotency_key)
        return bool(entry is not None and entry.status == "covered")