"""计划5 第3阶段：SiteFingerprintRegistry——规范站点指纹文件的运行时加载与匹配。

设计口径（对 05 §2.3 的诚实实现）：
- v1 正确性优先：全量判定保证零遗漏；icon_hash 精确桶/统计桶先行建设，
  真正的剪枝召回（AC 自动机/Rust 批量）在性能阶段接入，且必须先过 §2.3.1
  一致性门禁（索引结果==全量结果）。任何快路径都不得改变命中集合。
- 证据判断零新轮子：规则以 canonical_rule 走运行时同一 parse/evaluate（FingerPrint），
  置信度直读编译产物（编译期已做合并与 bonus，运行时不再二次 merge）。
- 失败语义：文件缺失/损坏/format 不符 → ok=False，调用方必须显式降级 legacy，
  禁止空规则静默启动（05 第4阶段冷启动约束）。
- 热重载：按 (mtime, size, sha256前16) 判定，规则文件重编译后各进程自然切换。
"""
import copy
import gzip
import hashlib
import json
import logging
import os
import threading

from app.config import Config
from app.fp_common import (
    estimate_human_rule_confidence,
    merge_key,
    parse_human_rule,
    to_human_rule,
)
from app.services.fingerprint import FingerPrint
from app.services.fingerprint_cache import split_fingerprint_result_items

# 架构 Review 轮 2：解析函数在 fp_common 零依赖公共层（单一实现，05 §零.1）。
# 运行时不得 import app.tools.build_unified_fingerprints——构建脚本层变化/依赖
# 缺失不应能打断生产指纹链。

FINGERPRINT_VERSION_KEY = "arl:fingerprint:unified:ver"
_OVERLAY_CHECK_INTERVAL = 60.0
# ver 读不到（Redis 从未写过/曾故障）时的低频对账间隔：防 route bump 恰好丢失后永不定格
_OVERLAY_FALLBACK_INTERVAL = 600.0

logger = logging.getLogger(__name__)

SUPPORTED_SITE_FORMATS = {"arl_site_fingerprint_v1"}

# 模块级单例（gunicorn/celery 各进程持有自己的一份）
_registry_instance = None
_registry_lock = threading.Lock()


class SiteFingerprintRegistry:
    def __init__(self, path):
        self.path = path
        self.ok = False
        self.load_error = ""
        self.rules = []
        self.icon_index = {}  # icon_hash 精确值 -> [rule]
        self.file_token = None
        self._parsed_lock = threading.Lock()
        self._base_rules = []  # 文件基线（overlay 重建时复用）
        self._overlay_error = ""
        self._version = None
        self._last_version_check = 0.0
        self._redis_client = None
        # 规则判定异常观测（Review 轮 2）：跳过可以，静默不行——计数带 rule id。
        self.rule_error_total = 0
        self._rule_error_counts = {}
        self._rule_error_lock = threading.Lock()

    # ---------- 加载 ----------

    def _read_bytes(self):
        if self.path.endswith(".gz"):
            with gzip.open(self.path, "rb") as f:
                return f.read()
        with open(self.path, "rb") as f:
            return f.read()

    def load(self):
        try:
            raw = self._read_bytes()
        except OSError as exc:
            self._fail("file_unreadable: {}".format(exc))
            return self
        token = hashlib.sha256(raw).hexdigest()[:16]
        if token == self.file_token and self.ok:
            return self
        try:
            doc = json.loads(raw.decode("utf-8"))
            meta = doc.get("meta", {})
            if meta.get("format") not in SUPPORTED_SITE_FORMATS:
                raise ValueError("unsupported format: {}".format(meta.get("format")))
            rules = []
            for item in doc.get("fingerprints", []):
                if not item.get("enabled", True):
                    continue
                rules.append(self._build_rule(item))
            icon_index = {}
            for rule in rules:
                for branch in rule["match"].get("any", []):
                    for cond in branch.get("all", []):
                        if cond["field"] == "icon_hash" and cond["operator"] == "equals":
                            icon_index.setdefault(cond["value"], []).append(rule)
            self._base_rules = rules
            self._rebuild_with_overlay()
            self.file_token = token
            self.ok = True
            self.load_error = ""
        except Exception as exc:
            self._fail("parse_failed: {}".format(exc))
        return self

    def _build_rule(self, item):
        canonical = item.get("canonical_rule") or ""
        return {
            "id": item.get("id", ""),
            "name": item.get("name", ""),
            "confidence": int(item.get("confidence", 70)),
            "sources": list(item.get("sources", [])),
            "match": item.get("match", {}),
            "fp": FingerPrint(item.get("name", ""), canonical),
        }

    def _fail(self, reason):
        self.ok = False
        self.load_error = reason
        self.rules = []
        self.icon_index = {}
        logger.error("site fingerprint registry load failed: %s (path=%s)", reason, self.path)

    # ---------- Mongo 用户规则 overlay（第4阶段：真相源=Mongo，policy 豁免用户意图） ----------

    def _rebuild_with_overlay(self):
        # 深拷贝 match/sources：merge 分支会 extend/改写条目，绝不能污染 _base_rules
        rules = [
            {**r, "match": copy.deepcopy(r["match"]), "sources": list(r["sources"])}
            for r in self._base_rules
        ]
        self._overlay_error = ""
        overlay = 0
        try:
            from app.utils import conn_db
            cursor = conn_db("fingerprint").find({}, {"name": 1, "human_rule": 1})
            by_key = {merge_key(r["name"]): r for r in rules}
            for doc in cursor:
                name = str(doc.get("name") or "").strip()
                rule_text = str(doc.get("human_rule") or "").strip()
                if not name or not rule_text:
                    continue
                match, problems = parse_human_rule(rule_text)
                if problems:
                    # 用户规则只验格式不施 policy：body="login" 这类用户显式意图必须保留
                    continue
                key = merge_key(name)
                existing = by_key.get(key)
                if existing is None:
                    rules.append(self._build_rule({
                        "id": "site:" + key,
                        "name": name,
                        "confidence": int(estimate_human_rule_confidence(to_human_rule(match))),
                        "sources": ["mongo_user"],
                        "match": match,
                        "canonical_rule": to_human_rule(match),
                    }))
                    by_key[key] = rules[-1]
                else:
                    existing["match"]["any"].extend(match["any"])
                    if "mongo_user" not in existing["sources"]:
                        existing["sources"].append("mongo_user")
                    existing["canonical_rule"] = to_human_rule(existing["match"])
                    existing["confidence"] = int(estimate_human_rule_confidence(existing["canonical_rule"]))
                    existing["fp"] = FingerPrint(existing["name"], existing["canonical_rule"])
                overlay += 1
        except Exception as exc:
            # Mongo 不可达：基线照常服务（冷启动兜底），显式记录不静默
            self._overlay_error = "overlay_unavailable: {}".format(exc)
            logger.warning("fingerprint mongo overlay unavailable, baseline only: %s", exc)
        self.rules = rules
        icon_index = {}
        for rule in rules:
            for branch in rule["match"].get("any", []):
                for cond in branch.get("all", []):
                    if cond["field"] == "icon_hash" and cond["operator"] == "equals":
                        icon_index.setdefault(cond["value"], []).append(rule)
        self.icon_index = icon_index
        logger.info(
            "site fingerprint registry built rules=%d overlay=%d icon_buckets=%d token=%s",
            len(rules), overlay, len(icon_index), self.file_token,
        )

    def _maybe_check_version(self):
        """Redis 版本号触发重建（update_cache 尾部 INCR）。

        ver 读不到（键从未写过/Redis 曾故障）时退化为 _OVERLAY_FALLBACK_INTERVAL 低频对账，
        防止"恰好在 bump 窗口丢失更新"后永不定格。Redis 关闭则仅靠文件变化重建。
        """
        import time as _time
        now = _time.monotonic()
        interval = _OVERLAY_CHECK_INTERVAL if self._version is not None else _OVERLAY_FALLBACK_INTERVAL
        if now - self._last_version_check < interval:
            return
        self._last_version_check = now
        try:
            if self._redis_client is None:
                from app.services.fingerprint_cache import finger_db_cache
                client = finger_db_cache.get_redis_client()
                if client is None:
                    return
                self._redis_client = client
            raw = self._redis_client.get(FINGERPRINT_VERSION_KEY)
            if raw is None:
                self._version = None
                return
            version = int(raw)
            if self._version is None:
                self._version = version
                self._rebuild_with_overlay()
                return
            if version != self._version:
                self._version = version
                self._rebuild_with_overlay()
        except Exception as exc:
            logger.warning("fingerprint unified version check failed: %s", exc)

    # ---------- 匹配 ----------

    def reload_if_stale(self):
        try:
            stat = os.stat(self.path)
            cheap_token = "{}:{}".format(int(stat.st_mtime), stat.st_size)
            if self.file_token is None or getattr(self, "_cheap_token", None) != cheap_token:
                self._cheap_token = cheap_token
                self.load()
                return self
        except OSError:
            if self.ok:
                self._fail("file_missing_on_reload")
            return self
        if self.ok:
            self._maybe_check_version()
        return self

    def candidate_indices(self, variables):
        """召回候选下标。v1 全量兜底：任何快路径只做提前组织，绝不做排除。

        icon_hash 精确桶给出高优先命中，其余规则保持全量判定（零遗漏契约）。
        """
        priority = []
        seen = set()
        icon_value = str(variables.get("icon_hash", "") or "")
        if icon_value and icon_value != "0":
            for rule in self.icon_index.get(icon_value, []):
                idx = id(rule)
                if idx not in seen:
                    seen.add(idx)
                    priority.append(rule)
        return priority

    def match(self, variables):
        """返回 fingerprint_cache split/merge 可直接消费的 items。"""
        if not self.ok:
            return []
        items = []
        matched_ids = set()
        for rule in self.candidate_indices(variables):
            if self._rule_hits(rule, variables):
                matched_ids.add(rule["id"])
                items.append(self._to_item(rule, variables))
        for rule in self.rules:
            if rule["id"] in matched_ids:
                continue
            if self._rule_hits(rule, variables):
                items.append(self._to_item(rule, variables))
        return items

    def _rule_hits(self, rule, variables):
        try:
            return bool(rule["fp"].identify(variables))
        except Exception as exc:
            # pyparsing 偶发解析失败：与运行时旧链一致跳过该规则（identify_detail 同款 except 语义），
            # 但必须计数带 rule id（Review 轮 2 闭环 05 §2.6 观测预留）。
            self._record_rule_error(rule, exc)
            return False

    def _record_rule_error(self, rule, exc):
        rid = str(rule.get("id") or rule.get("name") or "?")[:120]
        with self._rule_error_lock:
            self.rule_error_total += 1
            total = self.rule_error_total
            first_seen = rid not in self._rule_error_counts
            self._rule_error_counts[rid] = self._rule_error_counts.get(rid, 0) + 1
            distinct = len(self._rule_error_counts)
        if first_seen:
            logger.warning(
                "site fingerprint rule evaluate failed stage:site_identify rule_id:%s "
                "error_type:%s (first occurrence per rule)",
                rid, type(exc).__name__,
            )
        elif total % 1000 == 0:
            logger.warning(
                "site fingerprint rule errors ongoing stage:site_identify total:%d distinct_rules:%d",
                total, distinct,
            )

    def rule_error_snapshot(self):
        """累计异常计数快照：消费方（fetchSite）按差值汇入任务 metrics。"""
        with self._rule_error_lock:
            return self.rule_error_total

    def stats(self):
        with self._rule_error_lock:
            return {
                "ok": self.ok,
                "rule_count": len(self.rules),
                "rule_error_total": self.rule_error_total,
                "rule_error_distinct_rules": len(self._rule_error_counts),
                "load_error": self.load_error,
                "overlay_error": self._overlay_error,
            }

    def _to_item(self, rule, variables):
        fields = []
        for branch in rule["match"].get("any", []):
            for cond in branch.get("all", []):
                if self._cond_hits(cond, variables):
                    fields.append(cond["field"])
                    break
        return {
            "name": rule["name"],
            "confidence": rule["confidence"],
            "sources": rule["sources"],
            "match_fields": sorted(set(fields)),
        }

    @staticmethod
    def _cond_hits(cond, variables):
        field_value = str(variables.get(cond["field"], "") or "")
        value = cond["value"]
        op = cond["operator"]
        if op == "contains":
            return value in field_value
        if op == "equals":
            return field_value == value
        return False


def split_unified_items(items):
    """与旧链同一 split 语义（confirmed/candidates 阈值同源）。"""
    return split_fingerprint_result_items(items)


def get_site_registry():
    """进程级 Registry 单例；调用方以 registry.ok 判断能否走 unified。"""
    global _registry_instance
    path = str(getattr(Config, "SITE_FINGERPRINT_FILE", "") or "")
    with _registry_lock:
        if _registry_instance is None or _registry_instance.path != path:
            _registry_instance = SiteFingerprintRegistry(path)
            _registry_instance.load()
        else:
            _registry_instance.reload_if_stale()
        return _registry_instance


def reset_site_registry_for_test():
    global _registry_instance
    with _registry_lock:
        _registry_instance = None
