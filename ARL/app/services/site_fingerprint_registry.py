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
import gzip
import hashlib
import json
import logging
import os
import threading

from app.config import Config
from app.services.fingerprint import FingerPrint
from app.services.fingerprint_cache import split_fingerprint_result_items

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
            self.rules = rules
            self.icon_index = icon_index
            self.file_token = token
            self.ok = True
            self.load_error = ""
            logger.info(
                "site fingerprint registry loaded rules=%d icon_buckets=%d token=%s",
                len(rules), len(icon_index), token,
            )
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

    # ---------- 匹配 ----------

    def reload_if_stale(self):
        try:
            stat = os.stat(self.path)
            cheap_token = "{}:{}".format(int(stat.st_mtime), stat.st_size)
            if self.file_token is None or getattr(self, "_cheap_token", None) != cheap_token:
                self._cheap_token = cheap_token
                self.load()
        except OSError:
            if self.ok:
                self._fail("file_missing_on_reload")
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
        except Exception:
            # pyparsing 偶发解析失败：与运行时旧链一致跳过该规则（identify_detail 同款 except 语义），
            # 但不静默——低频计数留给观测阶段补 metrics（05 §2.6）。
            return False

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
