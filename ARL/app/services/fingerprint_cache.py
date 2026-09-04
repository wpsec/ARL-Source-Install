"""
指纹缓存管理
"""
import json
import re

from collections import defaultdict

try:
    import redis
except Exception:
    redis = None

from app.config import Config
from .fingerprint import FingerPrint
from .kscan_fingerprint import load_kscan_fingerprint_rules
from app.utils import get_logger, conn_db
from app.fp_common import (
    estimate_human_rule_confidence,
    extract_human_rule_fields,
    safe_int as _safe_int,
)

logger = get_logger()


def _normalize_text_list(value, lower=False):
    if isinstance(value, (list, tuple, set)):
        values = value
    elif value is None:
        values = []
    else:
        values = [value]

    out = []
    seen = set()
    for item in values:
        text = str(item or "").strip()
        if not text:
            continue
        if lower:
            text = text.lower()
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _get_confirmed_confidence_min():
    return max(60, min(99, _safe_int(getattr(Config, "FINGER_CONFIDENCE_MIN", 85), 85)))


def _get_candidate_confidence_min():
    return max(40, min(_get_confirmed_confidence_min(), _safe_int(getattr(Config, "FINGER_CANDIDATE_CONFIDENCE_MIN", 70), 70)))


def _get_legacy_rule_confidence():
    return max(_get_candidate_confidence_min(), min(90, _safe_int(getattr(Config, "FINGER_LEGACY_RULE_CONFIDENCE", 72), 72)))


def _get_wappalyzer_confidence_min():
    return max(_get_candidate_confidence_min(), min(95, _safe_int(getattr(Config, "WAPPALYZER_CONFIDENCE_MIN", 70), 70)))


def _get_candidate_max_items():
    return max(0, _safe_int(getattr(Config, "FINGER_CANDIDATE_MAX_ITEMS", 8), 8))


def classify_fingerprint_confidence(confidence):
    score = _safe_int(confidence, 0)
    if score >= _get_confirmed_confidence_min():
        return "confirmed"
    if score >= _get_candidate_confidence_min():
        return "candidate"
    return "discarded"


def _build_result_item(
    name,
    confidence,
    match_fields=None,
    sources=None,
    matched_rule_count=0,
    version="",
    website="",
    categories=None,
):
    score = max(0, min(99, _safe_int(confidence, 0)))
    item = {
        "name": str(name or "").strip(),
        "confidence": score,
        "confidence_level": classify_fingerprint_confidence(score),
        "match_fields": _normalize_text_list(match_fields, lower=True),
        "sources": _normalize_text_list(sources, lower=True),
        "matched_rule_count": max(0, _safe_int(matched_rule_count, 0)),
        "version": str(version or "").strip(),
        "website": str(website or "").strip(),
        "categories": _normalize_text_list(categories, lower=False),
    }
    return item


def merge_fingerprint_result_items(items):
    result_map = {}

    for raw_item in items or []:
        if not isinstance(raw_item, dict):
            continue

        name = str(raw_item.get("name", "") or "").strip()
        if not name:
            continue

        item = _build_result_item(
            name=name,
            confidence=raw_item.get("confidence", 0),
            match_fields=raw_item.get("match_fields"),
            sources=raw_item.get("sources"),
            matched_rule_count=raw_item.get("matched_rule_count", 0),
            version=raw_item.get("version", ""),
            website=raw_item.get("website", ""),
            categories=raw_item.get("categories"),
        )
        key = item["name"].lower()

        current = result_map.get(key)
        if current is None:
            result_map[key] = item
            continue

        old_source_count = len(current.get("sources", []))
        old_field_count = len(current.get("match_fields", []))

        merged_sources = _normalize_text_list(
            list(current.get("sources", [])) + list(item.get("sources", [])),
            lower=True,
        )
        merged_fields = _normalize_text_list(
            list(current.get("match_fields", [])) + list(item.get("match_fields", [])),
            lower=True,
        )
        merged_categories = _normalize_text_list(
            list(current.get("categories", [])) + list(item.get("categories", [])),
            lower=False,
        )

        merged_confidence = max(
            _safe_int(current.get("confidence"), 0),
            _safe_int(item.get("confidence"), 0),
        )
        if len(merged_sources) > old_source_count:
            merged_confidence += 2
        if len(merged_fields) > old_field_count and len(merged_fields) >= 2:
            merged_confidence += 1

        current["confidence"] = min(99, merged_confidence)
        current["confidence_level"] = classify_fingerprint_confidence(current["confidence"])
        current["sources"] = merged_sources
        current["match_fields"] = merged_fields
        current["categories"] = merged_categories
        current["matched_rule_count"] = max(
            _safe_int(current.get("matched_rule_count"), 0),
            _safe_int(item.get("matched_rule_count"), 0),
        )
        if not current.get("version") and item.get("version"):
            current["version"] = item.get("version", "")
        if not current.get("website") and item.get("website"):
            current["website"] = item.get("website", "")

    return sorted(
        result_map.values(),
        key=lambda item: (
            -_safe_int(item.get("confidence"), 0),
            str(item.get("name", "")),
        ),
    )


def split_fingerprint_result_items(items):
    confirmed = []
    candidates = []
    candidate_max_items = _get_candidate_max_items()

    for item in merge_fingerprint_result_items(items):
        level = classify_fingerprint_confidence(item.get("confidence", 0))
        item["confidence_level"] = level
        if level == "confirmed":
            confirmed.append(item)
        elif level == "candidate":
            candidates.append(item)

    if candidate_max_items > 0:
        candidates = candidates[:candidate_max_items]

    return confirmed, candidates


def build_legacy_fingerprint_items(names):
    items = []
    base_confidence = _get_legacy_rule_confidence()
    for name in names or []:
        name_text = str(name or "").strip()
        if not name_text:
            continue
        items.append(
            _build_result_item(
                name=name_text,
                confidence=base_confidence,
                sources=["legacy_rule"],
            )
        )
    return items


def normalize_wappalyzer_fingerprint_items(applications):
    raw_items = []
    min_confidence = _get_wappalyzer_confidence_min()

    for app in applications or []:
        if not isinstance(app, dict):
            continue

        name = str(app.get("name", "") or "").strip()
        if not name:
            continue

        confidence = _safe_int(app.get("confidence", 0), 0)
        if confidence < min_confidence:
            continue

        raw_items.append(
            _build_result_item(
                name=name,
                confidence=confidence,
                sources=["wappalyzer"],
                version=app.get("version", ""),
                website=app.get("website", ""),
                categories=app.get("categories"),
            )
        )

    return split_fingerprint_result_items(raw_items)


def _finalize_match_state(result_state):
    match_fields = _normalize_text_list(result_state.get("match_fields", []), lower=True)
    sources = _normalize_text_list(result_state.get("sources", []), lower=True)
    matched_rule_count = max(0, _safe_int(result_state.get("matched_rule_count"), 0))
    confidence = max(0, _safe_int(result_state.get("max_rule_confidence"), 0))
    field_set = set(match_fields)

    if matched_rule_count >= 2:
        confidence += min(10, 4 + (matched_rule_count - 2) * 2)

    if len(field_set) >= 2:
        confidence += min(8, (len(field_set) - 1) * 3)

    if len(sources) >= 2:
        confidence += min(4, (len(sources) - 1) * 2)

    if "icon_hash" in field_set and len(field_set) >= 2:
        confidence += 2

    if matched_rule_count == 1 and field_set == {"body"}:
        confidence = min(confidence, 76)
    elif matched_rule_count == 1 and field_set == {"title"}:
        confidence = min(confidence, 80)
    elif matched_rule_count == 1 and field_set == {"url"}:
        confidence = min(confidence, 78)
    elif matched_rule_count == 1 and field_set == {"header"}:
        confidence = min(confidence, 82)
    elif matched_rule_count == 1 and field_set == {"response"}:
        confidence = min(confidence, 84)

    confidence = max(35, min(99, confidence))

    return _build_result_item(
        name=result_state.get("name", ""),
        confidence=confidence,
        match_fields=match_fields,
        sources=sources or ["fingerprint_rule"],
        matched_rule_count=matched_rule_count,
    )


# 用于缓存指纹数据，避免每次请求都从MongoDB中获取数据
class FingerPrintCache:
    REDIS_KEY = "arl:fingerprint:rules:v3"

    def __init__(self):
        self.cache = None
        self.redis_client = None
        self.redis_enabled = bool(Config.REDIS_ENABLE)

    def is_cache_valid(self):
        return self.cache is not None

    def get_redis_client(self):
        """
        获取 Redis 客户端（单例懒加载）
        """
        if not self.redis_enabled:
            return None
        if redis is None:
            logger.warning("redis package not installed, fallback to memory cache")
            return None
        if self.redis_client is not None:
            return self.redis_client

        try:
            self.redis_client = redis.Redis(
                host=Config.REDIS_HOST,
                port=Config.REDIS_PORT,
                db=Config.REDIS_DB,
                password=Config.REDIS_PASSWORD or None,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
                socket_keepalive=True,
                health_check_interval=30,
                retry_on_timeout=True
            )
            self.redis_client.ping()
            logger.info("redis cache enabled host:{} port:{} db:{}".format(
                Config.REDIS_HOST, Config.REDIS_PORT, Config.REDIS_DB))
            return self.redis_client
        except Exception as e:
            logger.warning("redis connect failed, fallback to memory cache: {}".format(e))
            self.redis_client = None
            return None

    def build_finger_list(self, rules):
        """
        将规则列表转换成 FingerPrint 实例列表
        """
        finger_list = []
        for rule in rules:
            try:
                name = rule.get("name", "")
                human_rule = rule.get("human_rule", "")
                if not name or not human_rule:
                    continue
                sources = rule.get("sources")
                if not sources:
                    sources = rule.get("source") or ["fingerprint_rule"]
                finger_list.append(FingerPrint(name, human_rule, sources=sources))
            except Exception as e:
                logger.warning("build fingerprint item error: {}".format(e))
        return finger_list

    def get_cache_from_redis(self):
        """
        从 Redis 读取指纹规则缓存
        """
        client = self.get_redis_client()
        if client is None:
            return None

        try:
            data = client.get(self.REDIS_KEY)
            if not data:
                return None
            rules = json.loads(data)
            if not isinstance(rules, list):
                return None
            return self.build_finger_list(rules)
        except Exception as e:
            logger.warning("read fingerprint cache from redis failed: {}".format(e))
            return None

    def save_cache_to_redis(self, finger_rules):
        """
        将指纹规则写入 Redis
        """
        client = self.get_redis_client()
        if client is None:
            return

        try:
            payload = json.dumps(finger_rules, ensure_ascii=False)
            expire = int(Config.REDIS_CACHE_EXPIRE)
            if expire > 0:
                client.setex(self.REDIS_KEY, expire, payload)
            else:
                client.set(self.REDIS_KEY, payload)
        except Exception as e:
            logger.warning("write fingerprint cache to redis failed: {}".format(e))

    def get_data(self):
        if self.is_cache_valid():
            return self.cache

        redis_cache = self.get_cache_from_redis()
        if redis_cache is not None:
            self.cache = redis_cache
            return self.cache

        self.cache = self.fetch_data_from_mongodb()
        return self.cache

    def fetch_data_from_mongodb(self) -> [FingerPrint]:
        items = list(conn_db('fingerprint').find({}, {"name": 1, "human_rule": 1}))
        rule_map = {}

        def merge_rule(name, human_rule, source_name):
            name = str(name or "").strip()
            human_rule = str(human_rule or "").strip()
            source_name = str(source_name or "").strip().lower()
            if not name or not human_rule:
                return

            key = (name.lower(), human_rule)
            current = rule_map.get(key)
            if current is None:
                current = {
                    "name": name,
                    "human_rule": human_rule,
                    "sources": [],
                }
                rule_map[key] = current

            if source_name and source_name not in current["sources"]:
                current["sources"].append(source_name)

        for item in items:
            merge_rule(item.get("name", ""), item.get("human_rule", ""), "db")

        kscan_rules = load_kscan_fingerprint_rules()
        for item in kscan_rules:
            merge_rule(item.get("name", ""), item.get("human_rule", ""), "kscan")

        rules = sorted(
            rule_map.values(),
            key=lambda item: (str(item.get("name", "")).lower(), str(item.get("human_rule", ""))),
        )

        logger.info(
            "fingerprint cache build db_rules:{} kscan_rules:{} final_rules:{} final_apps:{}".format(
                len(items), len(kscan_rules), len(rules), len(set(item.get("name", "") for item in rules))
            )
        )

        self.save_cache_to_redis(rules)
        return self.build_finger_list(rules)

    def update_cache(self, force_db=True):
        """
        手动更新缓存
        force_db=True: 强制从 MongoDB 刷新并回写 Redis（用于规则变更后）
        force_db=False: 优先尝试 Redis，失败再从 MongoDB 获取
        """
        if force_db:
            self.cache = self.fetch_data_from_mongodb()
            return self.cache

        redis_cache = self.get_cache_from_redis()
        if redis_cache is not None:
            self.cache = redis_cache
            return self.cache

        self.cache = self.fetch_data_from_mongodb()
        return self.cache


finger_db_cache = FingerPrintCache()


def finger_db_identify(variables: dict) -> [str]:
    return [item["name"] for item in finger_db_identify_detail(variables)]


def finger_db_identify_detail(variables: dict) -> [dict]:
    """
    返回带置信度与命中特征的指纹识别结果
    """
    finger_list = finger_db_cache.get_data()
    result_map = {}

    for finger in finger_list:
        try:
            if not finger.identify(variables):
                continue
        except Exception as e:
            logger.warning("error on identify {} {}".format(finger.app_name, e))
            continue

        key = str(finger.app_name or "").strip().lower()
        if not key:
            continue

        current = result_map.get(key)
        if current is None:
            current = {
                "name": finger.app_name,
                "match_fields": set(),
                "sources": set(),
                "matched_rule_count": 0,
                "max_rule_confidence": 0,
            }
            result_map[key] = current

        current["matched_rule_count"] += 1
        current["match_fields"].update(extract_human_rule_fields(finger.human_rule))
        current["sources"].update(_normalize_text_list(finger.sources or ["fingerprint_rule"], lower=True))
        current["max_rule_confidence"] = max(
            current["max_rule_confidence"],
            estimate_human_rule_confidence(finger.human_rule),
        )

    results = [_finalize_match_state(item) for item in result_map.values()]
    return sorted(
        results,
        key=lambda item: (-int(item.get("confidence", 0)), str(item.get("name", ""))),
    )


def have_human_rule_from_db(rule: str) -> bool:
    query = {
        "human_rule": rule,
    }

    if conn_db('fingerprint').find_one(query):
        return True
    else:
        return False
