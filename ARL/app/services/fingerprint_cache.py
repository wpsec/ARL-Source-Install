"""
指纹缓存管理
"""
import json

try:
    import redis
except Exception:
    redis = None

from app.config import Config
from .fingerprint import FingerPrint
from app.utils import get_logger, conn_db

logger = get_logger()


# 用于缓存指纹数据，避免每次请求都从MongoDB中获取数据
class FingerPrintCache:
    REDIS_KEY = "arl:fingerprint:rules:v1"

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
            # decode_responses=True 便于直接读写 JSON 字符串
            self.redis_client = redis.Redis(
                host=Config.REDIS_HOST,
                port=Config.REDIS_PORT,
                db=Config.REDIS_DB,
                password=Config.REDIS_PASSWORD or None,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2
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
                finger_list.append(FingerPrint(name, human_rule))
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

        # 先尝试从 Redis 读取，失败再回落到 MongoDB
        redis_cache = self.get_cache_from_redis()
        if redis_cache is not None:
            self.cache = redis_cache
            return self.cache

        self.cache = self.fetch_data_from_mongodb()
        return self.cache

    def fetch_data_from_mongodb(self) -> [FingerPrint]:
        items = list(conn_db('fingerprint').find({}, {"name": 1, "human_rule": 1}))
        rules = []
        for item in items:
            rules.append({
                "name": item.get("name", ""),
                "human_rule": item.get("human_rule", "")
            })

        # MongoDB 为事实来源，回填 Redis 提升后续命中率
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
    finger_list = finger_db_cache.get_data()
    finger_name_list = []

    for finger in finger_list:
        try:
            if finger.identify(variables):
                finger_name_list.append(finger.app_name)
        except Exception as e:
            logger.warning("error on identify {} {}".format(finger.app_name, e))

    return finger_name_list


def have_human_rule_from_db(rule: str) -> bool:
    query = {
        "human_rule": rule,
    }

    if conn_db('fingerprint').find_one(query):
        return True
    else:
        return False
