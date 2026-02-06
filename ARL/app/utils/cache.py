"""
Redis 缓存通用工具

功能说明：
- 提供统一的 Redis 缓存读写接口
- 业务代码可通过 cached_call 快速接入缓存
- Redis 不可用时自动降级为直连数据库，不影响主流程
"""
import pickle
import hashlib
import logging

try:
    import redis
except Exception:
    redis = None

from app.config import Config
logger = logging.getLogger('arlv2')

_redis_client = None


def get_redis_client():
    """
    获取 Redis 客户端（单例懒加载）
    """
    global _redis_client
    if not Config.REDIS_ENABLE:
        return None
    if redis is None:
        return None
    if _redis_client is not None:
        return _redis_client

    try:
        _redis_client = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=Config.REDIS_DB,
            password=Config.REDIS_PASSWORD or None,
            decode_responses=False,
            socket_connect_timeout=2,
            socket_timeout=2
        )
        _redis_client.ping()
        return _redis_client
    except Exception as e:
        logger.warning("cache redis connect failed: {}".format(e))
        _redis_client = None
        return None


def build_cache_key(prefix, *parts):
    """
    构建缓存 key
    """
    raw = "{}:{}".format(prefix, ":".join([str(x) for x in parts]))
    # key 过长时做一次哈希压缩，避免 Redis key 过长影响性能
    if len(raw) > 180:
        digest = hashlib.md5(raw.encode("utf-8")).hexdigest()
        return "{}:md5:{}".format(prefix, digest)
    return raw


def cache_get_obj(key):
    """
    读取缓存对象
    """
    client = get_redis_client()
    if client is None:
        return None
    try:
        payload = client.get(key)
        if not payload:
            return None
        return pickle.loads(payload)
    except Exception as e:
        logger.warning("cache get error key:{} err:{}".format(key, e))
        return None


def cache_set_obj(key, value, expire=None):
    """
    写入缓存对象
    """
    client = get_redis_client()
    if client is None:
        return False
    try:
        payload = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        ttl = int(expire if expire is not None else Config.REDIS_CACHE_EXPIRE)
        if ttl > 0:
            client.setex(key, ttl, payload)
        else:
            client.set(key, payload)
        return True
    except Exception as e:
        logger.warning("cache set error key:{} err:{}".format(key, e))
        return False


def cache_delete_obj(key):
    """
    删除指定缓存
    """
    client = get_redis_client()
    if client is None:
        return False
    try:
        client.delete(key)
        return True
    except Exception as e:
        logger.warning("cache delete error key:{} err:{}".format(key, e))
        return False


def cached_call(key, loader, expire=None):
    """
    读取缓存，不命中时执行 loader 并回写缓存
    """
    data = cache_get_obj(key)
    if data is not None:
        return data

    data = loader()
    cache_set_obj(key, data, expire=expire)
    return data
