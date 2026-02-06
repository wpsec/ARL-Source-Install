"""
MongoDB数据库连接和操作
"""
import urllib3
import time
import requests
from app.config import Config
from pymongo import MongoClient
from requests.exceptions import ReadTimeout

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


CONTENT_CHUNK_SIZE = 10 * 1024


UA = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"


proxies = {
    'https': "http://127.0.0.1:8080",
    'http': "http://127.0.0.1:8080"
}

SET_PROXY = False


# requests/models.py:824
def patch_content(response, timeout=None):
    """Content of the response, in bytes."""
    start_at = time.time()
    if response._content is False:
        # Read the contents.
        if response._content_consumed:
            raise RuntimeError("The content for this response was already consumed")

        if response.status_code == 0 or response.raw is None:
            response._content = None
        else:
            body = b''
            for part in response.iter_content(CONTENT_CHUNK_SIZE):
                body += part
                if timeout is not None and time.time() - start_at >= timeout:
                    raise ReadTimeout(f"patch_content read http response timeout: {timeout}")
            response._content = body
    response._content_consumed = True
    # don't need to release the connection; that's been handled by urllib3
    # since we exhausted the data.
    return response._content


def http_req(url, method='get', **kwargs):
    kwargs.setdefault('verify', False)
    kwargs.setdefault('timeout', (10.1, 30.1))
    kwargs.setdefault('allow_redirects', False)

    headers = kwargs.get("headers", {})
    headers.setdefault("User-Agent", UA)
    # 不允许缓存
    headers.setdefault("Cache-Control", "max-age=0")

    kwargs["headers"] = headers
    kwargs["stream"] = True

    if Config.PROXY_URL:
        proxies['https'] = Config.PROXY_URL
        proxies['http'] = Config.PROXY_URL
        kwargs["proxies"] = proxies

    conn = getattr(requests, method)(url, **kwargs)

    timeout = kwargs.get("timeout")
    if len(timeout) > 1 and timeout[1]:
        timeout = timeout[1]

    patch_content(conn, timeout)

    return conn


class ConnMongo(object):
    def __new__(self):
        if not hasattr(self, 'instance'):
            self.instance = super(ConnMongo, self).__new__(self)
            self.instance.conn = MongoClient(Config.MONGO_URL)
        return self.instance


class CachedCollectionProxy(object):
    """
    MongoDB Collection 代理

    说明：
    - 统一拦截写操作，在写成功后清理对应列表缓存
    - 保证新增/编辑/删除后，列表页刷新立即看到最新数据
    """
    WRITE_METHODS = {
        # 新版写接口
        "insert_one",
        "insert_many",
        "update_one",
        "update_many",
        "replace_one",
        "find_one_and_replace",
        "find_one_and_update",
        "find_one_and_delete",
        "delete_one",
        "delete_many",
        "bulk_write",
        # 兼容旧版 PyMongo 写接口（项目中仍有存量调用）
        "insert",
        "update",
        "remove",
        "save",
        "find_and_modify",
    }

    def __init__(self, collection_name, collection_obj):
        self.collection_name = collection_name
        self.collection_obj = collection_obj

    def _invalidate_collection_list_cache(self):
        """
        失效该集合对应的列表缓存
        """
        try:
            from app.utils.cache import cache_delete_by_prefix
            cache_delete_by_prefix("route:build_data:{}:".format(self.collection_name))
        except Exception:
            # 缓存失效异常不影响主流程
            pass

    def __getattr__(self, item):
        target = getattr(self.collection_obj, item)
        if item in self.WRITE_METHODS and callable(target):
            def _wrapped(*args, **kwargs):
                result = target(*args, **kwargs)
                self._invalidate_collection_list_cache()
                return result
            return _wrapped

        return target


def conn_db(collection, db_name=None):
    conn = ConnMongo().conn
    if db_name:
        collection_obj = conn[db_name][collection]
    else:
        collection_obj = conn[Config.MONGO_DB][collection]

    return CachedCollectionProxy(collection, collection_obj)
