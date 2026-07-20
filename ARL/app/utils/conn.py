"""
MongoDB数据库连接和操作
"""
import urllib3
import time
import requests
from urllib.parse import urlparse
from app.config import Config
from pymongo import MongoClient
from requests.exceptions import ReadTimeout
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


CONTENT_CHUNK_SIZE = 10 * 1024


UA = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"


class DirectIPHTTPAdapter(HTTPAdapter):
    """
    通过指定 IP 建立连接，同时保留原始域名用于 Host/SNI。
    """
    def __init__(self, connect_ip, server_hostname="", **kwargs):
        self.connect_ip = str(connect_ip or "").strip()
        self.server_hostname = str(server_hostname or "").strip()
        super().__init__(**kwargs)

    def get_connection(self, url, proxies=None):
        parsed = urlparse(url)
        scheme = str(parsed.scheme or "http").strip().lower() or "http"
        pool_kwargs = {}
        if scheme == "https" and self.server_hostname:
            pool_kwargs["server_hostname"] = self.server_hostname
            pool_kwargs["assert_hostname"] = self.server_hostname

        return self.poolmanager.connection_from_host(
            self.connect_ip,
            port=parsed.port,
            scheme=scheme,
            pool_kwargs=pool_kwargs,
        )


def _remember_response_meta(response):
    if response is None:
        return

    raw = getattr(response, "raw", None)
    version = getattr(raw, "version", None)
    if version == 10:
        response._arl_http_version = "1.0"
    else:
        response._arl_http_version = "1.1"

    response._arl_status = getattr(raw, "status", response.status_code)
    response._arl_reason = getattr(raw, "reason", getattr(response, "reason", ""))

    raw_headers = ""
    raw_fp = getattr(raw, "_fp", None)
    raw_fp_headers = getattr(raw_fp, "headers", None)
    if raw_fp_headers is not None:
        raw_headers = str(raw_fp_headers).strip()
    response._arl_raw_headers = raw_headers


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
    waf_guard = kwargs.pop("waf_guard", None)
    waf_module = kwargs.pop("waf_module", "")
    connect_ip = str(kwargs.pop("connect_ip", "") or "").strip()
    server_hostname = str(kwargs.pop("server_hostname", "") or "").strip()
    host_header = str(kwargs.pop("host_header", "") or "").strip()

    kwargs.setdefault('verify', False)
    kwargs.setdefault('timeout', (10.1, 30.1))
    kwargs.setdefault('allow_redirects', False)

    headers = kwargs.get("headers", {})
    headers.setdefault("User-Agent", UA)
    # 不允许缓存
    headers.setdefault("Cache-Control", "max-age=0")
    if connect_ip:
        parsed = urlparse(str(url or ""))
        if not host_header:
            host_header = str(parsed.netloc or "").strip()
        if host_header:
            headers.setdefault("Host", host_header)

    if waf_guard:
        should_skip, detail = waf_guard.should_skip(url, module=waf_module)
        if should_skip:
            return waf_guard.build_skip_response(url, detail)

        # WAF 试探绕过仅在守卫允许时生效，默认只给主动渗透链路加轻量 Header/节流参数。
        headers, waf_delay, _ = waf_guard.prepare_request(
            url,
            module=waf_module,
            method=method,
            headers=headers,
        )
        if waf_delay > 0:
            time.sleep(waf_delay)

    kwargs["headers"] = headers
    kwargs["stream"] = True

    if Config.PROXY_URL:
        _proxies = {
            'https': Config.PROXY_URL,
            'http': Config.PROXY_URL,
        }
        kwargs["proxies"] = _proxies
    else:
        # 未显式配置代理时，禁用 requests 环境变量代理，避免扫描链路被隐式转发
        # 导致“DNS 解析结果与实际连接目标”不一致。
        kwargs.setdefault("proxies", {"http": None, "https": None})

    if connect_ip:
        # 指定 connect_ip 时强制直连，避免代理再次按域名转发。
        kwargs["proxies"] = {"http": None, "https": None}

    request_method = str(method or "get").strip().lower() or "get"
    session = None
    conn = None
    try:
        if connect_ip:
            session = requests.Session()
            session.trust_env = False
            adapter = DirectIPHTTPAdapter(connect_ip=connect_ip, server_hostname=server_hostname)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            conn = session.request(request_method, url, **kwargs)
        else:
            conn = getattr(requests, request_method)(url, **kwargs)

        timeout = kwargs.get("timeout")
        if isinstance(timeout, (list, tuple)):
            if len(timeout) > 1 and timeout[1]:
                timeout = timeout[1]

        patch_content(conn, timeout)
        _remember_response_meta(conn)

        if waf_guard:
            waf_guard.observe_response(url, conn, module=waf_module)

        if connect_ip and conn is not None:
            conn.close()

        return conn
    finally:
        if session is not None:
            session.close()


class ConnMongo(object):
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(ConnMongo, cls).__new__(cls)
            cls.instance.conn = MongoClient(
                Config.MONGO_URL,
                maxPoolSize=Config.MONGO_MAX_POOL_SIZE,
                minPoolSize=Config.MONGO_MIN_POOL_SIZE,
                maxIdleTimeMS=Config.MONGO_MAX_IDLE_TIME_MS,
                serverSelectionTimeoutMS=Config.MONGO_SERVER_SELECTION_TIMEOUT_MS,
                connectTimeoutMS=Config.MONGO_CONNECT_TIMEOUT_MS,
                socketTimeoutMS=Config.MONGO_SOCKET_TIMEOUT_MS,
                retryWrites=True,
                retryReads=True,
            )
        return cls.instance


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
