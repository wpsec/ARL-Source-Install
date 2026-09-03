"""
MongoDB数据库连接和操作
"""
import urllib3
import threading
import time
import requests
from urllib.parse import urlparse
from app.config import Config
from pymongo import MongoClient
from requests.exceptions import ReadTimeout
from requests.adapters import HTTPAdapter
from .provider_http import (
    current_provider_context,
    current_stage_remaining_sec,
    provider_deadline_exceeded,
    provider_proxy_fallback_enabled,
    provider_timeout,
    record_request,
)

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


_PLAIN_POOL_ADAPTER = None
_PLAIN_POOL_LOCK = threading.Lock()


def _plain_pool_adapter():
    """普通 HTTP 路径共享的 urllib3 连接适配器(连接池)。

    为什么安全：
    - 每次请求仍使用新建 requests.Session 并挂接本适配器 → cookie/鉴权状态按请求隔离，
      与既有 `requests.get()` 语义一致，不会把上一个目标的 Set-Cookie 带给新目标;
    - 半读错误(读超时/断流)由 urllib3 `_error_catcher` 关闭并丢弃底层连接，池自愈，
      不会把脏连接归还后造成响应错位;
    - 直连 IP(connect_ip)与 provider 分支不经过此池：其连接目标与 DNS policy
      钉定语义强相关，按 `(类别 × 直连IP)` 分池需另行方案评审。

    注意：使用本适配器的 Session 不得调用 close()——requests 会连带关闭挂载的
    适配器从而摧毁共享连接池。
    """
    global _PLAIN_POOL_ADAPTER
    if _PLAIN_POOL_ADAPTER is None:
        with _PLAIN_POOL_LOCK:
            if _PLAIN_POOL_ADAPTER is None:
                try:
                    pool_connections = int(getattr(Config, "HTTP_POOL_CONNECTIONS", 10) or 10)
                except (TypeError, ValueError):
                    pool_connections = 10
                try:
                    pool_maxsize = int(getattr(Config, "HTTP_POOL_MAXSIZE", 64) or 64)
                except (TypeError, ValueError):
                    pool_maxsize = 64
                _PLAIN_POOL_ADAPTER = HTTPAdapter(
                    pool_connections=max(1, pool_connections),
                    pool_maxsize=max(1, pool_maxsize),
                )
    return _PLAIN_POOL_ADAPTER


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
            chunks = []
            for part in response.iter_content(CONTENT_CHUNK_SIZE):
                chunks.append(part)
                if timeout is not None and time.time() - start_at >= timeout:
                    raise ReadTimeout(f"patch_content read http response timeout: {timeout}")
                if provider_deadline_exceeded():
                    raise ReadTimeout("stage/provider deadline exceeded while reading response")
            response._content = b"".join(chunks)
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
    provider_context = current_provider_context()
    explicit_proxies = "proxies" in kwargs
    kwargs.setdefault('timeout', (10.1, 30.1))
    if provider_context:
        kwargs["timeout"] = provider_timeout(kwargs.get("timeout"))
    else:
        stage_remaining = current_stage_remaining_sec()
        if stage_remaining is not None:
            stage_timeout = max(0.001, stage_remaining)
            raw_timeout = kwargs.get("timeout")
            if isinstance(raw_timeout, (tuple, list)):
                values = []
                for value in raw_timeout[:2]:
                    try:
                        values.append(min(max(float(value), 0.1), stage_timeout))
                    except (TypeError, ValueError):
                        values.append(stage_timeout)
                kwargs["timeout"] = tuple(values or [stage_timeout])
            else:
                try:
                    kwargs["timeout"] = min(max(float(raw_timeout), 0.1), stage_timeout)
                except (TypeError, ValueError):
                    kwargs["timeout"] = stage_timeout
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

    if provider_context:
        # provider 请求由下方的直连/代理兜底循环决定，不能在这里提前写入默认代理。
        pass
    elif Config.PROXY_URL:
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
    provider_attempts = [None]
    if provider_context and not connect_ip and not explicit_proxies:
        try:
            retry_max = max(0, int(getattr(Config, "SEARCH_PROVIDER_RETRY_MAX", 1) or 0))
        except (TypeError, ValueError):
            retry_max = 1
        provider_attempts = [None] * (retry_max + 1)
        configured_proxy = str(getattr(Config, "PROXY_URL", "") or "").strip()
        if configured_proxy and provider_proxy_fallback_enabled():
            provider_attempts.append(configured_proxy)

    last_error = None
    for attempt_index, provider_proxy in enumerate(provider_attempts):
        session = None
        conn = None
        # pooled_session=True 的 Session 关闭会摧毁共享连接池，必须跳过 close()。
        pooled_session = False
        attempt_kwargs = dict(kwargs)
        using_provider_proxy = provider_context and provider_proxy is not None
        attempt_started = time.monotonic()
        if provider_context:
            attempt_kwargs["proxies"] = (
                {"http": provider_proxy, "https": provider_proxy}
                if using_provider_proxy
                else {"http": None, "https": None}
            )
        try:
            if provider_deadline_exceeded():
                raise requests.exceptions.Timeout("provider stage timeout")
            if connect_ip or provider_context:
                session = requests.Session()
                session.trust_env = False
                if connect_ip:
                    adapter = DirectIPHTTPAdapter(connect_ip=connect_ip, server_hostname=server_hostname)
                    session.mount("http://", adapter)
                    session.mount("https://", adapter)
                conn = session.request(request_method, url, **attempt_kwargs)
            else:
                session = requests.Session()
                session.trust_env = False
                pooled_adapter = _plain_pool_adapter()
                session.mount("http://", pooled_adapter)
                session.mount("https://", pooled_adapter)
                pooled_session = True
                conn = session.request(request_method, url, **attempt_kwargs)

            timeout = attempt_kwargs.get("timeout")
            if isinstance(timeout, (list, tuple)):
                if len(timeout) > 1 and timeout[1]:
                    timeout = timeout[1]

            patch_content(conn, timeout)
            elapsed = max(0.0, time.monotonic() - attempt_started)
            _remember_response_meta(conn)

            if waf_guard:
                waf_guard.observe_response(url, conn, module=waf_module)

            if provider_context:
                record_request(
                    success=True,
                    retry=attempt_index > 0,
                    proxy_fallback=using_provider_proxy,
                    elapsed_sec=elapsed,
                )

            if (connect_ip or provider_context) and conn is not None:
                conn.close()
            return conn
        except requests.exceptions.RequestException as exc:
            last_error = exc
            if provider_context:
                text = str(exc).lower()
                record_request(
                    success=False,
                    timeout=isinstance(exc, requests.exceptions.Timeout) or "timeout" in text,
                    retry=attempt_index > 0,
                    proxy_fallback=using_provider_proxy,
                    elapsed_sec=max(0.0, time.monotonic() - attempt_started),
                )
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            if session is not None and not pooled_session:
                session.close()
            retryable = isinstance(
                exc,
                (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.ConnectTimeout,
                ),
            )
            if not retryable and not using_provider_proxy:
                # 读取超时通常表示目标或 provider 已经接受连接，重复请求只会继续放大等待。
                raise
            if attempt_index + 1 >= len(provider_attempts):
                raise
        finally:
            if session is not None and not pooled_session:
                session.close()

    if last_error is not None:
        raise last_error
    raise requests.RequestException("provider request failed")


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
