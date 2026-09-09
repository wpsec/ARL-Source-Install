"""ICP 查询适配、任务持久化和结果导出服务。

该模块只实现 ARL 内部需要的查询能力，不启动上游项目的 Web 服务，也不接受
客户端提供的任意 URL 或代理地址。外部请求由 Celery Worker 调用本模块完成。
"""

import base64
import binascii
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import io
import json
import random
import re
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
from bson import ObjectId
from flask import make_response
from requests.adapters import HTTPAdapter

from app import utils
from app.config import Config

try:
    import numpy as np
    from PIL import Image
except ImportError:  # pragma: no cover - 镜像构建前的最小导入路径
    np = None
    Image = None


logger = utils.get_logger()

ICP_QUERY_TYPES = {
    "web": {"label": "网站备案", "service_type": 1, "black": False},
    "app": {"label": "App备案", "service_type": 6, "black": False},
    "mapp": {"label": "小程序备案", "service_type": 7, "black": False},
    "kapp": {"label": "快应用备案", "service_type": 8, "black": False},
    "bweb": {"label": "违规域名", "service_type": 1, "black": True},
    "bapp": {"label": "违规App", "service_type": 6, "black": True},
    "bmapp": {"label": "违规小程序", "service_type": 7, "black": True},
    "bkapp": {"label": "违规快应用", "service_type": 8, "black": True},
}

ICP_QUERY_COLLECTION = "icp_query_task"
ICP_HISTORY_COLLECTION = "icp_query_history"
ICP_RESULT_COLLECTION = "icp_query_result"
ICP_LOG_COLLECTION = "icp_query_log"

ICP_HOME_URL = "https://beian.miit.gov.cn/"
ICP_AUTH_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
ICP_CAPTCHA_IMAGE_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/getCheckImagePoint"
ICP_CAPTCHA_CHECK_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/checkImage"
ICP_QUERY_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition"
ICP_BLACK_DOMAIN_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/blackListDomain/queryByCondition"
ICP_BLACK_APP_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/blackListDomain/queryByCondition_appAndMini"
ICP_DETAIL_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryDetailByAppAndMiniId"
ICP_ALLOWED_HOSTS = {"beian.miit.gov.cn", "hlwicpfwc.miit.gov.cn"}

ICP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36"
)
SENSITIVE_KEY_RE = re.compile(r"token|sign|cookie|authorization|password|secret|captcha|image", re.I)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r'''(?ix)
    (?P<prefix>
        ["']?\b(?:token|sign|authorization|cookie|password|secret)\b["']?
        \s*(?:=|:)\s*
    )
    (?P<quote>["']?)
    (?P<value>[^"'\s,;}\]]+)
    (?P=quote)
    '''
)
_INDEXES_READY = False


class IcpQueryError(Exception):
    """可展示给用户的 ICP 查询异常。"""

    def __init__(self, message, category="upstream_error", retryable=False):
        super().__init__(message)
        self.category = category
        self.retryable = retryable


class IcpBlockedError(IcpQueryError):
    def __init__(self, message="当前访问被上游风控拦截"):
        super().__init__(message, category="upstream_blocked", retryable=False)


class IcpTaskCancelled(IcpQueryError):
    def __init__(self):
        super().__init__("ICP 查询任务已取消", category="cancelled", retryable=False)


def _utc_now():
    return datetime.now(timezone.utc)


def _safe_int(value, default, minimum=0, maximum=None):
    try:
        resolved = int(value)
    except (TypeError, ValueError):
        return default
    if resolved < minimum:
        return default
    if maximum is not None and resolved > maximum:
        return maximum
    return resolved


def _config_int(name, default, minimum=1, maximum=None):
    return _safe_int(getattr(Config, name, default), default, minimum, maximum)


def _config_bool(name, default):
    value = getattr(Config, name, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _config_float(name, default, minimum=0.1, maximum=None):
    try:
        value = float(getattr(Config, name, default))
    except (TypeError, ValueError):
        return default
    if value < minimum:
        return default
    if maximum is not None and value > maximum:
        return maximum
    return value


def _redact_text(value, max_length=600):
    text = utils.safe_error_text(value, max_length=max_length)
    return SENSITIVE_ASSIGNMENT_RE.sub(
        lambda match: "{}{}[REDACTED]{}".format(
            match.group("prefix"), match.group("quote"), match.group("quote")
        ),
        text,
    )


def _network_error_kind(error):
    if isinstance(error, requests.exceptions.ProxyError):
        return "代理连接失败"
    if isinstance(error, requests.exceptions.SSLError):
        return "TLS 证书校验失败"
    if isinstance(error, requests.exceptions.ConnectionError):
        return "无法连接官方接口"
    return "请求传输失败"


def _safe_json_value(value, depth=0):
    if depth > 4:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, str):
            return value[:2000]
        return value
    if isinstance(value, (datetime, ObjectId)):
        return str(value)
    if isinstance(value, dict):
        return {
            str(key): _safe_json_value(item, depth + 1)
            for key, item in value.items()
            if not SENSITIVE_KEY_RE.search(str(key))
        }
    if isinstance(value, (list, tuple)):
        return [_safe_json_value(item, depth + 1) for item in list(value)[:500]]
    return str(value)[:2000]


def _validate_url(url):
    parsed = urlparse(str(url or ""))
    return parsed.scheme == "https" and parsed.hostname in ICP_ALLOWED_HOSTS


def _normalize_proxy_url(value, log_label="proxy"):
    value = str(value or "").strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        port = None
        parsed = None
    if (
        parsed is None
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or (port is not None and not 1 <= port <= 65535)
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        logger.warning("ICP query ignored invalid %s proxy configuration", log_label)
        return None
    return value


def _proxy_url():
    return _normalize_proxy_url(getattr(Config, "PROXY_URL", ""), "ARL")


def _icp_tunnel_url():
    return _normalize_proxy_url(
        getattr(Config, "ICP_QUERY_TUNNEL_URL", ""), "ICP tunnel"
    )


def _proxy_api_url():
    value = str(getattr(Config, "ICP_QUERY_EXTRA_API_URL", "") or "").strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        parsed = None
    if parsed is None or parsed.scheme not in {"http", "https"} or not parsed.hostname:
        logger.warning("ICP query ignored invalid extra proxy API configuration")
        return None
    return value


def _normalize_proxy_candidate(value):
    candidate = str(value or "").strip()
    if not candidate or candidate.startswith("#"):
        return None
    if "://" not in candidate:
        candidate = "http://{}".format(candidate)
    try:
        parsed = urlparse(candidate)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or port is None
        or not 1 <= port <= 65535
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        return None
    return candidate


def _discover_global_ipv6_addresses(output):
    addresses = []
    seen = set()
    for line in str(output or "").splitlines():
        if "scope global" not in line:
            continue
        match = re.search(r"\binet6\s+([^/\s]+)/\d+", line, re.I)
        if not match:
            continue
        value = match.group(1)
        try:
            address = ipaddress.IPv6Address(value)
        except ValueError:
            continue
        if (
            address.is_unspecified
            or address.is_loopback
            or address.is_link_local
            or address.is_private
            or address.is_multicast
        ):
            continue
        normalized = address.compressed
        if normalized not in seen:
            seen.add(normalized)
            addresses.append(normalized)
    return addresses


class IcpIpv6Pool(object):
    """按请求轮换本机 scope global IPv6；失败时保留直连回退。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._addresses = []
        self._cursor = 0
        self._loaded_at = 0.0

    def _refresh(self, refresh_sec):
        try:
            completed = subprocess.run(
                ["ip", "-6", "addr", "show"],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
            addresses = _discover_global_ipv6_addresses(completed.stdout)
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("ICP IPv6 address discovery failed: %s", _redact_text(exc))
            addresses = []
        if addresses:
            self._addresses = addresses
            self._cursor %= len(addresses)
        self._loaded_at = time.monotonic()

    def next_address(self, enabled, refresh_sec):
        if not enabled:
            return None
        with self._lock:
            now = time.monotonic()
            if not self._addresses or now - self._loaded_at >= refresh_sec:
                self._refresh(refresh_sec)
            if not self._addresses:
                return None
            address = self._addresses[self._cursor % len(self._addresses)]
            self._cursor += 1
            return address


class IcpSourceAddressAdapter(HTTPAdapter):
    """仅供 ICP Session 使用的源地址绑定适配器。"""

    def __init__(self, source_address, **kwargs):
        self.source_address = str(source_address or "").strip()
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["source_address"] = (self.source_address, 0)
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["source_address"] = (self.source_address, 0)
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class IcpProxyPool(object):
    """维护用户配置的 ICP 代理 API 结果，不抓取或生成第三方代理。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._api_url = None
        self._verify = None
        self._loaded_at = 0.0
        self._proxies = []

    @staticmethod
    def _fetch_candidates(api_url, timeout, verify):
        session = requests.Session()
        session.trust_env = False
        try:
            response = session.get(
                api_url,
                headers={"User-Agent": ICP_USER_AGENT, "Accept": "text/plain, */*"},
                timeout=(min(3.0, timeout), timeout),
                verify=verify,
                allow_redirects=False,
            )
            if response.status_code < 200 or response.status_code >= 300:
                logger.warning("ICP extra proxy API returned HTTP %s", response.status_code)
                return []
            candidates = []
            seen = set()
            for line in (response.text or "")[:1024 * 1024].splitlines():
                proxy = _normalize_proxy_candidate(line)
                if proxy and proxy not in seen:
                    seen.add(proxy)
                    candidates.append(proxy)
            return candidates
        except requests.exceptions.RequestException as exc:
            logger.warning("ICP extra proxy API request failed: %s", _network_error_kind(exc))
            return []
        finally:
            try:
                session.close()
            except Exception as exc:
                logger.debug("ICP proxy API session close failed: %s", _redact_text(exc))

    @staticmethod
    def _check_proxy(proxy, timeout, verify):
        session = requests.Session()
        session.trust_env = False
        try:
            response = session.get(
                ICP_HOME_URL,
                headers={"User-Agent": ICP_USER_AGENT},
                proxies={"http": proxy, "https": proxy},
                timeout=(min(3.0, timeout), timeout),
                verify=verify,
                allow_redirects=False,
            )
            body = (response.text or "")[:4096]
            if "当前访问疑似黑客攻击" in body or "当前访问已被创宇盾拦截" in body:
                return None
            if 200 <= response.status_code < 300:
                return proxy
        except requests.exceptions.RequestException:
            return None
        finally:
            try:
                session.close()
            except Exception as exc:
                logger.debug("ICP proxy check session close failed: %s", _redact_text(exc))
        return None

    def _reload(self, api_url, verify, refresh_sec, pool_size, check_enabled, timeout, concurrency):
        candidates = self._fetch_candidates(api_url, timeout, verify)
        candidates = candidates[: max(pool_size * 2, pool_size)]
        if check_enabled and candidates:
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                checked = executor.map(
                    lambda proxy: self._check_proxy(proxy, timeout, verify), candidates
                )
                candidates = [proxy for proxy in checked if proxy]
        self._api_url = api_url
        self._verify = verify
        self._loaded_at = time.monotonic()
        self._proxies = candidates[:pool_size]
        if self._proxies:
            logger.info("ICP extra proxy pool refreshed count=%s", len(self._proxies))
        else:
            logger.warning("ICP extra proxy pool is empty")

    def choose(self, api_url, verify, refresh_sec, pool_size, check_enabled, timeout, concurrency):
        if not api_url:
            with self._lock:
                self._api_url = None
                self._proxies = []
            return None
        with self._lock:
            now = time.monotonic()
            if (
                api_url != self._api_url
                or verify != self._verify
                or self._loaded_at == 0
                or now - self._loaded_at >= refresh_sec
            ):
                self._reload(
                    api_url,
                    verify,
                    refresh_sec,
                    pool_size,
                    check_enabled,
                    timeout,
                    concurrency,
                )
            if not self._proxies:
                return None
            return random.choice(self._proxies)


_ICP_IPV6_POOL = IcpIpv6Pool()
_ICP_PROXY_POOL = IcpProxyPool()


def _request_config():
    return {
        "timeout": _config_int("ICP_QUERY_TIMEOUT_SEC", 30, minimum=5, maximum=180),
        "retry": _config_int("ICP_QUERY_RETRY", 2, minimum=0, maximum=5),
        "page_size": _config_int("ICP_QUERY_PAGE_SIZE", 26, minimum=1, maximum=26),
        "max_pages": _config_int("ICP_QUERY_MAX_PAGES", 100, minimum=1, maximum=500),
        # SSL 与出口设置只在 ICP Session 内生效，不改变其它扫描模块。
        "tls_verify": _config_bool("ICP_QUERY_TLS_VERIFY", True),
        "ipv6_enable": _config_bool("ICP_QUERY_IPV6_ENABLE", False),
        "ipv6_refresh_sec": _config_int(
            "ICP_QUERY_IPV6_REFRESH_SEC", 60, minimum=5, maximum=3600
        ),
        "extra_api_refresh_sec": _config_int(
            "ICP_QUERY_EXTRA_API_REFRESH_SEC", 180, minimum=5, maximum=86400
        ),
        "extra_api_pool_size": _config_int(
            "ICP_QUERY_EXTRA_API_POOL_SIZE", 20, minimum=1, maximum=200
        ),
        "extra_api_check": _config_bool("ICP_QUERY_EXTRA_API_CHECK", True),
        "extra_api_check_timeout_sec": _config_float(
            "ICP_QUERY_EXTRA_API_CHECK_TIMEOUT_SEC", 5.0, minimum=1.0, maximum=30.0
        ),
        "extra_api_check_concurrency": _config_int(
            "ICP_QUERY_EXTRA_API_CHECK_CONCURRENCY", 4, minimum=1, maximum=32
        ),
    }


def _select_icp_proxy(config):
    """按 ICP 专用优先级选择出口：代理池、固定隧道、既有 ARL 代理。"""
    tunnel = _icp_tunnel_url() or _proxy_url()
    api_url = _proxy_api_url()
    if not api_url:
        return tunnel
    return _ICP_PROXY_POOL.choose(
        api_url,
        config["tls_verify"],
        config["extra_api_refresh_sec"],
        config["extra_api_pool_size"],
        config["extra_api_check"],
        config["extra_api_check_timeout_sec"],
        config["extra_api_check_concurrency"],
    ) or tunnel


class IcpQueryEngine(object):
    """官方 ICP 查询协议的最小 ARL 适配实现。"""

    def __init__(self, session_factory=None):
        self.session_factory = session_factory or requests.Session
        self.config = _request_config()
        self.proxy = _proxy_url()

    def _session(self):
        session = self.session_factory()
        self.proxy = _select_icp_proxy(self.config)
        session.trust_env = False
        session.headers.update({
            "User-Agent": ICP_USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Origin": ICP_HOME_URL.rstrip("/"),
            "Referer": ICP_HOME_URL,
            "Cache-Control": "no-cache",
            "Cookie": "__jsluid_s={}".format(uuid.uuid4().hex),
        })
        ipv6_address = _ICP_IPV6_POOL.next_address(
            self.config["ipv6_enable"], self.config["ipv6_refresh_sec"]
        )
        if ipv6_address and callable(getattr(session, "mount", None)):
            adapter = IcpSourceAddressAdapter(ipv6_address)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
        return session

    def _request(
        self,
        session,
        method,
        url,
        *,
        json_body=None,
        form_body=None,
        headers=None,
        operation="接口请求",
    ):
        if not _validate_url(url):
            raise IcpQueryError("ICP 请求目标不在允许范围内", category="policy_error")

        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        try:
            response = session.request(
                method,
                url,
                json=json_body,
                data=form_body,
                headers=headers or {},
                proxies=proxies,
                timeout=(min(10, self.config["timeout"]), self.config["timeout"]),
                verify=self.config["tls_verify"],
                allow_redirects=False,
            )
        except requests.exceptions.Timeout as exc:
            logger.warning("ICP upstream timeout operation=%s", operation)
            raise IcpQueryError(
                "ICP 接口请求超时（{}）".format(operation),
                category="timeout",
                retryable=True,
            ) from exc
        except requests.exceptions.RequestException as exc:
            error_kind = _network_error_kind(exc)
            logger.warning(
                "ICP upstream request failed operation=%s kind=%s",
                operation,
                error_kind,
            )
            raise IcpQueryError(
                "ICP 接口网络请求失败（{}）".format(error_kind),
                category="network_error",
                retryable=True,
            ) from exc

        text = response.text or ""
        if "当前访问疑似黑客攻击" in text or "当前访问已被创宇盾拦截" in text:
            raise IcpBlockedError()
        if response.status_code < 200 or response.status_code >= 300:
            retryable_statuses = {408, 425, 429}
            is_rate_limited = response.status_code == 429
            raise IcpQueryError(
                "ICP 接口访问频率受限，请稍后重试"
                if is_rate_limited
                else "ICP 接口返回 HTTP {}".format(response.status_code),
                category="rate_limited" if is_rate_limited else "upstream_http_error",
                retryable=response.status_code in retryable_statuses or response.status_code >= 500,
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise IcpQueryError("ICP 接口返回格式异常", category="invalid_response") from exc
        if not isinstance(payload, dict):
            raise IcpQueryError("ICP 接口返回格式异常", category="invalid_response")
        return payload

    @staticmethod
    def _base_headers():
        return {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Origin": ICP_HOME_URL.rstrip("/"),
            "Referer": ICP_HOME_URL,
        }

    def _get_token(self, session):
        timestamp = int(time.time() * 1000)
        auth_key = hashlib.md5(("testtest" + str(timestamp)).encode("utf-8")).hexdigest()
        payload = self._request(
            session,
            "POST",
            ICP_AUTH_URL,
            form_body={"authKey": auth_key, "timeStamp": timestamp},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            operation="获取访问凭证",
        )
        params = payload.get("params") if isinstance(payload, dict) else None
        token = params.get("bussiness") if isinstance(params, dict) else None
        if not token:
            raise IcpQueryError("ICP 接口未返回访问令牌", category="auth_error", retryable=True)
        expire = _safe_int(params.get("expire"), 0) if isinstance(params, dict) else 0
        return str(token), max(0, expire)

    @staticmethod
    def _client_uid():
        return "point-{}".format(uuid.uuid4())

    @staticmethod
    def _slider_offset(small_image_b64, big_image_b64):
        if Image is None or np is None:
            raise IcpQueryError("ICP 验证码图像依赖未安装", category="dependency_error")
        try:
            def decode_image(value):
                encoded = str(value or "")
                if encoded.startswith("data:") and "," in encoded:
                    encoded = encoded.split(",", 1)[1]
                return base64.b64decode(encoded)

            small_bytes = decode_image(small_image_b64)
            big_bytes = decode_image(big_image_b64)
            with Image.open(io.BytesIO(small_bytes)) as small_image:
                small_width, small_height = small_image.size
            with Image.open(io.BytesIO(big_bytes)) as big_image:
                pixels = np.asarray(big_image.convert("RGB"), dtype=np.int16)
        except (binascii.Error, ValueError, OSError) as exc:
            raise IcpQueryError("验证码图片无法解析", category="captcha_error") from exc

        if (
            small_width <= 0
            or small_height <= 0
            or pixels.ndim != 3
            or pixels.shape[0] < small_height
            or pixels.shape[1] < small_width
        ):
            raise IcpQueryError("验证码图片尺寸异常", category="captcha_error")

        # 上游验证码缺口是量化后的连续色块；使用纵向连续长度找候选矩形，
        # 比固定横向窗口更能适配缺口边缘和图片压缩噪声。
        resized = pixels[::2, ::2]
        height, width = resized.shape[:2]
        if height == 0 or width == 0:
            raise IcpQueryError("验证码图片尺寸异常", category="captcha_error")
        min_side = max(1, int(min(small_width, small_height) * 0.25))
        skip_left = min(width, max(0, small_width // 4))
        good_enough = (min_side * min_side * 3) // 2
        quantized = resized.astype(np.int32) & ~3
        color_id = quantized[:, :, 0] + quantized[:, :, 1] * 256 + quantized[:, :, 2] * 65536
        colors, counts = np.unique(color_id, return_counts=True)
        if not len(colors):
            raise IcpQueryError("未找到验证码缺口", category="captcha_error", retryable=True)
        candidates = colors[np.argsort(counts)[-min(3, len(colors)):]]
        best_area = 0
        best_x = 0
        column_run = np.empty((height, width), dtype=np.int32)
        for color in candidates:
            mask = color_id == color
            column_run[0] = mask[0]
            for row_index in range(1, height):
                column_run[row_index] = (column_run[row_index - 1] + 1) * mask[row_index]
            for row_index in range(min_side, height):
                row = column_run[row_index]
                x = skip_left
                while x < width:
                    if row[x] < min_side:
                        x += 1
                        continue
                    start = x
                    while x < width and row[x] >= min_side:
                        x += 1
                    run_width = x - start
                    run_height = int(row[start])
                    if run_height <= 0:
                        continue
                    ratio = run_width / run_height
                    area = run_width * run_height
                    if 0.7 < ratio < 1.4 and area > best_area:
                        best_area = area
                        best_x = start
                        if best_area >= good_enough:
                            return int(best_x * 2)
        if best_area <= 0:
            raise IcpQueryError("未找到验证码缺口", category="captcha_error", retryable=True)
        return int(best_x * 2)

    def _get_captcha(self, session, token):
        payload = self._request(
            session,
            "POST",
            ICP_CAPTCHA_IMAGE_URL,
            json_body={"clientUid": self._client_uid()},
            headers={**self._base_headers(), "token": token},
            operation="获取验证码",
        )
        params = payload.get("params") if isinstance(payload, dict) else None
        if not isinstance(params, dict):
            raise IcpQueryError("ICP 验证码响应缺少参数", category="captcha_error", retryable=True)
        captcha_uuid = params.get("uuid")
        offset = self._slider_offset(params.get("smallImage", ""), params.get("bigImage", ""))
        check_payload = self._request(
            session,
            "POST",
            ICP_CAPTCHA_CHECK_URL,
            json_body={"key": captcha_uuid, "value": str(offset)},
            headers={**self._base_headers(), "token": token},
            operation="校验验证码",
        )
        if not check_payload.get("success"):
            raise IcpQueryError("验证码识别失败", category="captcha_error", retryable=True)
        sign = check_payload.get("params")
        if not captcha_uuid or not sign:
            raise IcpQueryError("验证码校验响应异常", category="captcha_error", retryable=True)
        return str(captcha_uuid), str(sign)

    def _query_once(self, session, query_type, keyword, page, page_size):
        type_info = ICP_QUERY_TYPES[query_type]
        token, _expire = self._get_token(session)
        captcha_uuid, sign = self._get_captcha(session, token)
        headers = {
            **self._base_headers(),
            "token": token,
            "uuid": captcha_uuid,
            "sign": sign,
        }
        if type_info["black"]:
            if query_type == "bweb":
                body = {"domainName": keyword}
                endpoint = ICP_BLACK_DOMAIN_URL
            else:
                body = {"serviceName": keyword, "serviceType": type_info["service_type"]}
                endpoint = ICP_BLACK_APP_URL
        else:
            body = {
                "pageNum": page,
                "pageSize": page_size,
                "unitName": keyword,
                "serviceType": type_info["service_type"],
            }
            endpoint = ICP_QUERY_URL
        raw = self._request(
            session,
            "POST",
            endpoint,
            json_body=body,
            headers=headers,
            operation="提交查询",
        )
        return raw, token, captcha_uuid, sign

    def _query_detail(self, session, item, query_type, token, captcha_uuid, sign):
        data_id = item.get("dataId") if isinstance(item, dict) else None
        if not data_id:
            return item
        service_type = ICP_QUERY_TYPES[query_type]["service_type"]
        try:
            result = self._request(
                session,
                "POST",
                ICP_DETAIL_URL,
                json_body={"dataId": data_id, "serviceType": service_type},
                headers={
                    **self._base_headers(),
                    "token": token,
                    "uuid": captcha_uuid,
                    "sign": sign,
                },
                operation="获取详情",
            )
            detail = result.get("params") if isinstance(result, dict) else None
            return detail if isinstance(detail, dict) else item
        except IcpQueryError as exc:
            logger.warning("ICP detail lookup failed category=%s", exc.category)
            return item

    def query_page(self, query_type, keyword, page=1, page_size=None):
        query_type = _validate_query_type(query_type)
        keyword = _validate_keyword(keyword)
        page = _safe_int(page, 1, 1, self.config["max_pages"])
        page_size = _safe_int(page_size, self.config["page_size"], 1, 26)
        attempts = self.config["retry"] + 1
        last_error = None
        for attempt in range(attempts):
            session = self._session()
            try:
                raw, token, captcha_uuid, sign = self._query_once(
                    session, query_type, keyword, page, page_size
                )
                params = raw.get("params") if isinstance(raw, dict) else None
                if isinstance(params, dict):
                    records = params.get("list") or []
                    total = _safe_int(params.get("total"), len(records), 0)
                elif isinstance(params, list):
                    records = params
                    total = len(records)
                else:
                    records = []
                    total = 0
                code = _safe_int(raw.get("code"), 200 if raw.get("success") else 500, 0)
                if raw.get("success") is False or code not in (0, 200):
                    raise IcpQueryError(
                        _redact_text(raw.get("message") or raw.get("msg") or "上游查询失败"),
                        category="upstream_error",
                        retryable=True,
                    )
                if not isinstance(records, list):
                    records = []
                if query_type in {"app", "mapp", "kapp"}:
                    records = [
                        self._query_detail(session, record, query_type, token, captcha_uuid, sign)
                        for record in records
                    ]
                return {
                    "query_type": query_type,
                    "keyword": keyword,
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "records": [normalize_record(item, query_type) for item in records if isinstance(item, dict)],
                    "raw_code": code,
                }
            except IcpQueryError as exc:
                last_error = exc
                if not exc.retryable or attempt >= attempts - 1:
                    raise
                time.sleep(min(2.0, 0.25 * (attempt + 1)))
            finally:
                try:
                    session.close()
                except Exception as exc:
                    logger.debug("ICP session close failed: %s", _redact_text(exc))
        raise last_error or IcpQueryError("ICP 查询失败")

    def query_all_pages(self, query_type, keyword, cancel_check=None):
        if callable(cancel_check) and cancel_check():
            raise IcpTaskCancelled()
        first = self.query_page(query_type, keyword, page=1)
        if ICP_QUERY_TYPES[query_type]["black"]:
            first["page_count"] = 1
            return first
        all_records = list(first["records"])
        page = 1
        page_count = 1
        while len(all_records) < first["total"] and len(first["records"]) >= first["page_size"]:
            if callable(cancel_check) and cancel_check():
                raise IcpTaskCancelled()
            page += 1
            if page > self.config["max_pages"]:
                first["truncated"] = True
                break
            current = self.query_page(query_type, keyword, page=page, page_size=first["page_size"])
            all_records.extend(current["records"])
            page_count += 1
            if not current["records"]:
                break
        first["records"] = all_records
        first["page"] = 1
        first["page_count"] = page_count
        first["total"] = max(first["total"], len(all_records))
        return first


def normalize_record(record, query_type):
    """将不同 ICP 类型的响应转换为可持久化的稳定结构。"""
    source = _safe_json_value(record)
    if not isinstance(source, dict):
        source = {}
    aliases = {
        "company_name": ("unitName", "companyName", "unitname", "主体名称", "单位名称"),
        "domain": ("domainName", "domain", "网站域名", "域名"),
        "service_name": ("serviceName", "appName", "名称", "服务名称"),
        "license_number": (
            "licenseNo",
            "mainLicence",
            "serviceLicence",
            "mainLicense",
            "serviceLicense",
            "备案号",
            "备案编号",
        ),
        "record_status": ("status", "natureName", "状态", "备案状态"),
        "website": ("url", "webSite", "website", "网站首页"),
        "province": ("province", "provinceName", "省份"),
        "city": ("city", "cityName", "城市"),
        "update_time": ("updateRecordTime", "updateTime", "updateDate", "更新时间"),
    }
    normalized = {"record_type": query_type}
    used = set()
    for target, candidates in aliases.items():
        for key in candidates:
            if key in source and source[key] not in (None, "", []):
                normalized[target] = source[key]
                used.add(key)
                break
    normalized["extra"] = {
        key: value
        for key, value in source.items()
        if key not in used and key != "dataId" and not SENSITIVE_KEY_RE.search(key)
    }
    return normalized


def _validate_keyword(value):
    if not isinstance(value, str):
        raise IcpQueryError("查询关键词必须是文本", category="validation_error")
    keyword = value.strip()
    max_length = _config_int("ICP_QUERY_KEYWORD_MAX_LENGTH", 255, 1, 1000)
    if not keyword:
        raise IcpQueryError("查询关键词为空", category="validation_error")
    if len(keyword) > max_length:
        raise IcpQueryError("查询关键词长度超限", category="validation_error")
    if re.search(r"[\x00-\x1f\x7f]", keyword):
        raise IcpQueryError("查询关键词包含非法控制字符", category="validation_error")
    return keyword


def _validate_query_type(query_type):
    resolved = str(query_type or "").strip().lower()
    if resolved not in ICP_QUERY_TYPES:
        raise IcpQueryError("不支持的 ICP 查询类型", category="validation_error")
    return resolved


def _parse_history_time(value, end=False):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        resolved = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IcpQueryError("历史时间参数格式错误", category="validation_error") from exc
    if resolved.tzinfo is None:
        resolved = resolved.replace(tzinfo=timezone.utc)
    if end and len(text) == 10:
        resolved += timedelta(days=1)
    return resolved.astimezone(timezone.utc)


def _task_collection():
    return utils.conn_db(ICP_QUERY_COLLECTION)


def _history_collection():
    return utils.conn_db(ICP_HISTORY_COLLECTION)


def _result_collection():
    return utils.conn_db(ICP_RESULT_COLLECTION)


def _log_collection():
    return utils.conn_db(ICP_LOG_COLLECTION)


def _serialize(value, field_name=""):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {
            str(key): _serialize(item, str(key))
            for key, item in value.items()
            if str(key) != "_id" and not SENSITIVE_KEY_RE.search(str(key))
        }
    if isinstance(value, list):
        return [_serialize(item, field_name) for item in value]
    if isinstance(value, str):
        if field_name.lower() in {"message", "error_message", "error_summary"}:
            return _redact_text(value)
        return value
    return value


def _task_status_payload(task):
    if not task:
        return None
    payload = _serialize(dict(task))
    payload.pop("_id", None)
    return payload


def _write_log(level, event, message, task_id="", history_id=""):
    safe_message = _redact_text(message, 1000)
    item = {
        "level": str(level or "INFO").upper(),
        "event": str(event or "icp_query"),
        "task_id": str(task_id or ""),
        "history_id": str(history_id or ""),
        "message": safe_message,
        "created_at": _utc_now(),
        "expires_at": _utc_now() + timedelta(days=_config_int("ICP_QUERY_LOG_RETENTION_DAYS", 7, 1, 365)),
    }
    try:
        _log_collection().insert_one(item)
    except Exception as exc:
        logger.warning("persist ICP log failed: %s", _redact_text(exc))


def _new_task(kind, query_type, keywords):
    ensure_indexes()
    task_id = uuid.uuid4().hex
    now = _utc_now()
    item_list = [
        {
            "item_id": uuid.uuid4().hex,
            "keyword": keyword,
            "status": "queued",
            "history_id": "",
            "result_count": 0,
            "error_category": "",
            "error_message": "",
        }
        for keyword in keywords
    ]
    task = {
        "task_id": task_id,
        "task_kind": kind,
        "query_type": query_type,
        "status": "queued",
        "total": len(item_list),
        "queued_count": len(item_list),
        "running_count": 0,
        "succeeded_count": 0,
        "empty_count": 0,
        "failed_count": 0,
        "cancelled_count": 0,
        "cancel_requested": False,
        "items": item_list,
        "created_at": now,
        "started_at": None,
        "finished_at": None,
        "error_summary": "",
        "expires_at": now + timedelta(days=_config_int("ICP_QUERY_HISTORY_RETENTION_DAYS", 30, 1, 365)),
    }
    _task_collection().insert_one(task)
    _write_log("INFO", "task_created", "创建 ICP 查询任务", task_id=task_id)
    return task


def mark_task_dispatch_failed(task_id, error):
    """记录消息投递失败，避免 API 异常后留下永久 queued 任务。"""
    safe_message = _redact_text(error)
    try:
        _task_collection().update_one(
            {"task_id": str(task_id or "").strip()},
            {
                "$set": {
                    "error_summary": "ICP 任务投递失败: {}".format(safe_message),
                    "items.$[item].status": "failed",
                    "items.$[item].error_category": "dispatch_error",
                    "items.$[item].error_message": safe_message,
                }
            },
            array_filters=[{"item.status": {"$in": ["queued", "running"]}}],
        )
        _recount_task(str(task_id or "").strip())
    except Exception as exc:
        logger.error("mark ICP dispatch failure failed task_id=%s error=%s", task_id, _redact_text(exc))


def dispatch_task(task_id):
    """将 ICP 任务投递到现有 arlweb 队列，并记录恢复所需的派发元数据。"""
    safe_task_id = str(task_id or "").strip()
    try:
        from app import celerytask

        async_result = celerytask.run_icp_query_task.apply_async(
            args=[safe_task_id],
            queue="arlweb",
        )
    except Exception as exc:
        mark_task_dispatch_failed(safe_task_id, exc)
        raise

    dispatch_ts = int(time.time())
    try:
        _task_collection().update_one(
            {"task_id": safe_task_id},
            {
                "$set": {
                    "celery_id": str(getattr(async_result, "id", "") or ""),
                    "dispatch_queue": "arlweb",
                    "dispatch_time": _utc_now(),
                    "dispatch_ts": dispatch_ts,
                }
            },
        )
    except Exception as exc:
        # 消息已经进入 broker，元数据写失败时保留任务执行机会，并把异常写入日志供恢复排查。
        logger.error("record ICP dispatch metadata failed task_id=%s error=%s", safe_task_id, _redact_text(exc))
    return async_result


def mark_task_started(task_id, celery_id):
    """由 Worker 消费消息时补写真实 task id，避免投递元数据写入失败造成重复恢复。"""
    safe_task_id = str(task_id or "").strip()
    safe_celery_id = str(celery_id or "").strip()
    if not safe_task_id or not safe_celery_id:
        return
    try:
        _task_collection().update_one(
            {
                "task_id": safe_task_id,
                "status": {"$in": ["queued", "running"]},
                "$or": [
                    {"celery_id": {"$in": ["", None]}},
                    {"celery_id": safe_celery_id},
                ],
            },
            {
                "$set": {
                    "status": "running",
                    "celery_id": safe_celery_id,
                    "started_at": _utc_now(),
                }
            },
        )
    except Exception as exc:
        logger.warning("mark ICP task started failed task_id=%s error=%s", safe_task_id, _redact_text(exc))


def create_single_task(query_type, keyword, page=1, page_size=26):
    query_type = _validate_query_type(query_type)
    task = _new_task("single", query_type, [_validate_keyword(keyword)])
    _task_collection().update_one(
        {"task_id": task["task_id"]},
        {"$set": {"requested_page": _safe_int(page, 1, 1, 500), "requested_page_size": _safe_int(page_size, 26, 1, 26)}},
    )
    return get_task(task["task_id"])


def create_batch_task(query_type, keywords):
    query_type = _validate_query_type(query_type)
    if not isinstance(keywords, (list, tuple)):
        raise IcpQueryError("批量关键词必须是数组", category="validation_error")
    max_items = _config_int("ICP_QUERY_MAX_ITEMS", 200, 1, 10000)
    cleaned = []
    seen = set()
    for value in keywords:
        if not isinstance(value, str):
            raise IcpQueryError("批量关键词必须是文本", category="validation_error")
        keyword = value.strip()
        if not keyword or keyword in seen:
            continue
        keyword = _validate_keyword(keyword)
        seen.add(keyword)
        cleaned.append(keyword)
        if len(cleaned) > max_items:
            raise IcpQueryError("批量查询最多支持 {} 条".format(max_items), category="validation_error")
    if not cleaned:
        raise IcpQueryError("批量查询内容为空", category="validation_error")
    return _new_task("batch", query_type, cleaned)


def get_task(task_id):
    return _task_collection().find_one({"task_id": str(task_id or "").strip()})


def list_tasks(page=1, size=20, status=""):
    query = {"task_kind": "batch"}
    if status:
        query["status"] = status
    page = _safe_int(page, 1, 1, 100000)
    size = _safe_int(size, 20, 1, 100)
    collection = _task_collection()
    total = collection.count_documents(query)
    items = list(collection.find(query).sort("created_at", -1).skip((page - 1) * size).limit(size))
    return {"items": [_task_status_payload(item) for item in items], "total": total, "page": page, "size": size}


def list_history(page=1, size=20, query_type="", keyword="", status="", created_from="", created_to=""):
    query = {}
    if query_type:
        query["query_type"] = query_type
    if keyword:
        query["keyword"] = {"$regex": re.escape(keyword), "$options": "i"}
    if status:
        query["status"] = status
    start_time = _parse_history_time(created_from)
    end_time = _parse_history_time(created_to, end=True)
    if start_time or end_time:
        query["created_at"] = {}
        if start_time:
            query["created_at"]["$gte"] = start_time
        if end_time:
            query["created_at"]["$lt"] = end_time
    page = _safe_int(page, 1, 1, 100000)
    size = _safe_int(size, 20, 1, 100)
    collection = _history_collection()
    total = collection.count_documents(query)
    items = list(collection.find(query).sort("created_at", -1).skip((page - 1) * size).limit(size))
    return {"items": [_serialize(item) for item in items], "total": total, "page": page, "size": size}


def get_history(history_id):
    return _history_collection().find_one({"history_id": str(history_id or "").strip()})


def get_history_results(history_id, page=1, size=50):
    page = _safe_int(page, 1, 1, 100000)
    size = _safe_int(size, 50, 1, 200)
    query = {"history_id": str(history_id or "").strip()}
    collection = _result_collection()
    total = collection.count_documents(query)
    items = list(collection.find(query).sort([("page", 1), ("order", 1)]).skip((page - 1) * size).limit(size))
    return {"items": [_serialize(item) for item in items], "total": total, "page": page, "size": size}


def _save_history(task_id, item, result=None, status="succeeded", error=None):
    now = _utc_now()
    history_id = uuid.uuid4().hex
    records = list((result or {}).get("records") or [])
    query_type = item.get("query_type") or ((result or {}).get("query_type") or "")
    history = {
        "history_id": history_id,
        "task_id": str(task_id),
        "batch_item_id": str(item.get("item_id") or ""),
        "query_type": query_type,
        "keyword": item.get("keyword", ""),
        "status": status,
        "result_count": len(records),
        "page_count": _safe_int((result or {}).get("page_count"), 1, 1),
        "total": _safe_int((result or {}).get("total"), len(records), 0),
        "created_at": now,
        "finished_at": now,
        "error_category": getattr(error, "category", "") if error else "",
        "error_message": _redact_text(error) if error else "",
        "expires_at": now + timedelta(days=_config_int("ICP_QUERY_HISTORY_RETENTION_DAYS", 30, 1, 365)),
    }
    _history_collection().insert_one(history)
    if records:
        result_docs = []
        for index, record in enumerate(records):
            safe_record = _safe_json_value(record)
            if not isinstance(safe_record, dict):
                safe_record = {}
            result_docs.append({
                **safe_record,
                "history_id": history_id,
                "page": _safe_int((result or {}).get("page"), 1, 1),
                "order": index,
                "expires_at": history["expires_at"],
            })
        _result_collection().insert_many(result_docs)
    _write_log("INFO" if status in {"succeeded", "empty"} else "WARNING", "history_saved", "保存 ICP 查询历史", task_id, history_id)
    return history


def _save_failure_history(task_id, item, error):
    try:
        return _save_history(task_id, item, {}, "failed", error)
    except Exception as exc:
        logger.error(
            "persist ICP failure history failed task_id=%s error=%s",
            task_id,
            _redact_text(exc),
        )
        _write_log(
            "ERROR",
            "history_save_failed",
            "ICP 失败历史保存异常: {}".format(_redact_text(exc)),
            task_id=task_id,
        )
        return None


def _update_item(task_id, item_id, status, **values):
    update = {"items.$.status": status}
    update.update({"items.$.{}".format(key): value for key, value in values.items()})
    _task_collection().update_one({"task_id": task_id, "items.item_id": item_id}, {"$set": update})


def _set_task_error_summary(task_id, message):
    """保留首个可展示错误，避免批量任务被后续错误覆盖。"""
    safe_message = _redact_text(message)
    try:
        _task_collection().update_one(
            {
                "task_id": task_id,
                "$or": [
                    {"error_summary": {"$exists": False}},
                    {"error_summary": None},
                    {"error_summary": ""},
                ],
            },
            {"$set": {"error_summary": safe_message}},
        )
    except Exception as exc:
        logger.warning(
            "set ICP task error summary failed task_id=%s error=%s",
            task_id,
            _redact_text(exc),
        )


def _is_task_cancel_requested(task_id):
    try:
        task = get_task(task_id)
    except Exception as exc:
        logger.warning("read ICP task cancellation state failed task_id=%s error=%s", task_id, _redact_text(exc))
        return False
    return bool(task and task.get("cancel_requested"))


def _recount_task(task_id):
    task = get_task(task_id)
    if not task:
        return None
    counts = {"queued": 0, "running": 0, "succeeded": 0, "empty": 0, "failed": 0, "cancelled": 0}
    for item in task.get("items", []):
        status = str(item.get("status", "queued"))
        if status in counts:
            counts[status] += 1
    terminal = counts["succeeded"] + counts["empty"] + counts["failed"] + counts["cancelled"]
    status = task.get("status", "queued")
    if terminal >= len(task.get("items", [])):
        if task.get("cancel_requested") and counts["cancelled"]:
            status = "cancelled"
        elif counts["failed"] and counts["succeeded"] + counts["empty"]:
            status = "partial"
        elif counts["failed"]:
            status = "failed"
        else:
            status = "succeeded"
    elif counts["running"]:
        status = "running"
    elif counts["queued"]:
        status = "queued"
    update = {
        "status": status,
        "queued_count": counts["queued"],
        "running_count": counts["running"],
        "succeeded_count": counts["succeeded"],
        "empty_count": counts["empty"],
        "failed_count": counts["failed"],
        "cancelled_count": counts["cancelled"],
    }
    if status in {"succeeded", "partial", "failed", "cancelled"}:
        update["finished_at"] = _utc_now()
    _task_collection().update_one({"task_id": task_id}, {"$set": update})
    return get_task(task_id)


def request_cancel(task_id):
    task = get_task(task_id)
    if not task:
        return None
    if task.get("status") in {"succeeded", "partial", "failed", "cancelled"}:
        return task
    _task_collection().update_one({"task_id": task_id}, {"$set": {"cancel_requested": True}})
    if task.get("status") == "queued":
        _task_collection().update_one(
            {"task_id": task_id},
            {"$set": {"items.$[item].status": "cancelled"}},
            array_filters=[{"item.status": "queued"}],
        )
        _recount_task(task_id)
    _write_log("INFO", "task_cancel_requested", "收到 ICP 查询取消请求", task_id=task_id)
    return get_task(task_id)


def delete_task(task_id):
    task = get_task(task_id)
    if not task:
        return False
    if task.get("status") in {"queued", "running"}:
        raise IcpQueryError("运行中的 ICP 任务不能直接删除，请先取消", category="state_error")
    history_ids = []
    seen_history_ids = set()
    for item in task.get("items", []):
        history_id = str(item.get("history_id") or "").strip()
        if history_id and history_id not in seen_history_ids:
            history_ids.append(history_id)
            seen_history_ids.add(history_id)
    # 子项状态更新与历史写入不是同一个 Mongo 事务；补查 task_id 可以清理
    # “历史已落库、子项关联字段尚未来得及回写”的孤儿历史和结果。
    for history in _history_collection().find({"task_id": task_id}, {"history_id": 1}):
        history_id = str(history.get("history_id") or "").strip()
        if history_id and history_id not in seen_history_ids:
            history_ids.append(history_id)
            seen_history_ids.add(history_id)
    if history_ids:
        _result_collection().delete_many({"history_id": {"$in": history_ids}})
        _history_collection().delete_many({"history_id": {"$in": history_ids}})
    _task_collection().delete_one({"task_id": task_id})
    _write_log("INFO", "task_deleted", "删除 ICP 查询任务", task_id=task_id)
    return True


def clear_history():
    # 清空接口的语义是清空 ICP 结果域；直接删除结果集合可以同时覆盖
    # 关联字段回写失败留下的孤儿结果，不依赖历史集合当前是否完整。
    _result_collection().delete_many({})
    try:
        _task_collection().update_many(
            {"items.history_id": {"$exists": True}},
            {
                "$set": {
                    "items.$[item].history_id": "",
                    "items.$[item].result_count": 0,
                }
            },
            array_filters=[{"item.history_id": {"$exists": True, "$ne": ""}}],
        )
    except Exception as exc:
        logger.warning("clear ICP history task references failed: %s", _redact_text(exc))
    result = _history_collection().delete_many({})
    return int(getattr(result, "deleted_count", 0) or 0)


def delete_history(history_id):
    _result_collection().delete_many({"history_id": history_id})
    result = _history_collection().delete_one({"history_id": history_id})
    if int(getattr(result, "deleted_count", 0) or 0) > 0:
        try:
            _task_collection().update_many(
                {"items.history_id": history_id},
                {
                    "$set": {
                        "items.$[item].history_id": "",
                        "items.$[item].result_count": 0,
                    }
                },
                array_filters=[{"item.history_id": history_id}],
            )
        except Exception as exc:
            logger.warning("delete ICP history task reference failed: %s", _redact_text(exc))
    return int(getattr(result, "deleted_count", 0) or 0) > 0


def clear_logs():
    result = _log_collection().delete_many({})
    return int(getattr(result, "deleted_count", 0) or 0)


def list_logs(page=1, size=50, level="", created_from="", created_to=""):
    query = {"level": level.upper()} if level else {}
    start_time = _parse_history_time(created_from)
    end_time = _parse_history_time(created_to, end=True)
    if start_time or end_time:
        query["created_at"] = {}
        if start_time:
            query["created_at"]["$gte"] = start_time
        if end_time:
            query["created_at"]["$lt"] = end_time
    page = _safe_int(page, 1, 1, 100000)
    size = _safe_int(size, 50, 1, 200)
    collection = _log_collection()
    total = collection.count_documents(query)
    items = list(collection.find(query).sort("created_at", -1).skip((page - 1) * size).limit(size))
    return {"items": [_serialize(item) for item in items], "total": total, "page": page, "size": size}


def export_history(
    file_format="json",
    history_id="",
    task_id="",
    query_type="",
    keyword="",
    status="",
    created_from="",
    created_to="",
):
    query = {}
    if history_id:
        query["history_id"] = history_id
    elif task_id:
        query["task_id"] = task_id
    if query_type:
        query["query_type"] = query_type
    if keyword:
        query["keyword"] = {"$regex": re.escape(str(keyword)), "$options": "i"}
    if status:
        query["status"] = status
    start_time = _parse_history_time(created_from)
    end_time = _parse_history_time(created_to, end=True)
    if start_time or end_time:
        query["created_at"] = {}
        if start_time:
            query["created_at"]["$gte"] = start_time
        if end_time:
            query["created_at"]["$lt"] = end_time
    histories = list(_history_collection().find(query).sort("created_at", -1).limit(10000))
    history_ids = [item.get("history_id") for item in histories]
    results = list(_result_collection().find({"history_id": {"$in": history_ids}}).sort([("history_id", 1), ("page", 1), ("order", 1)])) if history_ids else []
    result_map = {}
    for item in results:
        # 结果集合可能包含旧版本或异常写入的数据；导出边界再次过滤，
        # 避免仅依赖写入路径的标准化保护。
        result_map.setdefault(item.get("history_id"), []).append(
            _serialize(_safe_json_value(item))
        )
    rows = []
    for history in histories:
        item = _serialize(history)
        item["records"] = result_map.get(history.get("history_id"), [])
        rows.append(item)
    if file_format == "json":
        response = make_response(json.dumps(rows, ensure_ascii=False).encode("utf-8"))
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        response.headers["Content-Disposition"] = "attachment; filename=icp_history_{}.json".format(int(time.time()))
        return response
    if file_format != "xlsx":
        raise IcpQueryError("不支持的导出格式", category="validation_error")
    try:
        from openpyxl import Workbook
    except ImportError as exc:
        raise IcpQueryError("Excel 导出依赖未安装", category="dependency_error") from exc
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "ICP查询"
    sheet.append(["查询类型", "关键词", "状态", "结果数量", "查询时间", "结果"])
    for history in rows:
        keyword_value = history.get("keyword", "")
        if isinstance(keyword_value, str) and keyword_value[:1] in {"=", "+", "-", "@"}:
            keyword_value = "'" + keyword_value
        sheet.append([
            history.get("query_type", ""),
            keyword_value,
            history.get("status", ""),
            history.get("result_count", 0),
            history.get("created_at", ""),
            json.dumps(history.get("records", []), ensure_ascii=False),
        ])
    output = io.BytesIO()
    workbook.save(output)
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    response.headers["Content-Disposition"] = "attachment; filename=icp_history_{}.xlsx".format(int(time.time()))
    return response


def _execute_task_item(task_id, task_kind, query_type, requested_page, requested_page_size, item):
    current = get_task(task_id)
    if not current:
        return
    if current.get("cancel_requested"):
        _update_item(task_id, item["item_id"], "cancelled")
        _recount_task(task_id)
        return
    if item.get("status") != "queued":
        return
    # 允许历史残留消息与重投消息同时抵达，但每个子项只能被一个执行者认领。
    claim = _task_collection().update_one(
        {
            "task_id": task_id,
            "cancel_requested": {"$ne": True},
            "items": {"$elemMatch": {"item_id": item["item_id"], "status": "queued"}},
        },
        {
            "$set": {
                "items.$.status": "running",
                "items.$.started_at": _utc_now(),
            }
        },
    )
    if int(getattr(claim, "modified_count", 0) or 0) <= 0:
        return
    item_with_type = {**item, "query_type": query_type}
    try:
        if task_kind == "single":
            result = IcpQueryEngine().query_page(
                query_type,
                item.get("keyword", ""),
                requested_page,
                requested_page_size,
            )
        else:
            result = IcpQueryEngine().query_all_pages(
                query_type,
                item.get("keyword", ""),
                cancel_check=lambda: _is_task_cancel_requested(task_id),
            )
        if _is_task_cancel_requested(task_id):
            _update_item(task_id, item["item_id"], "cancelled")
            _write_log("INFO", "item_cancelled", "ICP 查询项已取消", task_id=task_id)
            _recount_task(task_id)
            return
        history_status = "empty" if not result.get("records") else "succeeded"
        history = _save_history(task_id, item_with_type, result, history_status)
        _update_item(
            task_id,
            item["item_id"],
            history_status,
            history_id=history["history_id"],
            result_count=len(result.get("records", [])),
        )
    except IcpTaskCancelled:
        _update_item(task_id, item["item_id"], "cancelled")
        _write_log("INFO", "item_cancelled", "ICP 查询项已取消", task_id=task_id)
    except IcpQueryError as exc:
        _set_task_error_summary(task_id, exc)
        history = _save_failure_history(task_id, item_with_type, exc)
        history_id = history["history_id"] if history else ""
        _update_item(
            task_id,
            item["item_id"],
            "failed",
            history_id=history_id,
            error_category=exc.category,
            error_message=_redact_text(exc),
        )
        _write_log("WARNING", "query_failed", exc, task_id=task_id, history_id=history_id)
    except Exception as exc:
        safe_message = _redact_text(exc)
        _set_task_error_summary(task_id, safe_message)
        history = _save_failure_history(
            task_id,
            item_with_type,
            IcpQueryError(safe_message, "internal_error"),
        )
        history_id = history["history_id"] if history else ""
        _update_item(
            task_id,
            item["item_id"],
            "failed",
            history_id=history_id,
            error_category="internal_error",
            error_message=safe_message,
        )
        logger.error("ICP query task failed task_id=%s error=%s", task_id, safe_message)
    _recount_task(task_id)


def execute_task(task_id):
    task = get_task(task_id)
    if not task:
        return None
    if task.get("status") in {"succeeded", "partial", "failed", "cancelled"}:
        return task
    _task_collection().update_one(
        {"task_id": task_id},
        {"$set": {"status": "running", "started_at": _utc_now()}},
    )
    task = get_task(task_id)
    if not task:
        return None
    items = list(task.get("items", []))
    item_args = [
        (
            task_id,
            task.get("task_kind", "single"),
            task.get("query_type", "web"),
            task.get("requested_page", 1),
            task.get("requested_page_size", 26),
            item,
        )
        for item in items
    ]
    if task.get("task_kind") == "batch":
        workers = min(
            _config_int("ICP_QUERY_BATCH_CONCURRENCY", 2, minimum=1, maximum=10),
            max(1, len(item_args)),
        )
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="icp-query") as executor:
            list(executor.map(lambda args: _execute_task_item(*args), item_args))
    else:
        for args in item_args:
            _execute_task_item(*args)
    return _recount_task(task_id)


def ensure_indexes():
    """首次创建任务时幂等创建 ICP 集合索引。"""
    global _INDEXES_READY
    if _INDEXES_READY:
        return
    try:
        _task_collection().create_index("task_id", unique=True)
        _task_collection().create_index([("status", 1), ("created_at", -1)])
        _task_collection().create_index("expires_at", expireAfterSeconds=0)
        _history_collection().create_index("history_id", unique=True)
        _history_collection().create_index([("query_type", 1), ("created_at", -1)])
        _history_collection().create_index("expires_at", expireAfterSeconds=0)
        _result_collection().create_index([("history_id", 1), ("page", 1), ("order", 1)])
        _result_collection().create_index("expires_at", expireAfterSeconds=0)
        _log_collection().create_index([("created_at", -1)])
        _log_collection().create_index("expires_at", expireAfterSeconds=0)
        _INDEXES_READY = True
    except Exception as exc:
        logger.warning("ensure ICP indexes failed: %s", _redact_text(exc))
