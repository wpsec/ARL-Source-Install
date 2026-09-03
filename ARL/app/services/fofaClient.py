"""
FOFA搜索引擎客户端
"""
#  -*- coding:UTF-8 -*-
import base64
import threading
import time
from app.config import Config
from app import utils
from app.utils.log_safety import safe_error_text
from celery.utils.log import get_task_logger
logger = get_task_logger(__name__)


class FofaClient:
    request_interval = 1.0
    rate_limit_retry = 3
    rate_limit_backoff = 2.0
    rate_limit_max_sleep = 30.0
    _request_lock = threading.Lock()
    _last_request_at = 0.0

    def __init__(self, email, key, page_size=9999):
        self.email = email
        self.key = key
        self.base_url = Config.FOFA_URL
        self.search_api_url = "/api/v1/search/all"
        self.info_my_api_url = "/api/v1/info/my"
        self.page_size = page_size
        self.param = {}

    def info_my(self):
        param = {
            "email": self.email,
            "key": self.key,
        }
        self.param = param
        data = self._api(self.base_url + self.info_my_api_url)
        return data

    def fofa_search_all(self, query, page=None):
        qbase64 = base64.b64encode(query.encode())
        param = {
            "email": self.email,
            "key": self.key,
            "qbase64": qbase64.decode('utf-8'),
            "size": self.page_size
        }
        if page is not None:
            param["page"] = page

        self.param = param
        data = self._api(self.base_url + self.search_api_url)
        return data

    @classmethod
    def _wait_for_request_slot(cls):
        """同一 worker 内串行化 FOFA 请求，降低短时间连续调用触发 45012 的概率。"""
        with cls._request_lock:
            elapsed = time.monotonic() - cls._last_request_at
            wait_time = max(0.0, cls.request_interval - elapsed)
            if wait_time > 0:
                time.sleep(wait_time)
            cls._last_request_at = time.monotonic()

    @staticmethod
    def _is_rate_limited(data):
        if not isinstance(data, dict):
            return False
        code = str(data.get("code") or data.get("error_code") or "").strip()
        message = str(data.get("errmsg") or data.get("message") or "").strip().lower()
        return code == "45012" or "45012" in message or "请求速度过快" in message or "rate limit" in message

    def _api(self, url):
        for attempt in range(self.rate_limit_retry + 1):
            self._wait_for_request_slot()
            data = utils.http_req(url, 'get', params=self.param).json()
            if not isinstance(data, dict):
                raise Exception("FOFA 响应格式异常")

            if self._is_rate_limited(data):
                if attempt >= self.rate_limit_retry:
                    raise Exception("FOFA 请求限频，重试次数已耗尽")

                sleep_time = min(
                    self.rate_limit_backoff * (2 ** attempt),
                    self.rate_limit_max_sleep,
                )
                logger.warning(
                    "FOFA rate limit endpoint:{} retry:{}/{} sleep:{:.1f}s".format(
                        self.search_api_url if url.endswith(self.search_api_url) else self.info_my_api_url,
                        attempt + 1,
                        self.rate_limit_retry,
                        sleep_time,
                    )
                )
                time.sleep(sleep_time)
                continue

            if data.get("error") and data.get("errmsg"):
                raise Exception(data["errmsg"])
            return data

        raise Exception("FOFA 请求失败")

    def search_cert(self, cert):
        query = 'cert="{}"'.format(cert)
        data = self.fofa_search_all(query)
        results = data["results"]
        return results


def fetch_ip_bycert(cert, size=9999):
    ip_set = set()
    logger.info("fetch_ip_bycert {}".format(cert))
    try:
        client = FofaClient(Config.FOFA_EMAIL, Config.FOFA_KEY, page_size=size)
        items = client.search_cert(cert)
        for item in items:
            ip_set.add(item[1])
    except Exception as e:
        logger.warning("{} error: {}".format(cert, safe_error_text(e)))

    return list(ip_set)


def fofa_query(query, page_size=9999):
    try:
        if not Config.FOFA_EMAIL or not Config.FOFA_KEY:
            return "please set fofa key in config-docker.yaml"

        client = FofaClient(Config.FOFA_EMAIL, Config.FOFA_KEY, page_size=page_size)
        info = client.info_my()
        if info.get("vip_level") == 0:
            return "不支持注册用户"

        # 普通会员，最多只查100条
        if info.get("vip_level") == 1:
            client.page_size = min(page_size, 100)

        data = client.fofa_search_all(query)
        return data

    except Exception as e:
        error_msg = safe_error_text(e)
        secret = str(Config.FOFA_KEY or "")
        if secret:
            error_msg = error_msg.replace(secret, "***")
        return error_msg


def fofa_query_result(query, page_size=9999):
    try:
        ip_set = set()
        data = fofa_query(query, page_size)

        if isinstance(data, dict):
            if data['error']:
                return data['errmsg']

            for item in data["results"]:
                ip_set.add(item[1])
            return list(ip_set)

        raise Exception(data)
    except Exception as e:
        error_msg = str(e)
        return error_msg
