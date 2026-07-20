"""
HTTP连接状态检查
"""
import time

from app import utils
from app.config import Config
from .baseThread import BaseThread

import requests.exceptions
logger = utils.get_logger()


class CheckHTTP(BaseThread):
    def __init__(self, urls, concurrency=10):
        super().__init__(urls, concurrency=concurrency)
        self.timeout = (5, 3)
        self.checkout_map = {}
        self.dns_policy_cache = {}
        self.http_connect_cache = {}

    def check(self, url):
        allow_scan, policy_detail = utils.check_dns_policy_for_url(url, cache_map=self.dns_policy_cache)
        if not allow_scan:
            logger.info(
                "skip check_http by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    url,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return None

        connect_kwargs = utils.build_http_connect_kwargs_for_url(
            url,
            policy_detail=policy_detail,
            cache_map=self.http_connect_cache,
        )
        conn = utils.http_req(url, method="get", timeout=self.timeout, stream=True, **connect_kwargs)
        conn.close()

        if conn.status_code == 400:
            # 特殊情况排除
            etag = conn.headers.get("ETag")
            date = conn.headers.get("Date")
            if not etag or not date:
                return None

        # *** 特殊情况过滤
        if conn.status_code == 422 or conn.status_code == 410:
            return None

        if (conn.status_code >= 501) and (conn.status_code < 600):
            return None

        if conn.status_code == 403:
            conn2 = utils.http_req(url, **connect_kwargs)
            check = b'</title><style type="text/css">body{margin:5% auto 0 auto;padding:0 18px}'
            if check in conn2.content:
                return None

        item = {
            "status": conn.status_code,
            "content-type": conn.headers.get("Content-Type", "")
        }

        return item

    def work(self, url):
        try:
            out = self.check(url)
            if out is not None:
                self.checkout_map[url] = out

        except requests.exceptions.RequestException as e:
            pass

        except Exception as e:
            logger.warning("error on url {}".format(url))
            logger.warning(e)

    def run(self):
        t1 = time.time()
        logger.info("start check http {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        return self.checkout_map


def check_http(urls, concurrency=None):
    if concurrency is None:
        concurrency = Config.HTTP_CHECK_CONCURRENCY
    c = CheckHTTP(urls, concurrency)
    return c.run()
