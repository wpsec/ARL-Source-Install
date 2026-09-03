"""
HTTP连接状态检查
"""
import threading
import time
from urllib.parse import urlparse

from app import utils
from app.config import Config
from .baseThread import BaseThread

import requests.exceptions
from app.utils.log_safety import safe_error_text
logger = utils.get_logger()


class CheckHTTP(BaseThread):
    def __init__(self, urls, concurrency=10, prevalidated_dns_domains=None):
        super().__init__(urls, concurrency=concurrency)
        self.timeout = (5, 3)
        self.checkout_map = {}
        self.dns_policy_cache = {}
        self.http_connect_cache = {}
        self.prevalidated_dns_domains = self._normalize_domains(prevalidated_dns_domains)
        self._metrics = {
            "request_count": 0,
            "dns_policy_skip_count": 0,
            "dns_policy_override_count": 0,
            "request_error_count": 0,
        }
        self._metrics_lock = threading.Lock()

    @staticmethod
    def _normalize_domains(domains):
        normalized = set()
        for domain in domains or []:
            value = utils.normalize_domain(domain)
            if value:
                normalized.add(value)
        return normalized

    @staticmethod
    def _url_hostname(url):
        try:
            return (urlparse(str(url)).hostname or "").strip().lower().rstrip(".")
        except Exception:
            return ""

    def _increment_metric(self, name):
        with self._metrics_lock:
            self._metrics[name] += 1

    def _allow_prevalidated_public_dns_drift(self, url, policy_detail):
        """仅放行已由端口结果证明存在的公网域名的解析视图漂移。"""
        if not self.prevalidated_dns_domains:
            return False

        if policy_detail.get("reason") != "dns_drift_no_overlap":
            return False

        hostname = self._url_hostname(url)
        normalized_hostname = utils.normalize_domain(hostname) or hostname
        if normalized_hostname not in self.prevalidated_dns_domains:
            return False

        resolver_ips = list(policy_detail.get("resolver_ips") or [])
        system_ips = list(policy_detail.get("system_ips") or [])
        if not resolver_ips or not system_ips:
            return False

        resolver_public_ips = [ip for ip in resolver_ips if utils.get_ip_type(ip) == "PUBLIC"]
        system_public_ips = [ip for ip in system_ips if utils.get_ip_type(ip) == "PUBLIC"]
        return (
            len(resolver_public_ips) == len(resolver_ips)
            and len(system_public_ips) == len(system_ips)
        )

    def check(self, url):
        allow_scan, policy_detail = utils.check_dns_policy_for_url(url, cache_map=self.dns_policy_cache)
        if not allow_scan:
            if self._allow_prevalidated_public_dns_drift(url, policy_detail):
                policy_detail = dict(policy_detail)
                policy_detail["policy_override"] = "prevalidated_public_endpoint"
                allow_scan = True
                self._increment_metric("dns_policy_override_count")
                logger.warning(
                    "allow check_http by prevalidated public endpoint host:{} "
                    "reason:{} resolver_count:{} system_count:{}".format(
                        self._url_hostname(url),
                        policy_detail.get("reason", ""),
                        len(policy_detail.get("resolver_ips", [])),
                        len(policy_detail.get("system_ips", [])),
                    )
                )

        if not allow_scan:
            self._increment_metric("dns_policy_skip_count")
            logger.info(
                "skip check_http by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    url,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return None

        self._increment_metric("request_count")
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
            self._increment_metric("request_error_count")
            logger.warning(
                "check_http request failed host:{} error_type:{} error:{}".format(
                    self._url_hostname(url),
                    type(e).__name__,
                    safe_error_text(e),
                )
            )

        except Exception as e:
            self._increment_metric("request_error_count")
            logger.warning(
                "check_http failed host:{} error_type:{} error:{}".format(
                    self._url_hostname(url),
                    type(e).__name__,
                    safe_error_text(e),
                )
            )

    def run(self):
        t1 = time.time()
        logger.info("start check http {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        with self._metrics_lock:
            metrics = dict(self._metrics)
        logger.info(
            "end check http candidates:{} result:{} dns_policy_skipped:{} "
            "dns_policy_overridden:{} request_count:{} request_errors:{} elapsed:{}".format(
                len(self.targets),
                len(self.checkout_map),
                metrics["dns_policy_skip_count"],
                metrics["dns_policy_override_count"],
                metrics["request_count"],
                metrics["request_error_count"],
                elapse,
            )
        )
        return self.checkout_map


def check_http(urls, concurrency=None, prevalidated_dns_domains=None):
    if concurrency is None:
        concurrency = Config.HTTP_CHECK_CONCURRENCY
    c = CheckHTTP(
        urls,
        concurrency,
        prevalidated_dns_domains=prevalidated_dns_domains,
    )
    return c.run()
