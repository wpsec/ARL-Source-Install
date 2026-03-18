"""
hunter.how 域名查询插件

能力说明：
- 调用 hunter.how Search API 查询同根域资产
- 支持按 IP 查询并提取关联域名
- 兼容不同返回结构并支持分页与限频退避
"""

import base64
import json
import time
from urllib.parse import urlparse

from app.services.dns_query import DNSQueryBase
from app import utils


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "hunter_how"
        self.support_ip_query = True
        self.api_url = "https://api.hunter.how/search"
        self.api_key = None
        self.page_size = 100
        self.max_page = 5
        self.request_interval = 1.0
        self.rate_limit_retry = 4
        self.rate_limit_backoff = 2
        self.rate_limit_max_sleep = 60

    def init_key(
        self,
        api_key=None,
        page_size=100,
        max_page=5,
        request_interval=1.0,
        rate_limit_retry=4,
        rate_limit_backoff=2,
        rate_limit_max_sleep=60,
    ):
        self.api_key = api_key
        self.page_size = max(self._safe_to_int(page_size, 100), 1)
        self.max_page = max(self._safe_to_int(max_page, 5), 1)
        self.request_interval = max(self._safe_to_float(request_interval, 1.0), 0.0)
        self.rate_limit_retry = max(self._safe_to_int(rate_limit_retry, 4), 0)
        self.rate_limit_backoff = max(self._safe_to_int(rate_limit_backoff, 2), 1)
        self.rate_limit_max_sleep = max(self._safe_to_int(rate_limit_max_sleep, 60), self.rate_limit_backoff)

    @staticmethod
    def _encode_search(search):
        if not isinstance(search, str):
            search = str(search or "")
        return base64.urlsafe_b64encode(search.encode("utf-8")).decode("utf-8")

    @staticmethod
    def _extract_items(data):
        if not isinstance(data, dict):
            return []

        def _as_list(value):
            return value if isinstance(value, list) else None

        for key in ("arr", "list", "results", "matches"):
            items = _as_list(data.get(key))
            if items is not None:
                return items

        payload = data.get("data")
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("arr", "list", "results", "matches"):
                items = _as_list(payload.get(key))
                if items is not None:
                    return items

        return []

    @staticmethod
    def _extract_domain(item):
        if not isinstance(item, dict):
            return ""

        for key in ("domain", "host", "hostname", "name"):
            domain = str(item.get(key) or "").strip().lower().rstrip(".")
            if domain:
                return domain

        for key in ("url", "web", "web_url", "link"):
            raw_url = str(item.get(key) or "").strip()
            if not raw_url:
                continue
            parsed = urlparse(raw_url if "://" in raw_url else "//{}".format(raw_url))
            domain = str(parsed.hostname or "").strip().lower().rstrip(".")
            if domain:
                return domain

        return ""

    @staticmethod
    def _safe_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "on"}
        return False

    def _search_page(self, params, headers, target, curr_page):
        attempt = 0
        while True:
            attempt += 1
            conn = utils.http_req(self.api_url, "get", params=params, headers=headers, timeout=(30.1, 50.1))
            try:
                data = conn.json()
            except Exception:
                data = {}

            message = ""
            if isinstance(data, dict):
                message = str(data.get("error") or data.get("message") or "")

            if not self._is_rate_limited(status_code=conn.status_code, data=data, message=message):
                return conn.status_code, data

            if attempt > self.rate_limit_retry:
                self.logger.error(
                    "hunter_how rate limit retry exhausted target:{} curr_page:{} code:{} message:{}".format(
                        target, curr_page, conn.status_code, message
                    )
                )
                return conn.status_code, data

            sleep_time = self._calc_retry_sleep(
                attempt=attempt,
                conn=conn,
                data=data,
                base=self.rate_limit_backoff,
                cap=self.rate_limit_max_sleep,
            )
            self.logger.info(
                "hunter_how rate limit target:{} curr_page:{} retry:{}/{} sleep:{}s".format(
                    target, curr_page, attempt, self.rate_limit_retry, sleep_time
                )
            )
            time.sleep(sleep_time)

    def _query_domains_by_searches(self, searches, log_target=""):
        results = []
        seen_domains = set()
        normalized_searches = []
        for search in searches:
            search = str(search or "").strip()
            if not search:
                continue
            if search in normalized_searches:
                continue
            normalized_searches.append(search)

        headers = {"api-key": self.api_key}
        for search in normalized_searches:
            encoded_search = self._encode_search(search)
            params = {
                "query": encoded_search,
                "search": encoded_search,
                "page": 1,
                "page_size": self.page_size,
                "api-key": self.api_key,
            }

            curr_page = 1
            while True:
                self.logger.debug(
                    "hunter_how search:{} target:{} page_size:{} curr_page:{}".format(
                        search, log_target or "-", self.page_size, curr_page
                    )
                )
                params["page"] = curr_page
                status_code, data = self._search_page(
                    params=params,
                    headers=headers,
                    target=log_target or search,
                    curr_page=curr_page,
                )

                if status_code != 200:
                    self.logger.error("hunter_how query error:{}".format(json.dumps(data, ensure_ascii=False)))
                    break

                if not isinstance(data, dict):
                    self.logger.error("hunter_how query error: invalid response {}".format(type(data)))
                    break

                items = self._extract_items(data)
                api_code = data.get("code")
                if api_code not in (None, 0, "0", 200, "200") and not items:
                    self.logger.error("hunter_how query error:{}".format(json.dumps(data, ensure_ascii=False)))
                    break

                for item in items:
                    domain = self._extract_domain(item)
                    if not domain or utils.is_vaild_ip_target(domain):
                        continue
                    if domain in seen_domains:
                        continue
                    seen_domains.add(domain)
                    results.append(domain)

                has_more = self._safe_bool(data.get("more"))
                if isinstance(data.get("data"), dict):
                    has_more = has_more or self._safe_bool(data["data"].get("more"))

                self.logger.debug(
                    "hunter_how search:{} target:{} page_size:{} curr_page:{} curr_size:{} more:{}".format(
                        search, log_target or "-", self.page_size, curr_page, len(items), has_more
                    )
                )

                if not items:
                    break
                if len(items) < self.page_size and not has_more:
                    break

                time.sleep(max(self.request_interval, 0.0))
                curr_page += 1
                if curr_page > self.max_page:
                    break

            if search != normalized_searches[-1]:
                time.sleep(max(self.request_interval, 0.0))

        return list(set(results))

    def sub_domains(self, target):
        target = str(target or "").strip().lower().rstrip(".")
        if not target:
            return []

        searches = [
            "domain=\"{}\"".format(target),
            "domain.suffix=\"{}\"".format(target),
        ]
        return self._query_domains_by_searches(searches, log_target=target)

    def sub_domains_by_ip(self, ip):
        ip = str(ip or "").strip()
        if not ip or not utils.is_vaild_ip_target(ip):
            return []

        search = 'ip=="{}"'.format(ip)
        return self._query_domains_by_searches([search], log_target=ip)
