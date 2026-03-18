"""
Shodan 域名查询插件

能力说明：
- 通过 Shodan DNS API 查询子域名
- 支持分页与限频退避重试
"""

import json
import time

from app.services.dns_query import DNSQueryBase
from app import utils


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "shodan"
        self.api_url = "https://api.shodan.io/dns/domain/{}"
        self.api_key = None
        self.max_page = 20
        self.request_interval = 1.0
        self.rate_limit_retry = 4
        self.rate_limit_backoff = 2
        self.rate_limit_max_sleep = 60

    def init_key(
        self,
        api_key=None,
        max_page=20,
        request_interval=1.0,
        rate_limit_retry=4,
        rate_limit_backoff=2,
        rate_limit_max_sleep=60,
    ):
        self.api_key = api_key
        self.max_page = max(self._safe_to_int(max_page, 20), 1)
        self.request_interval = max(self._safe_to_float(request_interval, 1.0), 0.0)
        self.rate_limit_retry = max(self._safe_to_int(rate_limit_retry, 4), 0)
        self.rate_limit_backoff = max(self._safe_to_int(rate_limit_backoff, 2), 1)
        self.rate_limit_max_sleep = max(self._safe_to_int(rate_limit_max_sleep, 60), self.rate_limit_backoff)

    @staticmethod
    def _safe_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "on"}
        return False

    def _request_page(self, target, curr_page):
        params = {
            "key": self.api_key,
            "page": curr_page
        }
        request_url = self.api_url.format(target)

        attempt = 0
        while True:
            attempt += 1
            conn = utils.http_req(request_url, "get", params=params, timeout=(30.1, 50.1))
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
                    "shodan rate limit retry exhausted target:{} curr_page:{} code:{} message:{}".format(
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
                "shodan rate limit target:{} curr_page:{} retry:{}/{} sleep:{}s".format(
                    target, curr_page, attempt, self.rate_limit_retry, sleep_time
                )
            )
            time.sleep(sleep_time)

    def sub_domains(self, target):
        target = str(target or "").strip().lower().rstrip(".")
        if not target:
            return []

        results = []
        curr_page = 1
        while True:
            self.logger.debug("shodan target:{} curr_page:{}".format(target, curr_page))
            status_code, data = self._request_page(target=target, curr_page=curr_page)

            if status_code != 200:
                self.logger.error("shodan query error:{}".format(json.dumps(data, ensure_ascii=False)))
                break

            if not isinstance(data, dict):
                self.logger.error("shodan query error: invalid response {}".format(type(data)))
                break

            subdomains = data.get("subdomains", [])
            if not isinstance(subdomains, list):
                self.logger.error("shodan query error: invalid subdomains type {}".format(type(subdomains)))
                break

            for item in subdomains:
                sub = str(item or "").strip().strip(".").lower()
                if not sub:
                    continue
                domain = "{}.{}".format(sub, target)
                if domain.endswith("." + target) and utils.is_valid_domain(domain):
                    results.append(domain)

            has_more = self._safe_bool(data.get("more"))
            self.logger.debug(
                "shodan target:{} curr_page:{} total:{} curr_size:{} more:{}".format(
                    target, curr_page, data.get("total", 0), len(subdomains), has_more
                )
            )

            if not has_more:
                break

            time.sleep(max(self.request_interval, 0.0))
            curr_page += 1
            if curr_page > self.max_page:
                break

        return list(set(results))
