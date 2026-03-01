import json
import time

from app.services.dns_query import DNSQueryBase
from app import utils


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "alienvault"
        self.api_url = "https://otx.alienvault.com/"
        self.rate_limit_retry = 2
        self.rate_limit_backoff = 2
        self.rate_limit_max_sleep = 30

    def _request_passive_dns(self, target):
        """
        请求 AlienVault passive DNS，遇到限流自动退避重试。
        """
        url = "{}api/v1/indicators/domain/{}/passive_dns".format(self.api_url, target)
        attempt = 0
        while True:
            attempt += 1
            conn = utils.http_req(url, 'get', timeout=(30.1, 50.1))
            try:
                data = conn.json()
            except Exception:
                data = {}

            message = ""
            if isinstance(data, dict):
                message = data.get("message") or data.get("detail") or data.get("error") or ""

            if not self._is_rate_limited(status_code=conn.status_code, data=data, message=message):
                return conn.status_code, data

            if attempt > self.rate_limit_retry:
                self.logger.warning(
                    "{} rate limit retry exhausted target:{} retry:{}/{} status:{} message:{}".format(
                        self.source_name, target, attempt, self.rate_limit_retry, conn.status_code, message
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
                "{} rate limit target:{} retry:{}/{} sleep:{}s".format(
                    self.source_name, target, attempt, self.rate_limit_retry, sleep_time
                )
            )
            time.sleep(sleep_time)

    @staticmethod
    def _extract_items(data):
        if isinstance(data, list):
            return data

        if not isinstance(data, dict):
            return []

        for key in ("passive_dns", "results", "list", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return value

        nested = data.get("data")
        if isinstance(nested, dict):
            for key in ("passive_dns", "results", "list", "items"):
                value = nested.get(key)
                if isinstance(value, list):
                    return value
        elif isinstance(nested, list):
            return nested

        return []

    def sub_domains(self, target):
        status_code, data = self._request_passive_dns(target)
        items = self._extract_items(data)

        if status_code != 200 and not items:
            log_msg = "{} query error status:{} response:{}".format(
                self.source_name, status_code, json.dumps(data, ensure_ascii=False)
            )
            if status_code in [401, 403, 429]:
                self.logger.warning(log_msg)
            else:
                self.logger.error(log_msg)
            return []

        results = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            hostname = str(item.get("hostname") or item.get("host") or item.get("name") or "").strip().lower()
            hostname = hostname.rstrip(".")
            if hostname:
                results.add(hostname)

        return list(results)
