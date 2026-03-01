import base64
import json
import time
import re
from app.services.dns_query import DNSQueryBase
from app import utils


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "quake_360"
        self.api_url = "https://quake.360.net/api/v3/search/quake_service"
        self.quake_token = None
        self.max_size = 500
        self.rate_limit_retry = 4
        self.rate_limit_backoff = 3
        self.rate_limit_max_sleep = 90

    def init_key(
        self,
        quake_token=None,
        max_size=500,
        rate_limit_retry=4,
        rate_limit_backoff=3,
        rate_limit_max_sleep=90,
    ):
        self.quake_token = quake_token
        self.max_size = max(self._safe_to_int(max_size, 500), 1)
        self.rate_limit_retry = max(self._safe_to_int(rate_limit_retry, 4), 0)
        self.rate_limit_backoff = max(self._safe_to_int(rate_limit_backoff, 3), 1)
        self.rate_limit_max_sleep = max(self._safe_to_int(rate_limit_max_sleep, 90), self.rate_limit_backoff)

    def _search_quake(self, json_data, headers, target):
        """
        请求 Quake 数据，遇到 q3005/429 自动退避重试。
        """
        attempt = 0
        while True:
            attempt += 1
            conn = utils.http_req(self.api_url, 'post', json=json_data, headers=headers, timeout=(30.1, 100.1))

            try:
                data = conn.json()
            except Exception:
                data = {}

            if conn.status_code == 200 and isinstance(data, dict) and data.get("code") == 0:
                return conn.status_code, data

            message = ""
            if isinstance(data, dict):
                message = data.get("message", "")

            if not self._is_rate_limited(status_code=conn.status_code, data=data, message=message):
                return conn.status_code, data

            if attempt > self.rate_limit_retry:
                self.logger.error(
                    "quake_360 rate limit retry exhausted target:{} retry:{}/{} code:{} message:{}".format(
                        target, attempt, self.rate_limit_retry, data.get("code", ""), message
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
                "quake_360 rate limit target:{} retry:{}/{} sleep:{}s".format(
                    target, attempt, self.rate_limit_retry, sleep_time
                )
            )
            time.sleep(sleep_time)

    def sub_domains(self, target):
        # 文档 https://quake.360.net/quake/#/help?id=5e77423bcb9954d2f8a01656&title=%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E
        json_data = {
            "query": "domain:\"{}\"".format(target),
            "include": ["service.http.host"],
            "start": 0,
            "size": self.max_size,
            "latest": True
        }
        headers = {
            "X-QuakeToken": self.quake_token
        }
        status_code, data = self._search_quake(json_data=json_data, headers=headers, target=target)
        if status_code != 200:
            raise Exception(
                "{} http status:{} response:{}".format(
                    self.source_name, status_code, json.dumps(data, ensure_ascii=False)
                )
            )

        if not isinstance(data, dict):
            raise Exception("{} error: invalid response {}".format(self.source_name, type(data)))

        if data.get("code") != 0:
            raise Exception("{} error: {}".format(self.source_name, json.dumps(data, ensure_ascii=False)))

        self.logger.debug("{}: target:{} meta:{}".format(self.source_name, target, data["meta"]))

        results = []
        items = data["data"]
        for item in items:
            hostname = item["service"]["http"]["host"]
            if hostname.endswith("." + target):
                results.append(hostname)

        return list(set(results))
