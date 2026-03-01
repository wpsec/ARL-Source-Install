import json
import time

from app.services.dns_query import DNSQueryBase
from app import utils


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "zoomeye"
        self.api_url = "https://api.zoomeye.org/domain/search"
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

    def _request_page(self, param, headers, target, curr_page):
        """
        请求单页数据，遇到频率受限时自动退避重试。
        """
        attempt = 0
        while True:
            attempt += 1
            conn = utils.http_req(self.api_url, 'get', params=param, headers=headers, timeout=(30.1, 50.1))
            try:
                data = conn.json()
            except Exception:
                data = {}

            message = ""
            if isinstance(data, dict):
                message = data.get("message", "")

            if not self._is_rate_limited(status_code=conn.status_code, data=data, message=message):
                return conn.status_code, data

            if attempt > self.rate_limit_retry:
                self.logger.error(
                    "zoomeye rate limit retry exhausted target:{} curr_page:{} code:{} message:{}".format(
                        target,
                        curr_page,
                        conn.status_code,
                        message,
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
                "zoomeye rate limit target:{} curr_page:{} retry:{}/{} sleep:{}s".format(
                    target, curr_page, attempt, self.rate_limit_retry, sleep_time
                )
            )
            time.sleep(sleep_time)

    def sub_domains(self, target):
        param = {
            "q": target,
            "page": 1,
            "type": "1",
        }

        headers = {
            "API-KEY": self.api_key
        }

        results = []

        curr_page = 1
        while True:
            self.logger.debug("zoomeye target:{} curr_page:{}".format(target, curr_page))
            param["page"] = curr_page
            status_code, data = self._request_page(param=param, headers=headers, target=target, curr_page=curr_page)

            if status_code != 200:
                self.logger.error("zoomeye query error:{}".format(json.dumps(data, ensure_ascii=False)))
                break

            if not isinstance(data, dict):
                self.logger.error("zoomeye query error: invalid response {}".format(type(data)))
                break

            items = data.get("list", [])
            if not items:
                break

            for item in items:
                name = item["name"]
                if name.endswith("." + target):
                    results.append(name)

            self.logger.debug(
                "zoomeye target:{} curr_page:{} total:{} curr_size:{}".format(
                    target, curr_page, data.get("total", 0), len(items)))

            # zoomeye 是每页返回30条数据
            if len(items) < 30:
                break

            # 常规翻页也做轻微节流，降低触发频率限制概率
            time.sleep(max(self.request_interval, 0))
            curr_page += 1

            if curr_page > self.max_page:
                break

        return list(set(results))
