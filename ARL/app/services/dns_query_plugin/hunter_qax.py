import base64
import json
import time
from urllib.parse import urlparse

from app.services.dns_query import DNSQueryBase
from app import utils


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "hunter_qax"
        self.support_ip_query = True
        self.support_cert_query = True
        self.api_url = "https://hunter.qianxin.com/openApi/search"
        self.api_key = None
        self.page_size = 10
        self.max_page = 10
        self.request_interval = 1.0
        self.rate_limit_retry = 4
        self.rate_limit_backoff = 2
        self.rate_limit_max_sleep = 60

    def init_key(
        self,
        api_key=None,
        page_size=10,
        max_page=5,
        request_interval=1.0,
        rate_limit_retry=4,
        rate_limit_backoff=2,
        rate_limit_max_sleep=60,
    ):
        self.api_key = api_key
        self.page_size = max(self._safe_to_int(page_size, 10), 1)
        self.max_page = max(self._safe_to_int(max_page, 5), 1)
        self.request_interval = max(self._safe_to_float(request_interval, 1.0), 0.0)
        self.rate_limit_retry = max(self._safe_to_int(rate_limit_retry, 4), 0)
        self.rate_limit_backoff = max(self._safe_to_int(rate_limit_backoff, 2), 1)
        self.rate_limit_max_sleep = max(self._safe_to_int(rate_limit_max_sleep, 60), self.rate_limit_backoff)

    def _search_page(self, param, search_hint="", curr_page=1):
        """
        请求单页数据，遇到频率受限时自动退避重试。
        """
        attempt = 0
        while True:
            attempt += 1
            conn = utils.http_req(self.api_url, 'get', params=param)
            try:
                data = conn.json()
            except Exception:
                data = {}

            code = data.get("code") if isinstance(data, dict) else ""
            message = data.get("message", "") if isinstance(data, dict) else ""
            if not self._is_rate_limited(status_code=conn.status_code, data=data, message=message):
                return data

            if attempt > self.rate_limit_retry:
                self.logger.error(
                    "hunter_qax rate limit retry exhausted search:{} curr_page:{} code:{} message:{}".format(
                        search_hint, curr_page, code, message
                    )
                )
                return data

            sleep_time = self._calc_retry_sleep(
                attempt=attempt,
                conn=conn,
                data=data,
                base=self.rate_limit_backoff,
                cap=self.rate_limit_max_sleep,
            )
            self.logger.info(
                "hunter_qax rate limit search:{} curr_page:{} code:{} retry:{}/{} sleep:{}s".format(
                    search_hint, curr_page, code, attempt, self.rate_limit_retry, sleep_time
                )
            )
            time.sleep(sleep_time)

    def sub_domains(self, target):
        search = "domain.suffix=\"{}\"".format(target)

        param = {
            "search": base64.urlsafe_b64encode(search.encode("utf-8")),
            "page": 1,
            "page_size": self.page_size,
            "is_web": "1",
            "api-key": self.api_key
        }

        results = []

        curr_page = 1
        while True:
            self.logger.debug("hunter_qax target:{} page_size:{} curr_page:{}".format(target, self.page_size, curr_page))
            param["page"] = curr_page
            data = self._search_page(param=param, search_hint=search, curr_page=curr_page)

            if not isinstance(data, dict):
                self.logger.error("hunter_qax query error: invalid response {}".format(type(data)))
                break

            if data.get("code") != 200 and data.get("code") != 40205:
                self.logger.error("hunter_qax query error:{}".format(json.dumps(data, ensure_ascii=False)))
                break

            if data.get("code") == 40205:
                self.logger.info(data["message"])

            arr = (data.get("data") or {}).get("arr")
            if arr is None:
                break

            for item in arr:
                name = item["domain"]
                if name.endswith("." + target):
                    results.append(name)

            self.logger.debug(
                "hunter_qax target:{} page_size:{} curr_page:{} total:{} curr_size:{}".format(
                    target, self.page_size, curr_page, (data.get("data") or {}).get("total", 0), len(arr)))

            if len(arr) < self.page_size:
                break

            # 常规翻页也做轻微节流，降低触发频率限制概率
            time.sleep(max(self.request_interval, 0))
            curr_page += 1

            if curr_page > self.max_page:
                break

        return list(set(results))

    def _query_search(self, search):
        """
        Hunter 通用查询方法，返回提取到的域名列表
        """
        param = {
            "search": base64.urlsafe_b64encode(search.encode("utf-8")),
            "page": 1,
            "page_size": self.page_size,
            "is_web": "1",
            "api-key": self.api_key
        }

        results = []
        curr_page = 1
        while True:
            self.logger.debug(
                "hunter_qax search:{} page_size:{} curr_page:{}".format(search, self.page_size, curr_page)
            )
            param["page"] = curr_page
            data = self._search_page(param=param, search_hint=search, curr_page=curr_page)

            if not isinstance(data, dict):
                self.logger.error("hunter_qax query error: invalid response {}".format(type(data)))
                break

            if data.get("code") != 200 and data.get("code") != 40205:
                self.logger.error("hunter_qax query error:{}".format(json.dumps(data, ensure_ascii=False)))
                break

            if data.get("code") == 40205:
                self.logger.info(data["message"])

            arr = (data.get("data") or {}).get("arr")
            if arr is None:
                break

            for item in arr:
                domain = str(item.get("domain") or "").strip().lower().rstrip(".")
                if not domain:
                    raw_url = str(item.get("url") or "").strip()
                    if raw_url:
                        try:
                            domain = (urlparse(raw_url).hostname or "").strip().lower().rstrip(".")
                        except Exception:
                            domain = ""

                if domain and not utils.is_vaild_ip_target(domain):
                    results.append(domain)

            self.logger.debug(
                "hunter_qax search:{} page_size:{} curr_page:{} total:{} curr_size:{}".format(
                    search, self.page_size, curr_page, (data.get("data") or {}).get("total", 0), len(arr))
            )

            if len(arr) < self.page_size:
                break

            time.sleep(max(self.request_interval, 0))
            curr_page += 1
            if curr_page > self.max_page:
                break

        return list(set(results))

    def sub_domains_by_ip(self, ip):
        """
        按IP查询 Hunter 并提取域名
        """
        search = "ip=\"{}\"".format(ip)
        return self._query_search(search)

    def sub_domains_by_cert(self, cert):
        """
        按证书指纹查询 Hunter 并提取域名
        """
        fingerprint = cert.get("fingerprint") or {}
        cert_sha1 = ""
        if isinstance(fingerprint, dict):
            cert_sha1 = str(fingerprint.get("sha1") or "").strip().lower()

        if not cert_sha1:
            return []

        search = "cert.sha-1=\"{}\"".format(cert_sha1)
        return self._query_search(search)
