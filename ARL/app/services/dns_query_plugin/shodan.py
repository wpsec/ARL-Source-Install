"""
Shodan 域名查询插件

能力说明：
- 支持按域名、IP、证书信息查询关联域名
- 兼容 Shodan DNS API 与 host search API
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
        self.support_ip_query = True
        self.support_cert_query = True
        self.dns_api_url = "https://api.shodan.io/dns/domain/{}"
        self.search_api_url = "https://api.shodan.io/shodan/host/search"
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

    @staticmethod
    def _normalize_hash(value):
        return str(value or "").strip().lower().replace(":", "").replace(" ", "")

    @staticmethod
    def _normalize_serial(value):
        return str(value or "").strip().lower().replace(" ", "")

    @staticmethod
    def _extract_domains_from_text(value):
        candidates = set()
        if not isinstance(value, str):
            return candidates

        for raw_item in value.split(","):
            item = str(raw_item or "").strip()
            if not item:
                continue
            if ":" in item:
                prefix, suffix = item.split(":", 1)
                if prefix.strip().lower() in {"dns", "cn"}:
                    item = suffix

            domain = utils.normalize_domain(item)
            if not domain or utils.is_vaild_ip_target(domain) or not utils.is_valid_domain(domain):
                continue
            candidates.add(domain)

        return candidates

    def _extract_cert_domains(self, cert_obj):
        domains = set()
        if not isinstance(cert_obj, dict):
            return domains

        subject = cert_obj.get("subject") or {}
        if isinstance(subject, dict):
            for key in ("cn", "CN", "common_name", "commonName"):
                domain = utils.normalize_domain(subject.get(key))
                if domain and not utils.is_vaild_ip_target(domain) and utils.is_valid_domain(domain):
                    domains.add(domain)

        for key in ("subjectAltName", "subjectaltname"):
            domains.update(self._extract_domains_from_text(cert_obj.get(key)))

        extensions = cert_obj.get("extensions") or {}
        if isinstance(extensions, dict):
            for key in ("subjectAltName", "subjectaltname"):
                domains.update(self._extract_domains_from_text(extensions.get(key)))

        for key in ("dns", "domains", "hostnames", "alt_names", "names"):
            values = cert_obj.get(key)
            if not isinstance(values, list):
                continue
            for value in values:
                domain = utils.normalize_domain(value)
                if not domain or utils.is_vaild_ip_target(domain) or not utils.is_valid_domain(domain):
                    continue
                domains.add(domain)

        return domains

    def _extract_domains_from_match(self, item):
        domains = set()
        if not isinstance(item, dict):
            return domains

        for key in ("domains", "hostnames"):
            values = item.get(key)
            if not isinstance(values, list):
                continue
            for value in values:
                domain = utils.normalize_domain(value)
                if not domain or utils.is_vaild_ip_target(domain) or not utils.is_valid_domain(domain):
                    continue
                domains.add(domain)

        ssl_obj = item.get("ssl") or {}
        if isinstance(ssl_obj, dict):
            cert_obj = ssl_obj.get("cert") or {}
            domains.update(self._extract_cert_domains(cert_obj))

        return domains

    def _request_dns_page(self, target, curr_page):
        params = {
            "key": self.api_key,
            "page": curr_page
        }
        request_url = self.dns_api_url.format(target)

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

    def _request_search_page(self, search, curr_page):
        params = {
            "key": self.api_key,
            "query": search,
            "page": curr_page,
        }

        attempt = 0
        while True:
            attempt += 1
            conn = utils.http_req(self.search_api_url, "get", params=params, timeout=(30.1, 50.1))
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
                    "shodan search rate limit retry exhausted search:{} curr_page:{} code:{} message:{}".format(
                        search, curr_page, conn.status_code, message
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
                "shodan search rate limit search:{} curr_page:{} retry:{}/{} sleep:{}s".format(
                    search, curr_page, attempt, self.rate_limit_retry, sleep_time
                )
            )
            time.sleep(sleep_time)

    def _query_dns_api(self, target):
        results = []
        curr_page = 1
        while True:
            self.logger.debug("shodan target:{} curr_page:{}".format(target, curr_page))
            status_code, data = self._request_dns_page(target=target, curr_page=curr_page)

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

    def _search_domains_by_queries(self, searches, log_target=""):
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

        for search in normalized_searches:
            curr_page = 1
            while True:
                self.logger.debug(
                    "shodan search:{} target:{} curr_page:{}".format(search, log_target or "-", curr_page)
                )
                status_code, data = self._request_search_page(search=search, curr_page=curr_page)

                if status_code != 200:
                    self.logger.error("shodan search error:{}".format(json.dumps(data, ensure_ascii=False)))
                    break

                if not isinstance(data, dict):
                    self.logger.error("shodan search error: invalid response {}".format(type(data)))
                    break

                matches = data.get("matches", [])
                if not isinstance(matches, list):
                    self.logger.error("shodan search error: invalid matches type {}".format(type(matches)))
                    break

                for item in matches:
                    for domain in self._extract_domains_from_match(item):
                        if domain in seen_domains:
                            continue
                        seen_domains.add(domain)
                        results.append(domain)

                total = int(self._safe_to_int(data.get("total"), 0) or 0)
                self.logger.debug(
                    "shodan search:{} target:{} curr_page:{} total:{} curr_size:{}".format(
                        search, log_target or "-", curr_page, total, len(matches)
                    )
                )

                if not matches:
                    break
                if len(matches) < 100:
                    break
                if total > 0 and curr_page * 100 >= total:
                    break

                time.sleep(max(self.request_interval, 0.0))
                curr_page += 1
                if curr_page > self.max_page:
                    break

            if search != normalized_searches[-1]:
                time.sleep(max(self.request_interval, 0.0))

        return list(set(results))

    def _build_domain_queries(self, target):
        queries = ["hostname:{}".format(target)]
        fld = utils.get_fld(target)
        if fld and fld == target:
            queries.insert(0, "domain:{}".format(target))
        return queries

    def _build_cert_queries(self, cert):
        queries = []
        if not isinstance(cert, dict):
            return queries

        subject = cert.get("subject") or {}
        if isinstance(subject, dict):
            common_name = utils.normalize_domain(
                subject.get("common_name") or subject.get("commonName") or subject.get("cn") or subject.get("CN")
            )
            if common_name:
                queries.append('ssl.cert.subject.cn:"{}"'.format(common_name))

        fingerprint = cert.get("fingerprint") or {}
        if isinstance(fingerprint, dict):
            sha1_value = self._normalize_hash(fingerprint.get("sha1"))
            if sha1_value:
                queries.append('ssl.cert.fingerprint:"{}"'.format(sha1_value))

        serial_number = self._normalize_serial(cert.get("serial_number"))
        if serial_number:
            if serial_number.isdigit():
                queries.append("ssl.cert.serial:{}".format(serial_number))
            else:
                queries.append('ssl.cert.serial:"{}"'.format(serial_number))

        return queries

    def sub_domains(self, target):
        target = str(target or "").strip().lower().rstrip(".")
        if not target:
            return []

        results = []
        results.extend(self._query_dns_api(target))
        results.extend(
            self._search_domains_by_queries(self._build_domain_queries(target), log_target=target)
        )
        return list(set(results))

    def sub_domains_by_ip(self, ip):
        ip = str(ip or "").strip()
        if not ip or not utils.is_vaild_ip_target(ip):
            return []

        return self._search_domains_by_queries(["ip:{}".format(ip)], log_target=ip)

    def sub_domains_by_cert(self, cert):
        queries = self._build_cert_queries(cert)
        if not queries:
            return []

        return self._search_domains_by_queries(queries, log_target="cert")
