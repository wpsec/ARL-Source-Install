"""
网站URL爬虫
"""
import re
import time
from collections import deque
from xml.etree import ElementTree
from app import utils
from app.utils.url import urlsimilar
from .baseThread import BaseThread
from urllib.parse import urljoin, urlparse
from pyquery import PyQuery as pq

logger = utils.get_logger()


class URLTYPE:
    document = "document"
    js = "js"
    css = "css"


class URLInfo(object):
    def __init__(self, entry_url, crawl_url, url_type):
        self.entry_url = entry_url
        self.crawl_url = crawl_url
        self._similar_hash = urlsimilar(self.crawl_url)
        self.type = url_type or URLTYPE.document

    def to_dict(self):
        obj = dict()
        obj["base_url"] = self.entry_url
        obj["crawl_url"] = self.crawl_url
        obj["type"] = self.type
        return obj

    def __eq__(self, other):
        if not isinstance(other, URLInfo):
            return False
        return self.crawl_url == self.crawl_url

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return str(self.to_dict())

    def __str__(self):
        return self.__repr__()

    def __hash__(self):
        return self._similar_hash

    def similar_hash(self):
        return self._similar_hash


class URLList(object):
    def __init__(self):
        self.result = []
        self.similar_hash_pool = []

    def __iter__(self):
        return self.result.__iter__()

    def __getitem__(self, item):
        return self.result[item]

    def __len__(self):
        return self.result.__len__()

    def add(self, element: URLInfo):
        """
        正常添加
        :param element: URLInfo
        :return:
        """
        if not isinstance(element, URLInfo):
            raise TypeError("need URLInfo")
        if element not in self.result:
            self.result.append(element)

    def __repr__(self):
        return str(self.result)

    def __str__(self):
        return self.__repr__()

    def __contains__(self, item):
        if not isinstance(item, URLInfo):
            return False

        return item.similar_hash() in self.similar_hash_pool


class URLSimilarList(URLList):
    def add(self, element: URLInfo):
        """
        URL去除相似后添加
        :param element: URLInfo
        :return:
        """
        if not isinstance(element, URLInfo):
            raise TypeError("need URLinfo")

        if element.similar_hash() not in self.similar_hash_pool:
            self.result.append(element)
            self.similar_hash_pool.append(element.similar_hash())


class SiteURLSpider(object):
    def __init__(self, entry_urls=None, deep_num=3, waf_guard=None):
        entry_url_list = URLSimilarList()
        for url in entry_urls:
            entry_url_list.add(URLInfo(url, url, URLTYPE.document))

        self.entry_url_list = entry_url_list
        self.done_url_list = URLSimilarList()
        self.deep_num = deep_num
        self.all_url_list = URLSimilarList()
        self.max_url = max(60, len(entry_urls)*6)
        self.max_sitemap_urls = max(40, len(entry_urls) * 20)
        self.scope_url = entry_urls[0]
        self.dns_policy_cache = {}
        self.waf_guard = waf_guard

        self.tagMap = [{'name': 'a', 'attr': 'href', 'type': URLTYPE.document},
                       {'name': 'form', 'attr': 'action', 'type': URLTYPE.document},
                       {'name': 'iframe', 'attr': 'src', 'type': URLTYPE.document},
                       #{'name': 'script', 'attr': 'src', 'type': URLTYPE.js},
                       #{'name': 'link', 'attr': 'href', 'type': URLTYPE.css}
                       ]

        self.ignore_ext = [".pdf", ".xls", ".xlsx", ".doc", ".docx", ".ppt", ".pptx", ".zip", ".rar"]
        self.ignore_ext.extend([".png", ".jpg", ".gif", ".js", ".css", ".ico"])

    @staticmethod
    def _extract_text_body(conn) -> str:
        try:
            body = getattr(conn, "text", None)
            if body is not None:
                return str(body or "")
        except Exception:
            pass

        raw_body = getattr(conn, "content", b"")
        if isinstance(raw_body, bytes):
            try:
                return raw_body.decode("utf-8", "ignore")
            except Exception:
                return ""
        return str(raw_body or "")

    def _is_same_scope_url(self, value: str) -> bool:
        normalized = utils.normal_url(value)
        if not normalized:
            return False
        return utils.same_netloc(normalized, self.scope_url)

    def _fetch_sitemap_candidates(self):
        scope_parsed = urlparse(self.scope_url)
        if not scope_parsed.scheme or not scope_parsed.netloc:
            return []

        base_origin = "{}://{}".format(scope_parsed.scheme, scope_parsed.netloc)
        robots_url = "{}/robots.txt".format(base_origin.rstrip("/"))
        default_sitemap_url = "{}/sitemap.xml".format(base_origin.rstrip("/"))
        candidates = [default_sitemap_url]

        try:
            allow_scan, policy_detail = utils.check_dns_policy_for_url(robots_url, cache_map=self.dns_policy_cache)
            if allow_scan:
                conn = utils.http_req(robots_url, waf_guard=self.waf_guard, waf_module="site_spider")
                if str((getattr(conn, "headers", {}) or {}).get("X-ARL-WAF-SMART-SKIP", "")) != "1":
                    body_text = self._extract_text_body(conn)
                    for line in body_text.splitlines():
                        if not re.match(r"^\s*sitemap\s*:", line, flags=re.I):
                            continue
                        sitemap_url = str(line.split(":", 1)[1] or "").strip()
                        if self._is_same_scope_url(sitemap_url):
                            candidates.append(sitemap_url)
            else:
                logger.info(
                    "skip site_spider robots by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                        robots_url,
                        policy_detail.get("reason", ""),
                        policy_detail.get("resolver_ips", []),
                        policy_detail.get("system_ips", []),
                    )
                )
        except Exception as e:
            logger.debug("site spider robots parse failed {} {}".format(robots_url, e))

        deduped = []
        seen = set()
        for item in candidates:
            normalized = utils.normal_url(item)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(normalized)
        return deduped

    def _collect_sitemap_urls(self) -> URLSimilarList:
        result = URLSimilarList()
        sitemap_queue = deque()
        queued = set()
        visited = set()

        for sitemap_url in self._fetch_sitemap_candidates():
            sitemap_queue.append(sitemap_url)
            queued.add(sitemap_url)

        while sitemap_queue and len(result) < self.max_sitemap_urls:
            sitemap_url = sitemap_queue.popleft()
            if sitemap_url in visited:
                continue
            visited.add(sitemap_url)

            try:
                allow_scan, policy_detail = utils.check_dns_policy_for_url(sitemap_url, cache_map=self.dns_policy_cache)
                if not allow_scan:
                    logger.info(
                        "skip site_spider sitemap by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                            sitemap_url,
                            policy_detail.get("reason", ""),
                            policy_detail.get("resolver_ips", []),
                            policy_detail.get("system_ips", []),
                        )
                    )
                    continue

                conn = utils.http_req(sitemap_url, waf_guard=self.waf_guard, waf_module="site_spider")
                if str((getattr(conn, "headers", {}) or {}).get("X-ARL-WAF-SMART-SKIP", "")) == "1":
                    logger.info("skip site_spider sitemap by waf smart skip url:{}".format(sitemap_url))
                    continue
                body_text = self._extract_text_body(conn)
                if not body_text or "<loc" not in body_text.lower():
                    continue
                try:
                    root = ElementTree.fromstring(body_text.encode("utf-8", "ignore"))
                except Exception:
                    continue

                for node in root.iter():
                    if not str(node.tag or "").lower().endswith("loc"):
                        continue
                    loc_text = str(node.text or "").strip()
                    normalized = utils.normal_url(loc_text)
                    if not normalized or not self._is_same_scope_url(normalized):
                        continue
                    if normalized.lower().endswith(".xml"):
                        if normalized not in queued and normalized not in visited and len(queued) + len(visited) < self.max_sitemap_urls:
                            sitemap_queue.append(normalized)
                            queued.add(normalized)
                        continue
                    if utils.url_ext(normalized) in self.ignore_ext:
                        continue
                    result.add(URLInfo(self.scope_url, normalized, URLTYPE.document))
                    if len(result) >= self.max_sitemap_urls:
                        break
            except Exception as e:
                logger.debug("site spider sitemap parse failed {} {}".format(sitemap_url, e))

        return result

    def get_urls(self, entry_url):
        return self._work(entry_url)

    def _work(self, entry_url):
        try:
            logger.debug("[{}] req = > {}".format(len(self.done_url_list), entry_url))
            if utils.url_ext(entry_url) in self.ignore_ext:
                return URLSimilarList()

            allow_scan, policy_detail = utils.check_dns_policy_for_url(entry_url, cache_map=self.dns_policy_cache)
            if not allow_scan:
                logger.info(
                    "skip site_spider by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                        entry_url,
                        policy_detail.get("reason", ""),
                        policy_detail.get("resolver_ips", []),
                        policy_detail.get("system_ips", []),
                    )
                )
                return URLSimilarList()

            conn = utils.http_req(entry_url, waf_guard=self.waf_guard, waf_module="site_spider")
            if str((conn.headers or {}).get("X-ARL-WAF-SMART-SKIP", "")) == "1":
                logger.info("skip site_spider by waf smart skip url:{}".format(entry_url))
                return URLSimilarList()

            if conn.status_code in [301, 302, 307]:
                _url = urljoin(entry_url, conn.headers.get("Location", "")).strip()
                _url = utils.normal_url(_url)
                if _url is None:
                    return URLSimilarList()

                allow_scan, policy_detail = utils.check_dns_policy_for_url(_url, cache_map=self.dns_policy_cache)
                if not allow_scan:
                    logger.info(
                        "skip site_spider redirect by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                            _url,
                            policy_detail.get("reason", ""),
                            policy_detail.get("resolver_ips", []),
                            policy_detail.get("system_ips", []),
                        )
                    )
                    return URLSimilarList()

                url_info = URLInfo(entry_url, _url, URLTYPE.document)
                if utils.same_netloc(entry_url, _url) and (url_info not in self.done_url_list):
                    entry_url = _url
                    logger.info("[{}] req 302 = > {}".format(len(self.done_url_list), entry_url))
                    conn = utils.http_req(_url, waf_guard=self.waf_guard, waf_module="site_spider")
                    if str((conn.headers or {}).get("X-ARL-WAF-SMART-SKIP", "")) == "1":
                        logger.info("skip site_spider redirect by waf smart skip url:{}".format(_url))
                        return URLSimilarList()
                    self.done_url_list.add(url_info)
                    self.all_url_list.add(url_info)

            html = conn.content
            if "html" not in conn.headers.get("Content-Type", "").lower():
                return URLSimilarList()
            if not html or not html.strip():
                logger.info("skip site spider empty html {}".format(entry_url))
                return URLSimilarList()

            dom = pq(html)
            ret_url = URLSimilarList()
            for tag in self.tagMap:
                items = dom(tag['name']).items()
                for i in items:
                    _url = urljoin(entry_url, i.attr(tag['attr'])).strip()
                    _url = utils.normal_url(_url)
                    if _url is None:
                        continue

                    if utils.url_ext(_url) in self.ignore_ext:
                        continue

                    _type = tag["type"]
                    if utils.same_netloc(_url, entry_url):
                        url_info = URLInfo(entry_url, _url, _type)
                        ret_url.add(url_info)
                        self.all_url_list.add(url_info)
            return ret_url
        except Exception as e:
            logger.warning("skip site spider parse {} {}".format(entry_url, e))
            return URLSimilarList()

    def run(self):
        tmp_urls = URLSimilarList()
        for item in self.entry_url_list:
            tmp_urls.add(item)
        for item in self._collect_sitemap_urls():
            tmp_urls.add(item)

        for num in range(0, self.deep_num):
            if len(tmp_urls) > 0:
                logger.info("{} deep num {}, len {}".format(self.scope_url, num + 1, len(tmp_urls)))

            new_url = URLSimilarList()
            for info in tmp_urls:
                self.all_url_list.add(info)
                if len(self.done_url_list) > self.max_url:
                    logger.warning("exit on request max url {}".format(self.scope_url))
                    return self.all_url_list

                if info not in self.done_url_list:
                    ret_urls = self.get_urls(info.crawl_url)
                    self.done_url_list.add(info)
                    for x in ret_urls:
                        new_url.add(x)

            tmp_urls = new_url

        return self.all_url_list


class SiteURLSpiderThread(BaseThread):
    def __init__(self, entry_urls_list, concurrency=6, deep_num=5, waf_guard=None):
        super().__init__(entry_urls_list, concurrency=concurrency)
        self.site_url_map = {}
        self.deep_num = deep_num
        self.waf_guard = waf_guard

    def work(self, entry_urls):
        # entry_urls 是一个数组，第一个是当前站点
        site = entry_urls[0]
        self.site_url_map[site] = site_spider(entry_urls, self.deep_num, waf_guard=self.waf_guard)

    def run(self):
        t1 = time.time()
        logger.info("start site url spider entry_urls_list:{}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        logger.info("end site url spider ({:.2f}s)".format(elapse))
        return self.site_url_map


def site_spider_thread(entry_urls_list, deep_num=5, waf_guard=None):
    s = SiteURLSpiderThread(entry_urls_list, concurrency=6, deep_num=deep_num, waf_guard=waf_guard)
    return s.run()


def site_spider(entry_url, deep_num=3, waf_guard=None):
    if isinstance(entry_url, str):
        entry_url = [entry_url]

    ret = []
    s = SiteURLSpider(entry_url, deep_num, waf_guard=waf_guard)
    for x in s.run():
        if urlparse(x.crawl_url).path == "/" or (not urlparse(x.crawl_url).path):
            continue

        if x.type == URLTYPE.document:
            ret.append(x.crawl_url)

    return ret




