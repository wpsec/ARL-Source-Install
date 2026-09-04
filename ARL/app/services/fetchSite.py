"""
Web站点获取和探测
"""
import time
from pyquery import PyQuery as pq
import binascii
from urllib.parse import urljoin, urlparse
from urllib3.util.url import parse_url, get_host
import mmh3
from app import utils
from app.config import Config
from .baseThread import BaseThread
from .fingerprint_cache import build_legacy_fingerprint_items, split_fingerprint_result_items
from .site_fingerprint_registry import get_site_registry, split_unified_items
from .page_semantics import enrich_page_item

logger = utils.get_logger()
from .autoTag import auto_tag
from app.utils import http_req, normal_url
from app.utils.fingerprint import load_fingerprint, fetch_fingerprint


class _CachedResponse(object):
    """将任务级缓存转换为 FetchSite 所需的最小响应对象。"""

    def __init__(self, response):
        self.status_code = int(getattr(response, "status_code", 0) or 0)
        self.headers = dict(getattr(response, "headers", {}) or {})
        self.content = bytes(getattr(response, "body", b"") or b"")


class FetchSite(BaseThread):
    def __init__(
        self,
        sites,
        concurrency=6,
        http_timeout=None,
        waf_guard=None,
        discovery_context=None,
    ):
        super().__init__(sites, concurrency)
        self.site_info_list = []
        self.fingerprint_list = load_fingerprint()
        self.dns_policy_cache = {}
        self.http_connect_cache = {}
        self.http_timeout = http_timeout
        self.waf_guard = waf_guard
        self.discovery_context = discovery_context
        if http_timeout is None:
            self.http_timeout = (10.1, 30.1)

    def fetch_fingerprint(self, item, content):
        favicon_hash = item["favicon"].get("hash", 0)
        if self._try_unified_fingerprint(item, content, favicon_hash):
            return
        basic_names = fetch_fingerprint(
            content=content,
            headers=item["headers"],
            title=item["title"],
            favicon_hash=favicon_hash,
            finger_list=self.fingerprint_list,
        )
        detail_list = finger_identify_detail(
            content=content,
            header=item["headers"],
            title=item["title"],
            favicon_hash=str(favicon_hash),
            url=item["site"],
        )

        merged_items = build_legacy_fingerprint_items(basic_names)
        merged_items.extend(detail_list)

        finger, finger_candidates = split_fingerprint_result_items(merged_items)
        if finger:
            item["finger"] = finger
        if finger_candidates:
            item["finger_candidates"] = finger_candidates

    def _try_unified_fingerprint(self, item, content, favicon_hash) -> bool:
        """SITE_FINGERPRINT_SOURCE=unified 时走规范文件链；返回 False 表示调用方继续 legacy。

        降级是显式行为：加载失败必须带 ERROR 证据，不允许空规则静默出结果。
        """
        mode = str(getattr(Config, "SITE_FINGERPRINT_SOURCE", "legacy") or "legacy").strip().lower()
        if mode != "unified":
            return False
        registry = get_site_registry()
        if not registry.ok:
            logger.warning(
                "unified site fingerprint unavailable, fallback to legacy: %s", registry.load_error)
            return False
        variables = build_identify_variables(
            content, item["headers"], item["title"], str(favicon_hash), item["site"])
        items = registry.match(variables)
        finger, finger_candidates = split_unified_items(items)
        if finger:
            item["finger"] = finger
        if finger_candidates:
            item["finger_candidates"] = finger_candidates
        return True

    def _release_inflight_site(self, site, inflight_owner):
        """先行者未走 put_response 的退出路径必须释放槽位，避免等待方干等超时。"""
        if not inflight_owner or self.discovery_context is None:
            return
        try:
            self.discovery_context.release_fetch_slot(site, request_profile="html_get")
        except Exception:
            pass


    def work(self, site, max_redirect=5):
        if max_redirect <= 0:
            return

        allow_scan, policy_detail = utils.check_dns_policy_for_url(site, cache_map=self.dns_policy_cache)
        if not allow_scan:
            logger.info(
                "skip fetch_site by dns policy site:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    site,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return

        _, hostname, _ = get_host(site)

        connect_kwargs = utils.build_http_connect_kwargs_for_url(
            site,
            policy_detail=policy_detail,
            cache_map=self.http_connect_cache,
        )
        cached_response = None
        inflight_owner = False
        if self.discovery_context is not None:
            cached_response = self.discovery_context.get_response(
                site,
                request_profile="html_get",
                consumer="fetch_site",
            )
            if cached_response is None:
                # 并发 miss 合并：等待先行者结果，拿不到才自己抓。
                cached_response, follower = self.discovery_context.await_singleflight_leader(
                    site, request_profile="html_get", consumer="fetch_site")
                inflight_owner = not follower

        lease = None
        if cached_response is not None:
            conn = _CachedResponse(cached_response)
        else:
            if self.discovery_context is not None:
                lease, lease_reason = self.discovery_context.acquire_request(site, "normal")
                if lease is None:
                    if lease_reason == "blocked":
                        # WAF 类别熔断：跳过必须可见，不能伪装成站点不存在。
                        logger.info("fetch_site skipped by waf traffic policy site:%s", site)
                        self._release_inflight_site(site, inflight_owner)
                        return
                    # 等待超时 fail-open：宁可超额发一次也不丢种子站点结果，超限量单独计数。
                    logger.warning("fetch_site over capacity, continue request site:%s", site)
            try:
                conn = utils.http_req(
                    site,
                    timeout=self.http_timeout,
                    waf_guard=self.waf_guard,
                    waf_module="fetch_site",
                    **connect_kwargs
                )
            except Exception:
                if self.discovery_context is not None:
                    self.discovery_context.record_metric("failed_count")
                    self._release_inflight_site(site, inflight_owner)
                raise
            finally:
                if lease is not None:
                    lease.release()

        if str((conn.headers or {}).get("X-ARL-WAF-SMART-SKIP", "")) == "1":
            logger.info("skip fetch_site by waf smart skip site:{}".format(site))
            self._release_inflight_site(site, inflight_owner)
            return

        if self.discovery_context is not None and cached_response is None:
            self.discovery_context.put_response(
                url=site,
                method="GET",
                request_profile="html_get",
                status_code=getattr(conn, "status_code", 0),
                headers=getattr(conn, "headers", {}) or {},
                content_type=(getattr(conn, "headers", {}) or {}).get("Content-Type", ""),
                body=getattr(conn, "content", b"") or b"",
                source="fetch_site",
                consumer="fetch_site",
            )

        item = {
            "site": site[:200],
            "hostname": hostname,
            "ip": "",
            "title": utils.get_title(conn.content),
            "status": conn.status_code,
            "headers": utils.get_headers(conn),
            "http_server": conn.headers.get("Server", ""),
            "body_length": len(conn.content),
            "finger": [],
            "favicon": fetch_favicon(
                site,
                waf_guard=self.waf_guard,
                page_body=conn.content if cached_response is None else getattr(cached_response, "body", b""),
                discovery_context=self.discovery_context,
            )
        }
        try:
            # site 文档补 body_excerpt/semantic_tags；status_code 字段名与 url 文档不同，双写状态键兼容读取。
            item["status_code"] = conn.status_code
            enrich_page_item(item, body=getattr(conn, "content", b""), headers=getattr(conn, "headers", None))
            item.pop("status_code", None)
        except Exception as exc:
            logger.debug("fetch_site semantics failed error_type:{}".format(type(exc).__name__))

        # 直连 IP 来自 DNS policy 的已验证视角，即使测试/内部域名无法被
        # 公共后缀库识别，也不能丢失这个实际连接目标。
        if connect_kwargs.get("connect_ip"):
            item["ip"] = connect_kwargs["connect_ip"]

        self.fetch_fingerprint(item, content=conn.content)
        domain_parsed = utils.domain_parsed(hostname)
        if domain_parsed:
            item["fld"] = domain_parsed["fld"]
            if not item["ip"]:
                ips = utils.get_ip(hostname)
                if ips:
                    item["ip"] = ips[0]
        elif not item["ip"]:
            item["ip"] = hostname

        # 保存站点信息
        if max_redirect == 5 or max_redirect == 1 \
                or (conn.status_code != 301 and conn.status_code != 302):
            self.site_info_list.append(item)

        if conn.status_code == 301 or conn.status_code == 302:
            url_302 = urljoin(site, conn.headers.get("Location", ""))
            url_302 = normal_url(url_302)

            # 防御性编程，防止url过长
            if len(url_302) > 260:
                return

            if url_302 != site and same_netloc_and_scheme(url_302, site):
                self.work(url_302, max_redirect=max_redirect - 1)

    def run(self):
        t1 = time.time()
        logger.info("start fetch site {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        logger.info("end fetch site elapse {}".format(elapse))

        # 对站点信息自动打标签
        auto_tag(self.site_info_list)

        return self.site_info_list


def finger_identify(content: bytes, header: str, title: str, favicon_hash: str, url=""):
    detail_list = finger_identify_detail(
        content=content,
        header=header,
        title=title,
        favicon_hash=favicon_hash,
        url=url,
    )
    return [item["name"] for item in detail_list]


def build_identify_variables(content, header: str, title: str, favicon_hash: str, url=""):
    """unified 与 legacy 明细链共用同一字段归一（两条路径必须看到同一变量空间）。"""
    if isinstance(content, (bytes, bytearray)):
        try:
            content = bytes(content).decode("utf-8")
        except UnicodeDecodeError:
            content = bytes(content).decode("gbk", "ignore")
    return {
        "body": content,
        "header": header,
        "title": title,
        "icon_hash": favicon_hash,
        # 兼容规则中的 response 字段（头+体）
        "response": "{}\n{}".format(header, content),
        "url": str(url or ""),
    }


def finger_identify_detail(content: bytes, header: str, title: str, favicon_hash: str, url=""):
    from app.services import finger_db_identify_detail

    return finger_db_identify_detail(
        build_identify_variables(content, header, title, favicon_hash, url)
    )


def same_netloc_and_scheme(u1, u2):
    u1 = normal_url(u1)
    u2 = normal_url(u2)
    parsed1 = parse_url(u1)
    parsed2 = parse_url(u2)

    if parsed1.scheme == parsed2.scheme and parsed1.netloc == parsed2.netloc:
        return True

    return False


def fetch_favicon(url, waf_guard=None, page_body=None, discovery_context=None):
    f = FetchFavicon(url, waf_guard=waf_guard, page_body=page_body, discovery_context=discovery_context)
    return f.run()


def fetch_site(sites, concurrency=None, http_timeout=None, waf_guard=None, discovery_context=None):
    if concurrency is None:
        concurrency = Config.HTTP_FETCH_SITE_CONCURRENCY
    # 预热指纹缓存（优先命中进程内/Redis，减少重复查询 MongoDB）
    from app.services import finger_db_cache
    finger_db_cache.update_cache(force_db=False)

    f = FetchSite(
        sites,
        concurrency=concurrency,
        http_timeout=http_timeout,
        waf_guard=waf_guard,
        discovery_context=discovery_context,
    )
    return f.run()


class FetchFavicon(object):
    def __init__(self, url, waf_guard=None, page_body=None, discovery_context=None):
        self.url = url
        self.favicon_url = None
        self.dns_policy_cache = {}
        self.http_connect_cache = {}
        self.waf_guard = waf_guard
        # 原始页面正文由调用方传入，避免 favicon 解析对同一页面二次请求。
        self.page_body = page_body if isinstance(page_body, (bytes, bytearray)) else None
        self.discovery_context = discovery_context

    def build_result(self, data):
        result = {
            "data": data,
            "url": self.favicon_url,
            "hash": mmh3.hash(data)
        }
        return result

    def run(self):
        result = {}
        try:
            favicon_url = urljoin(self.url, "/favicon.ico")
            data = self.get_favicon_data(favicon_url)
            if data:
                self.favicon_url = favicon_url
                return self.build_result(data)

            favicon_url = self.find_icon_url_from_html()
            if not favicon_url:
                return result
            data = self.get_favicon_data(favicon_url)
            if data:
                self.favicon_url = favicon_url
                return self.build_result(data)

        except Exception as e:
            logger.warning("error on {} {}".format(self.url, e))

        return result

    def _cached_favicon(self, favicon_url):
        if self.discovery_context is None:
            return None
        cached = self.discovery_context.get_response(
            favicon_url, request_profile="favicon_get", consumer="fetch_favicon")
        if cached is None or int(getattr(cached, "status_code", 0) or 0) != 200:
            return cached
        return cached

    def get_favicon_data(self, favicon_url):
        allow_scan, policy_detail = utils.check_dns_policy_for_url(favicon_url, cache_map=self.dns_policy_cache)
        if not allow_scan:
            logger.info(
                "skip fetch_favicon by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    favicon_url,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return

        cached = self._cached_favicon(favicon_url)
        if cached is not None:
            status_code = int(getattr(cached, "status_code", 0) or 0)
            if status_code != 200:
                return
            cached_body = bytes(getattr(cached, "body", b"") or b"")
            if len(cached_body) <= 80:
                return
            return self.encode_bas64_lines(cached_body)

        connect_kwargs = utils.build_http_connect_kwargs_for_url(
            favicon_url,
            policy_detail=policy_detail,
            cache_map=self.http_connect_cache,
        )
        lease = None
        if self.discovery_context is not None:
            lease, lease_reason = self.discovery_context.acquire_request(favicon_url, "normal")
            if lease is None and lease_reason == "blocked":
                return
        try:
            conn = http_req(favicon_url, waf_guard=self.waf_guard, waf_module="fetch_favicon", **connect_kwargs)
        finally:
            if lease is not None:
                lease.release()
        if self.discovery_context is not None:
            self.discovery_context.put_response(
                url=favicon_url,
                method="GET",
                request_profile="favicon_get",
                status_code=getattr(conn, "status_code", 0),
                headers=getattr(conn, "headers", {}) or {},
                content_type=(getattr(conn, "headers", {}) or {}).get("Content-Type", ""),
                body=getattr(conn, "content", b"") or b"",
                source="fetch_favicon",
                consumer="fetch_favicon",
            )
        if conn.status_code != 200:
            return

        if len(conn.content) <= 80:
            logger.debug("favicon content len lt 100")
            return

        if "image" in conn.headers.get("Content-Type", ""):
            data = self.encode_bas64_lines(conn.content)
            return data

    def encode_bas64_lines(self, s):
        """Encode a string into multiple lines of base-64 data."""
        MAXLINESIZE = 76  # Excluding the CRLF
        MAXBINSIZE = (MAXLINESIZE // 4) * 3
        pieces = []
        for i in range(0, len(s), MAXBINSIZE):
            chunk = s[i: i + MAXBINSIZE]
            pieces.append(bytes.decode(binascii.b2a_base64(chunk)))
        return "".join(pieces)

    def find_icon_url_from_html(self):
        allow_scan, policy_detail = utils.check_dns_policy_for_url(self.url, cache_map=self.dns_policy_cache)
        if not allow_scan:
            logger.info(
                "skip fetch_favicon html by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    self.url,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return

        connect_kwargs = utils.build_http_connect_kwargs_for_url(
            self.url,
            policy_detail=policy_detail,
            cache_map=self.http_connect_cache,
        )
        html = self.page_body
        if html is None:
            conn = http_req(self.url, waf_guard=self.waf_guard, waf_module="fetch_favicon_html", **connect_kwargs)
            html = conn.content
        if not html or b"<link" not in html:
            return
        d = pq(html)
        links = d('link').items()
        icon_link_list = []
        for link in links:
            if link.attr("href") and 'icon' in link.attr("rel"):
                icon_link_list.append(link)

        for link in icon_link_list:
            if "shortcut" in link:
                return urljoin(self.url, link.attr('href'))

        if icon_link_list:
            return urljoin(self.url, icon_link_list[0].attr('href'))
