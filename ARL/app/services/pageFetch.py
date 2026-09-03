"""
网页内容获取
"""
import time
import json
from app import  utils
from app.config import Config
from .baseThread import BaseThread
from .fileLeak import Page, HTTPReq, URL
from .page_semantics import enrich_page_item
from .discovery_context import traffic_class_for_module
logger = utils.get_logger()


class PageFetch(BaseThread):
    def __init__(
        self,
        sites,
        concurrency=6,
        waf_guard=None,
        waf_module="page_fetch",
        discovery_context=None,
        traffic_class=None,
    ):
        super().__init__(sites, concurrency = concurrency)
        self.page_map = {}
        self.waf_guard = waf_guard
        self.waf_module = waf_module
        self.discovery_context = discovery_context
        self.traffic_class = traffic_class or traffic_class_for_module(waf_module)

    @staticmethod
    def _cached_page_data(url, response):
        body = bytes(getattr(response, "body", b"") or b"")
        item = {
            "title": utils.get_title(body).strip(),
            "url": url,
            "content_length": len(body),
            "status_code": int(getattr(response, "status_code", 0) or 0),
        }
        # 缓存路径与真实抓取路径保持同一证据字段形状。
        return enrich_page_item(item, body=body, headers=getattr(response, "headers", None))

    def _release_inflight_site(self, site, inflight_owner):
        if not inflight_owner or self.discovery_context is None:
            return
        try:
            self.discovery_context.release_fetch_slot(site, request_profile="html_get")
        except Exception:
            pass

    def work(self, site):
        inflight_owner = False
        if self.discovery_context is not None:
            cached_response = self.discovery_context.get_response(
                site,
                request_profile="html_get",
                consumer=self.waf_module,
            )
            if cached_response is not None:
                if str((getattr(cached_response, "headers", {}) or {}).get("X-ARL-WAF-SMART-SKIP", "")) == "1":
                    return
                if getattr(cached_response, "body_truncated", False):
                    # 本消费者仅取 title/状态/长度（live 路径同样截断），计数留痕；
                    # 链接解析型消费者(spider/fetch_text)对截断缓存会回源。
                    self.discovery_context.record_metric("truncated_cache_hit_count")
                self.page_map[site] = self._cached_page_data(site, cached_response)
                return

            cached_response, follower = self.discovery_context.await_singleflight_leader(
                site, request_profile="html_get", consumer=self.waf_module)
            inflight_owner = not follower
            if cached_response is not None:
                if str((getattr(cached_response, "headers", {}) or {}).get("X-ARL-WAF-SMART-SKIP", "")) == "1":
                    self._release_inflight_site(site, inflight_owner)
                    return
                if getattr(cached_response, "body_truncated", False):
                    self.discovery_context.record_metric("truncated_cache_hit_count")
                self.page_map[site] = self._cached_page_data(site, cached_response)
                return

        lease = None
        if self.discovery_context is not None:
            lease, lease_reason = self.discovery_context.acquire_request(site, self.traffic_class)
            if lease is None and lease_reason == "blocked":
                logger.info(
                    "page fetch skipped by waf traffic policy site:%s module:%s",
                    site,
                    self.waf_module,
                )
                self._release_inflight_site(site, inflight_owner)
                return
            if lease is None:
                logger.warning(
                    "page fetch over capacity, continue request site:%s module:%s",
                    site,
                    self.waf_module,
                )
        req = HTTPReq(URL(site, ""), waf_guard=self.waf_guard, waf_module=self.waf_module)
        try:
            req.req()
        except Exception:
            if self.discovery_context is not None:
                self.discovery_context.record_metric("failed_count")
                self._release_inflight_site(site, inflight_owner)
            raise
        finally:
            if lease is not None:
                lease.release()
        if str((getattr(req.conn, "headers", {}) or {}).get("X-ARL-WAF-SMART-SKIP", "")) == "1":
            self._release_inflight_site(site, inflight_owner)
            return
        if self.discovery_context is not None:
            self.discovery_context.put_response(
                url=site,
                method="GET",
                request_profile="html_get",
                status_code=req.status_code,
                headers=getattr(req.conn, "headers", {}) or {},
                content_type=(getattr(req.conn, "headers", {}) or {}).get("Content-Type", ""),
                body=req.content or b"",
                source=self.waf_module,
                consumer=self.waf_module,
            )
        page = Page(req)

        data = page.dump_json()
        # Page.dump_json 已带证据字段；此处只兜底缓存外路径的 Content-Type 缺失。
        data = enrich_page_item(data, body=req.content, headers=getattr(req.conn, "headers", None))

        self.page_map[site] = data

    def run(self):
        t1 = time.time()
        logger.info("start PageFetch {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        logger.info("end PageFetch elapse {}".format(elapse))
        return self.page_map


def page_fetch(
    sites,
    concurrency=6,
    waf_guard=None,
    waf_module="page_fetch",
    discovery_context=None,
    traffic_class=None,
):
    s = PageFetch(
        sites,
        concurrency=concurrency,
        waf_guard=waf_guard,
        waf_module=waf_module,
        discovery_context=discovery_context,
        traffic_class=traffic_class,
    )
    return s.run()


