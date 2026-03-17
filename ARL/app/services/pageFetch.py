"""
网页内容获取
"""
import time
import json
from app import  utils
from app.config import Config
from .baseThread import BaseThread
from .fileLeak import Page, HTTPReq, URL
logger = utils.get_logger()


class PageFetch(BaseThread):
    def __init__(self, sites, concurrency=6, waf_guard=None, waf_module="page_fetch"):
        super().__init__(sites, concurrency = concurrency)
        self.page_map = {}
        self.waf_guard = waf_guard
        self.waf_module = waf_module

    def work(self, site):
        req = HTTPReq(URL(site, ""), waf_guard=self.waf_guard, waf_module=self.waf_module)
        req.req()
        if str((getattr(req.conn, "headers", {}) or {}).get("X-ARL-WAF-SMART-SKIP", "")) == "1":
            return
        page = Page(req)

        data = page.dump_json()

        self.page_map[site] = data

    def run(self):
        t1 = time.time()
        logger.info("start PageFetch {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        logger.info("end PageFetch elapse {}".format(elapse))
        return self.page_map


def page_fetch(sites, concurrency = 6, waf_guard=None, waf_module="page_fetch"):
    s = PageFetch(sites, concurrency = concurrency, waf_guard=waf_guard, waf_module=waf_module)
    return s.run()



