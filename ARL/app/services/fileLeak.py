"""
敏感文件泄露扫描
"""
import base64
import difflib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from urllib.parse import urlparse, urljoin
import urllib3
import psutil
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from tld import get_tld
import itertools

from app import utils
from app.config import Config
from app.utils.log_safety import safe_error_text
from .baseThread import BaseThread
from .page_semantics import enrich_page_item

logger = utils.get_logger()
DNS_POLICY_CACHE = {}

min_length = 100
max_length = 50*1024
read_timeout = 60
bool_ratio = 0.8
HEARTBEAT_UPDATE_INTERVAL_SEC = 1.0


class FileLeakPolicySkip(Exception):
    """File leak request is skipped by DNS policy."""


class FileLeakResult(list):
    """保持文件泄漏结果列表兼容，同时携带站点队列指标。"""

    def __init__(self, values=None, metrics=None):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})


class URL():
    def __init__(self, url, payload):
        self.url = url
        self.payload = payload
        self._scope = None
        self._path = None

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        if isinstance(other, URL):
            return self.url == other.url
        else:
            return False

    def __hash__(self):
        return hash(self.url)


    def __str__(self):
        return self.url

    def __repr__(self):
        return "<URL> " + self.__str__()

    def __lt__(self, other):
        return self.url < other.url

    def __gt__(self, other):
        return self.url > other.url

    @property
    def scope(self) -> str:
        if self._scope is None:
            parse = urlparse(self.url)
            scope = "{}://{}".format(parse.scheme, parse.netloc)
            self._scope = scope

        return self._scope

    @property
    def path(self) -> str:
        if self._path is None:
            parse = urlparse(self.url)
            self._path = parse.path

        return self._path


def _url_priority(url):
    """为高价值泄漏路径排序，不删除低优先级候选。"""
    path = str(getattr(url, "path", "") or "").lower()
    score = 0
    high_value_tokens = (
        "/.env", "/.git", "config", "backup", "dump", "database", "swagger",
        "actuator", "admin", "manage", "console", "debug",
    )
    for token in high_value_tokens:
        if token in path:
            score += 10
    if getattr(url, "is_backup_path", False):
        score += 15
    return (-score, path, str(getattr(url, "url", "")))

class _LeakCachedResponse(object):
    """任务内已获取响应的最小 conn 形态；raw 为 None 走既有非流式分支。"""

    def __init__(self, status_code, headers, content):
        self.status_code = int(status_code or 0)
        self.headers = dict(headers or {})
        self.content = bytes(content or b"")
        self.raw = None

    def close(self):
        return None


class HTTPReq():
    def __init__(
        self,
        url: URL,
        read_timeout=60,
        max_length=50 * 1024,
        waf_guard=None,
        waf_module="file_leak",
        progress_callback=None,
        response_cache=None,
    ):
        self.url = url
        self.read_timeout = read_timeout
        self.max_length = max_length
        self.conn = None
        self.status_code = None
        self.content = None
        self.waf_guard = waf_guard
        self.waf_module = waf_module
        self.progress_callback = progress_callback
        self.response_cache = response_cache or {}

    def _cached_conn(self):
        """目录扫描只消费同 profile 已完成覆盖的响应；带 WAF 跳过标记的不消费。"""

        if not self.response_cache:
            return None
        try:
            key = normal_url(str(self.url.url or "").strip())
        except Exception:
            return None
        entry = self.response_cache.get(key)
        if not isinstance(entry, dict):
            return None
        headers = dict(entry.get("headers") or {})
        if str(headers.get("X-ARL-WAF-SMART-SKIP", "")) == "1":
            return None
        body_b64 = str(entry.get("body_b64") or "")
        if not body_b64:
            return None
        try:
            body = base64.b64decode(body_b64)
        except Exception:
            return None
        if not body:
            return None
        return _LeakCachedResponse(int(entry.get("status_code") or 0), headers, body)

    def _touch_progress(self):
        if callable(self.progress_callback):
            try:
                self.progress_callback()
            except Exception:
                pass

    def req(self):
        self._touch_progress()
        cached_conn = self._cached_conn()
        if cached_conn is not None:
            self.conn = cached_conn
            self.status_code = cached_conn.status_code
            self.content = cached_conn.content[: self.max_length]
            content_len = self.conn.headers.get("Content-Length", len(self.content))
            self.conn.headers["Content-Length"] = content_len
            cached_conn.close()
            self._touch_progress()
            return self.status_code, self.content
        content = b''
        allow_scan, policy_detail = utils.check_dns_policy_for_url(self.url.url, cache_map=DNS_POLICY_CACHE)
        if not allow_scan:
            raise FileLeakPolicySkip(
                "skip file_leak by dns policy reason:{} resolver_ips:{} system_ips:{}".format(
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )

        conn = utils.http_req(
            self.url.url,
            'get',
            timeout=(3, 6),
            stream=True,
            waf_guard=self.waf_guard,
            waf_module=self.waf_module,
        )
        self.conn = conn
        self._touch_progress()

        # 兼容 smart_skip_waf 的本地构造响应：该响应没有 raw 流，不能走 iter_content。
        if getattr(conn, "raw", None) is None:
            content = bytes(getattr(conn, "content", b"") or b"")[:self.max_length]
        else:
            start_time = time.time()
            for data in conn.iter_content(chunk_size=512):
                self._touch_progress()
                if time.time() - start_time >= self.read_timeout:
                    break
                content += data
                if len(content) >= int(self.max_length):
                    break

        self.status_code = conn.status_code
        self.content = content[:self.max_length]

        content_len = self.conn.headers.get("Content-Length", len(self.content))
        self.conn.headers["Content-Length"] = content_len

        conn.close()
        self._touch_progress()

        return self.status_code, self.content




class Page():
    def __init__(self, req: HTTPReq):
        self.raw_req = req
        self.url = req.url
        self.content = req.content
        self.body_length = len(self.content)
        self.times = 0
        self.status_code = req.status_code
        self._title = None
        self._location_url = None
        self._is_back_up_path = None
        self._is_back_up_page = None
        self.back_up_suffix_list = [".tar", ".tar.gz", ".zip", ".rar", ".7z", ".bz2", ".gz", ".war"]

    def __eq__(self, other):
        if isinstance(other, Page):
            if self.status_code != other.status_code:
                return False

            if self.is_302() and other.is_302():
                self_new_url = self.location_url
                other_new_url = other.location_url

                self_new_url = urljoin(self.url.url, self_new_url)
                other_new_url = urljoin(other.url.url, other_new_url)

                if self_new_url.endswith(self.url.payload+ "/"):
                    if other_new_url.endswith(other.url.payload + "/"):
                        if not self.url.payload.endswith("/") and not other.url.payload.endswith("/"):
                            return False

                self_new_path = urlparse(self_new_url).path
                other_new_path = urlparse(other_new_url).path

                path1 = self_new_path.replace(self.url.payload, "$AAAA$")
                path2 = other_new_path.replace(other.url.payload, "$AAAA$")

                if urlparse(self_new_url).netloc == urlparse(other_new_url).netloc:
                    if path1 == path2 and self_new_path.endswith("$AAAA$/"):
                        if not self.url.payload.endswith("/") and not other.url.payload.endswith("/"):
                            return False

                if path1 == path2:
                    self.times += 1
                    return True
                else:
                    return False

            self_content = self.content.replace(self.url.payload.encode(), b"")
            other_content = other.content.replace(other.url.payload.encode(), b"")

            if abs(len(self_content) - len(other_content)) <= 5:
                self.times += 1
                return True

            min_len_content = min(len(self_content),  len(other_content))
            if abs(len(self_content) - len(other_content)) >= max(500, int(min_len_content*0.1)):
                return False

            if len(self.title) > 2 and self.title == other.title:
                return True

            quick_ratio = difflib.SequenceMatcher(None, self_content, other_content).quick_ratio()
            if quick_ratio >= bool_ratio:
                self.times +=1
                return True
            else:
                return False

        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        p = urlparse(self.url.url)
        return hash(p.scheme + "://" + p.netloc)

    @property
    def location_url(self) -> str:
        if self._location_url is None:
            location = self.raw_req.conn.headers.get("Location", "")
            new_url = urljoin(self.url.url, location)
            self._location_url =  new_url.split("?")[0]

        return self._location_url

    def is_302(self):
        return self.status_code in [301, 302, 307, 308]


    @property
    def title(self) -> str:
        if self._title is None:
            self._title = utils.get_title(self.content).strip()

        return self._title

    @property
    def is_backup_path(self) -> bool:
        if self._is_back_up_path is None:
            for suffix in self.back_up_suffix_list:
                if self.url.path.endswith(suffix):
                    self._is_back_up_path = True
                    return self._is_back_up_path

            self._is_back_up_path = False

        return self._is_back_up_path

    @property
    def is_backup_page(self) -> bool:
        if self._is_back_up_page is None:
            content_type = self.raw_req.conn.headers.get("Content-Type", "")
            if "application" in content_type.lower():
                self._is_back_up_page = True
            else:
                self._is_back_up_page = False

        return self._is_back_up_page

    def __str__(self):
        msg = "[{}][{}][{}]{}".format(self.status_code, self.title, len(self.content), self.url)
        return msg

    def __repr__(self):
        return "<Page> "+ self.__str__()

    def dump_json(self):
        item = {
            "title": self.title,
            "url": str(self.url),
            "content_length": len(self.content),
            "status_code": self.status_code,
        }

        # 证据采集：fileleak 结果经 subprocess 序列化回传，excerpt/tags 必须在此生成。
        try:
            headers = getattr(self.raw_req, "conn", None)
            headers = getattr(headers, "headers", None) if headers is not None else None
            enrich_page_item(item, body=self.content, headers=headers)
        except Exception as exc:
            # 采集失败不能影响 fileleak 结果回传，仅记录类型。
            logger.debug("fileleak semantics failed error_type:{}".format(type(exc).__name__))

        return item


class FileLeak(BaseThread):
    def __init__(
        self,
        target,
        urls,
        concurrency=None,
        waf_guard=None,
        progress_callback=None,
        response_cache=None,
    ):
        if concurrency is None:
            concurrency = Config.FILE_LEAK_CONCURRENCY
        super().__init__(urls, concurrency=concurrency)
        self.target = target.rstrip("/") + "/"
        self.response_cache = response_cache or {}
        self.urls = urls
        self.path_404 = "not_found_2222_111"
        self.page404_set = set()
        self.page200_set = set()
        self.page200_code_list = [200, 301, 302, 500]
        self.page404_title = ["404", "不存在", "错误", "403", "禁止访问", "请求含有不合法的参数"]
        self.page404_title.extend(["网络防火墙", "访问拦截", "由于安全原因JSP功能默认关闭"])
        self.page404_content = [b'<script>document.getElementById("a-link").click();</script>']
        self.location404 = ["/auth/login/", "error.html"]
        self.page_all = []
        self.error_times = 0
        self.record_page = False
        self.skip_302 = False
        self.location_404_url = set()
        self.skip_by_policy = False
        self.waf_guard = waf_guard
        self.progress_callback = progress_callback

    def _touch_progress(self):
        if callable(self.progress_callback):
            try:
                self.progress_callback()
            except Exception:
                pass

    @staticmethod
    def _validate_http_url(url_text: str):
        """
        校验 URL 基础合法性，避免 requests 在解析异常 URL 时抛出噪声日志。
        """
        text = str(url_text or "").strip()
        if not text:
            return False, "empty_url"

        parsed = urlparse(text)
        if parsed.scheme not in ("http", "https"):
            return False, "invalid_scheme"
        if not parsed.netloc:
            return False, "invalid_netloc"

        try:
            # 对如 :65000a1337 这类非法端口，urlparse.port 会抛 ValueError。
            port = parsed.port
        except ValueError:
            return False, "invalid_port"

        if port is not None and (port < 1 or port > 65535):
            return False, "invalid_port_range"

        return True, ""

    def _build_url_obj(self, raw_url: str, payload: str):
        ok, reason = self._validate_http_url(raw_url)
        if not ok:
            logger.info(
                "skip fileleak generated malformed_url url:{} reason:{}".format(
                    str(raw_url or "")[:260], reason
                )
            )
            return None
        return URL(raw_url, payload)

    def work(self, url):
        self._touch_progress()
        if self.error_times >= 20:
            return
        req = self.http_req(url)
        if req is None:
            return
        page = Page(req)


        if self.record_page:
            self.page_all.append(page)

        if self.is_404_page(page):
            self.page404_set.add(page)
            return

        if page not in self.page404_set:
            self.page200_set.add(page)
        self._touch_progress()


    def build_404_page(self):
        self._touch_progress()
        url_404 = URL(self.target + self.path_404, self.path_404)
        logger.info("req => {}".format(url_404))
        req = self.http_req(url_404)
        if req is None:
            return
        page_404 = Page(req)
        self.page404_set.add(page_404)
        if self.record_page:
            self.page_all.append(page_404)

        if page_404.is_302():
            self.location_404_url.add(page_404.location_url)

        if page_404.is_302() and page_404.location_url.endswith(page_404.url.payload + "/"):
            self.skip_302 = True

    def run(self):
        t1 = time.time()
        logger.info("start fileleak {}".format(len(self.targets)))
        self._touch_progress()

        self.build_404_page()
        if self.skip_by_policy:
            logger.info("skip fileleak target by dns policy target:{}".format(self.target))
            return set()

        if not self.page404_set:
            logger.warning("fileleak build_404_page failed target:{}".format(self.target))
            return set()

        # BaseThread 按 targets 顺序提交；高价值路径先进入受控并发队列，
        # 低优先级路径仍会继续执行，避免排序演变成结果裁剪。
        self.targets = sorted(self.urls, key=_url_priority)
        self._run()

        self.check_page_200()

        elapse = time.time() - t1
        logger.info("end fileleak elapse {}".format(elapse))
        self._touch_progress()

        return self.page200_set

    def http_req(self, url: URL):
        ok, reason = self._validate_http_url(url.url)
        if not ok:
            # 生成阶段异常 URL 直接跳过，不进入 requests 解析分支。
            logger.info(
                "skip fileleak request malformed_url url:{} reason:{}".format(
                    str(url.url or "")[:260], reason
                )
            )
            return None

        try:
            req = HTTPReq(
                url,
                waf_guard=self.waf_guard,
                waf_module="file_leak",
                progress_callback=self.progress_callback,
                response_cache=self.response_cache,
            )
            req.req()
            self._touch_progress()
            return req
        except FileLeakPolicySkip as e:
            self.skip_by_policy = True
            logger.info(str(e))
            return None
        except requests.exceptions.RequestException as e:
            # 网络层异常（如 DNS 解析失败、连接失败、超时）按可恢复错误处理，避免任务被异常中断。
            self.error_times += 1
            err_text = str(e)
            dns_error_flag = (
                "Name or service not known" in err_text
                or "Temporary failure in name resolution" in err_text
                or "nodename nor servname provided" in err_text
                or "Failed to establish a new connection" in err_text
            )
            if dns_error_flag:
                logger.info("skip fileleak request dns_unresolved url:{} err:{}".format(url.url, err_text[:300]))
            else:
                logger.warning("skip fileleak request network_error url:{} err:{}".format(url.url, err_text[:300]))
            return None
        except Exception as e:
            self.error_times += 1
            logger.warning("fileleak request unexpected_error url:{} err:{}".format(url.url, str(e)[:300]))
            raise e

    def is_404_page(self, page: Page):
        if page.status_code not in self.page200_code_list:
            return True

        if page.is_backup_path:
            if not page.is_backup_page:
                return True

        for title in self.page404_title:
            if title in page.title:
                return True

        for content in self.page404_content:
            if content in page.content:
                return True

        if "/." in page.url.url and page.status_code == 200:
            if len(page.content) == 0:
                return True

        if page.is_302():
            for location_404 in self.location404:
                if location_404 in page.location_url:
                    return True

            if not page.location_url.endswith(page.url.payload + "/"):
                self.location_404_url.add(page.location_url)
                return True

            return page.location_url in self.location_404_url

        return False

    def check_page_200(self):
        for page in self.page200_set:
            self._touch_progress()
            if page in self.page404_set:
                continue

            if self.skip_302:
                self.page404_set.add(page)
                continue

            url_404_list = self.gen_check_url(page.url)

            for url_404 in url_404_list:
                req = self.http_req(url_404)
                if req is None:
                    continue
                page_404 = Page(req)
                self.page404_set.add(page_404)

                if page_404.is_302() and page_404.location_url.endswith(page_404.url.payload + "/"):
                    self.page404_set.add(page)
                    self.skip_302 = True

        self.page200_set -= self.page404_set
        self._touch_progress()


    def gen_check_url(self, url: URL):
        payload = url.payload
        if url.path in url.scope:
            check_url = url.url + "1337"
        else:
            check_url = url.url.replace(url.path, url.path + "1337")
        end_check_url = self._build_url_obj(check_url, payload + "1337")

        payload_list = ["..", "?", "etc/passwd"]
        for p in payload_list:
            if p in payload:
                check_url = url.url.replace(p, p + "a1337")
                payload = payload.replace(p, p + "a1337")
                url_obj = self._build_url_obj(check_url, payload)
                return [url_obj] if url_obj else []

        if "." in url.path and "." in payload:
            path = url.path.replace(".", "a1337.")
            if not path.startswith("/"):
                path = "/" + path
            # 统一用 urljoin 拼接 scope + path，避免 host:port 与 path 直接字符串拼接。
            check_url = urljoin(url.scope + "/", path.lstrip("/"))
            payload = payload.replace(".", "a1337.")
            result = []
            dot_obj = self._build_url_obj(check_url, payload)
            if dot_obj:
                result.append(dot_obj)
            if end_check_url:
                result.append(end_check_url)
            return result

        if url.path.endswith("/"):
            raw_path = url.path or "/"
            if not raw_path.startswith("/"):
                raw_path = "/" + raw_path
            path = raw_path.rstrip("/") + "/a1337/"
            # 修复 "/" 场景下拼出 host:porta1337 的问题。
            check_url = urljoin(url.scope + "/", path.lstrip("/"))
            payload = payload + "a1337/"
            slash_obj = self._build_url_obj(check_url, payload)
            return [slash_obj] if slash_obj else []

        return [end_check_url] if end_check_url else []

def normal_url(url):
    scheme_map = {
        'http': 80,
        "https": 443
    }
    o = urlparse(url)

    scheme = o.scheme
    hostname = o.hostname
    path = o.path

    if scheme not in scheme_map:
        return ""

    if o.path == "":
        path = "/"


    if o.port == scheme_map[o.scheme] or o.port is None:
        ret_url = "{}://{}{}".format(scheme, hostname, path)

    else:
        ret_url = "{}://{}:{}{}".format(scheme, hostname, o.port, path)

    if o.query:
        ret_url = ret_url + "?" + o.query

    return ret_url

class GenBackDicts:
    def __init__(self, url):
        self.target = normal_url(url)
        self.suffixs = [".tar", ".tar.gz", ".zip", ".rar", ".7z", ".bz2", ".gz", "_bak.rar", ".war"]
        self.backup_path_deep = 7
        self.dymaic_dicts_deep = 5
        self.path = urlparse(self.target).path


    def gen_dict_from_domain(self):
        result = []
        res = get_tld(self.target, as_object=True, fail_silently=True)
        if res:
            result = [x for x in [str(res.parsed_url.netloc).split(":")[0], res.fld, res.subdomain,
                                 res.domain] + res.subdomain.split(".") if x != ""]

        return set(result)

    def gen_backup_dicts(self, nemes):
        out = []
        items = itertools.product(nemes, self.suffixs)
        for x in items:
            out.append("".join(x))
        return out

    def gen_dict_from_path(self):
        out = []
        dirs = os.path.dirname(self.path).split("/")
        if len(dirs)> 1 and dirs[-1]:
            out = self.gen_backup_dicts([dirs[-1]])
        return out


    def gen(self):
        ret = set()
        names = self.gen_dict_from_domain()

        for x in  self.gen_backup_dicts(names):
            ret.add(URL(urljoin(self.target, x), x))

        for x in  self.gen_dict_from_path():
            ret.add(URL(urljoin(self.target, x), x))
            ret.add(URL(urljoin(self.target, "./../"+ x), x))

        return ret


class GenURL():
    def __init__(self, target, dicts):
        self.target = normal_url(target).split("?")[0]
        self.dicts = set(dicts)
        self.urls = set()

    def build_urls(self):
        target = os.path.dirname(self.target)
        for d in self.dicts:
            u = URL("{}/{}".format(target, d.strip()), d.strip())
            self.urls.add(u)

    def gen(self, flag = True):
        if urlparse(self.target).path == "/":
            self.dicts |= GenBackDicts(self.target).gen_dict_from_domain()

        self.build_urls()
        if flag:
            self.urls |=  GenBackDicts(self.target).gen()

        return self.urls

def _serialize_urls(urls) -> List[dict]:
    items = []
    for url in sorted(urls, key=_url_priority):
        items.append(
            {
                "url": url.url,
                "payload": url.payload,
            }
        )
    return items


def _deserialize_urls(url_items) -> set:
    urls = set()
    for item in url_items or []:
        url_text = str((item or {}).get("url", "") or "").strip()
        if not url_text:
            continue
        payload = str((item or {}).get("payload", "") or "")
        urls.add(URL(url_text, payload))
    return urls


def _build_waf_guard_context(waf_guard) -> dict:
    if waf_guard is None:
        return {}

    return {
        "enabled": bool(getattr(waf_guard, "enabled", False)),
        "smart_skip_enabled": bool(getattr(waf_guard, "smart_skip_enabled", False)),
        "bypass_enabled": bool(getattr(waf_guard, "bypass_enabled", False)),
        "task_id": str(getattr(waf_guard, "task_id", "") or ""),
        "scope_sites": sorted(getattr(waf_guard, "scope_hosts", set()) or []),
        "weak_block_threshold": int(getattr(waf_guard, "weak_block_threshold", 3) or 3),
        "bypass_attempt_limit": int(getattr(waf_guard, "bypass_attempt_limit", 3) or 3),
    }


def _build_waf_guard_from_context(waf_guard_context):
    if not waf_guard_context or not waf_guard_context.get("enabled"):
        return None

    from .waf_guard import WAFSmartSkipGuard

    return WAFSmartSkipGuard(
        enabled=bool(waf_guard_context.get("enabled")),
        smart_skip_enabled=bool(waf_guard_context.get("smart_skip_enabled", waf_guard_context.get("enabled"))),
        bypass_enabled=bool(waf_guard_context.get("bypass_enabled", False)),
        task_id=str(waf_guard_context.get("task_id", "") or ""),
        scope_sites=list(waf_guard_context.get("scope_sites") or []),
        weak_block_threshold=int(waf_guard_context.get("weak_block_threshold", 3) or 3),
        bypass_attempt_limit=int(waf_guard_context.get("bypass_attempt_limit", 3) or 3),
    )


def _write_json_file(file_path: str, data):
    tmp_path = "{}.tmp".format(file_path)
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp_path, file_path)


def _read_json_file(file_path: str, default=None):
    if not os.path.isfile(file_path):
        return default

    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _touch_heartbeat_file(file_path: str):
    tmp_path = "{}.tmp".format(file_path)
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(str(time.time()))
    os.replace(tmp_path, file_path)


def _build_heartbeat_callback(heartbeat_path: str):
    state = {"last_write_at": 0.0}

    def _callback(force=False):
        now = time.time()
        if not force and now - float(state["last_write_at"]) < HEARTBEAT_UPDATE_INTERVAL_SEC:
            return
        _touch_heartbeat_file(heartbeat_path)
        state["last_write_at"] = now

    return _callback


def _read_heartbeat_timestamp(file_path: str, default_ts: float) -> float:
    try:
        return float(os.path.getmtime(file_path))
    except Exception:
        return float(default_ts)


def _cleanup_file_leak_watchdog_dir(temp_dir: str):
    shutil.rmtree(temp_dir, ignore_errors=True)


def _kill_file_leak_subprocess(proc):
    if proc is None:
        return

    try:
        if proc.poll() is not None:
            return
    except Exception:
        return

    try:
        proc.terminate()
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    pid = int(getattr(proc, "pid", 0) or 0)
    if pid > 0:
        try:
            parent = psutil.Process(pid)
            for child in parent.children(recursive=True):
                child.kill()
            parent.kill()
        except Exception:
            pass

    try:
        proc.wait(timeout=1)
    except Exception:
        pass


def _collect_child_waf_blocks(waf_guard):
    """把目录子进程内 guard 确认的阻断主机带回父进程，转成 directory 类别信号。"""

    if waf_guard is None:
        return []
    blocks = []
    try:
        summary = waf_guard.summary() or {}
        # 子进程只承载 file_leak 流量：主机级与类别级阻断都按 directory 证据回流。
        for key in ("blocked_hosts", "class_blocked_hosts"):
            for item in summary.get(key) or []:
                host = str(item.get("host", "") or "").strip()
                if not host:
                    continue
                blocks.append({"host": host, "reason": str(item.get("reason", "") or "")[:160]})
    except Exception as exc:
        logger.debug("fileleak waf block summary failed error_type:{}".format(type(exc).__name__))
    return blocks


def _scan_file_leak_site(
    target,
    url_items,
    concurrency,
    waf_guard_context=None,
    progress_callback=None,
    response_cache=None,
):
    if callable(progress_callback):
        try:
            progress_callback()
        except Exception:
            pass

    waf_guard = None
    try:
        urls = _deserialize_urls(url_items)
        waf_guard = _build_waf_guard_from_context(waf_guard_context)
        file_leak_runner = FileLeak(
            target,
            urls,
            concurrency=concurrency,
            waf_guard=waf_guard,
            progress_callback=progress_callback,
            response_cache=response_cache,
        )
        pages = file_leak_runner.run()

        page_items = []
        response_items = []
        for page in pages:
            logger.info("found => {}".format(page))
            page_items.append(page.dump_json())
            if len(response_items) < 64:
                try:
                    conn = getattr(page.raw_req, "conn", None)
                    body = getattr(page, "content", b"") or b""
                    if isinstance(body, str):
                        body = body.encode("utf-8", errors="ignore")
                    response_items.append({
                        "url": str(page.url),
                        "status_code": int(getattr(page, "status_code", 0) or 0),
                        "headers": {str(k): str(v) for k, v in
                                    dict(getattr(conn, "headers", {}) or {}).items()},
                        "body_b64": base64.b64encode(bytes(body)[:50 * 1024]).decode("ascii"),
                    })
                except Exception as exc:
                    logger.debug(
                        "fileleak response snapshot failed error_type:{}".format(
                            type(exc).__name__))

        if callable(progress_callback):
            try:
                progress_callback()
            except Exception:
                pass

        return {
            "ok": True,
            "pages": page_items,
            "responses": response_items,
            "skip_by_policy": bool(file_leak_runner.skip_by_policy),
            "waf_block_hosts": _collect_child_waf_blocks(waf_guard),
            "error": "",
        }
    except Exception as e:
        logger.warning("fileleak worker error target:{} error:{}".format(target, safe_error_text(e)))
        return {
            "ok": False,
            "pages": [],
            "skip_by_policy": False,
            "waf_block_hosts": _collect_child_waf_blocks(waf_guard),
            "error": str(e),
        }


def run_file_leak_worker_from_files(job_path: str, result_path: str, heartbeat_path: str):
    heartbeat_callback = _build_heartbeat_callback(heartbeat_path)
    heartbeat_callback(force=True)

    try:
        job = _read_json_file(job_path, default={}) or {}
        result = _scan_file_leak_site(
            job.get("target", ""),
            job.get("url_items") or [],
            int(job.get("concurrency") or Config.FILE_LEAK_CONCURRENCY),
            waf_guard_context=job.get("waf_guard_context") or {},
            progress_callback=heartbeat_callback,
            response_cache=job.get("response_cache") or {},
        )
    except Exception as e:
        logger.warning("fileleak worker bootstrap error:{}".format(safe_error_text(e)))
        result = {
            "ok": False,
            "pages": [],
            "skip_by_policy": False,
            "error": str(e),
        }

    _write_json_file(result_path, result)
    heartbeat_callback(force=True)


def _file_leak_worker_cwd() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))


def _build_file_leak_worker_command(job_path: str, result_path: str, heartbeat_path: str) -> List[str]:
    bootstrap = (
        "import sys; "
        "from app.services.fileLeak import run_file_leak_worker_from_files as _run; "
        "_run(sys.argv[1], sys.argv[2], sys.argv[3])"
    )
    return [sys.executable, "-c", bootstrap, job_path, result_path, heartbeat_path]


def _build_file_leak_response_cache(discovery_context, target_urls, max_entries=64, max_body_bytes=50 * 1024):
    """只导出与本次目录候选重叠的已完成响应，避免子进程重复请求 robots/sitemap 等路径。"""

    if discovery_context is None:
        return {}
    cache = {}
    for url_obj in target_urls:
        if len(cache) >= max_entries:
            break
        raw_url = str(getattr(url_obj, "url", url_obj) or "").strip()
        if not raw_url:
            continue
        try:
            cached = discovery_context.get_response(raw_url, request_profile="html_get", consumer="file_leak")
        except Exception as exc:
            logger.debug(
                "fileleak response cache lookup failed url:{} error_type:{}".format(
                    raw_url[:200], type(exc).__name__
                )
            )
            continue
        if cached is None or getattr(cached, "body_truncated", False):
            continue
        body = bytes(getattr(cached, "body", b"") or b"")
        if not body or len(body) > max_body_bytes:
            continue
        headers = {str(k): str(v) for k, v in dict(getattr(cached, "headers", {}) or {}).items()}
        try:
            cache_key = normal_url(raw_url)
        except Exception:
            continue
        cache[cache_key] = {
            "status_code": int(getattr(cached, "status_code", 0) or 0),
            "headers": headers,
            "body_b64": base64.b64encode(body).decode("ascii"),
        }
    return cache


def _apply_directory_waf_blocks(discovery_context, result):
    """目录子进程确认的阻断只暂停 directory 队列，不影响其它流量类别。"""

    if discovery_context is None or not isinstance(result, dict):
        return
    for item in list(result.get("waf_block_hosts") or []):
        host = str(item.get("host", "") or "").strip() if isinstance(item, dict) else ""
        if not host:
            continue
        reason = str(item.get("reason", "") or "directory_worker_block")[:160]
        try:
            discovery_context.record_waf_signal(host, "directory", reason=reason, force=True)
        except Exception as exc:
            logger.debug(
                "fileleak directory waf signal failed host:{} error_type:{}".format(
                    host, type(exc).__name__
                )
            )


def _apply_child_responses(discovery_context, result):
    """子进程命中页响应回登记：目录探测结果可被其它策略按 file_leak_get profile 复用。

    不复用 html_get profile——目录字典请求与站点探测语义不同，混用会让
    页面抓取误吃字典命中响应。失败静默降级（与缓存快照同为尽力而为）。
    """

    if discovery_context is None or not isinstance(result, dict):
        return
    for item in list(result.get("responses") or []):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        try:
            body = base64.b64decode(str(item.get("body_b64") or ""))
            headers = dict(item.get("headers") or {})
            discovery_context.put_response(
                url=url,
                method="GET",
                request_profile="file_leak_get",
                status_code=int(item.get("status_code") or 0),
                headers=headers,
                content_type=str(headers.get("Content-Type", "") or ""),
                body=body,
                source="file_leak",
                consumer="file_leak",
            )
        except Exception as exc:
            logger.debug(
                "fileleak response reflow failed url:{} error_type:{}".format(
                    url[:200], type(exc).__name__
                )
            )


def _file_leak_dict_signature(dicts) -> str:
    """字典内容签名：数量 + 内容摘要，作为账本 input_signature。"""
    items = [str(item or "") for item in list(dicts or [])]
    payload = "\n".join(items)
    digest = hashlib.md5(payload.encode("utf-8", "ignore")).hexdigest()[:16]
    return "n{}:{}".format(len(items), digest)


def _file_leak_ledger(discovery_context):
    if discovery_context is None:
        return None, None
    ledger = getattr(discovery_context, "ledger", None)
    return (ledger, discovery_context) if ledger is not None else (None, None)


def _run_file_leak_site_with_watchdog(
    target,
    urls,
    concurrency,
    site_timeout_sec,
    no_progress_timeout_sec,
    waf_guard=None,
    popen_factory=None,
    sleep_fn=None,
    time_fn=None,
    discovery_context=None,
) -> List[dict]:
    if not urls:
        return FileLeakResult([], metrics={"status": "skipped", "end_reason": "no_urls"})

    if discovery_context is not None and not discovery_context.waf_policy.allow(target, "directory"):
        # 目录类别已被目录自身触发的 WAF 证据熔断：暂停队列并保留待处理计数，
        # 不静默丢弃，也不连坐爬虫/WIH 流量。
        logger.info("fileleak directory queue paused by waf policy target:{}".format(target))
        return FileLeakResult(
            [],
            metrics={
                "status": "partial",
                "end_reason": "directory_waf_block",
                "input_count": len(urls),
                "output_count": 0,
                "pending_count": len(urls),
                "degraded_count": 1,
            },
        )

    response_cache = _build_file_leak_response_cache(discovery_context, urls)

    popen_factory = popen_factory or subprocess.Popen
    sleep_fn = sleep_fn or time.sleep
    time_fn = time_fn or time.time

    temp_dir = tempfile.mkdtemp(prefix="fileleak_watchdog_", dir=Config.TMP_PATH)
    job_path = os.path.join(temp_dir, "job.json")
    result_path = os.path.join(temp_dir, "result.json")
    heartbeat_path = os.path.join(temp_dir, "heartbeat.txt")

    try:
        _write_json_file(
            job_path,
            {
                "target": target,
                "url_items": _serialize_urls(urls),
                "concurrency": int(concurrency or Config.FILE_LEAK_CONCURRENCY),
                "waf_guard_context": _build_waf_guard_context(waf_guard),
                "response_cache": response_cache,
            },
        )
        _touch_heartbeat_file(heartbeat_path)

        command = _build_file_leak_worker_command(job_path, result_path, heartbeat_path)
        try:
            proc = popen_factory(command, cwd=_file_leak_worker_cwd(), close_fds=True)
        except Exception as e:
            logger.warning(
                "fileleak watchdog spawn_failed target:{} err:{} fallback:inline".format(
                    target, safe_error_text(e, max_length=300)
                )
            )
            result = _scan_file_leak_site(
                target,
                _serialize_urls(urls),
                concurrency=concurrency,
                waf_guard_context=_build_waf_guard_context(waf_guard),
                response_cache=response_cache,
            )
            _apply_directory_waf_blocks(discovery_context, result)
            _apply_child_responses(discovery_context, result)
            return FileLeakResult(
                result.get("pages") or [],
                metrics={
                    "status": "success" if result.get("ok") else "error",
                    "end_reason": "inline_fallback",
                    "input_count": len(urls),
                    "output_count": len(result.get("pages") or []),
                    "failed_count": 0 if result.get("ok") else 1,
                    "degraded_count": 1,
                },
            )

        start_at = float(time_fn())
        last_progress_at = start_at
        timeout_reason = ""

        while True:
            retcode = proc.poll()
            last_progress_at = max(
                last_progress_at,
                _read_heartbeat_timestamp(heartbeat_path, last_progress_at),
            )
            if retcode is not None:
                break

            now = float(time_fn())
            if int(site_timeout_sec or 0) > 0 and now - start_at >= int(site_timeout_sec):
                timeout_reason = "site_timeout"
                break

            if int(no_progress_timeout_sec or 0) > 0 and now - last_progress_at >= int(no_progress_timeout_sec):
                timeout_reason = "no_progress_timeout"
                break

            sleep_fn(1)

        if timeout_reason:
            logger.warning(
                "fileleak watchdog kill target:{} reason:{} elapsed:{:.2f}s idle:{:.2f}s urls:{}".format(
                    target,
                    timeout_reason,
                    float(time_fn()) - start_at,
                    max(0.0, float(time_fn()) - last_progress_at),
                    len(urls),
                )
            )
            _kill_file_leak_subprocess(proc)
            return FileLeakResult(
                [],
                metrics={
                    "status": "partial",
                    "end_reason": timeout_reason,
                    "input_count": len(urls),
                    "output_count": 0,
                    "pending_count": len(urls),
                    "timeout_count": 1,
                    "degraded_count": 1,
                },
            )

        try:
            proc.wait(timeout=1)
        except Exception:
            pass

        result = _read_json_file(result_path, default={}) or {}
        if not result:
            logger.warning(
                "fileleak watchdog missing_result target:{} returncode:{}".format(
                    target, getattr(proc, "returncode", None)
                )
            )
            return FileLeakResult(
                [],
                metrics={
                    "status": "error",
                    "end_reason": "missing_result",
                    "input_count": len(urls),
                    "output_count": 0,
                    "pending_count": len(urls),
                    "failed_count": 1,
                },
            )

        _apply_directory_waf_blocks(discovery_context, result)
        _apply_child_responses(discovery_context, result)

        if not result.get("ok"):
            logger.warning(
                "fileleak watchdog worker_error target:{} err:{}".format(
                    target, safe_error_text(result.get("error", "") or "", max_length=300)
                )
            )
            return FileLeakResult(
                [],
                metrics={
                    "status": "error",
                    "end_reason": "worker_error",
                    "input_count": len(urls),
                    "output_count": 0,
                    "pending_count": len(urls),
                    "failed_count": 1,
                },
            )

        pages = list(result.get("pages") or [])
        return FileLeakResult(
            pages,
            metrics={
                "status": "success",
                "end_reason": "completed",
                "input_count": len(urls),
                "output_count": len(pages),
                "success_count": 1,
            },
        )
    finally:
        _cleanup_file_leak_watchdog_dir(temp_dir)


def _calc_adaptive_timeout(base_sec: int, per_1000_urls_sec: int, max_sec: int, url_count: int) -> int:
    """
    按 URL 数量计算自适应超时：
    - 基础超时 + 每 1000 URL 追加预算
    - 命中 max 时截断
    - base<=0 视为关闭该类超时
    """
    base = int(base_sec or 0)
    if base <= 0:
        return 0

    url_total = max(int(url_count or 0), 0)
    timeout = base

    per_1000 = max(int(per_1000_urls_sec or 0), 0)
    if per_1000 > 0 and url_total > 1000:
        step = (url_total - 1) // 1000
        timeout += step * per_1000

    timeout_max = max(int(max_sec or 0), 0)
    if timeout_max > 0:
        timeout = min(timeout, timeout_max)

    return max(timeout, 0)


def _calc_file_leak_target_timeouts(url_count: int):
    site_timeout = _calc_adaptive_timeout(
        base_sec=Config.FILE_LEAK_SITE_TIMEOUT_SEC,
        per_1000_urls_sec=Config.FILE_LEAK_SITE_TIMEOUT_PER_1000_URLS_SEC,
        max_sec=Config.FILE_LEAK_SITE_TIMEOUT_MAX_SEC,
        url_count=url_count,
    )
    no_progress_timeout = _calc_adaptive_timeout(
        base_sec=Config.FILE_LEAK_NO_PROGRESS_TIMEOUT_SEC,
        per_1000_urls_sec=Config.FILE_LEAK_NO_PROGRESS_TIMEOUT_PER_1000_URLS_SEC,
        max_sec=Config.FILE_LEAK_NO_PROGRESS_TIMEOUT_MAX_SEC,
        url_count=url_count,
    )
    return site_timeout, no_progress_timeout


def file_leak(targets, dicts, gen_dict=True, waf_guard=None, discovery_context=None, scan_profile="") -> List[dict]:
    all_gen_url = set()
    map_url = dict()

    for site in targets:
        site = normal_url(site.strip())
        if not site:
            continue

        map_url[URL(site, "").scope] = set()
        a = GenURL(site, dicts)
        all_gen_url |= a.gen(gen_dict)

    for url in all_gen_url:
        map_url[url.scope].add(url)

    ret = []
    site_metrics = []
    # 高价值站点先开始，站点内部仍保留完整候选并按路径优先级提交。
    target_items = sorted(
        map_url.items(),
        key=lambda item: (
            min([_url_priority(url)[0] for url in item[1]] or [0]),
            item[0],
        ),
    )
    total = len(target_items)
    dict_signature = _file_leak_dict_signature(dicts)
    target_concurrency = max(1, int(Config.FILE_LEAK_TARGET_CONCURRENCY or 1))

    def _scan_one_target(index: int, item):
        target, target_urls = item
        site_timeout, no_progress_timeout = _calc_file_leak_target_timeouts(len(target_urls))
        logger.info(
            "start fileleak watchdog target:{} index:{}/{} urls:{} target_concurrency:{} req_concurrency:{} site_timeout:{} no_progress_timeout:{}".format(
                target,
                index,
                total,
                len(target_urls),
                target_concurrency,
                Config.FILE_LEAK_CONCURRENCY,
                site_timeout,
                no_progress_timeout,
            )
        )
        ledger, ledger_context = _file_leak_ledger(discovery_context)
        ledger_key = ""
        if ledger is not None:
            ledger_key = ledger_context.idempotency_key(
                "file_leak",
                target,
                scan_profile=str(scan_profile or "default"),
                input_signature=dict_signature,
            )
            entry = ledger.get(ledger_key)
            if entry is not None and getattr(entry, "status", "") == "covered":
                # 账本只加速恢复路径；covered 目标视为已完成，不计失败或待处理。
                logger.info(
                    "fileleak target skipped by ledger covered target:{} out:{}".format(
                        target, int(getattr(entry, "output_count", 0) or 0)
                    )
                )
                return FileLeakResult(
                    [],
                    metrics={
                        "status": "success",
                        "end_reason": "ledger_covered",
                        "input_count": int(getattr(entry, "input_count", 0) or 0),
                        "output_count": int(getattr(entry, "output_count", 0) or 0),
                        "reused_count": 1,
                    },
                )

        pages = _run_file_leak_site_with_watchdog(
            target,
            target_urls,
            concurrency=Config.FILE_LEAK_CONCURRENCY,
            site_timeout_sec=site_timeout,
            no_progress_timeout_sec=no_progress_timeout,
            waf_guard=waf_guard,
            discovery_context=discovery_context,
        )
        page_metrics = getattr(pages, "metrics", {}) or {}
        if (
            ledger is not None
            and ledger_key
            and str(page_metrics.get("end_reason") or "") == "completed"
            and str(page_metrics.get("status") or "success") == "success"
        ):
            ledger.finish(
                ledger_key,
                "covered",
                input_count=len(target_urls),
                output_count=int(page_metrics.get("output_count") or len(pages or [])),
            )
        return pages

    if target_concurrency <= 1 or total <= 1:
        for index, item in enumerate(target_items, start=1):
            try:
                pages = _scan_one_target(index, item)
                ret.extend(pages or [])
                site_metrics.append(getattr(pages, "metrics", {}) or {})
            except Exception as e:
                logger.warning("error on {}: {}".format(item[0], safe_error_text(e)))
                site_metrics.append(
                    {
                        "status": "error",
                        "end_reason": "worker_exception",
                        "failed_count": 1,
                    }
                )
        return FileLeakResult(
            ret,
            metrics={
                "status": (
                    "error"
                    if any(int(item.get("failed_count", 0) or 0) for item in site_metrics) and not ret
                    else "partial"
                    if any(
                        int(item.get(key, 0) or 0)
                        for item in site_metrics
                        for key in ("failed_count", "timeout_count", "degraded_count", "pending_count")
                    )
                    else "success"
                ),
                "end_reason": "completed" if not any(
                    int(item.get(key, 0) or 0)
                    for item in site_metrics
                    for key in ("failed_count", "timeout_count", "degraded_count", "pending_count")
                ) else "site_degraded",
                "target_count": total,
                "input_count": len(all_gen_url),
                "queued_count": total,
                "completed_target_count": len(site_metrics),
                "output_count": len(ret),
                "failed_count": sum(int(item.get("failed_count", 0) or 0) for item in site_metrics),
                "timeout_count": sum(int(item.get("timeout_count", 0) or 0) for item in site_metrics),
                "degraded_count": sum(int(item.get("degraded_count", 0) or 0) for item in site_metrics),
                "pending_count": sum(int(item.get("pending_count", 0) or 0) for item in site_metrics),
            },
        )

    logger.info("fileleak target parallel enabled total:{} target_concurrency:{}".format(total, target_concurrency))
    with ThreadPoolExecutor(max_workers=target_concurrency) as executor:
        future_map = {}
        for index, item in enumerate(target_items, start=1):
            future = executor.submit(_scan_one_target, index, item)
            future_map[future] = item[0]

        for future in as_completed(future_map):
            target = future_map[future]
            try:
                pages = future.result()
                ret.extend(pages or [])
                site_metrics.append(getattr(pages, "metrics", {}) or {})
            except Exception as e:
                logger.warning("error on {}: {}".format(target, safe_error_text(e)))
                site_metrics.append(
                    {
                        "status": "error",
                        "end_reason": "worker_exception",
                        "failed_count": 1,
                    }
                )

    failed_count = sum(int(item.get("failed_count", 0) or 0) for item in site_metrics)
    timeout_count = sum(int(item.get("timeout_count", 0) or 0) for item in site_metrics)
    degraded_count = sum(int(item.get("degraded_count", 0) or 0) for item in site_metrics)
    pending_count = sum(int(item.get("pending_count", 0) or 0) for item in site_metrics)
    if failed_count and not ret:
        status = "error"
    elif failed_count or timeout_count or degraded_count or pending_count:
        status = "partial"
    else:
        status = "success"
    return FileLeakResult(
        ret,
        metrics={
            "status": status,
            "end_reason": "completed" if status == "success" else "site_degraded",
            "input_count": len(all_gen_url),
            "target_count": total,
            "queued_count": total,
            "completed_target_count": len(site_metrics),
            "output_count": len(ret),
            "failed_count": failed_count,
            "timeout_count": timeout_count,
            "degraded_count": degraded_count,
            "pending_count": pending_count,
        },
    )
