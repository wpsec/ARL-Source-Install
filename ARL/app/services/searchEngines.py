"""
搜索引擎整合查询
"""
import re
from pyquery import PyQuery as pq
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urljoin, urlparse
from app import utils
from app.config import Config
from app.utils.log_safety import safe_error_text
from app.utils.provider_http import provider_request_context

logger = utils.get_logger()


class SearchResult(list):
    """保持搜索结果列表兼容，同时携带 provider 级指标。"""

    def __init__(self, values=None, metrics=None):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})


class BaiduSearch(object):
    def __init__(self, keyword=None, page_num=6):
        self.search_url = "https://www.baidu.com/s?rn=100&pn={page}&wd={keyword}"
        self.num_pattern = re.compile(r'百度为您找到相关结果约?([\d,]*)个')
        self.first_html = ""
        self.keyword = keyword
        self.page_num = page_num
        self.pq_query = "#content_left h3.t a"
        self.headers = {"Accept-Language": "zh-cn"}
        self.search_result_num = 0
        self.default_interval = 3
        self.dns_policy_cache = {}
        self._dns_policy_lock = threading.Lock()

    @staticmethod
    def _page_interval():
        try:
            return max(0.0, float(getattr(Config, "SEARCH_ENGINE_PAGE_INTERVAL_SEC", 0.5) or 0.0))
        except (TypeError, ValueError):
            return 0.5

    def _resolve_result_url(self, url):
        """校验搜索重定向并返回最终 URL；每个结果独立计时和失败。"""
        try:
            with provider_request_context("baidu", mode="redirect_head", target=url):
                with self._dns_policy_lock:
                    allow_scan, policy_detail = utils.check_dns_policy_for_url(
                        url, cache_map=self.dns_policy_cache
                    )
                if not allow_scan:
                    logger.info(
                        "skip baidu redirect by dns policy reason:{} resolver_ips:{} system_ips:{} socket_ips:{}".format(
                            policy_detail.get("reason", ""),
                            policy_detail.get("resolver_ips", []),
                            policy_detail.get("system_ips", []),
                            policy_detail.get("socket_ips", []),
                        )
                    )
                    return ""

                resp = utils.http_req(url, "head")
                real_url = resp.headers.get("Location")
                if not real_url:
                    return ""

                with self._dns_policy_lock:
                    allow_real_url, policy_detail = utils.check_dns_policy_for_url(
                        real_url, cache_map=self.dns_policy_cache
                    )
                if not allow_real_url:
                    logger.info(
                        "skip baidu real_url by dns policy reason:{} resolver_ips:{} system_ips:{} socket_ips:{}".format(
                            policy_detail.get("reason", ""),
                            policy_detail.get("resolver_ips", []),
                            policy_detail.get("system_ips", []),
                            policy_detail.get("socket_ips", []),
                        )
                    )
                    return ""
                return real_url
        except Exception as exc:
            logger.warning("baidu redirect head failed error:{}".format(safe_error_text(exc)))
            return ""

    def result_num(self):
        url = self.search_url.format(page=0, keyword=quote(self.keyword))
        html = utils.http_req(url, headers=self.headers).text
        self.first_html = html
        result = re.findall(self.num_pattern, html)
        if not result:
            logger.warning("Unable to get baidu search results， {}".format(self.keyword))
            return 0

        num = int("".join(result[0].split(",")))
        self.search_result_num = num
        return num

    def match_urls(self, html):
        result = re.findall(self.num_pattern, html)
        if not result:
            raise Exception("获取百度结果异常")

        dom = pq(html)
        result_items = dom(self.pq_query).items()
        urls_result = [item.attr("href") for item in result_items]
        urls = set()
        valid_urls = []
        for u in urls_result:
            try:
                if not re.match(r'^https?:/{2}\w.+$', u):
                    logger.info("url {} is invalid".format(u))
                    continue
                valid_urls.append(u)
            except Exception as exc:
                logger.warning("baidu result validation failed error:{}".format(safe_error_text(exc)))

        max_workers = min(
            max(1, int(getattr(Config, "SEARCH_PROVIDER_CONCURRENCY", 4) or 4)),
            8,
            len(valid_urls) or 1,
        )
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(self._resolve_result_url, url): url
                for url in valid_urls
            }
            for future in as_completed(future_map):
                try:
                    real_url = future.result()
                except Exception as exc:
                    logger.warning("baidu redirect worker failed error:{}".format(safe_error_text(exc)))
                    continue
                if real_url:
                    urls.add(real_url)
        return list(urls)

    def run(self):
        self.result_num()
        logger.info("baidu search {} results found for keyword {}".format(self.search_result_num, self.keyword))
        urls = []

        # 没有找到直接return
        if self.search_result_num == 0:
            return urls

        for page in range(1, min(int(self.search_result_num / 10) + 2, self.page_num + 1)):
            if page == 1:
                _urls = self.match_urls(self.first_html)
                urls.extend(_urls)
                logger.info("baidu firsturl result {}".format(len(_urls)))
            else:
                time.sleep(self._page_interval())
                url = self.search_url.format(page=(page - 1) * 10, keyword=quote(self.keyword))
                html = utils.http_req(url, headers=self.headers).text
                _urls = self.match_urls(html)
                logger.info("baidu search url {}, result {}".format(url, len(_urls)))
                urls.extend(_urls)
        return urls


class BingSearch(object):
    def __init__(self, keyword=None, page_num=6):
        self.search_url = "https://cn.bing.com/search?q={keyword}&qs=n&form=QBRE&sp=-1&first={page}"
        self.num_pattern = re.compile(r'<span class="sb_count">([^<]+)</span>')
        self.pq_query = "#b_results > li h2 > a"
        self.keyword = keyword
        self.page_num = page_num
        self.headers = {"Accept-Language": "zh-cn"}
        self.default_interval = 3
        self.search_result_num = 0
        self.first_html = ""

    @staticmethod
    def _page_interval():
        try:
            return max(0.0, float(getattr(Config, "SEARCH_ENGINE_PAGE_INTERVAL_SEC", 0.5) or 0.0))
        except (TypeError, ValueError):
            return 0.5

    def result_num(self):
        url = self.search_url.format(page=1, keyword=quote(self.keyword))
        html = utils.http_req(url, headers=self.headers).text
        self.first_html = html
        result = re.findall(self.num_pattern, html)

        if result:
            # 第一种情况
            result_num = re.findall(r"共 ([\d,]*) 条", result[0])
            if result_num:
                num = int("".join(result_num[0].split(",")))
                self.search_result_num = num

            # 第二种情况
            else:
                result_num_2 = re.findall(r" ([\d,]*) 个结果", result[0])
                if result_num_2:
                    num = int("".join(result_num_2[0].split(",")))
                    self.search_result_num = num
        else:
            logger.warning("Unable to get bing search results， {}".format(self.keyword))
            return 0

        return self.search_result_num

    def match_urls(self, html):
        if "搜索</title>" not in html:
            raise Exception("获取Bing结果异常")

        dom = pq(html)
        result_items = dom(self.pq_query).items()
        urls_result = [item.attr("href") for item in result_items]
        urls = set()
        for u in urls_result:
            urls.add(u)
        return list(urls)

    def run(self):
        self.result_num()
        logger.info("bing search {} results found for keyword {}".format(self.search_result_num, self.keyword))
        urls = []

        # 没有找到直接return
        if self.search_result_num == 0:
            return urls

        for page in range(1, min(int(self.search_result_num / 10) + 2, self.page_num + 1)):
            if page == 1:
                _urls = self.match_urls(self.first_html)
                urls.extend(_urls)
                logger.info("bing search first url result {}".format(len(_urls)))
            else:
                time.sleep(self._page_interval())
                url = self.search_url.format(page=(page - 1) * 10, keyword=quote(self.keyword))
                html = utils.http_req(url, headers=self.headers).text
                _urls = self.match_urls(html)
                logger.info("bing search url {}, result {}".format(url, len(_urls)))
                urls.extend(_urls)
        return urls


def baidu_search(domain, page_num=6):
    keyword = "site:{}".format(domain)
    b = BaiduSearch(keyword, page_num)
    urls = b.run()
    urls = [u for u in urls if domain in urlparse(u).netloc]
    return utils.rm_similar_url(urls)


def bing_search(domain, page_num=5):
    urls = []
    keyword = "site:{}".format(domain)
    b = BingSearch(keyword, page_num)
    urls.extend(b.run())
    if b.search_result_num > 1000 and len(urls) > 25:
        keywords = ["admin", "管理|后台", "登陆|密码", "login", "manage", "dashboard", "api",
                    "console"]
        for k in keywords:
            keyword = "site:{} {}".format(domain, k)
            try:
                try:
                    expansion_interval = max(
                        0.0,
                        float(getattr(Config, "SEARCH_ENGINE_EXPANSION_INTERVAL_SEC", 1.0) or 0.0),
                    )
                except (TypeError, ValueError):
                    expansion_interval = 1.0
                time.sleep(expansion_interval)
                b = BingSearch(keyword, page_num=1)
                urls.extend(b.run())
            except Exception as e:
                logger.warning(safe_error_text(e))
    urls = [u for u in urls if domain in urlparse(u).netloc]
    return utils.rm_similar_url(urls)


class SearchEngines(object):
    # *** 调用搜索引擎查找URL
    def __init__(self, base_domain):
        self.engines = [
            ("bing", bing_search),
            ("baidu", baidu_search),
        ]
        self.base_domain = base_domain

    def _run_single_engine(self, engine_name, engine_fn):
        start_time = time.time()
        try:
            stage_timeout_sec = max(
                0.0,
                float(getattr(Config, "SEARCH_PROVIDER_STAGE_TIMEOUT_SEC", 300) or 0.0),
            )
        except (TypeError, ValueError):
            stage_timeout_sec = 300.0
        try:
            with provider_request_context(
                engine_name,
                mode="search",
                target=self.base_domain,
                stage_timeout_sec=stage_timeout_sec,
            ) as metrics:
                urls = engine_fn(self.base_domain)
        except Exception as exc:
            elapsed = time.time() - start_time
            timeout_count = int(metrics.get("timeout_count", 0) or 0)
            logger.warning(
                "search_engine {} domain:{} failed elapsed:{:.2f}s timeout:{} error:{}".format(
                    engine_name,
                    self.base_domain,
                    elapsed,
                    timeout_count,
                    safe_error_text(exc),
                )
            )
            return SearchResult(
                [],
                metrics={
                    "provider": engine_name,
                    "provider_status": "partial" if timeout_count else "failed",
                    "provider_result_count": 0,
                    "request_count": int(metrics.get("request_count", 0) or 0),
                    "timeout_count": timeout_count,
                    "retry_count": int(metrics.get("retry_count", 0) or 0),
                    "network_wait_sec": float(metrics.get("network_wait_sec", 0.0) or 0.0),
                    "failed_count": 1,
                    "error_type": type(exc).__name__,
                },
            )
        elapsed = time.time() - start_time
        url_list = urls if isinstance(urls, list) else []
        timeout_count = int(metrics.get("timeout_count", 0) or 0)
        error_count = int(metrics.get("error_count", 0) or 0)
        provider_status = "partial" if timeout_count or error_count else "success"
        logger.info(
            "search_engine {} domain:{} result:{} elapsed:{:.2f}s requests:{} timeouts:{} retries:{} network_wait:{:.2f}s".format(
                engine_name,
                self.base_domain,
                len(url_list),
                elapsed,
                metrics.get("request_count", 0),
                metrics.get("timeout_count", 0),
                metrics.get("retry_count", 0),
                metrics.get("network_wait_sec", 0.0),
            )
        )
        return SearchResult(
            url_list,
            metrics={
                "provider": engine_name,
                "provider_status": provider_status,
                "provider_result_count": len(url_list),
                "request_count": int(metrics.get("request_count", 0) or 0),
                "timeout_count": timeout_count,
                "retry_count": int(metrics.get("retry_count", 0) or 0),
                "network_wait_sec": float(metrics.get("network_wait_sec", 0.0) or 0.0),
                "failed_count": 1 if error_count else 0,
            },
        )

    def run(self):
        # Bing / Baidu 独立网络调用，使用并行减少整体等待时间。
        all_urls = []
        provider_metrics = []
        if len(self.engines) <= 1:
            engine_name, engine_fn = self.engines[0]
            try:
                result = self._run_single_engine(engine_name, engine_fn)
                all_urls.extend(result)
                provider_metrics.append(result.metrics)
            except Exception as e:
                logger.warning(
                    "search_engine {} domain:{} failed error:{}".format(
                        engine_name, self.base_domain, safe_error_text(e)
                    )
                )
                provider_metrics.append({
                    "provider": engine_name,
                    "provider_status": "failed",
                    "provider_result_count": 0,
                    "failed_count": 1,
                })
            return SearchResult(
                utils.rm_similar_url(all_urls),
                metrics=self._aggregate_provider_metrics(provider_metrics),
            )

        with ThreadPoolExecutor(max_workers=min(len(self.engines), 4)) as executor:
            future_map = {
                executor.submit(self._run_single_engine, engine_name, engine_fn): engine_name
                for engine_name, engine_fn in self.engines
            }
            for future in as_completed(future_map):
                engine_name = future_map[future]
                try:
                    result = future.result()
                    all_urls.extend(result)
                    provider_metrics.append(result.metrics)
                except Exception as e:
                    logger.warning(
                        "search_engine {} domain:{} failed error:{}".format(
                            engine_name,
                            self.base_domain,
                            safe_error_text(e),
                        )
                    )
                    provider_metrics.append({
                        "provider": engine_name,
                        "provider_status": "failed",
                        "provider_result_count": 0,
                        "failed_count": 1,
                    })

        return SearchResult(
            utils.rm_similar_url(all_urls),
            metrics=self._aggregate_provider_metrics(provider_metrics),
        )

    @staticmethod
    def _aggregate_provider_metrics(provider_metrics):
        stats = list(provider_metrics or [])
        success_count = len(
            [item for item in stats if item.get("provider_status") == "success"]
        )
        failed_count = sum(int(item.get("failed_count", 0) or 0) for item in stats)
        timeout_count = sum(int(item.get("timeout_count", 0) or 0) for item in stats)
        if failed_count and success_count == 0:
            aggregate_status = "error"
        elif failed_count or timeout_count or any(
            item.get("provider_status") == "partial" for item in stats
        ):
            aggregate_status = "partial"
        else:
            aggregate_status = "success"
        return {
            "provider_count": len(stats),
            "provider_success_count": success_count,
            "failed_count": failed_count,
            "degraded_count": len(
                [item for item in stats if item.get("provider_status") in {"partial", "failed"}]
            ),
            "status": aggregate_status,
            "timeout_count": timeout_count,
            "retry_count": sum(int(item.get("retry_count", 0) or 0) for item in stats),
            "network_wait_sec": round(
                sum(float(item.get("network_wait_sec", 0.0) or 0.0) for item in stats),
                6,
            ),
            "provider_status": [
                {
                    "provider": str(item.get("provider", "") or ""),
                    "status": str(item.get("provider_status", "") or ""),
                    "result_count": int(item.get("provider_result_count", 0) or 0),
                }
                for item in stats
            ],
        }


def search_engines(base_domain):
    s = SearchEngines(base_domain)
    return s.run()


if __name__ == '__main__':
    for x in baidu_search("qq.com", 6):
        print(x)
