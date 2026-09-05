"""WebSiteFetch 具体扫描阶段服务。

这里保留 Python 对网络、浏览器、文件字典和 Mongo 的控制，只把 stage 业务边界
从 WebSiteFetch 移出；任务类仍通过同名方法提供兼容入口。
"""

import os
from urllib.parse import urlparse

from app import services, utils
from app.config import Config, normalize_dict_path_compat
from app.modules import CollectSource, WebSiteFetchOption
from app.utils.log_safety import safe_error_text


logger = utils.get_logger()


class WebSiteFetchStageService(object):
    """获取站点基础信息并更新可用站点集合。"""

    def __init__(self, task, services_module=None):
        self.task = task
        self.services = services_module or services

    def run(self):
        task = self.task
        fetch_kwargs = {"waf_guard": task.waf_guard}
        discovery_context = getattr(task, "discovery_context", None)
        if discovery_context is not None and self.services is services:
            fetch_kwargs["discovery_context"] = discovery_context
        task.site_info_list = self.services.fetch_site(task.sites, **fetch_kwargs)
        for site_info in task.site_info_list:
            curr_site = site_info["site"]
            task.available_sites.append(curr_site)
            if discovery_context is not None:
                discovery_context.register_candidate(
                    event_type="SiteDiscovered",
                    candidate=curr_site,
                    candidate_type="site",
                    source="fetch_site",
                    status="fetched",
                    metadata={
                        "status_code": int(site_info.get("status", 0) or 0),
                        "body_length": int(site_info.get("body_length", 0) or 0),
                    },
                )
        return task.site_info_list


class WebSiteIdentifyStageService(object):
    """执行站点指纹识别阶段。"""

    def __init__(self, task, services_module=None):
        self.task = task
        self.services = services_module or services

    def run(self):
        task = self.task
        identify_targets = task._build_site_identify_targets()
        identify_targets = task._filter_waf_blocked_targets(
            identify_targets,
            stage_name="site_identify",
        )
        if not identify_targets:
            logger.info(
                "task_id:{} skip site_identify, no staged targets".format(
                    task.task_id,
                )
            )
            task.web_analyze_map = {}
            return task.web_analyze_map

        task.web_analyze_map = self.services.web_analyze(identify_targets)
        return task.web_analyze_map


class WebSiteScreenshotStageService(object):
    """执行站点截图。"""

    def __init__(self, task, services_module=None, config=None):
        self.task = task
        self.services = services_module or services
        self.config = config or Config

    def run(self):
        task = self.task
        capture_save_dir = self.config.SCREENSHOT_DIR + "/" + task.task_id
        return self.services.site_screenshot(
            task.available_sites,
            concurrency=self.config.SITE_SCREENSHOT_CONCURRENCY,
            capture_dir=capture_save_dir,
            task_id=task.task_id,
        )


class WebSiteSpiderStageService(object):
    """执行站点爬虫、URL 写回和无 WIH 时的轻量情报补充。"""

    def __init__(self, task, url_item_builder, services_module=None):
        self.task = task
        self.url_item_builder = url_item_builder
        self.services = services_module or services

    def run(self):
        task = self.task
        entry_urls_list = []
        for site in task.available_sites:
            parsed_site = urlparse(site)
            if parsed_site.path != "":
                continue

            entry_urls = [site]
            entry_urls.extend(task.search_engines_result.get(site, []))
            entry_urls_list.append(entry_urls)

        spider_kwargs = {"waf_guard": task.waf_guard}
        discovery_context = getattr(task, "discovery_context", None)
        if discovery_context is not None and self.services is services:
            spider_kwargs["discovery_context"] = discovery_context
        site_spider_result = self.services.site_spider_thread(
            entry_urls_list,
            **spider_kwargs,
        )
        spider_urls = []
        for site in site_spider_result:
            target_urls = site_spider_result[site]
            new_target_urls = []
            for url in target_urls:
                if url in task.page_url_set:
                    continue
                new_target_urls.append(url)
                task.page_url_set.add(url)

            if new_target_urls:
                spider_urls.extend(new_target_urls)

        if spider_urls:
            logger.info("spider_urls {} task_id:{}".format(len(spider_urls), task.task_id))
            page_fetch_kwargs = {
                "waf_guard": task.waf_guard,
                "waf_module": "site_spider_probe",
            }
            discovery_context = getattr(task, "discovery_context", None)
            if discovery_context is not None and self.services is services:
                page_fetch_kwargs["discovery_context"] = discovery_context
                page_fetch_kwargs["traffic_class"] = "crawler"
            page_map = self.services.page_fetch(spider_urls, **page_fetch_kwargs)
            for url in page_map:
                item = self.url_item_builder(
                    url,
                    task.task_id,
                    source=CollectSource.SITESPIDER,
                )
                item.update(page_map[url])
                # worker 恢复/重试路径幂等：(task_id, source, url) 唯一。
                task._result_writer.upsert_one(
                    "url",
                    {
                        "task_id": task.task_id,
                        "source": item.get("source", CollectSource.SITESPIDER),
                        "url": item.get("url", ""),
                    },
                    item,
                )
                if discovery_context is not None and self.services is services:
                    # 已完成内容处理的 URL 迁移为 covered，避免被误判为仅出现过。
                    discovery_context.mark_candidate_status(url, "url", "covered")

        self._enhance_site_spider_urls_with_intel()
        return spider_urls

    def _enhance_site_spider_urls_with_intel(self):
        task = self.task
        if task.options.get(WebSiteFetchOption.Info_Hunter):
            return
        if not task.available_sites:
            return

        try:
            intel_kwargs = {}
            if self.services is services and getattr(task, "discovery_context", None) is not None:
                intel_kwargs["discovery_context"] = task.discovery_context
            page_intel_records = list(
                self.services.run_page_intel_scan(
                    task.available_sites,
                    [],
                    waf_guard=task.waf_guard,
                    **intel_kwargs,
                )
                or []
            )
            urlfinder_records = list(
                self.services.run_urlfinder_extract(
                    task.available_sites,
                    page_intel_records,
                    waf_guard=task.waf_guard,
                    **intel_kwargs,
                )
                or []
            )
            merged_records = list(set(page_intel_records + urlfinder_records))
            if not merged_records:
                return

            inserted_count = self.services.run_urlfinder_url_probe(
                task_id=task.task_id,
                sites=task.available_sites,
                wih_records=merged_records,
                page_url_set=task.page_url_set,
                waf_guard=task.waf_guard,
                **(
                    {"discovery_context": task.discovery_context}
                    if getattr(task, "discovery_context", None) is not None
                    and self.services is services
                    else {}
                ),
            )
            logger.info(
                "task_id:{} site_spider intel merge page_intel:{} urlfinder:{} "
                "url_probe_inserted:{}".format(
                    task.task_id,
                    len(page_intel_records),
                    len(urlfinder_records),
                    inserted_count,
                )
            )
        except Exception as exc:
            logger.warning(
                "task_id:{} site_spider intel merge failed err:{}".format(
                    task.task_id,
                    safe_error_text(exc),
                )
            )


class WebSiteFileLeakStageService(object):
    """执行文件泄漏候选探测并写回 fileleak/url collection。"""

    def __init__(self, task, services_module=None, utils_module=None, config=None):
        self.task = task
        self.services = services_module or services
        self.utils = utils_module or utils
        self.config = config or Config

    def _dict_path(self):
        task = self.task
        custom_path = normalize_dict_path_compat(task.options.get("file_leak_dict", ""))
        custom_path = str(custom_path or "").strip()
        default_path = self.config.FILE_LEAK_TOP_2k
        if custom_path:
            if os.path.isfile(custom_path):
                return custom_path
            logger.warning(
                "task_id:{} file_leak_dict not found, fallback default dict: {}".format(
                    task.task_id,
                    custom_path,
                )
            )
        return default_path

    def _merge_new_host_targets(self, poc_sites):
        """批次 17：候选图中的新子域在同一任务内进入目录扫描队列。

        有界（FILE_LEAK_NEW_HOST_MAX）、经任务范围校验；消费后候选迁移为
        queued，避免同任务重复分发。站点/WIH 队列注入仍按下一轮周期任务
        语义生效（当前 run 的站点集已在扫描中，不热改目标集）。
        """

        task = self.task
        context = getattr(task, "discovery_context", None)
        if context is None:
            return poc_sites
        if not bool(getattr(Config, "FILE_LEAK_NEW_HOST_ENABLE", True)):
            return poc_sites
        try:
            max_hosts = int(getattr(Config, "FILE_LEAK_NEW_HOST_MAX", 10) or 0)
        except Exception:
            max_hosts = 10
        if max_hosts <= 0:
            return poc_sites

        existing_hosts = set()
        for site in poc_sites:
            try:
                host = str(urlparse(str(site or "")).hostname or "").strip().lower()
            except Exception:
                host = ""
            if host:
                existing_hosts.add(host)

        merged = list(poc_sites)
        added = 0
        for candidate in context.iter_candidates(candidate_type="host", status="discovered"):
            host = str(candidate.candidate or "").strip().lower()
            if not host or host in existing_hosts:
                continue
            try:
                if not task._host_in_task_scope(host):
                    continue
            except Exception:
                continue
            merged.append("https://{}".format(host))
            existing_hosts.add(host)
            context.mark_candidate_status(candidate.candidate, "host", "queued")
            added += 1
            if added >= max_hosts:
                break

        if added:
            logger.info(
                "task_id:{} fileleak directory queue received new hosts:{} cap:{}".format(
                    task.task_id, added, max_hosts
                )
            )
        return sorted(set(merged)) if added else poc_sites

    def run(self):
        task = self.task
        file_leak_dict_words = self.utils.load_file(self._dict_path())
        poc_sites = self._merge_new_host_targets(sorted(task.poc_sites))
        if not poc_sites:
            return []

        leak_kwargs = {"waf_guard": task.waf_guard, "scan_profile": self._dict_path()}
        discovery_context = getattr(task, "discovery_context", None)
        if discovery_context is not None and self.services is services:
            leak_kwargs["discovery_context"] = discovery_context
        # 策略级消费协议（Review 20260905 §4 重要项2）：目录扫描的按目标
        # 完成证据由 file_leak 的 `file_leak|<target>` covered 账本落账；
        # 晚到/超上限候选由收尾器读取同一账本后显影 pending。
        pages = self.services.file_leak(
            poc_sites,
            file_leak_dict_words,
            **leak_kwargs,
        )
        site_scope_map = {}
        for site in poc_sites:
            normalized_site = self.utils.url.normal_url(site)
            parsed_site = urlparse(normalized_site)
            if parsed_site.scheme and parsed_site.netloc:
                site_scope_map["{}://{}".format(parsed_site.scheme, parsed_site.netloc)] = site

        inserted_count = 0
        for page in pages:
            item = task._result_item_service.build_fileleak_document(
                page,
                site_scope_map,
            )
            if not item:
                continue
            page_url = str(item.get("url", "") or "").strip()
            task._result_writer.insert_one("fileleak", item)
            inserted_count += 1
            if page_url:
                task._result_writer.delete_many(
                    "url",
                    {"task_id": task.task_id, "url": page_url},
                )
                if discovery_context is not None and self.services is services:
                    try:
                        discovery_context.register_candidate(
                            event_type="DirectoryCandidateDiscovered",
                            candidate=page_url,
                            candidate_type="path",
                            source="file_leak",
                            status="covered",
                            metadata={"hit": True},
                        )
                    except Exception:
                        # 候选登记失败不影响结果写回，事件观测在收尾日志中可见。
                        discovery_context.record_metric("degraded_count")

        logger.info(
            "task_id:{} fileleak sites:{} pages:{} target_concurrency:{}".format(
                task.task_id,
                len(poc_sites),
                inserted_count,
                self.config.FILE_LEAK_TARGET_CONCURRENCY,
            )
        )
        return pages
