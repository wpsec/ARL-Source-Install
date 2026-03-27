"""
通用任务执行框架
"""
import time
import re
import os
import json
import hashlib
from urllib.parse import urlparse, parse_qsl, urlencode, urlsplit, urlunsplit
from bson import ObjectId
from pymongo.errors import NetworkTimeout, AutoReconnect, ServerSelectionTimeoutError
from app import utils
from app import services
from app.config import Config, normalize_dict_path_compat
from app.modules import CollectSource, WebSiteFetchStatus, WebSiteFetchOption
from app.services.nuclei_scan import nuclei_scan, NucleiScan
from app.services.afrog_scan import run_afrog_scan
from app.services.waf_guard import WAFSmartSkipGuard
from app.services import run_risk_cruising, BaseUpdateTask
logger = utils.get_logger()


# 任务类中一些相关公共类
class CommonTask(object):
    def __init__(self, task_id):
        self.task_id = task_id

    def insert_task_stat(self):
        query = {
            "_id": ObjectId(self.task_id)
        }

        # 任务收尾阶段强制刷新统计，避免命中运行中旧缓存导致结果被写成 0。
        stat = utils.arl.task_statistic(self.task_id, force_refresh=True)

        logger.info("insert task stat task_id:{} stat:{}".format(self.task_id, stat))

        update = {"$set": {"statistic": stat}}

        utils.conn_db('task').update_one(query, update)

    def insert_finger_stat(self):
        # 任务收尾阶段强制刷新指纹统计，避免命中运行中旧缓存。
        finger_stat_map = utils.arl.gen_stat_finger_map(self.task_id, force_refresh=True)
        logger.info("insert finger stat {}".format(len(finger_stat_map)))

        for key in finger_stat_map:
            data = finger_stat_map[key].copy()
            data["task_id"] = self.task_id
            utils.conn_db('stat_finger').insert_one(data)

    def insert_cip_stat(self):
        cip_map = utils.arl.gen_cip_map(self.task_id)
        logger.info("insert cip stat {}".format(len(cip_map)))

        for cidr_ip in cip_map:
            item = cip_map[cidr_ip]
            ip_list = list(item["ip_set"])
            domain_list = list(item["domain_set"])

            data = {
                "cidr_ip": cidr_ip,
                "ip_count": len(ip_list),
                "ip_list": ip_list,
                "domain_count": len(domain_list),
                "domain_list": domain_list,
                "task_id": self.task_id
            }

            utils.conn_db('cip').insert_one(data)

    # 资产同步
    def sync_asset(self):
        options = getattr(self, 'options', {})
        if not options:
            logger.warning("not found options {}".format(self.task_id))
            return

        related_scope_id = options.get("related_scope_id", "")
        if not related_scope_id:
            return

        if len(related_scope_id) != 24:
            logger.warning("related_scope_id len not eq 24 {}".format(self.task_id, related_scope_id))
            return

        services.sync_asset(task_id=self.task_id, scope_id=related_scope_id)

    def common_run(self):
        self.insert_finger_stat()
        self.insert_cip_stat()
        self.insert_task_stat()
        self.sync_asset()


# *** 对用户提交的站点或者是发现的站点进行后续处理
class WebSiteFetch(object):
    # 低性能环境下，Mongo 读取可能因网络抖动/带宽占满触发超时；nuclei 目标构建最多重试 3 次。
    NUCLEI_TARGET_BUILD_RETRY_COUNT = 3
    NUCLEI_TARGET_BUILD_RETRY_SLEEP_SEC = 3
    RETRYABLE_MONGO_ERRORS = (NetworkTimeout, AutoReconnect, ServerSelectionTimeoutError)
    # 站点识别分层策略：先快扫，再对高价值站点精扫。
    SITE_IDENTIFY_AUTO_MIN_SELECT = 20
    SITE_IDENTIFY_AUTO_MAX_SELECT = 160
    SITE_IDENTIFY_AUTO_RATIO = 0.25
    SITE_IDENTIFY_FORCE_STATUS_SET = {401, 403}
    SITE_IDENTIFY_TITLE_KEYWORDS = (
        "login", "signin", "admin", "manage", "dashboard", "console",
        "swagger", "grafana", "jenkins", "gitlab", "jira", "confluence",
        "harbor", "nacos", "phpmyadmin", "tomcat", "weblogic", "kibana",
        "zabbix", "prometheus", "rabbitmq", "minio",
    )
    SITE_IDENTIFY_HOST_KEYWORDS = (
        "admin", "manage", "ops", "dev", "test", "staging", "pre",
        "console", "panel", "oa", "vpn", "api",
    )
    AI_POC_MAX_TAGS = 24
    AI_POC_MAX_KEYWORDS = 24
    AI_POC_MAX_CONTEXT_SITES = 24
    AI_POC_MAX_URL_HINTS = 80
    AI_POC_MAX_WIH_HINTS = 80
    AI_POC_INDEX_MAX_MATCHED_TOKENS = 24
    AI_POC_INDEX_MAX_CANDIDATE_TAGS = 48
    AI_POC_INDEX_MAX_CANDIDATE_KEYWORDS = 48
    AI_POC_AI_INPUT_MAX_TAGS = 64
    AI_POC_AI_INPUT_MAX_KEYWORDS = 64
    AI_PEN_TEST_MAX_CASES = 80
    AI_PEN_TEST_SOURCE_LIMIT = 260
    AI_PEN_TEST_FETCH_TIMEOUT = (5.1, 10.1)
    AI_PEN_TEST_MCP_MAX_TOOL_CALLS = 3
    AI_PEN_TEST_MCP_TIMEOUT_SEC = 12
    AI_PEN_TEST_BODY_MAX = 8192
    AI_PEN_TEST_EVIDENCE_MAX = 280
    AI_PEN_TEST_ERROR_MAX = 180
    AI_PEN_TEST_SENSITIVE_RECORD_TYPES = (
        "api_key",
        "access_key",
        "secret_key",
        "client_secret",
        "private_key",
        "token",
        "jwt",
        "authorization",
        "password",
        "passwd",
        "credential",
    )
    AI_POC_ALIAS_HINTS = {
        "alibaba": ["alibaba", "aliyun", "阿里", "阿里云"],
        "tencent": ["tencent", "qcloud", "腾讯", "腾讯云"],
        "huawei": ["huawei", "huawei cloud", "华为", "华为云"],
        "baidu": ["baidu", "百度", "百度云"],
        "aws": ["aws", "amazon"],
        "azure": ["azure", "microsoft"],
        "google": ["google", "gcp", "谷歌"],
        "spring": ["spring", "springboot", "spring cloud", "actuator"],
        "tomcat": ["tomcat"],
        "weblogic": ["weblogic"],
        "jboss": ["jboss", "wildfly"],
        "nacos": ["nacos"],
        "jenkins": ["jenkins"],
        "gitlab": ["gitlab"],
        "jira": ["jira", "atlassian"],
        "confluence": ["confluence", "atlassian"],
        "grafana": ["grafana"],
        "kibana": ["kibana", "elasticsearch"],
        "harbor": ["harbor"],
        "rabbitmq": ["rabbitmq"],
        "minio": ["minio"],
        "redis": ["redis"],
        "mongodb": ["mongodb", "mongo"],
        "wordpress": ["wordpress", "wp-login"],
        "drupal": ["drupal"],
        "joomla": ["joomla"],
    }
    AI_POC_ALIAS_TAG_MAP = {
        "alibaba": ["alibaba", "aliyun", "oss", "bucket", "misconfig", "exposure"],
        "tencent": ["tencent", "qcloud", "bucket", "misconfig", "exposure"],
        "huawei": ["huawei", "bucket", "misconfig", "exposure"],
        "aws": ["aws", "s3", "bucket", "misconfig", "exposure"],
        "azure": ["azure", "bucket", "misconfig", "exposure"],
        "google": ["gcp", "bucket", "misconfig", "exposure"],
        "spring": ["spring", "springboot", "java", "actuator"],
        "tomcat": ["tomcat", "java", "apache"],
        "weblogic": ["weblogic", "oracle", "java"],
        "jboss": ["jboss", "java"],
        "nacos": ["nacos", "default-login", "unauth"],
        "jenkins": ["jenkins", "default-login"],
        "gitlab": ["gitlab", "default-login"],
        "jira": ["jira", "atlassian"],
        "confluence": ["confluence", "atlassian"],
        "grafana": ["grafana", "default-login"],
        "kibana": ["kibana", "elasticsearch"],
        "harbor": ["harbor", "default-login"],
        "rabbitmq": ["rabbitmq", "default-login", "panel"],
        "minio": ["minio", "default-login"],
        "redis": ["redis", "unauth"],
        "mongodb": ["mongodb", "unauth"],
        "wordpress": ["wordpress"],
        "drupal": ["drupal"],
        "joomla": ["joomla"],
    }
    AI_POC_ALIAS_KEYWORD_MAP = {
        "alibaba": ["Alibaba", "Aliyun", "阿里"],
        "tencent": ["Tencent", "Qcloud", "腾讯"],
        "huawei": ["Huawei", "华为"],
        "baidu": ["Baidu", "百度"],
        "aws": ["AWS", "Amazon"],
        "azure": ["Azure", "Microsoft"],
        "google": ["Google", "GCP"],
        "spring": ["Spring", "SpringBoot", "Actuator"],
        "tomcat": ["Tomcat"],
        "weblogic": ["WebLogic"],
        "jboss": ["JBoss", "WildFly"],
        "nacos": ["Nacos"],
        "jenkins": ["Jenkins"],
        "gitlab": ["GitLab"],
        "jira": ["Jira", "Atlassian"],
        "confluence": ["Confluence", "Atlassian"],
        "grafana": ["Grafana"],
        "kibana": ["Kibana", "ElasticSearch"],
        "harbor": ["Harbor"],
        "rabbitmq": ["RabbitMQ"],
        "minio": ["MinIO"],
        "redis": ["Redis"],
        "mongodb": ["MongoDB"],
        "wordpress": ["WordPress"],
        "drupal": ["Drupal"],
        "joomla": ["Joomla"],
    }
    AI_POC_INDEX_ENV_KEY = "ARL_AI_POC_INDEX_FILE"
    AI_POC_INDEX_REL_PATH = os.path.join("docker", "ai", "sop", "poc_index.json")
    AI_POC_INDEX_REL_PATH_LEGACY = os.path.join("docker", "ai", "poc-index", "poc_index.json")
    _AI_POC_INDEX_CACHE = {
        "path": "",
        "mtime": 0.0,
        "data": {},
    }
    _AI_PEN_TEST_INDEX_READY = False

    def __init__(self, task_id: str, sites: list, options: dict, scope_domain: list = None):
        self.task_id = task_id
        self.sites = sites  # ** 这个是用户提交的目标
        self.options = options or {}
        self.smart_skip_waf = bool(self.options.get("smart_skip_waf", False))
        self.waf_bypass = bool(
            self.options.get(WebSiteFetchOption.WAF_BYPASS, False)
            and self.options.get(WebSiteFetchOption.PENETRATION_TEST, False)
        )
        self.waf_guard = WAFSmartSkipGuard(
            enabled=self.smart_skip_waf or self.waf_bypass,
            smart_skip_enabled=self.smart_skip_waf,
            bypass_enabled=self.waf_bypass,
            task_id=self.task_id,
            scope_sites=self.sites,
        )
        self.base_update_task = BaseUpdateTask(self.task_id)
        self.site_info_list = []  # *** 这个是来自 services.fetch_site 的结果
        self.available_sites = []  # *** 这个是存活的站点
        self.web_analyze_map = dict()
        self.wih_domain_set = set()  # 用于保存来自wih的域名，已添加的域名不再添加
        self.wih_record_set = set()  # 用于保存来自wih的记录，已添加的记录不再添加

        # 用于判断应该收集的子域名
        if not scope_domain:
            scope_domain = []

        self.scope_domain = scope_domain
        self.page_url_set = set()
        self.search_engines_result = dict()
        self._poc_sites = None  # 用于PoC 执行， 文件目录爆破 的目标
        self._task_domain_set = None  # 用于保存任务中的域名
        self._nuclei_deferred_retry_needed = False
        self._nuclei_final_skip = False
        self.ai_poc_runtime = {
            "enabled": False,
            "mode": "disabled",
            "nuclei_scan_profile": None,
            "afrog_keywords": "",
            "afrog_severity": "",
            "confidence": 0.0,
            "reason": "",
            "evidence": [],
            "raw_ai_reply": "",
        }

    def _filter_waf_blocked_targets(self, targets, stage_name="") -> list:
        target_list = list(targets or [])
        if not self.waf_guard:
            return target_list

        keep_targets, skipped = self.waf_guard.filter_targets(target_list)
        if skipped > 0:
            logger.info(
                "task_id:{} waf smart skip stage:{} keep:{} skipped:{}".format(
                    self.task_id,
                    stage_name or "-",
                    len(keep_targets),
                    skipped,
                )
            )
        return keep_targets

    def _save_waf_skip_summary(self):
        if not self.waf_guard or not getattr(self.waf_guard, "enabled", False):
            return

        summary = self.waf_guard.summary()
        summary["updated_at"] = utils.curr_date()
        summary_text = self.waf_guard.summary_text()

        query = {"_id": ObjectId(self.task_id)}
        utils.conn_db("task").update_one(query, {"$set": {"waf_skip_summary": summary}})
        service_name = "waf_smart_skip" if self.smart_skip_waf else "waf_observe"
        utils.conn_db("task").update_one(
            query,
            {
                "$push": {
                    "service": {
                        "name": service_name,
                        "elapsed": 0.0,
                        "detail": summary_text,
                    }
                }
            },
        )
        logger.info("task_id:{} waf smart skip summary {}".format(self.task_id, summary_text))

    @property
    def task_domain_set(self):
        if self._task_domain_set is None:
            self._task_domain_set = set(utils.arl.get_domain_by_id(self.task_id))

        return self._task_domain_set

    def _site_identify_score(self, site_info: dict) -> tuple:
        """
        基于站点元数据给出“高价值”评分，并返回是否强制识别。
        """
        info = site_info if isinstance(site_info, dict) else {}
        site = str(info.get("site", "") or "").strip()
        parsed = urlparse(site)
        hostname = str(parsed.hostname or "").strip().lower()
        path = str(parsed.path or "").strip()
        title = str(info.get("title", "") or "").strip().lower()
        headers = str(info.get("headers", "") or "").strip().lower()
        http_server = str(info.get("http_server", "") or "").strip().lower()

        status = info.get("status")
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 0

        score = 0
        force_pick = status in self.SITE_IDENTIFY_FORCE_STATUS_SET
        if force_pick:
            score += 120
        elif 200 <= status < 400:
            score += 8

        # 管理后台、登录页、控制台、中间件等入口优先识别。
        if any(keyword in title for keyword in self.SITE_IDENTIFY_TITLE_KEYWORDS):
            score += 70

        if any(keyword in hostname for keyword in self.SITE_IDENTIFY_HOST_KEYWORDS):
            score += 45

        if "www-authenticate" in headers:
            score += 30

        if "set-cookie:" in headers:
            score += 8

        if path and path != "/":
            score += 16

        if parsed.port:
            if parsed.port not in {80, 443}:
                score += 18

        body_length = info.get("body_length", 0)
        try:
            body_length = int(body_length)
        except (TypeError, ValueError):
            body_length = 0
        if body_length > 32 * 1024:
            score += 12
        elif body_length > 8 * 1024:
            score += 6

        finger_list = info.get("finger", [])
        finger_count = len(finger_list) if isinstance(finger_list, list) else 0
        if finger_count > 0:
            score += min(30, finger_count * 4)

        # 网关/中间件类入口通常具备较高识别价值。
        if any(token in http_server for token in ("kong", "apisix", "openresty", "weblogic", "tomcat", "jetty")):
            score += 22

        return score, force_pick

    def _build_site_identify_targets(self) -> list:
        """
        构建 site_identify 二阶段目标：
        第一阶段做全量存活探测；第二阶段仅识别高价值站点。
        """
        candidate_sites = list(dict.fromkeys(self.available_sites))
        total_count = len(candidate_sites)
        if total_count <= 0:
            return []

        site_info_map = {}
        for site_info in self.site_info_list:
            if not isinstance(site_info, dict):
                continue
            site = str(site_info.get("site", "") or "").strip()
            if not site:
                continue
            site_info_map[site] = site_info

        scored_items = []
        for site in candidate_sites:
            score, force_pick = self._site_identify_score(site_info_map.get(site, {"site": site}))
            scored_items.append((site, score, force_pick))

        scored_items.sort(key=lambda x: (-x[1], x[0]))

        if total_count <= self.SITE_IDENTIFY_AUTO_MIN_SELECT:
            target_count = total_count
        else:
            target_count = int(total_count * self.SITE_IDENTIFY_AUTO_RATIO)
            target_count = max(self.SITE_IDENTIFY_AUTO_MIN_SELECT, target_count)
            target_count = min(self.SITE_IDENTIFY_AUTO_MAX_SELECT, target_count, total_count)

        score_threshold = 40
        selected = []
        selected_set = set()

        # 401/403 等“受控入口”无论评分如何都进入第二阶段。
        for site, _, force_pick in scored_items:
            if not force_pick:
                continue
            selected.append(site)
            selected_set.add(site)

        for site, score, _ in scored_items:
            if score < score_threshold:
                continue
            if site in selected_set:
                continue
            selected.append(site)
            selected_set.add(site)
            if len(selected) >= target_count:
                break

        # 高分样本不足时，按排名补齐，保持“可控上限 + 稳定覆盖”。
        if len(selected) < target_count:
            for site, _, _ in scored_items:
                if site in selected_set:
                    continue
                selected.append(site)
                selected_set.add(site)
                if len(selected) >= target_count:
                    break

        logger.info(
            "task_id:{} site_identify staged select:{}/{} threshold:{} force:{} ratio:{} min:{} max:{}".format(
                self.task_id,
                len(selected),
                total_count,
                score_threshold,
                len([1 for _, _, force_pick in scored_items if force_pick]),
                self.SITE_IDENTIFY_AUTO_RATIO,
                self.SITE_IDENTIFY_AUTO_MIN_SELECT,
                self.SITE_IDENTIFY_AUTO_MAX_SELECT,
            )
        )
        return selected

    def site_identify(self):
        # 二阶段：第一阶段先快扫发现资产，第二阶段仅识别高价值站点。
        identify_targets = self._build_site_identify_targets()
        identify_targets = self._filter_waf_blocked_targets(identify_targets, stage_name="site_identify")
        if not identify_targets:
            logger.info("task_id:{} skip site_identify, no staged targets".format(self.task_id))
            self.web_analyze_map = {}
            return

        # ** 调用指纹识别（仅针对筛选后的高价值目标）
        self.web_analyze_map = services.web_analyze(identify_targets)

    def __str__(self):
        return "<WebSiteFetch> task_id:{}, sites: {}, available_sites:{}".format(
            self.task_id, len(self.sites), len(self.available_sites))

    def save_site_info(self):
        for site_info in self.site_info_list:
            curr_site = site_info["site"]
            site_path = "/image/" + self.task_id
            file_name = '{}/{}.jpg'.format(site_path, utils.gen_filename(curr_site))
            site_info["task_id"] = self.task_id
            site_info["screenshot"] = file_name

            # 调用读取站点识别的结果，并且去重
            if self.web_analyze_map:
                finger_list = self.web_analyze_map.get(curr_site, [])
                known_finger_set = set()
                for finger_item in site_info["finger"]:
                    known_finger_set.add(finger_item["name"].lower())

                for analyze_finger in finger_list:
                    analyze_name = analyze_finger["name"].lower()
                    if analyze_name not in known_finger_set:
                        site_info["finger"].append(analyze_finger)

        logger.info("save_site_info site:{}, {}".format(len(self.site_info_list), self.__str__()))
        if self.site_info_list:
            utils.conn_db('site').insert_many(self.site_info_list)
            # 站点信息落库完成后，触发“站点”模块 AI 去噪增量分析。
            self.base_update_task.trigger_ai_denoise_stage(
                stage_name="site_saved",
                task_options=self.options,
            )

    def site_screenshot(self):
        # ***站点截图***
        capture_save_dir = Config.SCREENSHOT_DIR + "/" + self.task_id
        services.site_screenshot(
            self.available_sites,
            concurrency=Config.SITE_SCREENSHOT_CONCURRENCY,
            capture_dir=capture_save_dir,
            task_id=self.task_id
        )

    def site_spider(self):
        # *** 执行静态爬虫
        entry_urls_list = []  # 是一个二维数组
        for site in self.available_sites:
            o = urlparse(site)
            if o.path != "":
                continue

            entry_urls = [site]
            entry_urls.extend(self.search_engines_result.get(site, []))
            entry_urls_list.append(entry_urls)

        site_spider_result = services.site_spider_thread(entry_urls_list, waf_guard=self.waf_guard)
        spider_urls = []
        for site in site_spider_result:
            target_urls = site_spider_result[site]
            new_target_urls = []
            for url in target_urls:
                if url in self.page_url_set:
                    continue
                new_target_urls.append(url)

                self.page_url_set.add(url)

            if not new_target_urls:
                continue

            spider_urls.extend(new_target_urls)

        if len(spider_urls) > 0:
            logger.info("spider_urls {} task_id:{}".format( len(spider_urls), self.task_id))
            page_map = services.page_fetch(spider_urls, waf_guard=self.waf_guard, waf_module="site_spider_probe")
            for url in page_map:
                item = build_url_item(url, self.task_id, source=CollectSource.SITESPIDER)
                item.update(page_map[url])
                utils.conn_db('url').insert_one(item)

    def fetch_site(self):
        # ***站点信息获取***
        self.site_info_list = services.fetch_site(self.sites, waf_guard=self.waf_guard)
        for site_info in self.site_info_list:
            curr_site = site_info["site"]
            self.available_sites.append(curr_site)

    def file_leak(self):
        # 任务级 file_leak_dict 优先；未指定或不可用时回退系统默认配置字典。
        custom_file_leak_dict = normalize_dict_path_compat(self.options.get("file_leak_dict", ""))
        custom_file_leak_dict = str(custom_file_leak_dict or "").strip()
        file_leak_dict_path = Config.FILE_LEAK_TOP_2k
        if custom_file_leak_dict:
            if os.path.isfile(custom_file_leak_dict):
                file_leak_dict_path = custom_file_leak_dict
            else:
                logger.warning(
                    "task_id:{} file_leak_dict not found, fallback default dict: {}".format(
                        self.task_id, custom_file_leak_dict
                    )
                )

        file_leak_dict_words = utils.load_file(file_leak_dict_path)
        for site in self.poc_sites:
            pages = services.file_leak([site], file_leak_dict_words, waf_guard=self.waf_guard)
            for page in pages:
                item = page if isinstance(page, dict) else page.dump_json()
                item["task_id"] = self.task_id
                item["site"] = site
                utils.conn_db('fileleak').insert_one(item)

    @property
    def poc_sites(self):
        if self._poc_sites is None:
            self._poc_sites = set()
            for x in self.available_sites:
                cut_target = utils.url.cut_filename(x)
                if cut_target:
                    self._poc_sites.add(cut_target)

        return self._poc_sites

    def risk_cruising(self, npoc_service_target_set: set):
        # *** 运行PoC任务, 需要自己在外层手动调用
        poc_config = self.options.get("poc_config", [])
        plugins = []
        for info in poc_config:
            if not info.get("enable"):
                continue
            plugins.append(info["plugin_name"])

        poc_targets = self.poc_sites

        if npoc_service_target_set is not None:
            poc_targets = self.poc_sites | npoc_service_target_set

        result = run_risk_cruising(plugins=plugins, targets=poc_targets)
        for item in result:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('vuln').insert_one(item)

    def build_nuclei_targets(self):
        """
        组装 nuclei 扫描目标，附带站点指纹信息
        """
        poc_sites = sorted(self.poc_sites)
        if not poc_sites:
            return []

        # 标题关键词提示，用于补足指纹命名差异。
        title_hint_keywords = (
            "jenkins", "grafana", "kibana", "gitlab", "jira", "confluence",
            "harbor", "nacos", "rabbitmq", "minio", "tomcat", "weblogic",
            "kong", "apisix", "zabbix", "prometheus",
        )

        query = {
            "task_id": self.task_id,
            "site": {"$in": poc_sites},
        }
        fields = {"site": 1, "finger": 1, "http_server": 1, "title": 1}
        site_finger_map = {}
        for attempt in range(1, self.NUCLEI_TARGET_BUILD_RETRY_COUNT + 1):
            site_finger_map = {}
            try:
                for item in utils.conn_db('site').find(
                    query,
                    fields,
                    max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS
                ):
                    site = str(item.get("site", "")).strip()
                    if not site:
                        continue

                    finger_names = []
                    finger_list = item.get("finger", [])
                    if isinstance(finger_list, list):
                        for finger in finger_list:
                            if not isinstance(finger, dict):
                                continue
                            finger_name = str(finger.get("name", "")).strip().lower()
                            if finger_name:
                                finger_names.append(finger_name)

                    # 将 HTTP Server 头拆分成关键词并作为 hint。
                    http_server = str(item.get("http_server", "")).strip().lower()
                    if http_server:
                        finger_names.append(http_server)
                        for token in re.split(r"[^a-z0-9]+", http_server):
                            token = token.strip()
                            if len(token) >= 3:
                                finger_names.append(token)

                    # 将 title 中的高价值技术关键词加入 hint。
                    title_text = str(item.get("title", "")).strip().lower()
                    if title_text:
                        for keyword in title_hint_keywords:
                            if keyword in title_text:
                                finger_names.append(keyword)

                    site_finger_map[site] = sorted(set(finger_names))
                break
            except self.RETRYABLE_MONGO_ERRORS as e:
                if attempt >= self.NUCLEI_TARGET_BUILD_RETRY_COUNT:
                    logger.warning(
                        "build_nuclei_targets failed after retries task_id:{} attempts:{} error:{}".format(
                            self.task_id, self.NUCLEI_TARGET_BUILD_RETRY_COUNT, e
                        )
                    )
                    raise

                sleep_sec = self.NUCLEI_TARGET_BUILD_RETRY_SLEEP_SEC * attempt
                logger.warning(
                    "build_nuclei_targets mongo timeout task_id:{} attempt:{}/{} sleep:{}s error:{}".format(
                        self.task_id,
                        attempt,
                        self.NUCLEI_TARGET_BUILD_RETRY_COUNT,
                        sleep_sec,
                        e
                    )
                )
                time.sleep(sleep_sec)

        nuclei_targets = []
        for site in poc_sites:
            nuclei_targets.append(
                {
                    "target": site,
                    "finger": site_finger_map.get(site, []),
                }
            )

        return nuclei_targets

    @staticmethod
    def _count_yaml_files(dir_path: str) -> int:
        """
        统计目录下 YAML 文件数量。
        """
        scan_dir = str(dir_path or "").strip()
        if not scan_dir or not os.path.isdir(scan_dir):
            return 0

        yaml_count = 0
        for root, _, files in os.walk(scan_dir):
            for file_name in files:
                if file_name.endswith(".yaml") or file_name.endswith(".yml"):
                    yaml_count += 1
        return yaml_count

    def _load_ai_runtime_config(self):
        """
        读取 AI 管理运行配置（最佳努力，不阻断扫描流程）。
        """
        try:
            from app.routes import api_console as api_console_module
            resolve_func = getattr(api_console_module, "_resolve_config_path", None)
            load_func = getattr(api_console_module, "_load_config_from_file", None)
            extract_func = getattr(api_console_module, "_extract_ai_config", None)
            if callable(resolve_func) and callable(load_func) and callable(extract_func):
                config_obj = load_func(resolve_func())
                ai_config = extract_func(config_obj)
                if isinstance(ai_config, dict):
                    return ai_config
        except Exception as e:
            logger.warning("task_id:{} load ai runtime config failed err:{}".format(self.task_id, e))
        return {}

    @staticmethod
    def _safe_float_value(value, default_value=0.0):
        try:
            return float(value)
        except Exception:
            return float(default_value)

    @staticmethod
    def _normalize_ai_poc_tag(tag: str) -> str:
        text = re.sub(r"[^a-z0-9._-]", "", str(tag or "").strip().lower())
        if not text:
            return ""
        return text[:48]

    @classmethod
    def _normalize_ai_poc_tags(cls, value, max_count=None):
        limit = int(max_count or cls.AI_POC_MAX_TAGS)
        if limit < 1:
            limit = cls.AI_POC_MAX_TAGS

        items = []
        if isinstance(value, str):
            items = re.split(r"[,\s]+", value)
        elif isinstance(value, (list, tuple, set)):
            items = list(value)

        result = []
        seen = set()
        for item in items:
            tag = cls._normalize_ai_poc_tag(item)
            if not tag or tag in seen:
                continue
            seen.add(tag)
            result.append(tag)
            if len(result) >= limit:
                break
        return result

    @staticmethod
    def _normalize_ai_poc_keyword(keyword: str) -> str:
        text = str(keyword or "").strip().replace("\r", " ").replace("\n", " ").replace("\t", " ")
        if not text:
            return ""
        text = re.sub(r"\s+", " ", text).strip(" ,;|")
        text = text.replace('"', "").replace("'", "").replace("`", "")
        if not re.search(r"[A-Za-z0-9\u4e00-\u9fff]", text):
            return ""
        return text[:80]

    @classmethod
    def _normalize_ai_poc_keywords(cls, value, max_count=None):
        limit = int(max_count or cls.AI_POC_MAX_KEYWORDS)
        if limit < 1:
            limit = cls.AI_POC_MAX_KEYWORDS

        items = []
        if isinstance(value, str):
            items = re.split(r"[,\n\r]+", value)
        elif isinstance(value, (list, tuple, set)):
            items = list(value)

        result = []
        seen = set()
        for item in items:
            keyword = cls._normalize_ai_poc_keyword(item)
            lower_keyword = keyword.lower()
            if not keyword or lower_keyword in seen:
                continue
            seen.add(lower_keyword)
            result.append(keyword)
            if len(result) >= limit:
                break
        return result

    @staticmethod
    def _normalize_ai_poc_severity(value):
        allow = ["critical", "high", "medium", "low", "info"]
        if isinstance(value, str):
            items = re.split(r"[,\s]+", value)
        elif isinstance(value, (list, tuple, set)):
            items = list(value)
        else:
            items = []

        result = []
        seen = set()
        for item in items:
            severity = str(item or "").strip().lower()
            if severity not in allow or severity in seen:
                continue
            seen.add(severity)
            result.append(severity)
        return ",".join(result)

    @staticmethod
    def _extract_site_finger_names(value):
        names = []
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip()
                else:
                    name = str(item or "").strip()
                if name:
                    names.append(name)
        return names

    @staticmethod
    def _extract_url_host(url_text: str) -> str:
        parsed = urlparse(str(url_text or "").strip())
        return str(parsed.netloc or parsed.hostname or "").strip().lower()

    @staticmethod
    def _extract_url_path_hint(url_text: str) -> str:
        parsed = urlparse(str(url_text or "").strip())
        path_text = str(parsed.path or "").strip()
        if not path_text or path_text == "/":
            return ""
        if len(path_text) > 120:
            return path_text[:120]
        return path_text

    @staticmethod
    def _extract_ascii_tokens(text: str, max_tokens=80):
        token_list = []
        seen = set()
        for item in re.split(r"[^a-zA-Z0-9]+", str(text or "").lower()):
            token = str(item or "").strip()
            if len(token) < 3 or token.isdigit():
                continue
            if token in seen:
                continue
            seen.add(token)
            token_list.append(token)
            if len(token_list) >= max_tokens:
                break
        return token_list

    @staticmethod
    def _normalize_ai_poc_index_token(token: str) -> str:
        text = re.sub(r"[^a-z0-9._-]", "", str(token or "").strip().lower())
        if len(text) < 2 or text.isdigit():
            return ""
        return text[:64]

    @classmethod
    def _resolve_ai_poc_index_path(cls) -> str:
        env_path = str(os.environ.get(cls.AI_POC_INDEX_ENV_KEY, "") or "").strip()
        if env_path:
            return os.path.abspath(env_path)

        current_dir = os.path.abspath(os.path.dirname(__file__))
        primary_path = os.path.abspath(os.path.join(current_dir, os.pardir, os.pardir, cls.AI_POC_INDEX_REL_PATH))
        if os.path.isfile(primary_path):
            return primary_path

        legacy_path = os.path.abspath(
            os.path.join(current_dir, os.pardir, os.pardir, cls.AI_POC_INDEX_REL_PATH_LEGACY)
        )
        if os.path.isfile(legacy_path):
            return legacy_path

        return primary_path

    @classmethod
    def _normalize_ai_poc_index_tag_map(cls, raw_map):
        normalized = {}
        if not isinstance(raw_map, dict):
            return normalized

        for key, value in raw_map.items():
            token = cls._normalize_ai_poc_index_token(key)
            if not token:
                continue
            tags = cls._normalize_ai_poc_tags(value, max_count=80)
            if tags:
                normalized[token] = tags
        return normalized

    @classmethod
    def _normalize_ai_poc_index_keyword_map(cls, raw_map):
        normalized = {}
        if not isinstance(raw_map, dict):
            return normalized

        for key, value in raw_map.items():
            token = cls._normalize_ai_poc_index_token(key)
            if not token:
                continue
            keywords = cls._normalize_ai_poc_keywords(value, max_count=80)
            if keywords:
                normalized[token] = keywords
        return normalized

    @classmethod
    def _load_ai_poc_index_data(cls):
        index_path = cls._resolve_ai_poc_index_path()
        if not index_path or not os.path.isfile(index_path):
            return {}, ""

        try:
            mtime = float(os.path.getmtime(index_path))
        except Exception:
            mtime = 0.0

        cache = cls._AI_POC_INDEX_CACHE if isinstance(cls._AI_POC_INDEX_CACHE, dict) else {}
        cached_data = cache.get("data")
        if (
            cache.get("path") == index_path
            and float(cache.get("mtime", 0.0) or 0.0) == mtime
            and isinstance(cached_data, dict)
            and cached_data
        ):
            return cached_data, index_path

        try:
            with open(index_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception as e:
            logger.warning("load ai poc index failed path:{} err:{}".format(index_path, e))
            return {}, index_path

        if not isinstance(raw_data, dict):
            return {}, index_path

        nuclei_data = raw_data.get("nuclei") if isinstance(raw_data.get("nuclei"), dict) else {}
        afrog_data = raw_data.get("afrog") if isinstance(raw_data.get("afrog"), dict) else {}
        normalized_data = {
            "nuclei": {
                "token_to_tags": cls._normalize_ai_poc_index_tag_map(nuclei_data.get("token_to_tags")),
                "tag_to_templates": nuclei_data.get("tag_to_templates") if isinstance(nuclei_data.get("tag_to_templates"), dict) else {},
            },
            "afrog": {
                "token_to_keywords": cls._normalize_ai_poc_index_keyword_map(afrog_data.get("token_to_keywords")),
                "keyword_to_pocs": afrog_data.get("keyword_to_pocs") if isinstance(afrog_data.get("keyword_to_pocs"), dict) else {},
            },
            "meta": raw_data.get("meta") if isinstance(raw_data.get("meta"), dict) else {},
        }
        cls._AI_POC_INDEX_CACHE = {"path": index_path, "mtime": mtime, "data": normalized_data}
        return normalized_data, index_path

    def _collect_ai_poc_index_candidates(self, context_payload: dict, alias_hits: list):
        index_data, index_path = self._load_ai_poc_index_data()
        result = {
            "loaded": bool(index_data),
            "path": index_path,
            "matched_tokens": [],
            "nuclei_tags": [],
            "afrog_keywords": [],
            "nuclei_token_count": 0,
            "afrog_token_count": 0,
        }
        if not index_data:
            return result

        nuclei_token_map = index_data.get("nuclei", {}).get("token_to_tags")
        afrog_token_map = index_data.get("afrog", {}).get("token_to_keywords")
        if not isinstance(nuclei_token_map, dict):
            nuclei_token_map = {}
        if not isinstance(afrog_token_map, dict):
            afrog_token_map = {}

        result["nuclei_token_count"] = len(nuclei_token_map)
        result["afrog_token_count"] = len(afrog_token_map)
        if not nuclei_token_map and not afrog_token_map:
            return result

        token_source = []
        token_source.extend(context_payload.get("context_tokens", []))
        for alias_key in alias_hits or []:
            token_source.append(alias_key)
            token_source.extend(self._extract_ascii_tokens(" ".join(self.AI_POC_ALIAS_HINTS.get(alias_key, [])), max_tokens=20))

        for item in context_payload.get("site_contexts", []):
            if not isinstance(item, dict):
                continue
            raw_parts = []
            raw_parts.extend(item.get("finger", []))
            raw_parts.append(item.get("title", ""))
            raw_parts.append(item.get("http_server", ""))
            raw_parts.extend(item.get("url_hints", []))
            raw_parts.extend(item.get("wih_hints", []))
            token_source.extend(self._extract_ascii_tokens(" ".join([str(x or "") for x in raw_parts]), max_tokens=40))
            if len(token_source) >= 320:
                break

        normalized_tokens = []
        seen_tokens = set()
        for token in token_source:
            normalized = self._normalize_ai_poc_index_token(token)
            if not normalized or normalized in seen_tokens:
                continue
            seen_tokens.add(normalized)
            normalized_tokens.append(normalized)
            if len(normalized_tokens) >= 240:
                break

        tag_score_map = {}
        keyword_score_map = {}
        keyword_display_map = {}
        matched_token_score_map = {}

        for token in normalized_tokens:
            lookup_tokens = [token]
            compact_token = token.replace("-", "").replace("_", "").replace(".", "")
            if compact_token and compact_token != token:
                lookup_tokens.append(compact_token)

            token_hit = False
            for idx, lookup_token in enumerate(lookup_tokens):
                score_weight = 2 if idx == 0 else 1
                for tag in nuclei_token_map.get(lookup_token, []):
                    normalized_tag = self._normalize_ai_poc_tag(tag)
                    if not normalized_tag:
                        continue
                    tag_score_map[normalized_tag] = tag_score_map.get(normalized_tag, 0) + score_weight
                    token_hit = True

                for keyword in afrog_token_map.get(lookup_token, []):
                    normalized_keyword = self._normalize_ai_poc_keyword(keyword)
                    if not normalized_keyword:
                        continue
                    normalized_keyword_key = normalized_keyword.lower()
                    keyword_score_map[normalized_keyword_key] = keyword_score_map.get(normalized_keyword_key, 0) + score_weight
                    if normalized_keyword_key not in keyword_display_map:
                        keyword_display_map[normalized_keyword_key] = normalized_keyword
                    token_hit = True

            if token_hit:
                matched_token_score_map[token] = matched_token_score_map.get(token, 0) + 1

        sorted_tokens = sorted(
            matched_token_score_map.items(),
            key=lambda item: (-int(item[1]), len(item[0]), item[0]),
        )
        matched_tokens = [item[0] for item in sorted_tokens[: self.AI_POC_INDEX_MAX_MATCHED_TOKENS]]

        sorted_tags = sorted(
            tag_score_map.items(),
            key=lambda item: (-int(item[1]), len(item[0]), item[0]),
        )
        nuclei_tags = [item[0] for item in sorted_tags[: self.AI_POC_INDEX_MAX_CANDIDATE_TAGS]]

        sorted_keywords = sorted(
            keyword_score_map.items(),
            key=lambda item: (-int(item[1]), len(item[0]), item[0]),
        )
        afrog_keywords = [
            keyword_display_map.get(item[0], item[0])
            for item in sorted_keywords[: self.AI_POC_INDEX_MAX_CANDIDATE_KEYWORDS]
        ]

        result["matched_tokens"] = matched_tokens
        result["nuclei_tags"] = self._normalize_ai_poc_tags(
            nuclei_tags, max_count=self.AI_POC_INDEX_MAX_CANDIDATE_TAGS
        )
        result["afrog_keywords"] = self._normalize_ai_poc_keywords(
            afrog_keywords, max_count=self.AI_POC_INDEX_MAX_CANDIDATE_KEYWORDS
        )
        return result

    def _collect_ai_poc_context(self, poc_sites: list):
        hosts = {}
        for site in poc_sites:
            host = self._extract_url_host(site)
            if host and host not in hosts:
                hosts[host] = site
        host_set = set(hosts.keys())

        url_hints_map = {host: set() for host in host_set}
        wih_hints_map = {host: set() for host in host_set}

        if host_set:
            try:
                cursor = utils.conn_db("url").find(
                    {"task_id": self.task_id},
                    {"site": 1, "title": 1, "status_code": 1},
                    max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS
                ).limit(1600)
                for item in cursor:
                    site_url = str(item.get("site", "")).strip()
                    host = self._extract_url_host(site_url)
                    if not host or host not in host_set:
                        continue
                    path_hint = self._extract_url_path_hint(site_url)
                    if path_hint:
                        url_hints_map[host].add(path_hint)
                        if len(url_hints_map[host]) >= self.AI_POC_MAX_URL_HINTS:
                            continue
                    title_text = str(item.get("title", "")).strip()
                    if title_text:
                        url_hints_map[host].add("title:{}".format(title_text[:80]))
            except Exception as e:
                logger.warning("task_id:{} collect ai_poc url context failed err:{}".format(self.task_id, e))

            try:
                cursor = utils.conn_db("wih").find(
                    {"task_id": self.task_id},
                    {"site": 1, "record_type": 1, "content": 1},
                    max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS
                ).limit(2000)
                for item in cursor:
                    site_url = str(item.get("site", "")).strip()
                    host = self._extract_url_host(site_url)
                    if not host or host not in host_set:
                        continue
                    record_type = str(item.get("record_type", "")).strip().lower()
                    content = str(item.get("content", "")).strip()
                    if not content:
                        continue
                    hint_text = ""
                    if content.startswith("http://") or content.startswith("https://"):
                        hint_text = self._extract_url_path_hint(content)
                    if not hint_text:
                        hint_text = "{}:{}".format(record_type or "record", content[:100])
                    if hint_text:
                        wih_hints_map[host].add(hint_text)
                        if len(wih_hints_map[host]) >= self.AI_POC_MAX_WIH_HINTS:
                            continue
            except Exception as e:
                logger.warning("task_id:{} collect ai_poc wih context failed err:{}".format(self.task_id, e))

        site_contexts = []
        query = {"task_id": self.task_id, "site": {"$in": poc_sites}}
        fields = {"site": 1, "title": 1, "http_server": 1, "status": 1, "body_length": 1, "finger": 1}
        try:
            for item in utils.conn_db("site").find(query, fields, max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS):
                site = str(item.get("site", "")).strip()
                if not site:
                    continue
                host = self._extract_url_host(site)
                finger_names = self._extract_site_finger_names(item.get("finger", []))
                context_item = {
                    "site": site,
                    "status_code": int(item.get("status", 0) or 0),
                    "title": str(item.get("title", "")).strip()[:160],
                    "http_server": str(item.get("http_server", "")).strip()[:120],
                    "body_length": int(item.get("body_length", 0) or 0),
                    "finger": finger_names[:15],
                    "url_hints": sorted(list(url_hints_map.get(host, set())))[:10],
                    "wih_hints": sorted(list(wih_hints_map.get(host, set())))[:10],
                }
                site_contexts.append(context_item)
                if len(site_contexts) >= self.AI_POC_MAX_CONTEXT_SITES:
                    break
        except Exception as e:
            logger.warning("task_id:{} collect ai_poc site context failed err:{}".format(self.task_id, e))

        if not site_contexts:
            for site in poc_sites[: self.AI_POC_MAX_CONTEXT_SITES]:
                host = self._extract_url_host(site)
                site_contexts.append(
                    {
                        "site": site,
                        "status_code": 0,
                        "title": "",
                        "http_server": "",
                        "body_length": 0,
                        "finger": [],
                        "url_hints": sorted(list(url_hints_map.get(host, set())))[:8],
                        "wih_hints": sorted(list(wih_hints_map.get(host, set())))[:8],
                    }
                )

        context_tokens = []
        seen_tokens = set()
        for item in site_contexts:
            raw_parts = []
            raw_parts.extend(item.get("finger", []))
            raw_parts.append(item.get("title", ""))
            raw_parts.append(item.get("http_server", ""))
            raw_parts.extend(item.get("url_hints", []))
            raw_parts.extend(item.get("wih_hints", []))
            for token in self._extract_ascii_tokens(" ".join(raw_parts), max_tokens=60):
                if token in seen_tokens:
                    continue
                seen_tokens.add(token)
                context_tokens.append(token)
                if len(context_tokens) >= 180:
                    break
            if len(context_tokens) >= 180:
                break

        return {
            "site_contexts": site_contexts,
            "context_tokens": context_tokens,
        }

    def _collect_alias_hits(self, context_payload: dict):
        context_text_parts = []
        for item in context_payload.get("site_contexts", []):
            if not isinstance(item, dict):
                continue
            context_text_parts.extend(item.get("finger", []))
            context_text_parts.append(item.get("title", ""))
            context_text_parts.append(item.get("http_server", ""))
            context_text_parts.extend(item.get("url_hints", []))
            context_text_parts.extend(item.get("wih_hints", []))
        context_text_parts.extend(context_payload.get("context_tokens", []))
        context_text = " ".join([str(x or "") for x in context_text_parts]).lower()

        alias_hits = []
        for key, aliases in self.AI_POC_ALIAS_HINTS.items():
            for alias in aliases:
                alias_text = str(alias or "").strip().lower()
                if alias_text and alias_text in context_text:
                    alias_hits.append(key)
                    break
        return sorted(set(alias_hits))

    def _preview_nuclei_batch_plan(self, nuclei_targets: list):
        """
        基于当前目标预览 nuclei 批次计划（不执行扫描）。
        """
        if not nuclei_targets:
            return {
                "batch_count": 0,
                "auto_scan_batch_count": 0,
                "tag_sample": [],
                "all_tags": [],
            }

        try:
            scanner = NucleiScan(targets=nuclei_targets)
            batches = scanner._build_target_batches()
            all_tags = []
            auto_scan_batch_count = 0
            for batch in batches:
                if bool(batch.get("auto_scan", False)):
                    auto_scan_batch_count += 1
                tag_text = str(batch.get("tags", "") or "").strip()
                if not tag_text:
                    continue
                all_tags.extend(scanner._split_tag_text(tag_text))

            unique_tags = []
            seen = set()
            for tag in all_tags:
                normalized = self._normalize_ai_poc_tag(tag)
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                unique_tags.append(normalized)

            return {
                "batch_count": len(batches),
                "auto_scan_batch_count": auto_scan_batch_count,
                "tag_sample": unique_tags[:18],
                "all_tags": unique_tags[:120],
            }
        except Exception as e:
            logger.warning("task_id:{} preview nuclei batch plan failed err:{}".format(self.task_id, e))
            return {
                "batch_count": 0,
                "auto_scan_batch_count": 0,
                "tag_sample": [],
                "all_tags": [],
            }

    def _call_ai_poc_planner(self, ai_config: dict, nuclei_enabled: bool, afrog_enabled: bool, context_payload: dict, candidate_tags: list, candidate_keywords: list):
        """
        调用 AI 生成 PoC 匹配建议；失败时返回可解释状态，不阻断主流程。
        """
        result = {
            "ok": False,
            "status": "skipped",
            "message": "ai_poc disabled",
            "provider": "-",
            "model": "-",
            "profile": "-",
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "elapsed_ms": 0,
            "request_text": "",
            "reply_text": "",
            "output": {},
        }
        try:
            from app.routes import api_console as api_console_module

            normalize_profiles = getattr(api_console_module, "_normalize_ai_model_profiles", None)
            pick_active = getattr(api_console_module, "_pick_active_ai_model_profile", None)
            normalize_provider = getattr(api_console_module, "_normalize_ai_provider_id", None)
            normalize_model_name = getattr(api_console_module, "_normalize_ai_model_name", None)
            build_proxy_dict = getattr(api_console_module, "_build_ai_proxy_dict", None)
            safe_int = getattr(api_console_module, "_safe_int", None)
            safe_float = getattr(api_console_module, "_safe_float", None)
            is_model_unavailable = getattr(api_console_module, "_is_ai_model_unavailable_error", None)
            pick_retry_model = getattr(api_console_module, "_pick_ai_retry_model", None)
            extract_json_obj = getattr(api_console_module, "_extract_json_object_from_text", None)
            normalize_usage = getattr(api_console_module, "_normalize_ai_usage_dict", None)
            if not (
                callable(normalize_profiles)
                and callable(pick_active)
                and callable(normalize_provider)
                and callable(normalize_model_name)
                and callable(build_proxy_dict)
                and callable(safe_int)
                and callable(safe_float)
                and callable(is_model_unavailable)
                and callable(pick_retry_model)
                and callable(extract_json_obj)
                and callable(normalize_usage)
            ):
                result["message"] = "ai helper missing"
                return result

            model_profiles = normalize_profiles(ai_config.get("model_profiles"), legacy_ai_conf=ai_config)
            active_model_profile_id = str(ai_config.get("active_model_profile_id") or "").strip()
            active_profile = pick_active(model_profiles, active_model_profile_id)
            provider_id = normalize_provider(active_profile.get("provider") or "openai")
            model_name = normalize_model_name(provider_id, active_profile.get("model"))
            base_url = str(active_profile.get("base_url") or "").strip()
            api_key = str(active_profile.get("api_key") or "").strip()
            profile_name = str(active_profile.get("name") or active_profile.get("id") or "").strip()
            proxy_url = str(active_profile.get("proxy") or ai_config.get("proxy_url") or "").strip()
            request_proxies = build_proxy_dict(proxy_url)
            timeout_sec = safe_int(active_profile.get("timeout_sec"), 40, min_value=8)
            request_delay_ms = safe_int(ai_config.get("request_delay_ms"), 0, min_value=0)
            if request_delay_ms > 30000:
                request_delay_ms = 30000

            result["provider"] = provider_id
            result["model"] = model_name
            result["profile"] = profile_name

            if not base_url or not api_key or not model_name:
                result["message"] = "模型配置不完整"
                return result

            system_prompt = (
                "你是渗透测试PoC匹配助手。"
                "任务：根据站点指纹、Title、Server、URL/WIH线索，筛选最相关的 nuclei tags 和 afrog keywords。"
                "要求："
                "1. 仅输出 JSON 对象，不输出 Markdown。"
                "2. tags/keywords 尽量命中社区写法差异（别名、厂商简称、产品别名）。"
                "3. 证据不足时降低 confidence，不要给空泛高置信结论。"
                "4. 若某扫描器未启用，对应字段可留空。"
            )

            request_obj = {
                "task_id": str(self.task_id),
                "nuclei_enabled": bool(nuclei_enabled),
                "afrog_enabled": bool(afrog_enabled),
                "site_contexts": context_payload.get("site_contexts", [])[: self.AI_POC_MAX_CONTEXT_SITES],
                "context_tokens": context_payload.get("context_tokens", [])[:180],
                "candidate_tags": self._normalize_ai_poc_tags(
                    candidate_tags, max_count=self.AI_POC_AI_INPUT_MAX_TAGS
                ),
                "candidate_keywords": self._normalize_ai_poc_keywords(
                    candidate_keywords, max_count=self.AI_POC_AI_INPUT_MAX_KEYWORDS
                ),
                "alias_hint_groups": self.AI_POC_ALIAS_HINTS,
                "output_schema": {
                    "confidence": "0~1 float",
                    "nuclei": {
                        "tags": ["tag1", "tag2"],
                        "reason": "text",
                    },
                    "afrog": {
                        "keywords": ["keyword1", "keyword2"],
                        "severity": "critical,high,medium,low,info",
                        "reason": "text",
                    },
                    "evidence": ["text1", "text2"],
                },
            }
            request_text = json.dumps(request_obj, ensure_ascii=False)
            result["request_text"] = request_text
            request_url = "{}/chat/completions".format(base_url.rstrip("/"))

            headers = {
                "Authorization": "Bearer {}".format(api_key),
                "Content-Type": "application/json",
            }
            request_body = {
                "model": model_name,
                "temperature": min(max(safe_float(active_profile.get("temperature"), 0.1, min_value=0.0), 0.0), 1.0),
                "max_tokens": max(600, min(safe_int(active_profile.get("max_tokens"), 1800, min_value=400), 3200)),
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": request_text},
                ],
            }

            def _chat_with_model(target_model):
                started_at = time.perf_counter()
                call_body = dict(request_body)
                call_body["model"] = str(target_model or "").strip()
                kwargs = {
                    "headers": headers,
                    "json": call_body,
                    "timeout": (8, timeout_sec),
                }
                if request_proxies:
                    kwargs["proxies"] = request_proxies
                if request_delay_ms > 0:
                    time.sleep(float(request_delay_ms) / 1000.0)
                conn = utils.http_req(request_url, "post", **kwargs)
                status_code = int(getattr(conn, "status_code", 0) or 0)
                payload = {}
                try:
                    payload = conn.json() if conn is not None else {}
                except Exception:
                    payload = {}

                elapsed_ms = int((time.perf_counter() - started_at) * 1000.0)
                usage = normalize_usage(payload.get("usage") if isinstance(payload, dict) else {})

                if status_code != 200:
                    err_message = ""
                    if isinstance(payload, dict):
                        error_obj = payload.get("error")
                        if isinstance(error_obj, dict):
                            err_message = str(error_obj.get("message") or "").strip()
                        if not err_message:
                            err_message = str(payload.get("message") or "").strip()
                    return {
                        "ok": False,
                        "status_code": status_code,
                        "message": err_message or "HTTP {}".format(status_code),
                        "usage": usage,
                        "elapsed_ms": elapsed_ms,
                        "reply_text": "",
                    }

                reply_text = ""
                choices = payload.get("choices", []) if isinstance(payload, dict) else []
                message_obj = choices[0].get("message") if isinstance(choices, list) and choices else {}
                if isinstance(message_obj, dict):
                    content_obj = message_obj.get("content")
                    if isinstance(content_obj, str):
                        reply_text = content_obj.strip()
                    elif isinstance(content_obj, list):
                        text_parts = []
                        for fragment in content_obj:
                            if isinstance(fragment, dict) and str(fragment.get("type") or "").strip() == "text":
                                text_value = str(fragment.get("text") or "").strip()
                                if text_value:
                                    text_parts.append(text_value)
                        reply_text = "\n".join(text_parts).strip()
                return {
                    "ok": True,
                    "status_code": status_code,
                    "message": "",
                    "usage": usage,
                    "elapsed_ms": elapsed_ms,
                    "reply_text": reply_text,
                }

            call_ret = _chat_with_model(model_name)
            if (not call_ret.get("ok")) and is_model_unavailable(call_ret.get("message", "")):
                retry_model = pick_retry_model(provider_id, model_name)
                if retry_model:
                    retry_ret = _chat_with_model(retry_model)
                    if retry_ret.get("ok"):
                        model_name = retry_model
                        result["model"] = model_name
                        call_ret = retry_ret
                    else:
                        call_ret = retry_ret

            result["usage"] = call_ret.get("usage", result["usage"])
            result["elapsed_ms"] = int(call_ret.get("elapsed_ms", 0) or 0)
            result["reply_text"] = str(call_ret.get("reply_text", "") or "")
            if not call_ret.get("ok"):
                result["status"] = "error"
                result["message"] = str(call_ret.get("message", "") or "ai request failed")
                return result

            parsed = extract_json_obj(result["reply_text"])
            if not isinstance(parsed, dict):
                result["status"] = "error"
                result["message"] = "AI 返回格式不可解析"
                return result

            result["ok"] = True
            result["status"] = "ok"
            result["message"] = ""
            result["output"] = parsed
            return result
        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)
            return result

    def _write_ai_poc_usage_log(
        self,
        *,
        scene="ai_poc_scan_plan",
        status="skipped",
        provider="-",
        model="-",
        profile="-",
        request_text="",
        reply_text="",
        error_message="",
        elapsed_ms=0,
        usage=None,
        meta=None
    ):
        """
        写入 AI 管理中的 AI-POC 日志（计划日志 + 决策日志）。
        """
        try:
            from app.routes import api_console as api_console_module
            write_func = getattr(api_console_module, "_write_ai_usage_log", None)
            if callable(write_func):
                write_func(
                    scene=scene,
                    provider=provider,
                    model=model,
                    profile=profile,
                    status=status,
                    request_text=request_text,
                    reply_text=reply_text,
                    error_message=error_message,
                    elapsed_ms=elapsed_ms,
                    usage=usage if isinstance(usage, dict) else {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                    meta=meta if isinstance(meta, dict) else {},
                )
        except Exception as e:
            logger.warning("task_id:{} write ai_poc usage log failed err:{}".format(self.task_id, e))

    def _write_ai_pen_test_usage_log(
        self,
        *,
        scene="ai_pen_test_exec",
        status="ok",
        provider="local",
        model="rule-lite",
        profile="ai-pen-test",
        request_text="",
        reply_text="",
        error_message="",
        elapsed_ms=0,
        meta=None,
    ):
        """
        写入 AI 管理中的 AI 渗透测试执行日志（当前阶段为规则/验证引擎，token 计数固定为 0）。
        """
        try:
            from app.routes import api_console as api_console_module
            write_func = getattr(api_console_module, "_write_ai_usage_log", None)
            if callable(write_func):
                write_func(
                    scene=scene,
                    provider=str(provider or "local"),
                    model=str(model or "rule-lite"),
                    profile=str(profile or "ai-pen-test"),
                    status=status,
                    request_text=request_text,
                    reply_text=reply_text,
                    error_message=error_message,
                    elapsed_ms=elapsed_ms,
                    usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                    meta=meta if isinstance(meta, dict) else {},
                )
        except Exception as e:
            logger.warning("task_id:{} write ai_pen_test usage log failed err:{}".format(self.task_id, e))

    def run_ai_poc_scan_plan(self):
        """
        AI-POC 预扫描决策：
        - 开关关闭或模型不可用：保持现有扫描行为（pass-through）。
        - 开关开启且 AI 成功：将决策注入 nuclei/afrog 扫描参数。
        """
        self.ai_poc_runtime = {
            "enabled": False,
            "mode": "disabled",
            "nuclei_scan_profile": None,
            "afrog_keywords": "",
            "afrog_severity": "",
            "confidence": 0.0,
            "reason": "",
            "evidence": [],
            "raw_ai_reply": "",
        }

        nuclei_enabled = bool(self.options.get(WebSiteFetchOption.NUCLEI_SCAN))
        afrog_enabled = bool(self.options.get(WebSiteFetchOption.AFROG_SCAN))
        if not (nuclei_enabled or afrog_enabled):
            return

        t1 = time.time()
        ai_config = self._load_ai_runtime_config()
        ai_poc_scan_enable = bool(ai_config.get("ai_poc_scan_enable", True))

        nuclei_targets = self.build_nuclei_targets() if nuclei_enabled else []
        nuclei_finger_hit = 0
        for item in nuclei_targets:
            if item.get("finger"):
                nuclei_finger_hit += 1

        nuclei_plan = self._preview_nuclei_batch_plan(nuclei_targets) if nuclei_enabled else {
            "batch_count": 0,
            "auto_scan_batch_count": 0,
            "tag_sample": [],
            "all_tags": [],
        }

        afrog_target_count = len(self.poc_sites) if afrog_enabled else 0
        afrog_pocs_dir = str(getattr(Config, "AFROG_POCS_DIR", "") or "").strip()
        afrog_poc_count = self._count_yaml_files(afrog_pocs_dir) if afrog_enabled else 0

        context_payload = self._collect_ai_poc_context(sorted(self.poc_sites))
        alias_hits = self._collect_alias_hits(context_payload)
        index_candidates = self._collect_ai_poc_index_candidates(context_payload, alias_hits)

        candidate_tags = self._normalize_ai_poc_tags(nuclei_plan.get("all_tags", []), max_count=120)
        for alias_key in alias_hits:
            candidate_tags.extend(self.AI_POC_ALIAS_TAG_MAP.get(alias_key, []))
        candidate_tags.extend(index_candidates.get("nuclei_tags", []))
        candidate_tags = self._normalize_ai_poc_tags(candidate_tags, max_count=120)

        candidate_keywords = self._normalize_ai_poc_keywords(
            str(getattr(Config, "AFROG_SEARCH_KEYWORDS", "") or "").strip(),
            max_count=120,
        )
        for alias_key in alias_hits:
            candidate_keywords.extend(self.AI_POC_ALIAS_KEYWORD_MAP.get(alias_key, []))
        candidate_keywords.extend(index_candidates.get("afrog_keywords", []))
        candidate_keywords = self._normalize_ai_poc_keywords(candidate_keywords, max_count=120)

        applied_nuclei_tags = []
        applied_afrog_keywords = []
        applied_afrog_severity = ""
        ai_confidence = 0.0
        ai_reason = ""
        ai_evidence = []
        ai_status = "skipped"
        ai_error = ""
        ai_reply_text = ""
        ai_request_text = ""
        ai_provider = "-"
        ai_model = "-"
        ai_profile = "-"
        ai_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        ai_elapsed_ms = 0
        run_mode = "pass_through"

        if not ai_poc_scan_enable:
            run_mode = "disabled"
        else:
            ai_call_result = self._call_ai_poc_planner(
                ai_config=ai_config,
                nuclei_enabled=nuclei_enabled,
                afrog_enabled=afrog_enabled,
                context_payload=context_payload,
                candidate_tags=candidate_tags,
                candidate_keywords=candidate_keywords,
            )
            ai_status = str(ai_call_result.get("status", "skipped") or "skipped").strip().lower()
            ai_error = str(ai_call_result.get("message", "") or "").strip()
            ai_reply_text = str(ai_call_result.get("reply_text", "") or "")
            ai_request_text = str(ai_call_result.get("request_text", "") or "")
            ai_provider = str(ai_call_result.get("provider", "-") or "-")
            ai_model = str(ai_call_result.get("model", "-") or "-")
            ai_profile = str(ai_call_result.get("profile", "-") or "-")
            ai_usage = ai_call_result.get("usage") if isinstance(ai_call_result.get("usage"), dict) else ai_usage
            ai_elapsed_ms = int(ai_call_result.get("elapsed_ms", 0) or 0)

            if bool(ai_call_result.get("ok")):
                ai_output = ai_call_result.get("output") if isinstance(ai_call_result.get("output"), dict) else {}
                ai_confidence = max(0.0, min(1.0, self._safe_float_value(ai_output.get("confidence"), 0.0)))
                nuclei_data = ai_output.get("nuclei") if isinstance(ai_output.get("nuclei"), dict) else {}
                afrog_data = ai_output.get("afrog") if isinstance(ai_output.get("afrog"), dict) else {}

                ai_nuclei_tags = self._normalize_ai_poc_tags(
                    nuclei_data.get("tags") if nuclei_data else ai_output.get("nuclei_tags"),
                    max_count=self.AI_POC_MAX_TAGS,
                )
                ai_afrog_keywords = self._normalize_ai_poc_keywords(
                    afrog_data.get("keywords") if afrog_data else ai_output.get("afrog_keywords"),
                    max_count=self.AI_POC_MAX_KEYWORDS,
                )
                ai_afrog_severity = self._normalize_ai_poc_severity(
                    afrog_data.get("severity") if afrog_data else ai_output.get("afrog_severity")
                )

                entity_items = ai_output.get("entities", [])
                if isinstance(entity_items, (list, tuple, set)):
                    for entity in entity_items:
                        entity_text = str(entity or "").strip().lower()
                        if ":" in entity_text:
                            entity_text = entity_text.split(":", 1)[1].strip()
                        if entity_text in self.AI_POC_ALIAS_TAG_MAP:
                            ai_nuclei_tags.extend(self.AI_POC_ALIAS_TAG_MAP.get(entity_text, []))
                        if entity_text in self.AI_POC_ALIAS_KEYWORD_MAP:
                            ai_afrog_keywords.extend(self.AI_POC_ALIAS_KEYWORD_MAP.get(entity_text, []))

                ai_nuclei_tags = self._normalize_ai_poc_tags(ai_nuclei_tags, max_count=self.AI_POC_MAX_TAGS)
                ai_afrog_keywords = self._normalize_ai_poc_keywords(ai_afrog_keywords, max_count=self.AI_POC_MAX_KEYWORDS)

                ai_reason = str(
                    nuclei_data.get("reason")
                    or afrog_data.get("reason")
                    or ai_output.get("reason")
                    or ""
                ).strip()[:220]
                ai_evidence = self._normalize_ai_poc_keywords(ai_output.get("evidence"), max_count=8)

                if nuclei_enabled and ai_nuclei_tags:
                    applied_nuclei_tags = ai_nuclei_tags
                    self.ai_poc_runtime["nuclei_scan_profile"] = {
                        "name": "ai-poc",
                        "force_tags": applied_nuclei_tags,
                    }
                if afrog_enabled and ai_afrog_keywords:
                    applied_afrog_keywords = ai_afrog_keywords
                    self.ai_poc_runtime["afrog_keywords"] = ",".join(applied_afrog_keywords)
                if afrog_enabled and ai_afrog_severity:
                    applied_afrog_severity = ai_afrog_severity
                    self.ai_poc_runtime["afrog_severity"] = applied_afrog_severity

                if applied_nuclei_tags or applied_afrog_keywords or applied_afrog_severity:
                    run_mode = "ai_applied"
                    self.ai_poc_runtime["enabled"] = True
                else:
                    run_mode = "ai_no_action"
            else:
                run_mode = "ai_{}".format(ai_status or "error")

        self.ai_poc_runtime["mode"] = run_mode
        self.ai_poc_runtime["confidence"] = ai_confidence
        self.ai_poc_runtime["reason"] = ai_reason
        self.ai_poc_runtime["evidence"] = ai_evidence
        self.ai_poc_runtime["raw_ai_reply"] = ai_reply_text[:2200]

        detail_parts = [
            "enabled={}".format(str(ai_poc_scan_enable).lower()),
            "mode={}".format(run_mode),
            "nuclei={}".format("on" if nuclei_enabled else "off"),
            "afrog={}".format("on" if afrog_enabled else "off"),
            "nuclei_targets={}".format(len(nuclei_targets)),
            "nuclei_finger_hit={}".format(nuclei_finger_hit),
            "nuclei_batches={}".format(nuclei_plan.get("batch_count", 0)),
            "nuclei_auto_batches={}".format(nuclei_plan.get("auto_scan_batch_count", 0)),
            "nuclei_rule_tags={}".format(",".join(nuclei_plan.get("tag_sample", [])) or "-"),
            "nuclei_candidate_tags={}".format(",".join(candidate_tags[:16]) or "-"),
            "nuclei_apply_tags={}".format(",".join(applied_nuclei_tags) or "-"),
            "afrog_targets={}".format(afrog_target_count),
            "afrog_candidate_keywords={}".format(",".join(candidate_keywords[:16]) or "-"),
            "afrog_apply_keywords={}".format(",".join(applied_afrog_keywords) or "-"),
            "afrog_apply_severity={}".format(applied_afrog_severity or "-"),
            "afrog_poc_files={}".format(afrog_poc_count),
            "alias_hits={}".format(",".join(alias_hits) or "-"),
            "index_loaded={}".format("true" if index_candidates.get("loaded") else "false"),
            "index_tokens={}".format(",".join(index_candidates.get("matched_tokens", [])) or "-"),
            "ai_status={}".format(ai_status or "skipped"),
            "ai_confidence={:.2f}".format(ai_confidence),
            "ai_reason={}".format(ai_reason or "-"),
        ]
        if ai_error:
            detail_parts.append("ai_error={}".format(ai_error[:120]))
        detail_text = " | ".join(detail_parts)[:2000]
        logger.info("task_id:{} ai_poc_scan plan {}".format(self.task_id, detail_text))

        elapsed = time.time() - t1
        utils.conn_db("task").update_one(
            {"_id": ObjectId(self.task_id)},
            {
                "$push": {
                    "service": {
                        "name": "ai_poc_scan",
                        "elapsed": float("{:.2f}".format(elapsed)),
                        "detail": detail_text,
                    }
                }
            },
        )

        plan_meta = {
            "task_id": str(self.task_id),
            "ai_poc_scan_enable": ai_poc_scan_enable,
            "run_mode": run_mode,
            "nuclei_enabled": nuclei_enabled,
            "afrog_enabled": afrog_enabled,
            "nuclei_target_count": len(nuclei_targets),
            "nuclei_finger_hit_count": nuclei_finger_hit,
            "nuclei_batch_count": int(nuclei_plan.get("batch_count", 0) or 0),
            "nuclei_auto_batch_count": int(nuclei_plan.get("auto_scan_batch_count", 0) or 0),
            "nuclei_rule_tags": list(nuclei_plan.get("tag_sample", []) or []),
            "nuclei_candidate_tags": list(candidate_tags[:50]),
            "nuclei_apply_tags": list(applied_nuclei_tags),
            "afrog_target_count": afrog_target_count,
            "afrog_candidate_keywords": list(candidate_keywords[:50]),
            "afrog_apply_keywords": list(applied_afrog_keywords),
            "afrog_apply_severity": applied_afrog_severity,
            "afrog_poc_count": afrog_poc_count,
            "afrog_pocs_dir": afrog_pocs_dir,
            "alias_hits": alias_hits,
            "index_loaded": bool(index_candidates.get("loaded")),
            "index_path": str(index_candidates.get("path", "") or ""),
            "index_matched_tokens": list(index_candidates.get("matched_tokens", [])),
            "index_nuclei_token_count": int(index_candidates.get("nuclei_token_count", 0) or 0),
            "index_afrog_token_count": int(index_candidates.get("afrog_token_count", 0) or 0),
            "ai_status": ai_status,
            "ai_confidence": ai_confidence,
            "ai_reason": ai_reason,
            "ai_error": ai_error,
        }

        self._write_ai_poc_usage_log(
            scene="ai_poc_scan_plan",
            status="skipped",
            provider="-",
            model="-",
            profile="-",
            request_text="AI-POC 扫描计划",
            reply_text=detail_text,
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            meta=plan_meta,
        )

        if ai_poc_scan_enable:
            self._write_ai_poc_usage_log(
                scene="ai_poc_scan_decision",
                status=ai_status if ai_status in {"ok", "error", "skipped"} else "skipped",
                provider=ai_provider,
                model=ai_model,
                profile=ai_profile,
                request_text=ai_request_text,
                reply_text=ai_reply_text,
                error_message=ai_error,
                elapsed_ms=ai_elapsed_ms,
                usage=ai_usage,
                meta=plan_meta,
            )

    def nuclei_scan(self, deferred_retry=False):
        try:
            nuclei_targets = self.build_nuclei_targets()
        except self.RETRYABLE_MONGO_ERRORS as e:
            if deferred_retry:
                self._nuclei_final_skip = True
                logger.warning(
                    "nuclei_scan skipped task_id:{} after deferred retry due to mongo timeout:{}".format(
                        self.task_id, e
                    )
                )
            else:
                self._nuclei_deferred_retry_needed = True
                logger.warning(
                    "nuclei_scan deferred task_id:{} due to mongo timeout, will retry after later stages:{}".format(
                        self.task_id, e
                    )
                )
            return

        finger_hit_count = 0
        for item in nuclei_targets:
            if item.get("finger"):
                finger_hit_count += 1

        logger.info(
            "start nuclei_scan, poc_sites:{} finger_hit:{}".format(
                len(nuclei_targets), finger_hit_count
            )
        )
        scan_profile = None
        runtime_profile = self.ai_poc_runtime.get("nuclei_scan_profile") if isinstance(self.ai_poc_runtime, dict) else None
        if isinstance(runtime_profile, dict):
            force_tags = runtime_profile.get("force_tags")
            if isinstance(force_tags, str):
                force_tags = [x for x in force_tags.split(",") if x]
            if isinstance(force_tags, (list, tuple, set)) and force_tags:
                scan_profile = {
                    "name": str(runtime_profile.get("name", "ai-poc") or "ai-poc"),
                    "force_tags": list(force_tags),
                }
                logger.info(
                    "task_id:{} nuclei_scan use ai_poc profile:{} tags:{}".format(
                        self.task_id,
                        scan_profile.get("name"),
                        ",".join([str(x) for x in scan_profile.get("force_tags", [])])[:300],
                    )
                )

        scan_results = nuclei_scan(nuclei_targets, scan_profile=scan_profile)
        for item in scan_results:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('nuclei_result').insert_one(item)

        logger.info("end nuclei_scan， result:{}".format(len(scan_results)))

    def run_deferred_nuclei_scan(self):
        """
        首次 nuclei 阶段因 Mongo 读取超时时，延后到其它阶段后补跑一次。
        """
        self._nuclei_deferred_retry_needed = False
        deferred_status = "nuclei_scan_retry"
        logger.info(
            "start deferred nuclei_scan task_id:{}".format(self.task_id)
        )
        self.base_update_task.update_task_field("status", deferred_status)
        t1 = time.time()
        self.nuclei_scan(deferred_retry=True)
        elapse = time.time() - t1
        self.base_update_task.update_services(deferred_status, elapse)
        if self._nuclei_final_skip:
            logger.warning(
                "deferred nuclei_scan still failed and skipped task_id:{}".format(self.task_id)
            )

    @staticmethod
    def _build_afrog_detail_text(result, target, poc_id):
        """
        生成更可读的 afrog 详情，避免导出报告中出现大量固定占位信息。
        """
        verify_payload = {}
        verify_data_text = str(result.get("verify_data", "") or "").strip()
        if verify_data_text:
            try:
                parsed_payload = json.loads(verify_data_text)
                if isinstance(parsed_payload, dict):
                    verify_payload = parsed_payload
            except Exception:
                verify_payload = {}

        vuln_name = str(result.get("vuln_name", "") or "").strip()
        severity = str(result.get("severity", "") or "").strip().lower()
        references = verify_payload.get("reference", [])
        if isinstance(references, str):
            references = [references]
        if not isinstance(references, list):
            references = []
        references = [str(item or "").strip() for item in references if str(item or "").strip()][:2]

        parts = ["source=afrog", "poc_id={}".format(poc_id or "-")]
        if vuln_name:
            parts.append("name={}".format(vuln_name[:120]))
        if severity:
            parts.append("severity={}".format(severity[:24]))
        if target:
            parts.append("target={}".format(str(target)[:180]))
        if references:
            parts.append("reference={}".format(" ; ".join([item[:140] for item in references])))

        return " | ".join(parts)[:900]

    def afrog_scan(self):
        """
        运行 afrog Web 漏洞扫描，并写入 vuln 模块。

        字段映射：
        - plg_name: afrog:<poc_id>
        - plg_type: afrog
        - vul_name / severity / target: 来自 afrog 结果
        """
        afrog_targets = sorted(self.poc_sites)
        if not afrog_targets:
            logger.info("skip afrog_scan, no poc_sites")
            return

        origin_target_count = len(afrog_targets)
        afrog_targets = self._filter_waf_blocked_targets(afrog_targets, stage_name="afrog")
        if not afrog_targets:
            logger.info("skip afrog_scan, no targets after waf filter")
            return

        logger.info(
            "start afrog_scan targets:{} after_waf_filter:{} smart_skip_waf:{}".format(
                origin_target_count,
                len(afrog_targets),
                self.smart_skip_waf,
            )
        )
        ai_keywords = ""
        ai_severity = ""
        if isinstance(self.ai_poc_runtime, dict):
            ai_keywords = str(self.ai_poc_runtime.get("afrog_keywords", "") or "").strip()
            ai_severity = str(self.ai_poc_runtime.get("afrog_severity", "") or "").strip().lower()
            if ai_keywords or ai_severity:
                logger.info(
                    "task_id:{} afrog_scan use ai_poc keywords:{} severity:{}".format(
                        self.task_id,
                        ai_keywords[:220] if ai_keywords else "-",
                        ai_severity or "-",
                    )
                )
        scan_results = run_afrog_scan(
            afrog_targets,
            search_keywords=ai_keywords if ai_keywords else None,
            severity=ai_severity if ai_severity else None,
        )
        saved_count = 0
        for result in scan_results:
            target = str(result.get("target", "") or "").strip()
            if not target:
                continue

            poc_id = str(result.get("poc_id", "") or "").strip()
            detail_text = self._build_afrog_detail_text(result=result, target=target, poc_id=poc_id)
            item = {
                "plg_name": "afrog:{}".format(poc_id) if poc_id else "afrog",
                "plg_type": "afrog",
                "vul_name": str(result.get("vuln_name", "") or "afrog 漏洞").strip(),
                "app_name": "afrog",
                "target": target,
                "severity": str(result.get("severity", "") or "info").strip().lower(),
                "description": str(result.get("description", "") or "").strip(),
                "detail": detail_text,
                "verify_data": str(result.get("verify_data", "") or "").strip(),
                "task_id": self.task_id,
                "save_date": utils.curr_date(),
            }
            utils.conn_db('vuln').insert_one(item)
            saved_count += 1

        logger.info("end afrog_scan, result:{} saved:{}".format(len(scan_results), saved_count))

    def run_penetration_test(self):
        """
        运行 Web 专项渗透测试。

        说明：
        - 与 nuclei / afrog 的模板化 PoC 扫描解耦
        - 在未显式开启 WIH 时，自动补做一次 Web 信息收集，便于承接页面表单 /
          API 文档 / URL 资产等前置信息
        """
        if not self.options.get(WebSiteFetchOption.Info_Hunter) and not self.wih_record_set:
            logger.info(
                "task_id:{} penetration_test bootstrap web_info_hunter for prerequisite intel".format(
                    self.task_id
                )
            )
            self.run_web_info_hunter()

        scan_result = services.run_penetration_scan(
            task_id=self.task_id,
            sites=self.sites,
            page_url_set=self.page_url_set,
            waf_guard=self.waf_guard,
        )
        cloud_result = services.run_cloud_security_scan(
            task_id=self.task_id,
            sites=self.sites,
            page_url_set=self.page_url_set,
            waf_guard=self.waf_guard,
        )

        saved_count = 0
        all_findings = list(scan_result.get("findings", []) or []) + list(cloud_result.get("findings", []) or [])
        for result in all_findings:
            target = str(result.get("url", "") or "").strip()
            if not target:
                continue

            item = {
                "plg_name": "penetration:{}".format(str(result.get("type", "") or "unknown").strip().lower() or "unknown"),
                "plg_type": str(result.get("type", "") or "penetration").strip().lower() or "penetration",
                "vul_name": str(result.get("name", "") or "专项渗透测试发现").strip(),
                "app_name": "penetration_test",
                "target": target,
                "severity": str(result.get("severity", "") or "info").strip().lower(),
                "description": str(result.get("detail", "") or "").strip(),
                "detail": "source={} method={} param={} payload={}".format(
                    str(result.get("source", "") or "-").strip(),
                    str(result.get("method", "") or "GET").strip(),
                    str(result.get("param", "") or "-").strip(),
                    str(result.get("payload", "") or "-").strip()[:200],
                ),
                "verify_data": str(result.get("evidence", "") or "").strip(),
                "request_data": str(result.get("request", "") or "").strip(),
                "response_data": str(result.get("response", "") or "").strip(),
                "task_id": self.task_id,
                "save_date": utils.curr_date(),
            }
            utils.conn_db('vuln').insert_one(item)
            saved_count += 1

        logger.info(
            "end penetration_test, active_targets:{} cloud_targets:{} findings_saved:{}".format(
                len(scan_result.get("targets", [])),
                len(cloud_result.get("targets", [])),
                saved_count,
            )
        )

    @classmethod
    def _ensure_ai_pen_test_indexes(cls):
        """
        确保 ai_pen_test_result 集合索引存在（幂等）。
        """
        if cls._AI_PEN_TEST_INDEX_READY:
            return

        try:
            collection = utils.conn_db("ai_pen_test_result")
            collection.create_index(
                [("task_id", 1), ("source_collection", 1), ("source_id", 1)],
                unique=True,
                background=True,
            )
            collection.create_index([("task_id", 1), ("save_date", -1)], background=True)
            collection.create_index([("task_id", 1), ("decision", 1)], background=True)
            cls._AI_PEN_TEST_INDEX_READY = True
        except Exception as e:
            logger.warning("ensure ai_pen_test indexes failed err:{}".format(e))

    @staticmethod
    def _clip_text(value, max_len=220):
        text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
        if len(text) <= max_len:
            return text
        return "{}...".format(text[:max_len])

    @staticmethod
    def _is_http_target(value: str) -> bool:
        text = str(value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")

    @staticmethod
    def _normalize_object_id(value) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        return text

    @staticmethod
    def _normalize_risk_type(value, default_value="unknown"):
        text = str(value or "").strip().lower()
        if not text:
            return default_value
        return text[:64]

    @staticmethod
    def _safe_int_value(value, default_value=0):
        try:
            return int(value)
        except Exception:
            return int(default_value)

    @classmethod
    def _build_ai_pen_runtime_settings(cls, ai_config: dict):
        config_obj = ai_config if isinstance(ai_config, dict) else {}
        ai_pen_enable = bool(config_obj.get("ai_pen_test_enable", True))
        mcp_enable = bool(config_obj.get("ai_pen_mcp_enable", True))
        max_tool_calls = cls._safe_int_value(config_obj.get("ai_pen_mcp_max_tool_calls"), cls.AI_PEN_TEST_MCP_MAX_TOOL_CALLS)
        timeout_sec = cls._safe_int_value(config_obj.get("ai_pen_mcp_timeout_sec"), cls.AI_PEN_TEST_MCP_TIMEOUT_SEC)
        if max_tool_calls < 1:
            max_tool_calls = 1
        if max_tool_calls > 8:
            max_tool_calls = 8
        if timeout_sec < 1:
            timeout_sec = 1
        if timeout_sec > 60:
            timeout_sec = 60

        connect_timeout = float(cls.AI_PEN_TEST_FETCH_TIMEOUT[0] if isinstance(cls.AI_PEN_TEST_FETCH_TIMEOUT, tuple) else 5.1)
        read_timeout = float(timeout_sec) + 0.1
        if read_timeout < connect_timeout:
            read_timeout = connect_timeout

        return {
            "ai_pen_enable": ai_pen_enable,
            "mcp_enable": mcp_enable,
            "max_tool_calls": max_tool_calls,
            "timeout_sec": timeout_sec,
            "timeout": (connect_timeout, read_timeout),
        }

    @staticmethod
    def _contains_evidence(evidence_seed: str, body_text: str) -> bool:
        seed_text = str(evidence_seed or "").strip().lower()
        body_check_text = str(body_text or "").lower()
        if not seed_text or not body_check_text:
            return False
        if len(seed_text) >= 12:
            return seed_text in body_check_text
        # 证据过短时降低误命中概率，仅做弱匹配。
        return len(seed_text) >= 6 and seed_text in body_check_text

    @staticmethod
    def _build_probe_url_with_payload(target_url: str, payload: str):
        url_text = str(target_url or "").strip()
        payload_text = str(payload or "").strip()
        if not url_text or not payload_text:
            return url_text

        try:
            parsed = urlsplit(url_text)
            query_items = parse_qsl(parsed.query, keep_blank_values=True)
            if query_items:
                first_key = str(query_items[0][0] or "").strip() or "id"
                query_items[0] = (first_key, payload_text)
            else:
                query_items.append(("arl_probe", payload_text))
            updated_query = urlencode(query_items, doseq=True)
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, updated_query, parsed.fragment))
        except Exception:
            return url_text

    @classmethod
    def _is_sensitive_wih_record(cls, record_type: str, content: str):
        record_type_text = str(record_type or "").strip().lower()
        content_text = str(content or "").strip().lower()
        if not record_type_text and not content_text:
            return False

        if record_type_text in cls.AI_PEN_TEST_SENSITIVE_RECORD_TYPES:
            return True
        if record_type_text.endswith("_key") or record_type_text.endswith("_token"):
            return True
        if record_type_text.startswith("trufflehog_"):
            return True

        merged = "{} {}".format(record_type_text, content_text)
        sensitive_tokens = (
            "api_key",
            "access_key",
            "secret_key",
            "client_secret",
            "private_key",
            "authorization",
            "bearer",
            "password",
            "passwd",
            "credential",
            "jwt",
            "token",
        )
        return any(token in merged for token in sensitive_tokens)

    @classmethod
    def _classify_ai_pen_risk_type(cls, raw_type: str, risk_name: str, source_module: str = ""):
        type_text = str(raw_type or "").strip().lower()
        name_text = str(risk_name or "").strip().lower()
        source_text = str(source_module or "").strip().lower()
        merged = " ".join([type_text, name_text, source_text]).strip()
        if not merged:
            return "unknown"

        if "jwt" in merged:
            return "jwt"
        if "idor" in merged or "越权" in merged or "horizontal" in merged or "vertical" in merged:
            return "idor"
        if "ssrf" in merged:
            return "ssrf"
        if "csrf" in merged:
            return "csrf"
        if "xss" in merged:
            return "xss"
        if "sql" in merged and "inject" in merged:
            return "sqli"
        if ("command" in merged or "cmd" in merged or "rce" in merged) and "inject" in merged:
            return "cmdi"
        if "ldap" in merged and "inject" in merged:
            return "ldapi"
        if "xxe" in merged or "xml external" in merged:
            return "xxe"
        if "upload" in merged or "文件上传" in merged:
            return "file_upload"
        if "read" in merged or "download" in merged or "traversal" in merged or "文件读取" in merged:
            return "file_read"
        if "websocket" in merged or "ws://" in merged or "wss://" in merged:
            return "websocket"
        if "swagger" in merged or "openapi" in merged or "postman" in merged:
            return "api_doc"
        if "secret" in merged or "key" in merged or "token" in merged or "credential" in merged:
            return "sensitive_info"
        if "nuclei" in source_text or "afrog" in source_text:
            return "poc_scan"
        return cls._normalize_risk_type(type_text, default_value="unknown")

    def _build_ai_pen_payload_hint(self, risk_type: str, risk_name: str):
        merged = "{} {}".format(str(risk_type or ""), str(risk_name or "")).lower()
        if "xss" in merged:
            return "xss_probe", "<svg/onload=alert(1)>"
        if "sql" in merged:
            return "sqli_probe", "' OR '1'='1"
        if "cmd" in merged or "command" in merged:
            return "cmdi_probe", ";id"
        if "jwt" in merged:
            return "jwt_probe", '{"alg":"none"}'
        if "ssrf" in merged:
            return "ssrf_probe", "http://127.0.0.1/"
        if "idor" in merged or "越权" in merged:
            return "idor_probe", "id=1 -> id=2"
        if "upload" in merged or "文件上传" in merged:
            return "upload_probe", "filename=shell.php"
        return "replay", ""

    def _build_ai_pen_test_candidates(self):
        candidates = []
        seen = set()

        def _append_candidate(item):
            if not isinstance(item, dict):
                return
            source_collection = str(item.get("source_collection", "") or "").strip().lower()
            source_id = self._normalize_object_id(item.get("source_id"))
            if not source_collection or not source_id:
                return
            dedupe_key = "{}:{}".format(source_collection, source_id)
            if dedupe_key in seen:
                return
            seen.add(dedupe_key)
            candidates.append(item)

        # 1) 风险(vuln)结果
        try:
            vuln_cursor = utils.conn_db("vuln").find(
                {"task_id": self.task_id},
                {
                    "_id": 1,
                    "target": 1,
                    "plg_type": 1,
                    "vul_name": 1,
                    "severity": 1,
                    "verify_data": 1,
                    "description": 1,
                    "detail": 1,
                    "app_name": 1,
                },
                max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
            ).limit(self.AI_PEN_TEST_SOURCE_LIMIT)
            for row in vuln_cursor:
                target = str(row.get("target", "") or "").strip()
                vul_name = str(row.get("vul_name", "") or "").strip()
                risk_type = self._classify_ai_pen_risk_type(
                    raw_type=row.get("plg_type"),
                    risk_name=vul_name,
                    source_module=row.get("app_name"),
                )
                evidence_seed = str(
                    row.get("verify_data")
                    or row.get("description")
                    or row.get("detail")
                    or ""
                ).strip()
                _append_candidate(
                    {
                        "source_collection": "vuln",
                        "source_id": row.get("_id"),
                        "source_module": str(row.get("app_name", "") or "").strip().lower(),
                        "target": target,
                        "vuln_url": target if self._is_http_target(target) else "",
                        "risk_type": risk_type,
                        "risk_name": vul_name or "风险验证",
                        "severity": str(row.get("severity", "") or "").strip().lower(),
                        "evidence_seed": evidence_seed,
                    }
                )
        except Exception as e:
            logger.warning("task_id:{} build ai_pen candidates from vuln failed err:{}".format(self.task_id, e))

        # 2) PoC 风险结果(nuclei_result)
        try:
            nuclei_cursor = utils.conn_db("nuclei_result").find(
                {"task_id": self.task_id},
                {
                    "_id": 1,
                    "target": 1,
                    "vuln_url": 1,
                    "scanner_type": 1,
                    "vuln_name": 1,
                    "vuln_severity": 1,
                    "verify_data": 1,
                    "detail": 1,
                },
                max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
            ).limit(self.AI_PEN_TEST_SOURCE_LIMIT)
            for row in nuclei_cursor:
                vuln_url = str(row.get("vuln_url", "") or "").strip()
                target = str(row.get("target", "") or "").strip()
                preferred_url = vuln_url if self._is_http_target(vuln_url) else target
                scanner_type = str(row.get("scanner_type", "") or "").strip().lower()
                risk_type = self._classify_ai_pen_risk_type(
                    raw_type=scanner_type or "poc_scan",
                    risk_name=str(row.get("vuln_name", "") or "").strip(),
                    source_module=scanner_type,
                )
                _append_candidate(
                    {
                        "source_collection": "nuclei_result",
                        "source_id": row.get("_id"),
                        "source_module": scanner_type or "nuclei",
                        "target": target,
                        "vuln_url": preferred_url if self._is_http_target(preferred_url) else "",
                        "risk_type": self._normalize_risk_type(risk_type, default_value="poc_scan"),
                        "risk_name": str(row.get("vuln_name", "") or "").strip() or "PoC风险验证",
                        "severity": str(row.get("vuln_severity", "") or "").strip().lower(),
                        "evidence_seed": str(row.get("verify_data") or row.get("detail") or "").strip(),
                    }
                )
        except Exception as e:
            logger.warning("task_id:{} build ai_pen candidates from nuclei_result failed err:{}".format(self.task_id, e))

        # 3) WIH 信息线索
        try:
            wih_cursor = utils.conn_db("wih").find(
                {"task_id": self.task_id},
                {"_id": 1, "record_type": 1, "content": 1, "source": 1, "site": 1},
                max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
            ).limit(self.AI_PEN_TEST_SOURCE_LIMIT)
            for row in wih_cursor:
                record_type = str(row.get("record_type", "") or "").strip()
                content = str(row.get("content", "") or "").strip()
                if not self._is_sensitive_wih_record(record_type, content):
                    continue

                source_url = str(row.get("source", "") or "").strip()
                site_url = str(row.get("site", "") or "").strip()
                target = source_url if self._is_http_target(source_url) else site_url
                _append_candidate(
                    {
                        "source_collection": "wih",
                        "source_id": row.get("_id"),
                        "source_module": "wih",
                        "target": target or site_url or source_url,
                        "vuln_url": target if self._is_http_target(target) else "",
                        "risk_type": self._classify_ai_pen_risk_type(
                            raw_type=record_type or "sensitive_info",
                            risk_name=content,
                            source_module="wih",
                        ),
                        "risk_name": "WIH-{}".format(record_type or "info"),
                        "severity": "info",
                        "evidence_seed": content,
                    }
                )
        except Exception as e:
            logger.warning("task_id:{} build ai_pen candidates from wih failed err:{}".format(self.task_id, e))

        def _risk_score(item):
            score = 0
            risk_type = str(item.get("risk_type", "") or "").lower()
            severity = str(item.get("severity", "") or "").lower()
            if str(item.get("source_collection", "") or "") == "nuclei_result":
                score += 15
            if self._is_http_target(item.get("vuln_url", "")):
                score += 20
            if str(item.get("evidence_seed", "") or "").strip():
                score += 8
            if severity in ("critical", "high"):
                score += 12
            elif severity == "medium":
                score += 6
            if any(
                keyword in risk_type
                for keyword in ("xss", "sql", "sqli", "command", "cmdi", "jwt", "ssrf", "idor", "upload", "file_read")
            ):
                score += 16
            return score

        candidates.sort(
            key=lambda item: (
                -_risk_score(item),
                str(item.get("source_collection", "")),
                str(item.get("source_id", "")),
            )
        )
        return candidates

    def _verify_ai_pen_candidate(self, candidate: dict, mcp_settings=None):
        settings = mcp_settings if isinstance(mcp_settings, dict) else {}
        mcp_enable = bool(settings.get("mcp_enable", True))
        max_tool_calls = self._safe_int_value(settings.get("max_tool_calls"), self.AI_PEN_TEST_MCP_MAX_TOOL_CALLS)
        timeout_value = settings.get("timeout")
        if (
            isinstance(timeout_value, (list, tuple))
            and len(timeout_value) >= 2
            and timeout_value[0]
            and timeout_value[1]
        ):
            timeout_tuple = (float(timeout_value[0]), float(timeout_value[1]))
        else:
            timeout_tuple = self.AI_PEN_TEST_FETCH_TIMEOUT
        if max_tool_calls < 1:
            max_tool_calls = 1

        target_url = str(candidate.get("vuln_url") or candidate.get("target") or "").strip()
        risk_type = str(candidate.get("risk_type", "") or "").strip()
        risk_name = str(candidate.get("risk_name", "") or "").strip()
        evidence_seed = self._clip_text(candidate.get("evidence_seed", ""), self.AI_PEN_TEST_EVIDENCE_MAX)
        payload_type, payload = self._build_ai_pen_payload_hint(risk_type, risk_name)

        if not self._is_http_target(target_url):
            return {
                "status": "skipped",
                "decision": "needs_manual_review",
                "confidence": 0.35,
                "reason": "缺少可访问的 HTTP 目标，当前阶段仅完成上下文归档",
                "payload_type": payload_type,
                "payload": payload,
                "verification_step": "collect_context_only",
                "evidence_snippet": evidence_seed,
                "http_status": 0,
                "response_hash_diff": "",
                "tool_trace": "collect_context_only",
            }

        tool_trace_parts = []
        try:
            response = utils.http_req(
                target_url,
                "get",
                timeout=timeout_tuple,
                allow_redirects=True,
                waf_guard=self.waf_guard,
                waf_module="ai_pen_test",
            )
            tool_trace_parts.append("http_fetch(get,url={})".format(target_url[:220]))
            tool_calls = 1
            status_code = int(getattr(response, "status_code", 0) or 0)
            header_obj = getattr(response, "headers", {}) or {}
            if str(header_obj.get("X-ARL-WAF-SMART-SKIP", "")).strip() == "1":
                waf_name = str(header_obj.get("X-ARL-WAF-NAME", "") or "").strip()
                waf_reason = str(header_obj.get("X-ARL-WAF-SMART-SKIP-REASON", "") or "").strip()
                reason_parts = ["WAF 智能跳过"]
                if waf_name:
                    reason_parts.append("厂商:{}".format(waf_name))
                if waf_reason:
                    reason_parts.append("原因:{}".format(self._clip_text(waf_reason, 80)))
                return {
                    "status": "skipped",
                    "decision": "needs_manual_review",
                    "confidence": 0.32,
                    "reason": " | ".join(reason_parts),
                    "payload_type": payload_type,
                    "payload": payload,
                    "verification_step": "waf_smart_skip",
                    "evidence_snippet": evidence_seed,
                    "http_status": status_code,
                    "response_hash_diff": "",
                    "tool_trace": "http_fetch(skip_by_waf,url={})".format(target_url[:220]),
                }

            body_text = ""
            try:
                body_text = str(getattr(response, "text", "") or "")
            except Exception:
                body_text = ""

            base_body_excerpt = body_text[: self.AI_PEN_TEST_BODY_MAX]
            base_body_md5 = hashlib.md5(base_body_excerpt.encode("utf-8", "ignore")).hexdigest() if base_body_excerpt else ""
            evidence_hit = self._contains_evidence(evidence_seed, base_body_excerpt)

            probe_status = 0
            probe_body_excerpt = ""
            probe_body_md5 = ""
            payload_reflect_hit = False
            probe_error = ""
            payload_probe_types = {"xss_probe", "sqli_probe", "cmdi_probe", "jwt_probe", "ssrf_probe", "replay"}

            if mcp_enable and tool_calls < max_tool_calls and payload and payload_type in payload_probe_types:
                probe_url = self._build_probe_url_with_payload(target_url, payload)
                if probe_url and probe_url != target_url:
                    try:
                        probe_resp = utils.http_req(
                            probe_url,
                            "get",
                            timeout=timeout_tuple,
                            allow_redirects=True,
                            waf_guard=self.waf_guard,
                            waf_module="ai_pen_test",
                        )
                        tool_calls += 1
                        tool_trace_parts.append("payload_probe(get,url={})".format(probe_url[:220]))
                        probe_status = int(getattr(probe_resp, "status_code", 0) or 0)
                        probe_headers = getattr(probe_resp, "headers", {}) or {}
                        if str(probe_headers.get("X-ARL-WAF-SMART-SKIP", "")).strip() != "1":
                            try:
                                probe_body_text = str(getattr(probe_resp, "text", "") or "")
                            except Exception:
                                probe_body_text = ""
                            probe_body_excerpt = probe_body_text[: self.AI_PEN_TEST_BODY_MAX]
                            probe_body_md5 = (
                                hashlib.md5(probe_body_excerpt.encode("utf-8", "ignore")).hexdigest()
                                if probe_body_excerpt
                                else ""
                            )
                            if self._contains_evidence(evidence_seed, probe_body_excerpt):
                                evidence_hit = True
                            payload_text = str(payload or "").strip().lower()
                            if payload_text and len(payload_text) >= 6 and payload_text in str(probe_body_excerpt or "").lower():
                                payload_reflect_hit = True
                        else:
                            tool_trace_parts.append("payload_probe(skip_by_waf)")
                    except Exception as probe_exc:
                        probe_error = self._clip_text(probe_exc, self.AI_PEN_TEST_ERROR_MAX)
                        tool_trace_parts.append("payload_probe(error)")

            decision = "needs_manual_review"
            confidence = 0.56
            reason = "目标可访问，已完成 HTTP 重放验证"
            if evidence_hit:
                decision = "verified"
                confidence = 0.82
                reason = "响应中命中风险证据片段，验证通过"
            elif payload_reflect_hit:
                decision = "needs_manual_review"
                confidence = 0.74
                reason = "Payload 在响应中回显，疑似存在可利用注入点"
            elif probe_body_md5 and base_body_md5 and probe_body_md5 != base_body_md5:
                decision = "needs_manual_review"
                confidence = 0.66
                reason = "Payload 探针前后响应差异明显，建议人工复核"
            elif status_code >= 500 or status_code == 404:
                decision = "likely_false_positive"
                confidence = 0.66
                reason = "目标返回异常状态码 {}，当前证据不足".format(status_code)
            elif status_code in (401, 403):
                decision = "needs_manual_review"
                confidence = 0.48
                reason = "目标受访问控制保护（{}），建议结合登录态复核".format(status_code)
            if probe_error:
                reason = "{}；探针异常：{}".format(reason, probe_error)

            evidence_snippet = evidence_seed
            if not evidence_snippet:
                evidence_source = probe_body_excerpt or base_body_excerpt
                evidence_snippet = self._clip_text(evidence_source, self.AI_PEN_TEST_EVIDENCE_MAX)

            verification_step = "http_fetch_replay"
            if mcp_enable and max_tool_calls > 1:
                verification_step = "mcp_http_probe"

            response_hash_diff = base_body_md5
            if probe_body_md5:
                response_hash_diff = "base:{} | probe:{}".format(base_body_md5[:16], probe_body_md5[:16])

            return {
                "status": "ok",
                "decision": decision,
                "confidence": confidence,
                "reason": reason,
                "payload_type": payload_type,
                "payload": payload,
                "verification_step": verification_step,
                "evidence_snippet": evidence_snippet,
                "http_status": probe_status or status_code,
                "response_hash_diff": response_hash_diff,
                "tool_trace": " | ".join(tool_trace_parts)[:500],
            }
        except Exception as e:
            return {
                "status": "error",
                "decision": "needs_manual_review",
                "confidence": 0.30,
                "reason": "HTTP 验证失败: {}".format(self._clip_text(e, self.AI_PEN_TEST_ERROR_MAX)),
                "payload_type": payload_type,
                "payload": payload,
                "verification_step": "http_fetch_replay",
                "evidence_snippet": evidence_seed,
                "http_status": 0,
                "response_hash_diff": "",
                "tool_trace": "http_fetch(error,url={})".format(target_url[:220]),
            }

    def run_ai_penetration_test(self):
        """
        AI 渗透测试第一阶段（M1）：
        - 汇聚 vuln / nuclei_result / wih 候选
        - 执行轻量 HTTP 二次验证
        - 产出 ai_pen_test_result，支撑任务详情“AI渗透”页签
        """
        started_at = time.time()
        ai_config = self._load_ai_runtime_config()
        runtime_settings = self._build_ai_pen_runtime_settings(ai_config)
        ai_pen_enable = bool(runtime_settings.get("ai_pen_enable", True))
        mcp_enable = bool(runtime_settings.get("mcp_enable", True))
        mcp_max_tool_calls = self._safe_int_value(
            runtime_settings.get("max_tool_calls"), self.AI_PEN_TEST_MCP_MAX_TOOL_CALLS
        )
        mcp_timeout_sec = self._safe_int_value(
            runtime_settings.get("timeout_sec"), self.AI_PEN_TEST_MCP_TIMEOUT_SEC
        )
        runtime_provider = "local-mcp" if mcp_enable else "local"
        runtime_model = "mcp-rule-lite" if mcp_enable else "rule-lite"
        runtime_profile = "ai-pen-test-mcp" if mcp_enable else "ai-pen-test"

        if not ai_pen_enable:
            summary_text = "ai_pen_enable=false | candidates=0 | selected=0 | saved=0 | verified=0 | likely_fp=0 | error=0"
            logger.info("task_id:{} skip ai_pen_test, runtime disabled".format(self.task_id))
            self._write_ai_pen_test_usage_log(
                scene="ai_pen_test_plan",
                status="skipped",
                provider=runtime_provider,
                model=runtime_model,
                profile=runtime_profile,
                request_text="AI渗透测试计划",
                reply_text=summary_text,
                elapsed_ms=int((time.time() - started_at) * 1000.0),
                meta={
                    "task_id": self.task_id,
                    "ai_pen_enable": ai_pen_enable,
                    "mcp_enable": mcp_enable,
                    "mcp_max_tool_calls": mcp_max_tool_calls,
                    "mcp_timeout_sec": mcp_timeout_sec,
                    "candidate_count": 0,
                },
            )
            return

        self._ensure_ai_pen_test_indexes()
        candidates = self._build_ai_pen_test_candidates()
        if not candidates:
            logger.info("task_id:{} skip ai_pen_test, no candidates".format(self.task_id))
            self._write_ai_pen_test_usage_log(
                scene="ai_pen_test_plan",
                status="skipped",
                provider=runtime_provider,
                model=runtime_model,
                profile=runtime_profile,
                request_text="AI渗透测试计划",
                reply_text="candidates=0 | selected=0 | saved=0 | verified=0 | likely_fp=0 | error=0 | mcp={} | max_tool_calls={} | timeout_sec={}".format(
                    "on" if mcp_enable else "off",
                    mcp_max_tool_calls,
                    mcp_timeout_sec,
                ),
                elapsed_ms=int((time.time() - started_at) * 1000.0),
                meta={
                    "task_id": self.task_id,
                    "candidate_count": 0,
                    "mcp_enable": mcp_enable,
                    "mcp_max_tool_calls": mcp_max_tool_calls,
                    "mcp_timeout_sec": mcp_timeout_sec,
                },
            )
            return

        max_cases = self.AI_PEN_TEST_MAX_CASES
        try:
            configured_max = int(self.options.get("ai_pen_test_max_cases", 0) or 0)
            if configured_max > 0:
                max_cases = min(configured_max, 300)
        except Exception:
            max_cases = self.AI_PEN_TEST_MAX_CASES
        if max_cases < 1:
            max_cases = self.AI_PEN_TEST_MAX_CASES

        selected_candidates = candidates[:max_cases]
        saved_count = 0
        verified_count = 0
        false_positive_count = 0
        error_count = 0

        collection = utils.conn_db("ai_pen_test_result")
        for candidate in selected_candidates:
            verify_result = self._verify_ai_pen_candidate(candidate, mcp_settings=runtime_settings)
            now_text = utils.curr_date()

            status = str(verify_result.get("status", "skipped") or "skipped").strip().lower()
            decision = str(verify_result.get("decision", "needs_manual_review") or "needs_manual_review").strip().lower()
            if decision not in {"verified", "likely_false_positive", "needs_manual_review"}:
                decision = "needs_manual_review"

            if decision == "verified":
                verified_count += 1
            elif decision == "likely_false_positive":
                false_positive_count += 1
            if status == "error":
                error_count += 1

            confidence = verify_result.get("confidence", 0.0)
            try:
                confidence = float(confidence)
            except Exception:
                confidence = 0.0
            confidence = max(0.0, min(1.0, confidence))

            source_collection = str(candidate.get("source_collection", "") or "").strip()
            source_id = self._normalize_object_id(candidate.get("source_id"))
            if not source_collection or not source_id:
                continue

            set_fields = {
                "task_id": self.task_id,
                "source_collection": source_collection,
                "source_id": source_id,
                "source_module": str(candidate.get("source_module", "") or "").strip(),
                "target": str(candidate.get("target", "") or "").strip(),
                "vuln_url": str(candidate.get("vuln_url", "") or "").strip(),
                "risk_type": str(candidate.get("risk_type", "") or "").strip(),
                "risk_name": str(candidate.get("risk_name", "") or "").strip(),
                "severity": str(candidate.get("severity", "") or "").strip(),
                "payload_type": str(verify_result.get("payload_type", "") or "").strip(),
                "payload": str(verify_result.get("payload", "") or "").strip(),
                "verification_step": str(verify_result.get("verification_step", "") or "").strip(),
                "evidence_snippet": str(verify_result.get("evidence_snippet", "") or "").strip(),
                "http_status": int(verify_result.get("http_status", 0) or 0),
                "response_hash_diff": str(verify_result.get("response_hash_diff", "") or "").strip(),
                "decision": decision,
                "confidence": float("{:.4f}".format(confidence)),
                "reason": str(verify_result.get("reason", "") or "").strip(),
                "status": status,
                "model": runtime_model,
                "provider": runtime_provider,
                "tool_trace": str(verify_result.get("tool_trace", "") or "").strip(),
                "update_date": now_text,
            }

            collection.update_one(
                {
                    "task_id": self.task_id,
                    "source_collection": source_collection,
                    "source_id": source_id,
                },
                {
                    "$set": set_fields,
                    "$setOnInsert": {"save_date": now_text},
                },
                upsert=True,
            )
            saved_count += 1

        elapsed_ms = int((time.time() - started_at) * 1000.0)
        summary_text = "candidates={} | selected={} | saved={} | verified={} | likely_fp={} | error={} | mcp={} | max_tool_calls={} | timeout_sec={}".format(
            len(candidates),
            len(selected_candidates),
            saved_count,
            verified_count,
            false_positive_count,
            error_count,
            "on" if mcp_enable else "off",
            mcp_max_tool_calls,
            mcp_timeout_sec,
        )
        logger.info(
            "task_id:{} ai_pen_test done {} elapsed_ms:{}".format(
                self.task_id, summary_text, elapsed_ms
            )
        )
        self._write_ai_pen_test_usage_log(
            scene="ai_pen_test_plan",
            status="ok",
            provider=runtime_provider,
            model=runtime_model,
            profile=runtime_profile,
            request_text="AI渗透测试计划",
            reply_text=summary_text,
            elapsed_ms=elapsed_ms,
            meta={
                "task_id": self.task_id,
                "ai_pen_enable": ai_pen_enable,
                "mcp_enable": mcp_enable,
                "mcp_max_tool_calls": mcp_max_tool_calls,
                "mcp_timeout_sec": mcp_timeout_sec,
                "candidate_count": len(candidates),
                "selected_count": len(selected_candidates),
                "saved_count": saved_count,
                "verified_count": verified_count,
                "likely_false_positive_count": false_positive_count,
                "error_count": error_count,
            },
        )
        exec_status = "error" if (len(selected_candidates) > 0 and error_count >= len(selected_candidates)) else "ok"
        self._write_ai_pen_test_usage_log(
            scene="ai_pen_test_exec",
            status=exec_status,
            provider=runtime_provider,
            model=runtime_model,
            profile=runtime_profile,
            request_text="AI渗透测试执行",
            reply_text=summary_text,
            elapsed_ms=elapsed_ms,
            meta={
                "task_id": self.task_id,
                "ai_pen_enable": ai_pen_enable,
                "mcp_enable": mcp_enable,
                "mcp_max_tool_calls": mcp_max_tool_calls,
                "mcp_timeout_sec": mcp_timeout_sec,
                "candidate_count": len(candidates),
                "selected_count": len(selected_candidates),
                "saved_count": saved_count,
                "verified_count": verified_count,
                "likely_false_positive_count": false_positive_count,
                "error_count": error_count,
            },
        )

    def run_func(self, name: str, func: callable):
        logger.info("start run {}, {}".format(name, self.__str__()))
        self.base_update_task.update_task_field("status", name)
        t1 = time.time()
        func()
        elapse = time.time() - t1
        self.base_update_task.update_services(name, elapse)

        logger.info("end run {} ({:.2f}s), {}".format(name, elapse, self.__str__()))

    def update_page_url_set(self):
        from app.helpers import get_url_by_task_id
        # page_url_set 从数据库读取搜索引擎爬取到的URL
        urls = get_url_by_task_id(self.task_id)
        self.page_url_set |= set(urls)

        for u in self.page_url_set:
            o = urlparse(u)
            ret_url = "{}://{}".format(o.scheme, o.netloc)
            entry_urls = self.search_engines_result.get(ret_url, [])
            entry_urls.append(u)
            self.search_engines_result[ret_url] = entry_urls

    def add_wih_domain_set(self, record):
        if self.scope_domain:
            if record.recordType == "domain":
                # 如果是域名，需要判断是否在域名范围内
                if not domain_in_scope_domain(record.content, self.scope_domain):
                    return

                if utils.check_domain_black(record.content):
                    return

                # 在域名范围内，需要判断是否已经存在
                if record.content in self.wih_domain_set:
                    return

                # 已经保存的域名，不再保存
                if record.content in self.wih_domain_set:
                    return

                self.wih_domain_set.add(record.content)

    @staticmethod
    def _is_http_url(value: str) -> bool:
        """
        判断文本是否是 http/https URL。
        """
        text = str(value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")

    def _should_promote_wih_to_risk(self, record) -> bool:
        """
        判断 WIH 记录是否需要同步到风险(vuln)模块。
        """
        record_type = str(getattr(record, "recordType", "") or "").strip().lower()
        if not record_type:
            return False

        if record_type.startswith("trufflehog_"):
            return True

        sensitive_record_type_set = {
            "app_key",
            "api_key",
            "access_key",
            "secret_key",
            "client_secret",
            "private_key",
            "token",
            "jwt",
            "authorization",
            "password",
            "passwd",
            "credential",
        }
        if record_type in sensitive_record_type_set:
            return True

        if record_type.endswith("_key") or record_type.endswith("_token"):
            return True

        return False

    @staticmethod
    def _infer_wih_risk_severity(record_type: str, content: str) -> str:
        """
        基于记录类型和内容推断风险等级。
        """
        merged = "{} {}".format(str(record_type or "").lower(), str(content or "").lower())
        high_keywords = (
            "private_key",
            "secret_key",
            "client_secret",
            "password",
            "passwd",
            "(verified)",
        )
        medium_keywords = (
            "app_key",
            "api_key",
            "access_key",
            "token",
            "jwt",
            "(unknown)",
            "(unverified)",
        )
        if any(keyword in merged for keyword in high_keywords):
            return "high"
        if any(keyword in merged for keyword in medium_keywords):
            return "medium"
        return "info"

    def _build_wih_vuln_item(self, record):
        """
        将敏感 WIH 记录转换为风险(vuln)记录。
        """
        if not self._should_promote_wih_to_risk(record):
            return None

        record_type = str(getattr(record, "recordType", "") or "").strip()
        content_raw = str(getattr(record, "content", "") or "").strip()
        source = str(getattr(record, "source", "") or "").strip()
        site = str(getattr(record, "site", "") or "").strip()
        fnv_hash = str(getattr(record, "fnv_hash", "") or "").strip()

        # 凭证字段限制长度，避免超长内容影响风险列表与导出体验。
        verify_data = content_raw
        if len(verify_data) > 2048:
            verify_data = "{}...[truncated]".format(verify_data[:2048])

        normalized_type = record_type.lower()
        is_trufflehog = normalized_type.startswith("trufflehog_")
        detector_name = normalized_type.replace("trufflehog_", "", 1) if is_trufflehog else normalized_type
        detector_name = detector_name or "secret"

        if is_trufflehog:
            vul_name = "TruffleHog 检测到敏感信息 ({})".format(detector_name)
            plg_name = "trufflehog"
            app_name = "trufflehog"
        else:
            vul_name = "WIH 检测到敏感信息 ({})".format(detector_name)
            plg_name = "wih"
            app_name = "wih"

        target = source if self._is_http_url(source) else (site or source or "-")
        detail = "record_type={} source={} site={}".format(record_type or "-", source or "-", site or "-")
        severity = self._infer_wih_risk_severity(normalized_type, content_raw)

        return {
            "task_id": self.task_id,
            "plg_name": plg_name,
            "plg_type": "敏感信息泄露",
            "vul_name": vul_name,
            "app_name": app_name,
            "target": target,
            "severity": severity,
            "description": detail,
            "detail": detail,
            "verify_data": verify_data,
            "save_date": utils.curr_date(),
            "wih_fnv_hash": fnv_hash,
            "wih_record_type": record_type,
            "wih_source": source,
        }

    def _save_wih_risk(self, record):
        """
        将敏感 WIH 记录写入风险库，按任务+WIH哈希去重。
        """
        item = self._build_wih_vuln_item(record)
        if not item:
            return

        try:
            utils.conn_db('vuln').update_one(
                {
                    "task_id": self.task_id,
                    "wih_fnv_hash": item["wih_fnv_hash"],
                },
                {"$setOnInsert": item},
                upsert=True,
            )
        except Exception as e:
            logger.warning("save wih risk failed task_id:{} err:{}".format(self.task_id, e))

    def run_web_info_hunter(self):
        wih_targets = self._filter_waf_blocked_targets(self.sites, stage_name="wih")
        scan_sites = list(wih_targets or [])
        records = set(services.run_wih(wih_targets)) if wih_targets else set()

        urlfinder_records = set(
            services.run_urlfinder_extract(scan_sites, list(records), waf_guard=self.waf_guard)
        )
        if urlfinder_records:
            records |= urlfinder_records

        if scan_sites:
            page_intel_records = set(
                services.run_page_intel_scan(scan_sites, list(records), waf_guard=self.waf_guard)
            )
            if page_intel_records:
                records |= page_intel_records

        if scan_sites:
            api_doc_records = set(
                services.run_api_doc_scan(scan_sites, list(records), waf_guard=self.waf_guard)
            )
            if api_doc_records:
                records |= api_doc_records

        if records:
            js_intel_records = set(
                services.run_js_intel_scan(scan_sites, list(records), waf_guard=self.waf_guard)
            )
            if js_intel_records:
                records |= js_intel_records

        if records:
            # 对 URLFinder 提取出的同目标 URL/HTML/JS 做二次敏感信息扫描。
            urlfinder_sensitive_records = set(
                services.run_urlfinder_sensitive_scan(scan_sites, list(records), waf_guard=self.waf_guard)
            )
            if urlfinder_sensitive_records:
                records |= urlfinder_sensitive_records

        if records:
            trufflehog_records = set(services.run_trufflehog_js(scan_sites, list(records), waf_guard=self.waf_guard))
            if trufflehog_records:
                records |= trufflehog_records

        # 将 urlfinder 提取到的 URL 做可达性探测，并同步写入 URL 信息表。
        if records:
            services.run_urlfinder_url_probe(
                task_id=self.task_id,
                sites=scan_sites,
                wih_records=list(records),
                page_url_set=self.page_url_set,
                waf_guard=self.waf_guard,
            )

        for record in records:
            # 先判断记录是否已经存在
            if record.fnv_hash in self.wih_record_set:
                continue

            self.add_wih_domain_set(record)

            item = record.dump_json()
            item["task_id"] = self.task_id
            utils.conn_db('wih').insert_one(item)
            self.wih_record_set.add(record.fnv_hash)
            # WIH 的高价值敏感记录（含 TruffleHog 命中）同步进入风险模块统一处置。
            self._save_wih_risk(record)

    def run(self):
        self._nuclei_deferred_retry_needed = False
        self._nuclei_final_skip = False

        # *** 对站点进行基本信息的获取
        self.run_func(WebSiteFetchStatus.FETCH_SITE, self.fetch_site)

        # 第一阶段：快速发现 URL（无指纹精扫）
        if self.options.get(WebSiteFetchOption.SITE_SPIDER):
            self.update_page_url_set()
            self.run_func(WebSiteFetchStatus.SITE_SPIDER, self.site_spider)

        # 扫描策略默认分两阶段：
        # 1) 全量快扫（资产发现/端口/URL）
        # 2) 系统自动挑选高价值站点做精扫识别（用户无感知）
        self.run_func(WebSiteFetchStatus.SITE_IDENTIFY, self.site_identify)

        """ *** 保存站点信息到数据库 """
        self.save_site_info()

        # 清空，节省内存
        self.site_info_list = []

        """ *** 站点截图 """
        if self.options.get(WebSiteFetchOption.SITE_CAPTURE):
            self.run_func(WebSiteFetchStatus.SITE_CAPTURE, self.site_screenshot)

        """ *** 对站点进行文件目录爆破 """
        if self.options.get(WebSiteFetchOption.FILE_LEAK):
            self.run_func(WebSiteFetchStatus.FILE_LEAK, self.file_leak)

        # AI-POC 决策阶段：汇聚上下文并按开关注入 nuclei/afrog 扫描参数。
        if self.options.get(WebSiteFetchOption.NUCLEI_SCAN) or self.options.get(WebSiteFetchOption.AFROG_SCAN):
            self.run_ai_poc_scan_plan()

        """ *** 对站点运行 nuclei """
        if self.options.get(WebSiteFetchOption.NUCLEI_SCAN):
            self.run_func(WebSiteFetchStatus.NUCLEI_SCAN, self.nuclei_scan)

        """ *** 对站点运行 afrog """
        if self.options.get(WebSiteFetchOption.AFROG_SCAN):
            self.run_func(WebSiteFetchStatus.AFROG_SCAN, self.afrog_scan)

        """ *** 对站点调用 WebInfoHunter """
        if self.options.get(WebSiteFetchOption.Info_Hunter):
            self.run_func(WebSiteFetchStatus.Info_Hunter, self.run_web_info_hunter)
        else:
            logger.info("task_id:{} skip web_info_hunter because option disabled".format(self.task_id))

        """ *** 对站点运行专项渗透测试 """
        if self.options.get(WebSiteFetchOption.PENETRATION_TEST):
            self.run_func(WebSiteFetchStatus.PENETRATION_TEST, self.run_penetration_test)

        # nuclei 首次因 Mongo 超时延后时，在本任务末尾补跑一次。
        if self._nuclei_deferred_retry_needed:
            self.run_deferred_nuclei_scan()

        """ *** AI 渗透测试（后验证阶段） """
        if self.options.get(WebSiteFetchOption.AI_PENETRATION_TEST):
            self.run_func(WebSiteFetchStatus.AI_PEN_TEST, self.run_ai_penetration_test)

        self._save_waf_skip_summary()


def domain_in_scope_domain(domain: str, scope_domain: list):
    for scope in scope_domain:
        if domain.endswith("." + scope):
            return True
    return False


def build_url_item(site, task_id, source):
    item = {
        "site": site,
        "task_id": task_id,
        "source": source
    }
    domain_parsed = utils.domain_parsed(site)
    if domain_parsed:
        item["fld"] = domain_parsed["fld"]

    return item
