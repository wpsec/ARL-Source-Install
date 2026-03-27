"""
通用任务执行框架
"""
import time
import re
import os
import json
import subprocess
import base64
import hashlib
import hmac
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
    AI_PEN_TEST_AI_PLAN_MAX_CASES = 24
    AI_PEN_TEST_BODY_MAX = 8192
    AI_PEN_TEST_EVIDENCE_MAX = 280
    AI_PEN_TEST_ERROR_MAX = 180
    AI_PEN_TEST_REASON_MAX = 420
    AI_PEN_TEST_PAYLOAD_MAX = 220
    AI_PEN_TEST_SUPPORTED_PAYLOAD_TYPES = (
        "xss_probe",
        "sqli_probe",
        "cmdi_probe",
        "ssrf_probe",
        "idor_probe",
        "api_doc_probe",
        "jwt_probe",
        "websocket_probe",
        "upload_probe",
        "replay",
    )
    AI_PEN_EXTERNAL_TOOL_REGISTRY = (
        "sqlmap",
        "httpx",
    )
    AI_PEN_EXTERNAL_RESULT_MAX = 3
    AI_PEN_JWT_WEAK_SECRET_CANDIDATES = (
        "secret",
        "jwt",
        "token",
        "changeme",
        "password",
        "admin",
        "admin123",
        "123456",
        "12345678",
        "qwerty",
        "test",
        "default",
        "public",
        "private",
        "access_token",
        "jwt_secret",
        "jwtsecret",
        "api_secret",
    )
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
    AI_PEN_KNOWLEDGE_INDEX_ENV_KEY = "ARL_AI_PEN_KNOWLEDGE_INDEX_FILE"
    AI_PEN_KNOWLEDGE_INDEX_REL_PATH = os.path.join("docker", "ai", "sop", "ai_pen_knowledge_index.json")
    _AI_POC_INDEX_CACHE = {
        "path": "",
        "mtime": 0.0,
        "data": {},
    }
    _AI_PEN_KNOWLEDGE_INDEX_CACHE = {
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

    @classmethod
    def _resolve_ai_pen_knowledge_index_path(cls) -> str:
        env_path = str(os.environ.get(cls.AI_PEN_KNOWLEDGE_INDEX_ENV_KEY, "") or "").strip()
        if env_path:
            return os.path.abspath(env_path)

        current_dir = os.path.abspath(os.path.dirname(__file__))
        primary_path = os.path.abspath(
            os.path.join(current_dir, os.pardir, os.pardir, cls.AI_PEN_KNOWLEDGE_INDEX_REL_PATH)
        )
        return primary_path

    @classmethod
    def _load_ai_pen_knowledge_index_data(cls):
        index_path = cls._resolve_ai_pen_knowledge_index_path()
        if not index_path or not os.path.isfile(index_path):
            return {}, ""

        try:
            mtime = float(os.path.getmtime(index_path))
        except Exception:
            mtime = 0.0

        cache = cls._AI_PEN_KNOWLEDGE_INDEX_CACHE if isinstance(cls._AI_PEN_KNOWLEDGE_INDEX_CACHE, dict) else {}
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
            logger.warning("load ai pen knowledge index failed path:{} err:{}".format(index_path, e))
            return {}, index_path

        if not isinstance(raw_data, dict):
            return {}, index_path

        token_index = raw_data.get("token_index") if isinstance(raw_data.get("token_index"), dict) else {}
        normalized_token_index = {}
        for key, value in token_index.items():
            token = cls._normalize_ai_poc_index_token(key)
            if not token:
                continue
            item = value if isinstance(value, dict) else {}
            count = cls._safe_int_value(item.get("count"), 0)
            sources = item.get("sources") if isinstance(item.get("sources"), dict) else {}
            normalized_sources = {}
            for source_key, source_count in sources.items():
                source_text = str(source_key or "").strip()
                if not source_text:
                    continue
                source_num = cls._safe_int_value(source_count, 0)
                if source_num > 0:
                    normalized_sources[source_text] = source_num
            samples = []
            for sample in item.get("samples", []) if isinstance(item.get("samples"), list) else []:
                sample_text = str(sample or "").strip()
                if sample_text:
                    samples.append(sample_text[:200])
                if len(samples) >= 8:
                    break
            normalized_token_index[token] = {
                "count": max(0, count),
                "sources": normalized_sources,
                "samples": samples,
            }

        normalized_data = {
            "version": str(raw_data.get("version", "") or "").strip(),
            "generated_at": str(raw_data.get("generated_at", "") or "").strip(),
            "summary": raw_data.get("summary") if isinstance(raw_data.get("summary"), dict) else {},
            "token_index": normalized_token_index,
        }
        cls._AI_PEN_KNOWLEDGE_INDEX_CACHE = {"path": index_path, "mtime": mtime, "data": normalized_data}
        return normalized_data, index_path

    def _collect_ai_pen_knowledge_hits(self, candidate: dict):
        index_data, index_path = self._load_ai_pen_knowledge_index_data()
        result = {
            "loaded": bool(index_data),
            "path": index_path,
            "hit_tokens": [],
            "hit_samples": [],
            "score": 0,
            "index_token_count": 0,
        }
        token_index = index_data.get("token_index") if isinstance(index_data, dict) else {}
        if not isinstance(token_index, dict) or not token_index:
            return result

        result["index_token_count"] = len(token_index)
        token_source = []
        token_source.extend(
            self._extract_ascii_tokens(
                " ".join(
                    [
                        str(candidate.get("risk_type", "") or ""),
                        str(candidate.get("risk_name", "") or ""),
                        str(candidate.get("source_module", "") or ""),
                        str(candidate.get("target", "") or ""),
                        str(candidate.get("vuln_url", "") or ""),
                        str(candidate.get("evidence_seed", "") or ""),
                    ]
                ),
                max_tokens=120,
            )
        )

        normalized_tokens = []
        seen_tokens = set()
        for token in token_source:
            normalized = self._normalize_ai_poc_index_token(token)
            if not normalized or normalized in seen_tokens:
                continue
            seen_tokens.add(normalized)
            normalized_tokens.append(normalized)
            if len(normalized_tokens) >= 80:
                break

        matched_tokens = []
        sample_hits = []
        for token in normalized_tokens:
            lookup_tokens = [token]
            compact = self._normalize_ai_poc_index_token(token.replace("-", "").replace("_", "").replace(".", ""))
            if compact and compact not in lookup_tokens:
                lookup_tokens.append(compact)

            item = None
            for lookup in lookup_tokens:
                if lookup in token_index:
                    item = token_index.get(lookup)
                    break
            if not isinstance(item, dict):
                continue

            matched_tokens.append(token)
            for sample in item.get("samples", []) if isinstance(item.get("samples"), list) else []:
                sample_text = str(sample or "").strip()
                if sample_text and sample_text not in sample_hits:
                    sample_hits.append(sample_text[:200])
                if len(sample_hits) >= 6:
                    break
            if len(matched_tokens) >= 12:
                break

        score = min(12, len(matched_tokens) * 2)
        result["hit_tokens"] = matched_tokens
        result["hit_samples"] = sample_hits
        result["score"] = score
        return result

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
        usage=None,
        meta=None,
    ):
        """
        写入 AI 管理中的 AI 渗透测试日志（支持真实 AI token 统计）。
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
                    usage=usage if isinstance(usage, dict) else {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
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
    def _build_source_id_filter(source_id: str):
        source_text = str(source_id or "").strip()
        if not source_text:
            return {}
        try:
            return {"_id": ObjectId(source_text)}
        except Exception:
            return {"_id": source_text}

    def _sync_ai_pen_result_to_source(
            self,
            source_collection: str,
            source_id: str,
            decision: str,
            confidence: float,
            status: str,
            reason: str,
            verification_step: str,
            payload_type: str,
            update_date: str,
    ):
        source_name = str(source_collection or "").strip().lower()
        if source_name not in {"vuln", "nuclei_result", "wih", "site", "url"}:
            return

        source_filter = self._build_source_id_filter(source_id)
        if not source_filter:
            return

        source_filter["task_id"] = self.task_id
        update_fields = {
            "ai_pen_status": str(status or "").strip(),
            "ai_pen_decision": str(decision or "").strip(),
            "ai_pen_confidence": float("{:.4f}".format(float(confidence or 0.0))),
            "ai_pen_reason": self._clip_text(reason, 500),
            "ai_pen_verification_step": str(verification_step or "").strip(),
            "ai_pen_payload_type": str(payload_type or "").strip(),
            "ai_pen_update_date": str(update_date or "").strip(),
        }
        try:
            utils.conn_db(source_name).update_one(source_filter, {"$set": update_fields}, upsert=False)
        except Exception as e:
            logger.warning(
                "task_id:{} sync ai_pen result to source failed collection:{} source_id:{} err:{}".format(
                    self.task_id, source_name, source_id, e
                )
            )

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
        ai_planner_enable = bool(config_obj.get("ai_pen_ai_planner_enable", True))
        max_tool_calls = cls._safe_int_value(config_obj.get("ai_pen_mcp_max_tool_calls"), cls.AI_PEN_TEST_MCP_MAX_TOOL_CALLS)
        timeout_sec = cls._safe_int_value(config_obj.get("ai_pen_mcp_timeout_sec"), cls.AI_PEN_TEST_MCP_TIMEOUT_SEC)
        ai_plan_max_cases = cls._safe_int_value(
            config_obj.get("ai_pen_ai_plan_max_cases"), cls.AI_PEN_TEST_AI_PLAN_MAX_CASES
        )
        external_enable = bool(
            config_obj.get("ai_pen_external_enable", getattr(Config, "AI_PEN_MCP_EXTERNAL_ENABLE", False))
        )
        external_tools = cls._normalize_ai_pen_external_tools(
            config_obj.get("ai_pen_external_tools", getattr(Config, "AI_PEN_MCP_EXTERNAL_ALLOWED_TOOLS", "sqlmap,httpx"))
        )
        external_timeout_sec = cls._safe_int_value(
            config_obj.get("ai_pen_external_timeout_sec", getattr(Config, "AI_PEN_MCP_EXTERNAL_TIMEOUT_SEC", 45)),
            getattr(Config, "AI_PEN_MCP_EXTERNAL_TIMEOUT_SEC", 45),
        )
        external_max_runs = cls._safe_int_value(
            config_obj.get("ai_pen_external_max_runs", getattr(Config, "AI_PEN_MCP_EXTERNAL_MAX_RUNS", 1)),
            getattr(Config, "AI_PEN_MCP_EXTERNAL_MAX_RUNS", 1),
        )
        if max_tool_calls < 1:
            max_tool_calls = 1
        if max_tool_calls > 8:
            max_tool_calls = 8
        if timeout_sec < 1:
            timeout_sec = 1
        if timeout_sec > 60:
            timeout_sec = 60
        if ai_plan_max_cases < 1:
            ai_plan_max_cases = cls.AI_PEN_TEST_AI_PLAN_MAX_CASES
        if ai_plan_max_cases > 120:
            ai_plan_max_cases = 120
        if external_timeout_sec < 5:
            external_timeout_sec = 5
        if external_timeout_sec > 300:
            external_timeout_sec = 300
        if external_max_runs < 1:
            external_max_runs = 1
        if external_max_runs > 8:
            external_max_runs = 8

        connect_timeout = float(cls.AI_PEN_TEST_FETCH_TIMEOUT[0] if isinstance(cls.AI_PEN_TEST_FETCH_TIMEOUT, tuple) else 5.1)
        read_timeout = float(timeout_sec) + 0.1
        if read_timeout < connect_timeout:
            read_timeout = connect_timeout

        return {
            "ai_pen_enable": ai_pen_enable,
            "mcp_enable": mcp_enable,
            "ai_planner_enable": ai_planner_enable,
            "max_tool_calls": max_tool_calls,
            "timeout_sec": timeout_sec,
            "ai_plan_max_cases": ai_plan_max_cases,
            "external_enable": external_enable,
            "external_tools": external_tools,
            "external_timeout_sec": external_timeout_sec,
            "external_max_runs": external_max_runs,
            "timeout": (connect_timeout, read_timeout),
        }

    @staticmethod
    def _normalize_ai_pen_decision(value: str, default_value="needs_manual_review"):
        decision = str(value or "").strip().lower()
        if decision in {"verified", "likely_false_positive", "needs_manual_review"}:
            return decision
        return default_value

    @classmethod
    def _normalize_ai_pen_payload_type(cls, value: str, fallback_type="replay"):
        payload_type = str(value or "").strip().lower()
        if payload_type in cls.AI_PEN_TEST_SUPPORTED_PAYLOAD_TYPES:
            return payload_type
        fallback_text = str(fallback_type or "").strip().lower()
        if fallback_text in cls.AI_PEN_TEST_SUPPORTED_PAYLOAD_TYPES:
            return fallback_text
        if fallback_text:
            return fallback_text
        return ""

    @classmethod
    def _infer_ai_pen_payload_type_from_actions(cls, actions, fallback_type="replay"):
        action_texts = []
        if isinstance(actions, str):
            action_texts = [actions]
        elif isinstance(actions, (list, tuple, set)):
            action_texts = [str(item or "") for item in actions]
        merged = " ".join([str(item or "").lower() for item in action_texts])
        if not merged:
            return cls._normalize_ai_pen_payload_type("", fallback_type=fallback_type)
        if any(token in merged for token in ("xss", "dom", "script")):
            return "xss_probe"
        if any(token in merged for token in ("sql", "sqli", "union", "or 1=1")):
            return "sqli_probe"
        if any(token in merged for token in ("cmd", "command", "rce", "shell")):
            return "cmdi_probe"
        if any(token in merged for token in ("ssrf", "127.0.0.1", "metadata")):
            return "ssrf_probe"
        if any(token in merged for token in ("idor", "越权", "user_id", "account_id", "id=")):
            return "idor_probe"
        if any(token in merged for token in ("swagger", "openapi", "api-docs", "postman")):
            return "api_doc_probe"
        if any(token in merged for token in ("jwt", "alg=none", "authorization", "bearer")):
            return "jwt_probe"
        if any(token in merged for token in ("websocket", "ws://", "wss://", "socket.io", "handshake")):
            return "websocket_probe"
        if any(token in merged for token in ("upload", "multipart", "filename")):
            return "upload_probe"
        return cls._normalize_ai_pen_payload_type("", fallback_type=fallback_type)

    @classmethod
    def _normalize_ai_pen_external_tools(cls, value, max_count=4):
        allow_set = set([str(item).strip().lower() for item in cls.AI_PEN_EXTERNAL_TOOL_REGISTRY])
        items = []
        if isinstance(value, str):
            items = re.split(r"[,\s]+", value)
        elif isinstance(value, (list, tuple, set)):
            items = [str(item or "") for item in value]

        result = []
        seen = set()
        for item in items:
            tool = str(item or "").strip().lower()
            if not tool or tool in seen:
                continue
            if tool not in allow_set:
                continue
            seen.add(tool)
            result.append(tool)
            if len(result) >= max_count:
                break
        return result

    @staticmethod
    def _resolve_executable_path(preferred_path: str, fallback_name: str):
        for candidate in [preferred_path, fallback_name]:
            text = str(candidate or "").strip()
            if not text:
                continue
            resolved = utils.resolve_executable(text)
            if resolved:
                return resolved
        return ""

    @staticmethod
    def _contains_sqlmap_positive_evidence(output_text: str) -> bool:
        output = str(output_text or "").lower()
        positive_hints = (
            "is vulnerable",
            "identified the following injection point",
            "sql injection vulnerability",
            "parameter '",
            "injectable",
        )
        return any(hint in output for hint in positive_hints)

    @staticmethod
    def _contains_sqlmap_negative_evidence(output_text: str) -> bool:
        output = str(output_text or "").lower()
        negative_hints = (
            "all tested parameters do not appear to be injectable",
            "does not seem to be injectable",
            "not injectable",
            "no parameter(s) found for testing",
        )
        return any(hint in output for hint in negative_hints)

    def _run_external_command(self, command, timeout_sec=60):
        command_list = command if isinstance(command, list) else []
        if not command_list:
            return {
                "ok": False,
                "return_code": -1,
                "stdout": "",
                "stderr": "empty command",
                "elapsed_ms": 0,
            }

        timeout_value = max(5, min(300, self._safe_int_value(timeout_sec, 60)))
        started_at = time.perf_counter()
        try:
            process = subprocess.run(
                command_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_value,
            )
            elapsed_ms = int((time.perf_counter() - started_at) * 1000.0)
            return {
                "ok": True,
                "return_code": int(process.returncode),
                "stdout": str(process.stdout or ""),
                "stderr": str(process.stderr or ""),
                "elapsed_ms": elapsed_ms,
            }
        except subprocess.TimeoutExpired as e:
            elapsed_ms = int((time.perf_counter() - started_at) * 1000.0)
            return {
                "ok": False,
                "return_code": -2,
                "stdout": str(getattr(e, "stdout", "") or ""),
                "stderr": "timeout",
                "elapsed_ms": elapsed_ms,
            }
        except Exception as e:
            elapsed_ms = int((time.perf_counter() - started_at) * 1000.0)
            return {
                "ok": False,
                "return_code": -3,
                "stdout": "",
                "stderr": self._clip_text(e, self.AI_PEN_TEST_ERROR_MAX),
                "elapsed_ms": elapsed_ms,
            }

    def _run_ai_pen_external_tools(
            self,
            *,
            target_url: str,
            risk_type: str,
            payload_type: str,
            base_decision: str,
            base_confidence: float,
            settings: dict,
    ):
        runtime_settings = settings if isinstance(settings, dict) else {}
        if not bool(runtime_settings.get("external_enable", False)):
            return {
                "decision": base_decision,
                "confidence": base_confidence,
                "reason": "",
                "verification_step": "",
                "tool_trace": "",
                "tool_runs": [],
                "tool_hit": False,
            }

        allow_tools = self._normalize_ai_pen_external_tools(runtime_settings.get("external_tools", []))
        if not allow_tools:
            return {
                "decision": base_decision,
                "confidence": base_confidence,
                "reason": "外部工具白名单为空，已跳过",
                "verification_step": "",
                "tool_trace": "external(skip_no_allowlist)",
                "tool_runs": [],
                "tool_hit": False,
            }

        timeout_sec = self._safe_int_value(runtime_settings.get("external_timeout_sec"), 45)
        max_runs = self._safe_int_value(runtime_settings.get("external_max_runs"), 1)
        if max_runs < 1:
            max_runs = 1
        if max_runs > 8:
            max_runs = 8

        risk_text = str(risk_type or "").strip().lower()
        payload_text = str(payload_type or "").strip().lower()
        candidate_tools = []
        if payload_text == "sqli_probe" or "sqli" in risk_text or "sql" in risk_text:
            candidate_tools.append("sqlmap")
        if payload_text in {"websocket_probe", "api_doc_probe"} or risk_text in {"websocket", "api_doc"}:
            candidate_tools.append("httpx")

        if not candidate_tools:
            return {
                "decision": base_decision,
                "confidence": base_confidence,
                "reason": "",
                "verification_step": "",
                "tool_trace": "",
                "tool_runs": [],
                "tool_hit": False,
            }

        run_tools = []
        for tool_name in candidate_tools:
            if tool_name not in allow_tools:
                continue
            run_tools.append(tool_name)
            if len(run_tools) >= max_runs:
                break

        if not run_tools:
            return {
                "decision": base_decision,
                "confidence": base_confidence,
                "reason": "候选外部工具不在白名单内",
                "verification_step": "",
                "tool_trace": "external(skip_not_allowlisted)",
                "tool_runs": [],
                "tool_hit": False,
            }

        decision = self._normalize_ai_pen_decision(base_decision, default_value="needs_manual_review")
        confidence = self._clamp_ai_pen_confidence(base_confidence, 0.5)
        reason_parts = []
        tool_runs = []
        tool_trace_parts = []
        hit = False
        verification_step = ""

        for tool_name in run_tools:
            if tool_name == "sqlmap":
                parsed = urlsplit(target_url)
                if not str(parsed.query or "").strip():
                    tool_trace_parts.append("sqlmap(skip_no_query)")
                    continue

                sqlmap_bin = self._resolve_executable_path(
                    getattr(Config, "SQLMAP_BIN", "sqlmap"),
                    "sqlmap",
                )
                if not sqlmap_bin:
                    tool_trace_parts.append("sqlmap(skip_not_found)")
                    tool_runs.append({
                        "tool": "sqlmap",
                        "status": "skipped",
                        "message": "binary_not_found",
                        "elapsed_ms": 0,
                    })
                    continue

                sqlmap_cmd = [
                    sqlmap_bin,
                    "-u", target_url,
                    "--batch",
                    "--smart",
                    "--random-agent",
                    "--level", "1",
                    "--risk", "1",
                    "--threads", "1",
                    "--timeout", "10",
                    "--retries", "0",
                    "--disable-coloring",
                ]
                run_ret = self._run_external_command(sqlmap_cmd, timeout_sec=timeout_sec)
                output_text = "{}\n{}".format(run_ret.get("stdout", ""), run_ret.get("stderr", ""))
                return_code = int(run_ret.get("return_code", -1) or -1)
                elapsed_ms = int(run_ret.get("elapsed_ms", 0) or 0)

                run_status = "ok" if bool(run_ret.get("ok")) else "error"
                run_message = "exit={}".format(return_code)
                if run_status == "ok":
                    if self._contains_sqlmap_positive_evidence(output_text):
                        decision = "verified"
                        confidence = max(confidence, 0.94)
                        hit = True
                        verification_step = "mcp_external_sqlmap"
                        reason_parts.append("sqlmap 命中注入特征")
                        run_message = "positive"
                    elif self._contains_sqlmap_negative_evidence(output_text):
                        if decision != "verified":
                            decision = "likely_false_positive"
                            confidence = max(confidence, 0.68)
                        reason_parts.append("sqlmap 未发现可注入参数")
                        run_message = "negative"
                    else:
                        run_message = "inconclusive"
                else:
                    run_message = self._clip_text(run_ret.get("stderr", ""), 100) or "error"

                tool_runs.append({
                    "tool": "sqlmap",
                    "status": run_status,
                    "message": run_message,
                    "elapsed_ms": elapsed_ms,
                })
                tool_trace_parts.append("sqlmap({})".format(run_message))
            elif tool_name == "httpx":
                httpx_bin = self._resolve_executable_path(
                    getattr(Config, "HTTPX_BIN", "httpx"),
                    "httpx",
                )
                if not httpx_bin:
                    tool_trace_parts.append("httpx(skip_not_found)")
                    tool_runs.append({
                        "tool": "httpx",
                        "status": "skipped",
                        "message": "binary_not_found",
                        "elapsed_ms": 0,
                    })
                    continue
                httpx_cmd = [
                    httpx_bin,
                    "-u", target_url,
                    "-silent",
                    "-status-code",
                    "-title",
                ]
                run_ret = self._run_external_command(httpx_cmd, timeout_sec=timeout_sec)
                output_text = "{}\n{}".format(run_ret.get("stdout", ""), run_ret.get("stderr", ""))
                output_lower = output_text.lower()
                return_code = int(run_ret.get("return_code", -1) or -1)
                elapsed_ms = int(run_ret.get("elapsed_ms", 0) or 0)
                run_status = "ok" if bool(run_ret.get("ok")) else "error"
                run_message = "exit={}".format(return_code)
                if run_status == "ok":
                    if (" 101 " in output_lower or "websocket" in output_lower) and payload_text == "websocket_probe":
                        if decision != "verified":
                            decision = "needs_manual_review"
                        confidence = max(confidence, 0.72)
                        verification_step = verification_step or "mcp_external_httpx"
                        reason_parts.append("httpx 返回 WebSocket 相关特征")
                        run_message = "websocket_hint"
                    elif payload_text == "api_doc_probe" and any(token in output_lower for token in ("swagger", "openapi", "api-docs")):
                        if decision != "verified":
                            decision = "needs_manual_review"
                        confidence = max(confidence, 0.70)
                        verification_step = verification_step or "mcp_external_httpx"
                        reason_parts.append("httpx 返回 API 文档相关特征")
                        run_message = "api_doc_hint"
                    else:
                        run_message = "ok"
                else:
                    run_message = self._clip_text(run_ret.get("stderr", ""), 100) or "error"
                tool_runs.append({
                    "tool": "httpx",
                    "status": run_status,
                    "message": run_message,
                    "elapsed_ms": elapsed_ms,
                })
                tool_trace_parts.append("httpx({})".format(run_message))

        if len(tool_runs) > self.AI_PEN_EXTERNAL_RESULT_MAX:
            tool_runs = tool_runs[: self.AI_PEN_EXTERNAL_RESULT_MAX]

        return {
            "decision": decision,
            "confidence": confidence,
            "reason": "；".join([item for item in reason_parts if item])[:220],
            "verification_step": verification_step,
            "tool_trace": " | ".join(tool_trace_parts)[:260],
            "tool_runs": tool_runs,
            "tool_hit": hit,
        }

    @staticmethod
    def _clamp_ai_pen_confidence(value, default_value=0.5):
        try:
            confidence = float(value)
        except Exception:
            confidence = float(default_value)
        if confidence < 0.0:
            return 0.0
        if confidence > 1.0:
            return 1.0
        return confidence

    def _resolve_ai_pen_prompt_content(self, ai_config: dict):
        fallback_prompt = (
            "你是AI渗透测试助手。请结合风险类型、URL、参数、响应特征与知识命中，"
            "评估该结果可信度并给出下一步验证建议。输出JSON对象，字段包含："
            "decision/confidence/reason/payload_type/payload/evidence/next_actions。"
            "decision 仅允许 verified、likely_false_positive、needs_manual_review。"
        )
        config_obj = ai_config if isinstance(ai_config, dict) else {}
        prompt_templates = config_obj.get("prompt_templates")
        if not isinstance(prompt_templates, list):
            return fallback_prompt

        for item in prompt_templates:
            if not isinstance(item, dict):
                continue
            if str(item.get("id") or "").strip() == "default_ai_pen_test":
                content = str(item.get("content") or "").strip()
                if content:
                    return content

        for item in prompt_templates:
            if not isinstance(item, dict):
                continue
            if str(item.get("scene") or "").strip() == "ai_pen_test_plan":
                content = str(item.get("content") or "").strip()
                if content:
                    return content
        return fallback_prompt

    def _call_ai_pen_planner(self, ai_config: dict, candidate: dict, runtime_settings: dict, prompt_content: str):
        """
        调用 AI 规划当前候选项的验证动作（真实 AI，不阻断主流程）。
        """
        result = {
            "ok": False,
            "status": "skipped",
            "message": "ai_pen planner disabled",
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

            risk_type = str(candidate.get("risk_type", "") or "").strip()
            risk_name = str(candidate.get("risk_name", "") or "").strip()
            default_payload_type, default_payload = self._build_ai_pen_payload_hint(risk_type, risk_name)
            request_obj = {
                "task_id": str(self.task_id),
                "target": str(candidate.get("target", "") or "").strip(),
                "vuln_url": str(candidate.get("vuln_url", "") or "").strip(),
                "source_collection": str(candidate.get("source_collection", "") or "").strip(),
                "source_module": str(candidate.get("source_module", "") or "").strip(),
                "risk_type": risk_type,
                "risk_name": risk_name,
                "severity": str(candidate.get("severity", "") or "").strip(),
                "evidence_seed": self._clip_text(candidate.get("evidence_seed", ""), self.AI_PEN_TEST_EVIDENCE_MAX),
                "knowledge_hit_tokens": list(candidate.get("knowledge_hit_tokens", []) or [])[:20],
                "knowledge_hit_samples": list(candidate.get("knowledge_hit_samples", []) or [])[:6],
                "default_payload_type": default_payload_type,
                "default_payload": default_payload,
                "mcp_enable": bool(runtime_settings.get("mcp_enable", True)),
                "mcp_max_tool_calls": self._safe_int_value(
                    runtime_settings.get("max_tool_calls"), self.AI_PEN_TEST_MCP_MAX_TOOL_CALLS
                ),
                "supported_payload_types": list(self.AI_PEN_TEST_SUPPORTED_PAYLOAD_TYPES),
                "output_schema": {
                    "decision": "verified|likely_false_positive|needs_manual_review",
                    "confidence": "0~1 float",
                    "reason": "string",
                    "payload_type": "xss_probe|sqli_probe|cmdi_probe|ssrf_probe|idor_probe|api_doc_probe|jwt_probe|websocket_probe|upload_probe|replay",
                    "payload": "string",
                    "evidence": ["string"],
                    "next_actions": ["string"],
                },
            }
            request_text = json.dumps(request_obj, ensure_ascii=False)
            result["request_text"] = request_text

            system_prompt = str(prompt_content or "").strip()
            if not system_prompt:
                system_prompt = self._resolve_ai_pen_prompt_content(ai_config)
            system_prompt = (
                "{}\n\n输出要求：仅返回 JSON 对象，不要 Markdown；"
                "decision 只能是 verified/likely_false_positive/needs_manual_review。"
            ).format(system_prompt)

            request_url = "{}/chat/completions".format(base_url.rstrip("/"))
            headers = {
                "Authorization": "Bearer {}".format(api_key),
                "Content-Type": "application/json",
            }
            request_body = {
                "model": model_name,
                "temperature": min(max(safe_float(active_profile.get("temperature"), 0.15, min_value=0.0), 0.0), 1.0),
                "max_tokens": max(500, min(safe_int(active_profile.get("max_tokens"), 1200, min_value=256), 2400)),
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

            ai_decision = self._normalize_ai_pen_decision(parsed.get("decision"), default_value="")
            ai_confidence = self._clamp_ai_pen_confidence(parsed.get("confidence"), 0.55)
            ai_actions = self._normalize_ai_poc_keywords(parsed.get("next_actions"), max_count=4)
            ai_payload_type = self._normalize_ai_pen_payload_type(
                parsed.get("payload_type"),
                fallback_type="",
            )
            if not ai_payload_type:
                ai_payload_type = self._infer_ai_pen_payload_type_from_actions(
                    ai_actions,
                    fallback_type=default_payload_type,
                )
            if not ai_payload_type:
                ai_payload_type = default_payload_type
            ai_payload = str(parsed.get("payload") or "").strip()[: self.AI_PEN_TEST_PAYLOAD_MAX]
            if not ai_payload and ai_payload_type and ai_payload_type != "replay":
                inferred_payload_type, inferred_payload = self._build_ai_pen_payload_hint(ai_payload_type, risk_name)
                if inferred_payload_type == ai_payload_type and inferred_payload:
                    ai_payload = str(inferred_payload)[: self.AI_PEN_TEST_PAYLOAD_MAX]
            ai_reason = self._clip_text(parsed.get("reason", ""), self.AI_PEN_TEST_REASON_MAX)
            ai_evidence = self._normalize_ai_poc_keywords(parsed.get("evidence"), max_count=8)

            result["ok"] = True
            result["status"] = "ok"
            result["message"] = ""
            result["output"] = {
                "decision": ai_decision or "needs_manual_review",
                "confidence": ai_confidence,
                "reason": ai_reason,
                "payload_type": ai_payload_type,
                "payload": ai_payload,
                "evidence": ai_evidence,
                "next_actions": ai_actions,
            }
            return result
        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)
            return result

    def _merge_ai_pen_result_with_ai_plan(self, verify_result: dict, ai_plan_result: dict):
        merged = dict(verify_result or {})
        plan_ret = ai_plan_result if isinstance(ai_plan_result, dict) else {}
        plan_status = str(plan_ret.get("status", "skipped") or "skipped").strip().lower()
        plan_ok = bool(plan_ret.get("ok")) and plan_status == "ok"
        plan_output = plan_ret.get("output") if isinstance(plan_ret.get("output"), dict) else {}

        merged["ai_status"] = plan_status
        merged["ai_plan_reason"] = ""
        merged["ai_plan_decision"] = ""
        merged["ai_plan_confidence"] = 0.0
        merged["ai_plan_actions"] = []
        if not plan_ok:
            return merged

        ai_decision = self._normalize_ai_pen_decision(plan_output.get("decision"), default_value="")
        ai_confidence = self._clamp_ai_pen_confidence(plan_output.get("confidence"), 0.55)
        ai_reason = self._clip_text(plan_output.get("reason", ""), self.AI_PEN_TEST_REASON_MAX)
        ai_actions = self._normalize_ai_poc_keywords(plan_output.get("next_actions"), max_count=4)

        merged["ai_plan_reason"] = ai_reason
        merged["ai_plan_decision"] = ai_decision
        merged["ai_plan_confidence"] = ai_confidence
        merged["ai_plan_actions"] = ai_actions

        base_decision = self._normalize_ai_pen_decision(merged.get("decision"), default_value="needs_manual_review")
        base_confidence = self._clamp_ai_pen_confidence(merged.get("confidence"), 0.5)
        status = str(merged.get("status", "ok") or "ok").strip().lower()

        if ai_reason:
            base_reason = str(merged.get("reason", "") or "").strip()
            if base_reason:
                merged["reason"] = "{}；AI研判：{}".format(base_reason, ai_reason)
            else:
                merged["reason"] = "AI研判：{}".format(ai_reason)

        if status != "ok" or not ai_decision:
            return merged

        if ai_decision == base_decision:
            merged["confidence"] = max(base_confidence, min(0.99, ai_confidence))
            return merged

        if {ai_decision, base_decision} == {"verified", "likely_false_positive"}:
            merged["decision"] = "needs_manual_review"
            merged["confidence"] = max(0.62, min(0.9, (base_confidence + ai_confidence) / 2.0))
            merged["reason"] = "{}；AI与MCP探针结论冲突，转人工复核".format(
                str(merged.get("reason", "") or "").strip()
            ).strip("；")
            return merged

        if base_decision == "needs_manual_review" and ai_decision in {"verified", "likely_false_positive"} and ai_confidence >= 0.82:
            merged["decision"] = ai_decision
            merged["confidence"] = max(base_confidence, min(0.96, ai_confidence * 0.92))
            return merged

        if ai_decision == "needs_manual_review":
            merged["decision"] = "needs_manual_review"
            merged["confidence"] = max(base_confidence, min(0.88, ai_confidence))
            return merged
        return merged

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

    @staticmethod
    def _build_idor_probe_url(target_url: str):
        url_text = str(target_url or "").strip()
        if not url_text:
            return url_text

        try:
            parsed = urlsplit(url_text)
            query_items = parse_qsl(parsed.query, keep_blank_values=True)
            id_keys = {"id", "uid", "user_id", "userid", "account_id", "order_id", "doc_id"}
            changed = False
            if query_items:
                updated_items = []
                for key, value in query_items:
                    key_text = str(key or "").strip().lower()
                    value_text = str(value or "").strip()
                    if (key_text in id_keys or key_text.endswith("_id")) and value_text.isdigit():
                        updated_items.append((key, str(int(value_text) + 1)))
                        changed = True
                    elif not changed and value_text.isdigit():
                        updated_items.append((key, str(int(value_text) + 1)))
                        changed = True
                    else:
                        updated_items.append((key, value))
                if changed:
                    updated_query = urlencode(updated_items, doseq=True)
                    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, updated_query, parsed.fragment))

            path_text = str(parsed.path or "")
            match = re.search(r"(\d+)(/?$)", path_text)
            if match:
                number_text = match.group(1)
                next_number = str(int(number_text) + 1)
                new_path = "{}{}{}".format(path_text[: match.start(1)], next_number, path_text[match.end(1):])
                return urlunsplit((parsed.scheme, parsed.netloc, new_path, parsed.query, parsed.fragment))
            return url_text
        except Exception:
            return url_text

    @staticmethod
    def _build_api_doc_probe_targets(target_url: str, max_count=4):
        url_text = str(target_url or "").strip()
        if not url_text:
            return []

        try:
            parsed = urlsplit(url_text)
            base = "{}://{}".format(parsed.scheme, parsed.netloc)
            candidate_paths = [
                "/swagger-ui/index.html",
                "/swagger-ui.html",
                "/swagger.json",
                "/v3/api-docs",
                "/v2/api-docs",
                "/openapi.json",
            ]
            targets = []
            seen = set()
            for path in candidate_paths:
                full_url = "{}{}".format(base, path)
                if full_url in seen:
                    continue
                seen.add(full_url)
                targets.append(full_url)
                if len(targets) >= max(1, int(max_count or 1)):
                    break
            return targets
        except Exception:
            return []

    @staticmethod
    def _looks_like_api_doc_response(url_text: str, body_text: str, headers=None):
        """
        轻量判断响应是否命中 API 文档（Swagger/OpenAPI）。
        """
        url_lower = str(url_text or "").strip().lower()
        body_lower = str(body_text or "").strip().lower()
        header_obj = headers if isinstance(headers, dict) else {}
        content_type = str(header_obj.get("Content-Type", "") or "").strip().lower()

        if not body_lower and not content_type:
            return False

        url_markers = ("swagger", "openapi", "api-docs", "postman")
        body_markers = (
            '"openapi"',
            '"swagger"',
            "swagger-ui",
            "api-docs",
            '"paths"',
            "openapi:",
        )

        if any(marker in content_type for marker in ("application/openapi+json", "application/swagger+json")):
            return True
        if any(marker in body_lower for marker in body_markers):
            return True
        if any(marker in url_lower for marker in url_markers):
            return "html" in content_type or "json" in content_type
        return False

    @staticmethod
    def _extract_jwt_candidates(*text_values, max_count=3):
        """
        从输入文本中提取疑似 JWT token。
        """
        token_pattern = re.compile(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
        seen = set()
        tokens = []
        for value in text_values:
            text = str(value or "")
            if not text:
                continue
            for token in token_pattern.findall(text):
                token_text = str(token or "").strip()
                if not token_text or token_text in seen:
                    continue
                seen.add(token_text)
                tokens.append(token_text)
                if len(tokens) >= max(1, int(max_count or 1)):
                    return tokens
        return tokens

    @staticmethod
    def _jwt_b64url_decode(part_text: str):
        text = str(part_text or "").strip()
        if not text:
            return ""
        padding = "=" * ((4 - len(text) % 4) % 4)
        try:
            return base64.urlsafe_b64decode((text + padding).encode("utf-8")).decode("utf-8", "ignore")
        except Exception:
            return ""

    @staticmethod
    def _jwt_b64url_encode(raw_bytes: bytes):
        content = raw_bytes if isinstance(raw_bytes, (bytes, bytearray)) else b""
        return base64.urlsafe_b64encode(bytes(content)).decode("utf-8").rstrip("=")

    @classmethod
    def _parse_jwt_header(cls, token: str):
        token_text = str(token or "").strip()
        parts = token_text.split(".")
        if len(parts) != 3:
            return {}
        header_json = cls._jwt_b64url_decode(parts[0])
        if not header_json:
            return {}
        try:
            header_obj = json.loads(header_json)
            if isinstance(header_obj, dict):
                return header_obj
            return {}
        except Exception:
            return {}

    @classmethod
    def _build_jwt_none_token(cls, token: str):
        """
        复用原 token payload 构造 alg=none token。
        """
        token_text = str(token or "").strip()
        parts = token_text.split(".")
        if len(parts) != 3:
            return ""

        payload_part = str(parts[1] or "").strip()
        if not payload_part:
            return ""

        none_header = {"alg": "none", "typ": "JWT"}
        try:
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(none_header, separators=(",", ":")).encode("utf-8")
            ).decode("utf-8").rstrip("=")
        except Exception:
            return ""

        return "{}.{}.".format(header_b64, payload_part)

    @classmethod
    def _jwt_try_weak_hmac_secret(cls, token: str, extra_secrets=None, max_count=64):
        """
        对 HS256/HS384/HS512 token 执行弱密钥快速校验。
        """
        token_text = str(token or "").strip()
        if not token_text:
            return ""

        parts = token_text.split(".")
        if len(parts) != 3:
            return ""

        jwt_header = cls._parse_jwt_header(token_text)
        alg_text = str(jwt_header.get("alg", "") or "").strip().upper()
        digest_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        digest_func = digest_map.get(alg_text)
        if digest_func is None:
            return ""

        unsigned = "{}.{}".format(parts[0], parts[1])
        sign_part = str(parts[2] or "").strip()
        if not unsigned or not sign_part:
            return ""

        candidate_secrets = []
        seen = set()
        for item in cls.AI_PEN_JWT_WEAK_SECRET_CANDIDATES:
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            candidate_secrets.append(text)

        if isinstance(extra_secrets, (list, tuple, set)):
            for item in extra_secrets:
                text = str(item or "").strip()
                if not text or text in seen:
                    continue
                seen.add(text)
                candidate_secrets.append(text)

        test_count = max(1, int(max_count or 1))
        for secret in candidate_secrets[:test_count]:
            try:
                sign_bytes = hmac.new(
                    secret.encode("utf-8"),
                    unsigned.encode("utf-8"),
                    digest_func,
                ).digest()
                expected_part = cls._jwt_b64url_encode(sign_bytes)
                if hmac.compare_digest(expected_part, sign_part):
                    return secret
            except Exception:
                continue
        return ""

    @staticmethod
    def _build_websocket_handshake_url(target_url: str):
        """
        构造用于 WebSocket 握手探测的 http(s) URL（requests 不支持 ws(s) scheme）。
        """
        url_text = str(target_url or "").strip()
        if not url_text:
            return ""

        try:
            parsed = urlsplit(url_text)
            scheme = str(parsed.scheme or "").lower()
            if scheme == "ws":
                scheme = "http"
            elif scheme == "wss":
                scheme = "https"
            elif scheme not in {"http", "https"}:
                return ""

            path_text = str(parsed.path or "").strip()
            if not path_text:
                path_text = "/ws"
            return urlunsplit((scheme, parsed.netloc, path_text, parsed.query, parsed.fragment))
        except Exception:
            return ""

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
        if "swagger" in merged or "openapi" in merged or "postman" in merged or "api_doc" in merged:
            return "api_doc_probe", "/v3/api-docs"
        if "websocket" in merged or "socket.io" in merged or "sockjs" in merged:
            return "websocket_probe", "ws_handshake"
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

        # 4) 站点线索(site)：用于补充 API 文档暴露/WebSocket 入口验证。
        try:
            api_doc_keywords = ("swagger", "openapi", "api-docs", "knife4j", "redoc", "postman")
            websocket_keywords = ("websocket", "socket.io", "sockjs", "ws://", "wss://")
            jwt_keywords = ("jwt", "json web token", "oauth2", "openid", "oidc")
            site_cursor = utils.conn_db("site").find(
                {"task_id": self.task_id},
                {"_id": 1, "site": 1, "title": 1, "http_server": 1, "finger": 1, "status": 1},
                max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
            ).limit(self.AI_PEN_TEST_SOURCE_LIMIT)
            for row in site_cursor:
                site_url = str(row.get("site", "") or "").strip()
                if not self._is_http_target(site_url):
                    continue

                title_text = str(row.get("title", "") or "").strip()
                server_text = str(row.get("http_server", "") or "").strip()
                status_code = int(row.get("status", 0) or 0)
                finger_names = []
                for finger_item in (row.get("finger", []) or []):
                    if isinstance(finger_item, dict):
                        name_text = str(finger_item.get("name", "") or "").strip()
                        if name_text:
                            finger_names.append(name_text)

                merged_text = " ".join(
                    [
                        site_url.lower(),
                        title_text.lower(),
                        server_text.lower(),
                        " ".join([str(x).lower() for x in finger_names]),
                    ]
                )
                matched_keywords = []
                risk_type = ""
                risk_name = ""
                severity = "info"
                if any(keyword in merged_text for keyword in api_doc_keywords):
                    matched_keywords = [keyword for keyword in api_doc_keywords if keyword in merged_text][:4]
                    risk_type = "api_doc"
                    risk_name = "站点疑似暴露API文档"
                    severity = "medium"
                elif any(keyword in merged_text for keyword in websocket_keywords):
                    matched_keywords = [keyword for keyword in websocket_keywords if keyword in merged_text][:4]
                    risk_type = "websocket"
                    risk_name = "站点疑似存在WebSocket入口"
                    severity = "low"
                elif any(keyword in merged_text for keyword in jwt_keywords):
                    matched_keywords = [keyword for keyword in jwt_keywords if keyword in merged_text][:4]
                    risk_type = "jwt"
                    risk_name = "站点疑似存在JWT鉴权链路"
                    severity = "low"

                if not risk_type:
                    continue

                evidence_parts = []
                if title_text:
                    evidence_parts.append("title={}".format(title_text[:90]))
                if server_text:
                    evidence_parts.append("server={}".format(server_text[:64]))
                if matched_keywords:
                    evidence_parts.append("keywords={}".format(",".join(matched_keywords)))
                if status_code:
                    evidence_parts.append("status={}".format(status_code))
                if finger_names:
                    evidence_parts.append("finger={}".format(",".join(finger_names[:4])))
                evidence_seed = " | ".join(evidence_parts)

                _append_candidate(
                    {
                        "source_collection": "site",
                        "source_id": row.get("_id"),
                        "source_module": "site",
                        "target": site_url,
                        "vuln_url": site_url,
                        "risk_type": risk_type,
                        "risk_name": risk_name,
                        "severity": severity,
                        "evidence_seed": evidence_seed,
                    }
                )
        except Exception as e:
            logger.warning("task_id:{} build ai_pen candidates from site failed err:{}".format(self.task_id, e))

        # 5) URL 线索(url)：用于补充 IDOR/API 文档/WebSocket 场景验证。
        try:
            api_doc_keywords = ("swagger", "openapi", "api-docs", "knife4j", "redoc", "postman")
            websocket_keywords = ("websocket", "socket.io", "sockjs", "/ws", "/websocket")
            id_keys = {"id", "uid", "user_id", "userid", "account_id", "order_id", "doc_id"}
            jwt_token_keys = {"token", "jwt", "access_token", "id_token", "refresh_token", "authorization", "auth", "bearer"}
            url_cursor = utils.conn_db("url").find(
                {"task_id": self.task_id},
                {"_id": 1, "url": 1, "title": 1, "status_code": 1, "source": 1},
                max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
            ).limit(self.AI_PEN_TEST_SOURCE_LIMIT)
            for row in url_cursor:
                raw_url = str(row.get("url", "") or "").strip()
                if not self._is_http_target(raw_url):
                    continue

                lower_url = raw_url.lower()
                title_text = str(row.get("title", "") or "").strip()
                source_text = str(row.get("source", "") or "").strip().lower()
                status_code = int(row.get("status_code", 0) or 0)
                parsed = urlsplit(raw_url)
                query_items = parse_qsl(parsed.query, keep_blank_values=True)

                matched_keywords = []
                risk_type = ""
                risk_name = ""
                severity = "info"
                if any(keyword in lower_url or keyword in title_text.lower() for keyword in api_doc_keywords):
                    matched_keywords = [
                        keyword for keyword in api_doc_keywords
                        if keyword in lower_url or keyword in title_text.lower()
                    ][:4]
                    risk_type = "api_doc"
                    risk_name = "URL疑似暴露API文档"
                    severity = "medium"
                elif any(keyword in lower_url for keyword in websocket_keywords):
                    matched_keywords = [keyword for keyword in websocket_keywords if keyword in lower_url][:4]
                    risk_type = "websocket"
                    risk_name = "URL疑似WebSocket入口"
                    severity = "low"
                else:
                    jwt_token_hit = False
                    for key, value in query_items:
                        key_text = str(key or "").strip().lower()
                        value_text = str(value or "").strip()
                        if key_text not in jwt_token_keys:
                            continue
                        if "." in value_text and len(value_text) >= 24 and value_text.count(".") == 2:
                            risk_type = "jwt"
                            risk_name = "URL疑似JWT令牌参数"
                            severity = "medium"
                            matched_keywords = [key_text]
                            jwt_token_hit = True
                            break
                        if "jwt" in key_text and len(value_text) >= 16:
                            risk_type = "jwt"
                            risk_name = "URL疑似JWT参数"
                            severity = "low"
                            matched_keywords = [key_text]
                            jwt_token_hit = True
                            break

                    numeric_idor = False
                    if not risk_type:
                        for key, value in query_items:
                            key_text = str(key or "").strip().lower()
                            value_text = str(value or "").strip()
                            if (key_text in id_keys or key_text.endswith("_id")) and value_text.isdigit():
                                numeric_idor = True
                                matched_keywords = [key_text]
                                break

                        if numeric_idor:
                            risk_type = "idor"
                            risk_name = "URL参数越权探测"
                            severity = "medium"
                        elif re.search(r"/\d+($|/)", str(parsed.path or "")) and any(
                            token in lower_url for token in ("/user/", "/users/", "/account/", "/order/", "/api/")
                        ):
                            risk_type = "idor"
                            risk_name = "路径ID越权探测"
                            severity = "low"
                            matched_keywords = ["path_numeric_id"]

                if not risk_type:
                    continue

                evidence_parts = ["url={}".format(raw_url[:180])]
                if title_text:
                    evidence_parts.append("title={}".format(title_text[:90]))
                if source_text:
                    evidence_parts.append("source={}".format(source_text))
                if status_code:
                    evidence_parts.append("status={}".format(status_code))
                if matched_keywords:
                    evidence_parts.append("keywords={}".format(",".join(matched_keywords)))

                _append_candidate(
                    {
                        "source_collection": "url",
                        "source_id": row.get("_id"),
                        "source_module": source_text or "url",
                        "target": raw_url,
                        "vuln_url": raw_url,
                        "risk_type": risk_type,
                        "risk_name": risk_name,
                        "severity": severity,
                        "evidence_seed": " | ".join(evidence_parts),
                    }
                )
        except Exception as e:
            logger.warning("task_id:{} build ai_pen candidates from url failed err:{}".format(self.task_id, e))

        def _risk_score(item):
            score = 0
            risk_type = str(item.get("risk_type", "") or "").lower()
            severity = str(item.get("severity", "") or "").lower()
            if str(item.get("source_collection", "") or "") == "nuclei_result":
                score += 15
            elif str(item.get("source_collection", "") or "") in {"site", "url"}:
                score += 5
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
                for keyword in ("xss", "sql", "sqli", "command", "cmdi", "jwt", "ssrf", "idor", "upload", "file_read", "api_doc", "websocket")
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

    def _verify_ai_pen_candidate(self, candidate: dict, mcp_settings=None, ai_plan=None):
        settings = mcp_settings if isinstance(mcp_settings, dict) else {}
        plan_obj = ai_plan if isinstance(ai_plan, dict) else {}
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
        ai_plan_payload_type = self._normalize_ai_pen_payload_type(plan_obj.get("payload_type"), fallback_type=payload_type)
        ai_plan_payload = str(plan_obj.get("payload", "") or "").strip()[: self.AI_PEN_TEST_PAYLOAD_MAX]
        if ai_plan_payload_type:
            payload_type = ai_plan_payload_type
        if ai_plan_payload:
            payload = ai_plan_payload

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
                "external_tool_runs": [],
                "external_tool_hit": False,
            }

        tool_trace_parts = []
        if plan_obj:
            plan_trace_parts = []
            if str(plan_obj.get("decision", "") or "").strip():
                plan_trace_parts.append("decision={}".format(str(plan_obj.get("decision", "")).strip()))
            if payload_type:
                plan_trace_parts.append("payload_type={}".format(payload_type))
            if payload:
                plan_trace_parts.append("payload={}".format(str(payload)[:80]))
            if plan_trace_parts:
                tool_trace_parts.append("ai_plan({})".format(",".join(plan_trace_parts)))
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
                    "external_tool_runs": [],
                    "external_tool_hit": False,
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
            idor_diff_hit = False
            api_doc_hit = False
            api_doc_hit_url = ""
            api_doc_probe_count = 0
            jwt_token_found = ""
            jwt_alg_text = ""
            jwt_alg_none_hit = False
            jwt_none_probe_hit = False
            jwt_weak_secret = ""
            websocket_upgrade_hit = False
            websocket_upgrade_hint = False
            probe_error = ""
            payload_probe_types = {"xss_probe", "sqli_probe", "cmdi_probe", "ssrf_probe", "replay"}

            if mcp_enable and tool_calls < max_tool_calls:
                if payload and payload_type in payload_probe_types:
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
                elif payload_type == "idor_probe":
                    idor_url = self._build_idor_probe_url(target_url)
                    if idor_url and idor_url != target_url:
                        try:
                            idor_resp = utils.http_req(
                                idor_url,
                                "get",
                                timeout=timeout_tuple,
                                allow_redirects=True,
                                waf_guard=self.waf_guard,
                                waf_module="ai_pen_test",
                            )
                            tool_calls += 1
                            tool_trace_parts.append("idor_probe(get,url={})".format(idor_url[:220]))
                            probe_status = int(getattr(idor_resp, "status_code", 0) or 0)
                            idor_headers = getattr(idor_resp, "headers", {}) or {}
                            if str(idor_headers.get("X-ARL-WAF-SMART-SKIP", "")).strip() != "1":
                                try:
                                    idor_body_text = str(getattr(idor_resp, "text", "") or "")
                                except Exception:
                                    idor_body_text = ""
                                probe_body_excerpt = idor_body_text[: self.AI_PEN_TEST_BODY_MAX]
                                probe_body_md5 = (
                                    hashlib.md5(probe_body_excerpt.encode("utf-8", "ignore")).hexdigest()
                                    if probe_body_excerpt
                                    else ""
                                )
                                if self._contains_evidence(evidence_seed, probe_body_excerpt):
                                    evidence_hit = True
                                if probe_body_md5 and base_body_md5 and probe_body_md5 != base_body_md5:
                                    idor_diff_hit = True
                            else:
                                tool_trace_parts.append("idor_probe(skip_by_waf)")
                        except Exception as probe_exc:
                            probe_error = self._clip_text(probe_exc, self.AI_PEN_TEST_ERROR_MAX)
                            tool_trace_parts.append("idor_probe(error)")
                    else:
                        tool_trace_parts.append("idor_probe(skip_no_mutation)")
                elif payload_type == "api_doc_probe":
                    remain_calls = max(1, max_tool_calls - tool_calls)
                    doc_targets = self._build_api_doc_probe_targets(target_url, max_count=remain_calls)
                    if not doc_targets:
                        tool_trace_parts.append("api_doc_probe(skip_no_target)")
                    for doc_url in doc_targets:
                        if tool_calls >= max_tool_calls:
                            break
                        try:
                            doc_resp = utils.http_req(
                                doc_url,
                                "get",
                                timeout=timeout_tuple,
                                allow_redirects=True,
                                waf_guard=self.waf_guard,
                                waf_module="ai_pen_test",
                            )
                            tool_calls += 1
                            api_doc_probe_count += 1
                            tool_trace_parts.append("api_doc_probe(get,url={})".format(doc_url[:220]))
                            doc_status = int(getattr(doc_resp, "status_code", 0) or 0)
                            if not probe_status:
                                probe_status = doc_status

                            doc_headers = getattr(doc_resp, "headers", {}) or {}
                            if str(doc_headers.get("X-ARL-WAF-SMART-SKIP", "")).strip() == "1":
                                tool_trace_parts.append("api_doc_probe(skip_by_waf,url={})".format(doc_url[:180]))
                                continue

                            try:
                                doc_body_text = str(getattr(doc_resp, "text", "") or "")
                            except Exception:
                                doc_body_text = ""
                            doc_body_excerpt = doc_body_text[: self.AI_PEN_TEST_BODY_MAX]
                            doc_body_md5 = (
                                hashlib.md5(doc_body_excerpt.encode("utf-8", "ignore")).hexdigest()
                                if doc_body_excerpt
                                else ""
                            )
                            if doc_body_excerpt:
                                probe_body_excerpt = doc_body_excerpt
                            if doc_body_md5:
                                probe_body_md5 = doc_body_md5
                            if self._contains_evidence(evidence_seed, doc_body_excerpt):
                                evidence_hit = True
                            if self._looks_like_api_doc_response(doc_url, doc_body_excerpt, doc_headers):
                                api_doc_hit = True
                                api_doc_hit_url = doc_url
                                break
                        except Exception as probe_exc:
                            if not probe_error:
                                probe_error = self._clip_text(probe_exc, self.AI_PEN_TEST_ERROR_MAX)
                            tool_trace_parts.append("api_doc_probe(error,url={})".format(str(doc_url)[:180]))
                elif payload_type == "jwt_probe":
                    jwt_candidates = self._extract_jwt_candidates(
                        evidence_seed,
                        base_body_excerpt,
                        target_url,
                        max_count=2,
                    )
                    if jwt_candidates:
                        jwt_token_found = str(jwt_candidates[0] or "").strip()
                        jwt_header_obj = self._parse_jwt_header(jwt_token_found)
                        jwt_alg_text = str(jwt_header_obj.get("alg", "") or "").strip().lower()
                        if jwt_alg_text == "none":
                            jwt_alg_none_hit = True
                            tool_trace_parts.append("jwt_probe(found_alg_none)")

                        if jwt_alg_text in {"hs256", "hs384", "hs512"}:
                            extra_secrets = []
                            host_text = str(urlsplit(target_url).hostname or "").strip().lower()
                            if host_text:
                                extra_secrets.append(host_text)
                                for token in re.split(r"[^a-z0-9]+", host_text):
                                    token = str(token or "").strip()
                                    if len(token) >= 4:
                                        extra_secrets.append(token)
                            jwt_weak_secret = self._jwt_try_weak_hmac_secret(
                                jwt_token_found,
                                extra_secrets=extra_secrets,
                                max_count=64,
                            )
                            if jwt_weak_secret:
                                tool_trace_parts.append("jwt_probe(weak_secret={})".format(jwt_weak_secret[:32]))

                        none_token = self._build_jwt_none_token(jwt_token_found)
                        if none_token and tool_calls < max_tool_calls:
                            try:
                                jwt_headers = {"Authorization": "Bearer {}".format(none_token)}
                                jwt_resp = utils.http_req(
                                    target_url,
                                    "get",
                                    timeout=timeout_tuple,
                                    allow_redirects=True,
                                    headers=jwt_headers,
                                    waf_guard=self.waf_guard,
                                    waf_module="ai_pen_test",
                                )
                                tool_calls += 1
                                tool_trace_parts.append("jwt_probe(auth_none,url={})".format(target_url[:220]))
                                probe_status = int(getattr(jwt_resp, "status_code", 0) or 0)
                                jwt_resp_headers = getattr(jwt_resp, "headers", {}) or {}
                                if str(jwt_resp_headers.get("X-ARL-WAF-SMART-SKIP", "")).strip() != "1":
                                    try:
                                        jwt_body_text = str(getattr(jwt_resp, "text", "") or "")
                                    except Exception:
                                        jwt_body_text = ""
                                    probe_body_excerpt = jwt_body_text[: self.AI_PEN_TEST_BODY_MAX]
                                    probe_body_md5 = (
                                        hashlib.md5(probe_body_excerpt.encode("utf-8", "ignore")).hexdigest()
                                        if probe_body_excerpt
                                        else ""
                                    )
                                    if self._contains_evidence(evidence_seed, probe_body_excerpt):
                                        evidence_hit = True
                                    if (
                                        probe_status == status_code
                                        and probe_body_md5
                                        and base_body_md5
                                        and probe_body_md5 == base_body_md5
                                        and probe_status not in (401, 403)
                                    ):
                                        jwt_none_probe_hit = True
                                else:
                                    tool_trace_parts.append("jwt_probe(skip_by_waf)")
                            except Exception as probe_exc:
                                if not probe_error:
                                    probe_error = self._clip_text(probe_exc, self.AI_PEN_TEST_ERROR_MAX)
                                tool_trace_parts.append("jwt_probe(error)")
                    else:
                        tool_trace_parts.append("jwt_probe(skip_no_token)")
                elif payload_type == "websocket_probe":
                    ws_probe_url = self._build_websocket_handshake_url(target_url)
                    if not ws_probe_url:
                        tool_trace_parts.append("websocket_probe(skip_invalid_target)")
                    elif tool_calls < max_tool_calls:
                        try:
                            ws_headers = {
                                "Connection": "Upgrade",
                                "Upgrade": "websocket",
                                "Sec-WebSocket-Version": "13",
                                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                            }
                            ws_resp = utils.http_req(
                                ws_probe_url,
                                "get",
                                timeout=timeout_tuple,
                                allow_redirects=False,
                                headers=ws_headers,
                                waf_guard=self.waf_guard,
                                waf_module="ai_pen_test",
                            )
                            tool_calls += 1
                            tool_trace_parts.append("websocket_probe(handshake,url={})".format(ws_probe_url[:220]))
                            probe_status = int(getattr(ws_resp, "status_code", 0) or 0)
                            ws_resp_headers = getattr(ws_resp, "headers", {}) or {}
                            ws_upgrade_header = str(ws_resp_headers.get("Upgrade", "") or "").strip().lower()
                            ws_version_hint = str(ws_resp_headers.get("Sec-WebSocket-Version", "") or "").strip()

                            if str(ws_resp_headers.get("X-ARL-WAF-SMART-SKIP", "")).strip() != "1":
                                try:
                                    ws_body_text = str(getattr(ws_resp, "text", "") or "")
                                except Exception:
                                    ws_body_text = ""
                                probe_body_excerpt = ws_body_text[: self.AI_PEN_TEST_BODY_MAX]
                                probe_body_md5 = (
                                    hashlib.md5(probe_body_excerpt.encode("utf-8", "ignore")).hexdigest()
                                    if probe_body_excerpt
                                    else ""
                                )
                                if probe_status == 101 and "websocket" in ws_upgrade_header:
                                    websocket_upgrade_hit = True
                                elif probe_status in (400, 426) and ("websocket" in ws_upgrade_header or ws_version_hint):
                                    websocket_upgrade_hint = True
                            else:
                                tool_trace_parts.append("websocket_probe(skip_by_waf)")
                        except Exception as probe_exc:
                            if not probe_error:
                                probe_error = self._clip_text(probe_exc, self.AI_PEN_TEST_ERROR_MAX)
                            tool_trace_parts.append("websocket_probe(error)")

            decision = "needs_manual_review"
            confidence = 0.56
            reason = "目标可访问，已完成 HTTP 验证"
            if evidence_hit:
                decision = "verified"
                confidence = 0.82
                reason = "响应中命中风险证据片段，验证通过"
            elif payload_type == "jwt_probe" and jwt_weak_secret:
                decision = "verified"
                confidence = 0.93
                reason = "JWT 使用弱密钥签名（secret={}），可被离线伪造".format(jwt_weak_secret[:32])
            elif payload_type == "jwt_probe" and jwt_alg_none_hit:
                decision = "verified"
                confidence = 0.90
                reason = "JWT Header 使用 alg=none，存在未签名令牌风险"
            elif payload_type == "jwt_probe" and jwt_none_probe_hit:
                decision = "needs_manual_review"
                confidence = 0.80
                reason = "JWT none-token 重放与基线响应一致，疑似存在签名校验缺陷"
            elif payload_type == "jwt_probe" and jwt_token_found:
                decision = "needs_manual_review"
                confidence = 0.64
                reason = "发现疑似 JWT 令牌（alg={}），建议结合登录态进一步验证".format(jwt_alg_text or "-")
            elif payload_type == "websocket_probe" and websocket_upgrade_hit:
                decision = "verified"
                confidence = 0.86
                reason = "WebSocket 握手返回 101 且 Upgrade=websocket，入口验证通过"
            elif payload_type == "websocket_probe" and websocket_upgrade_hint:
                decision = "needs_manual_review"
                confidence = 0.70
                reason = "WebSocket 握手返回特征状态码（400/426）与版本提示，疑似存在可用入口"
            elif payload_type == "api_doc_probe" and api_doc_hit:
                decision = "verified"
                confidence = 0.86
                reason = "发现公开 API 文档端点 {}，可继续进行参数验证".format(api_doc_hit_url[:180])
            elif payload_reflect_hit:
                decision = "needs_manual_review"
                confidence = 0.74
                reason = "Payload 在响应中回显，疑似存在可利用注入点"
            elif payload_type == "idor_probe" and idor_diff_hit:
                decision = "needs_manual_review"
                confidence = 0.78
                reason = "ID 参数变异后响应差异明显，疑似存在越权风险"
            elif probe_body_md5 and base_body_md5 and probe_body_md5 != base_body_md5:
                decision = "needs_manual_review"
                confidence = 0.66
                reason = "Payload 探针前后响应差异明显，建议人工复核"
            elif payload_type == "api_doc_probe" and api_doc_probe_count > 0 and not api_doc_hit:
                decision = "likely_false_positive"
                confidence = 0.60
                reason = "已探测 {} 个常见 API 文档端点，暂未命中暴露特征".format(api_doc_probe_count)
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
            if mcp_enable and max_tool_calls > 1 and payload_type == "idor_probe":
                verification_step = "mcp_idor_probe"
            elif mcp_enable and max_tool_calls > 1 and payload_type == "api_doc_probe":
                verification_step = "mcp_api_doc_probe"
            elif mcp_enable and max_tool_calls > 1 and payload_type == "jwt_probe":
                verification_step = "mcp_jwt_probe"
            elif mcp_enable and max_tool_calls > 1 and payload_type == "websocket_probe":
                verification_step = "mcp_websocket_probe"
            elif mcp_enable and max_tool_calls > 1:
                verification_step = "mcp_http_probe"

            response_hash_diff = base_body_md5
            if probe_body_md5:
                response_hash_diff = "base:{} | probe:{}".format(base_body_md5[:16], probe_body_md5[:16])
            if payload_type == "api_doc_probe" and api_doc_hit_url:
                response_hash_diff = "{} | api_doc:{}".format(response_hash_diff, api_doc_hit_url[:120]).strip(" |")

            external_ret = self._run_ai_pen_external_tools(
                target_url=target_url,
                risk_type=risk_type,
                payload_type=payload_type,
                base_decision=decision,
                base_confidence=confidence,
                settings=settings,
            )
            if isinstance(external_ret, dict):
                decision = self._normalize_ai_pen_decision(
                    external_ret.get("decision"),
                    default_value=decision,
                )
                confidence = self._clamp_ai_pen_confidence(external_ret.get("confidence"), confidence)
                external_reason = self._clip_text(external_ret.get("reason", ""), self.AI_PEN_TEST_REASON_MAX)
                if external_reason:
                    if reason:
                        reason = "{}；{}".format(reason, external_reason)
                    else:
                        reason = external_reason
                external_step = str(external_ret.get("verification_step", "") or "").strip()
                if external_step:
                    verification_step = external_step
                external_trace = str(external_ret.get("tool_trace", "") or "").strip()
                if external_trace:
                    tool_trace_parts.append(external_trace)
            else:
                external_ret = {}

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
                "external_tool_runs": list(external_ret.get("tool_runs", []) or [])[: self.AI_PEN_EXTERNAL_RESULT_MAX],
                "external_tool_hit": bool(external_ret.get("tool_hit")),
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
                "external_tool_runs": [],
                "external_tool_hit": False,
            }

    def run_ai_penetration_test(self):
        """
        AI 渗透测试第一阶段（M1）：
        - 汇聚 vuln / nuclei_result / wih / site / url 候选
        - 执行轻量 HTTP 二次验证
        - 产出 ai_pen_test_result，支撑任务详情“AI渗透”页签
        """
        started_at = time.time()
        ai_config = self._load_ai_runtime_config()
        runtime_settings = self._build_ai_pen_runtime_settings(ai_config)
        ai_pen_enable = bool(runtime_settings.get("ai_pen_enable", True))
        mcp_enable = bool(runtime_settings.get("mcp_enable", True))
        ai_planner_enable = bool(runtime_settings.get("ai_planner_enable", True))
        mcp_max_tool_calls = self._safe_int_value(
            runtime_settings.get("max_tool_calls"), self.AI_PEN_TEST_MCP_MAX_TOOL_CALLS
        )
        mcp_timeout_sec = self._safe_int_value(
            runtime_settings.get("timeout_sec"), self.AI_PEN_TEST_MCP_TIMEOUT_SEC
        )
        ai_plan_max_cases = self._safe_int_value(
            runtime_settings.get("ai_plan_max_cases"), self.AI_PEN_TEST_AI_PLAN_MAX_CASES
        )
        external_enable = bool(runtime_settings.get("external_enable", False))
        external_tools = self._normalize_ai_pen_external_tools(runtime_settings.get("external_tools", []))
        external_timeout_sec = self._safe_int_value(
            runtime_settings.get("external_timeout_sec"), getattr(Config, "AI_PEN_MCP_EXTERNAL_TIMEOUT_SEC", 45)
        )
        external_max_runs = self._safe_int_value(
            runtime_settings.get("external_max_runs"), getattr(Config, "AI_PEN_MCP_EXTERNAL_MAX_RUNS", 1)
        )
        runtime_provider = "local-mcp" if mcp_enable else "local"
        runtime_model = "mcp-rule-lite" if mcp_enable else "rule-lite"
        runtime_profile = "ai-pen-test-mcp" if mcp_enable else "ai-pen-test"
        ai_prompt_content = self._resolve_ai_pen_prompt_content(ai_config)
        ai_plan_usage_total = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        ai_plan_call_count = 0
        ai_plan_ok_count = 0
        ai_plan_error_count = 0
        ai_plan_skip_count = 0
        ai_plan_error_samples = []

        if not ai_pen_enable:
            summary_text = "ai_pen_enable=false | candidates=0 | selected=0 | saved=0 | verified=0 | likely_fp=0 | error=0 | ai_plan_calls=0 | external={}".format(
                "on" if external_enable else "off"
            )
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
                usage=ai_plan_usage_total,
                meta={
                    "task_id": self.task_id,
                    "ai_pen_enable": ai_pen_enable,
                    "mcp_enable": mcp_enable,
                    "ai_planner_enable": ai_planner_enable,
                    "mcp_max_tool_calls": mcp_max_tool_calls,
                    "mcp_timeout_sec": mcp_timeout_sec,
                    "ai_plan_max_cases": ai_plan_max_cases,
                    "external_enable": external_enable,
                    "external_tools": external_tools,
                    "external_timeout_sec": external_timeout_sec,
                    "external_max_runs": external_max_runs,
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
                reply_text="candidates=0 | selected=0 | saved=0 | verified=0 | likely_fp=0 | error=0 | mcp={} | max_tool_calls={} | timeout_sec={} | ai_plan_calls=0 | external={} | external_tools={}".format(
                    "on" if mcp_enable else "off",
                    mcp_max_tool_calls,
                    mcp_timeout_sec,
                    "on" if external_enable else "off",
                    ",".join(external_tools) or "-",
                ),
                elapsed_ms=int((time.time() - started_at) * 1000.0),
                usage=ai_plan_usage_total,
                meta={
                    "task_id": self.task_id,
                    "candidate_count": 0,
                    "mcp_enable": mcp_enable,
                    "ai_planner_enable": ai_planner_enable,
                    "mcp_max_tool_calls": mcp_max_tool_calls,
                    "mcp_timeout_sec": mcp_timeout_sec,
                    "ai_plan_max_cases": ai_plan_max_cases,
                    "external_enable": external_enable,
                    "external_tools": external_tools,
                    "external_timeout_sec": external_timeout_sec,
                    "external_max_runs": external_max_runs,
                },
            )
            return

        knowledge_loaded = False
        knowledge_path = ""
        knowledge_index_token_count = 0
        knowledge_hit_tokens_set = set()
        for candidate in candidates:
            hit_info = self._collect_ai_pen_knowledge_hits(candidate)
            candidate["knowledge_hit_tokens"] = list(hit_info.get("hit_tokens", []) or [])
            candidate["knowledge_hit_samples"] = list(hit_info.get("hit_samples", []) or [])
            candidate["knowledge_score"] = int(hit_info.get("score", 0) or 0)
            if bool(hit_info.get("loaded")):
                knowledge_loaded = True
            if hit_info.get("path"):
                knowledge_path = str(hit_info.get("path") or "")
            if int(hit_info.get("index_token_count", 0) or 0) > knowledge_index_token_count:
                knowledge_index_token_count = int(hit_info.get("index_token_count", 0) or 0)
            for token in candidate.get("knowledge_hit_tokens", []):
                token_text = str(token or "").strip()
                if token_text:
                    knowledge_hit_tokens_set.add(token_text)

        # 有知识命中的候选优先进入执行窗口（同分保留原有风险优先顺序）。
        candidates.sort(key=lambda item: -int(item.get("knowledge_score", 0) or 0))
        source_counter = {}
        for candidate in candidates:
            source_name = str(candidate.get("source_collection", "") or "").strip().lower()
            if not source_name:
                source_name = "unknown"
            source_counter[source_name] = source_counter.get(source_name, 0) + 1

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
        external_tool_runs_total = 0
        external_tool_hit_count = 0

        collection = utils.conn_db("ai_pen_test_result")
        for candidate in selected_candidates:
            ai_plan_result = {
                "ok": False,
                "status": "skipped",
                "message": "planner_budget_exhausted",
                "provider": "-",
                "model": "-",
                "profile": "-",
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "elapsed_ms": 0,
                "request_text": "",
                "reply_text": "",
                "output": {},
            }
            if ai_planner_enable and ai_plan_call_count < ai_plan_max_cases:
                ai_plan_result = self._call_ai_pen_planner(
                    ai_config=ai_config,
                    candidate=candidate,
                    runtime_settings=runtime_settings,
                    prompt_content=ai_prompt_content,
                )
                ai_plan_call_count += 1
                ai_plan_status = str(ai_plan_result.get("status", "skipped") or "skipped").strip().lower()
                ai_usage = ai_plan_result.get("usage") if isinstance(ai_plan_result.get("usage"), dict) else {}
                ai_plan_usage_total["prompt_tokens"] += self._safe_int_value(ai_usage.get("prompt_tokens"), 0)
                ai_plan_usage_total["completion_tokens"] += self._safe_int_value(ai_usage.get("completion_tokens"), 0)
                ai_plan_usage_total["total_tokens"] += self._safe_int_value(ai_usage.get("total_tokens"), 0)
                if bool(ai_plan_result.get("ok")) and ai_plan_status == "ok":
                    ai_plan_ok_count += 1
                elif ai_plan_status == "error":
                    ai_plan_error_count += 1
                    ai_error_text = self._clip_text(ai_plan_result.get("message", ""), 120)
                    if ai_error_text:
                        ai_plan_error_samples.append(ai_error_text)
                else:
                    ai_plan_skip_count += 1
            else:
                ai_plan_skip_count += 1
                if not ai_planner_enable:
                    ai_plan_result["message"] = "planner_disabled"

            ai_plan_output = ai_plan_result.get("output") if isinstance(ai_plan_result.get("output"), dict) else {}
            verify_result = self._verify_ai_pen_candidate(
                candidate,
                mcp_settings=runtime_settings,
                ai_plan=ai_plan_output,
            )
            verify_result = self._merge_ai_pen_result_with_ai_plan(verify_result, ai_plan_result)
            now_text = utils.curr_date()

            status = str(verify_result.get("status", "skipped") or "skipped").strip().lower()
            decision = self._normalize_ai_pen_decision(verify_result.get("decision"), default_value="needs_manual_review")

            if decision == "verified":
                verified_count += 1
            elif decision == "likely_false_positive":
                false_positive_count += 1
            if status == "error":
                error_count += 1

            confidence = self._clamp_ai_pen_confidence(verify_result.get("confidence"), 0.0)
            external_tool_runs = list(verify_result.get("external_tool_runs", []) or [])
            if len(external_tool_runs) > self.AI_PEN_EXTERNAL_RESULT_MAX:
                external_tool_runs = external_tool_runs[: self.AI_PEN_EXTERNAL_RESULT_MAX]
            external_tool_runs_total += len(external_tool_runs)
            external_tool_hit = bool(verify_result.get("external_tool_hit"))
            if external_tool_hit:
                external_tool_hit_count += 1

            source_collection = str(candidate.get("source_collection", "") or "").strip()
            source_id = self._normalize_object_id(candidate.get("source_id"))
            if not source_collection or not source_id:
                continue

            record_provider = str(ai_plan_result.get("provider", "") or "").strip()
            record_model = str(ai_plan_result.get("model", "") or "").strip()
            record_profile = str(ai_plan_result.get("profile", "") or "").strip()
            if not record_provider or record_provider == "-":
                record_provider = runtime_provider
            if not record_model or record_model == "-":
                record_model = runtime_model
            if not record_profile or record_profile == "-":
                record_profile = runtime_profile
            runtime_provider = record_provider
            runtime_model = record_model
            runtime_profile = record_profile

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
                "model": record_model,
                "provider": record_provider,
                "profile": record_profile,
                "knowledge_hit_tokens": list(candidate.get("knowledge_hit_tokens", []) or []),
                "knowledge_hit_samples": list(candidate.get("knowledge_hit_samples", []) or []),
                "tool_trace": str(verify_result.get("tool_trace", "") or "").strip(),
                "external_tool_runs": external_tool_runs,
                "external_tool_hit": external_tool_hit,
                "ai_status": str(verify_result.get("ai_status", "") or "").strip(),
                "ai_plan_decision": self._normalize_ai_pen_decision(
                    verify_result.get("ai_plan_decision"), default_value=""
                ),
                "ai_plan_confidence": float(
                    "{:.4f}".format(self._clamp_ai_pen_confidence(verify_result.get("ai_plan_confidence"), 0.0))
                ),
                "ai_plan_reason": self._clip_text(verify_result.get("ai_plan_reason", ""), self.AI_PEN_TEST_REASON_MAX),
                "ai_plan_actions": list(verify_result.get("ai_plan_actions", []) or [])[:4],
                "ai_plan_request": self._clip_text(ai_plan_result.get("request_text", ""), 2600),
                "ai_plan_reply": self._clip_text(ai_plan_result.get("reply_text", ""), 2600),
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
            self._sync_ai_pen_result_to_source(
                source_collection=source_collection,
                source_id=source_id,
                decision=decision,
                confidence=confidence,
                status=status,
                reason=str(verify_result.get("reason", "") or "").strip(),
                verification_step=str(verify_result.get("verification_step", "") or "").strip(),
                payload_type=str(verify_result.get("payload_type", "") or "").strip(),
                update_date=now_text,
            )
            saved_count += 1

        elapsed_ms = int((time.time() - started_at) * 1000.0)
        knowledge_tokens_preview = ",".join(sorted(list(knowledge_hit_tokens_set))[:16]) or "-"
        source_counter_text = ",".join(
            ["{}:{}".format(name, source_counter[name]) for name in sorted(source_counter.keys())]
        ) or "-"
        summary_text = "candidates={} | selected={} | saved={} | verified={} | likely_fp={} | error={} | mcp={} | ai_planner={} | max_tool_calls={} | timeout_sec={} | external={} | external_tools={} | external_runs={} | external_hits={} | ai_plan_calls={} | ai_plan_ok={} | ai_plan_error={} | ai_tokens={} | sources={} | index_loaded={} | index_tokens={}".format(
            len(candidates),
            len(selected_candidates),
            saved_count,
            verified_count,
            false_positive_count,
            error_count,
            "on" if mcp_enable else "off",
            "on" if ai_planner_enable else "off",
            mcp_max_tool_calls,
            mcp_timeout_sec,
            "on" if external_enable else "off",
            ",".join(external_tools) or "-",
            external_tool_runs_total,
            external_tool_hit_count,
            ai_plan_call_count,
            ai_plan_ok_count,
            ai_plan_error_count,
            ai_plan_usage_total.get("total_tokens", 0),
            source_counter_text,
            "true" if knowledge_loaded else "false",
            knowledge_tokens_preview,
        )
        logger.info(
            "task_id:{} ai_pen_test done {} elapsed_ms:{}".format(
                self.task_id, summary_text, elapsed_ms
            )
        )
        plan_log_status = "ok"
        if ai_plan_call_count <= 0:
            plan_log_status = "skipped"
        elif ai_plan_ok_count <= 0 and ai_plan_error_count > 0:
            plan_log_status = "error"
        self._write_ai_pen_test_usage_log(
            scene="ai_pen_test_plan",
            status=plan_log_status,
            provider=runtime_provider,
            model=runtime_model,
            profile=runtime_profile,
            request_text="AI渗透测试计划",
            reply_text=summary_text,
            elapsed_ms=elapsed_ms,
            usage=ai_plan_usage_total,
            meta={
                "task_id": self.task_id,
                "ai_pen_enable": ai_pen_enable,
                "mcp_enable": mcp_enable,
                "ai_planner_enable": ai_planner_enable,
                "mcp_max_tool_calls": mcp_max_tool_calls,
                "mcp_timeout_sec": mcp_timeout_sec,
                "external_enable": external_enable,
                "external_tools": external_tools,
                "external_timeout_sec": external_timeout_sec,
                "external_max_runs": external_max_runs,
                "external_tool_runs_total": external_tool_runs_total,
                "external_tool_hit_count": external_tool_hit_count,
                "ai_plan_max_cases": ai_plan_max_cases,
                "ai_plan_call_count": ai_plan_call_count,
                "ai_plan_ok_count": ai_plan_ok_count,
                "ai_plan_error_count": ai_plan_error_count,
                "ai_plan_skip_count": ai_plan_skip_count,
                "ai_plan_error_samples": ai_plan_error_samples[:6],
                "ai_plan_usage": dict(ai_plan_usage_total),
                "ai_prompt_content_preview": self._clip_text(ai_prompt_content, 380),
                "source_counter": source_counter,
                "knowledge_index_loaded": knowledge_loaded,
                "knowledge_index_path": knowledge_path,
                "knowledge_index_token_count": knowledge_index_token_count,
                "knowledge_hit_tokens": sorted(list(knowledge_hit_tokens_set))[:80],
                "candidate_count": len(candidates),
                "selected_count": len(selected_candidates),
                "saved_count": saved_count,
                "verified_count": verified_count,
                "likely_false_positive_count": false_positive_count,
                "error_count": error_count,
            },
        )
        exec_status = "error" if (len(selected_candidates) > 0 and error_count >= len(selected_candidates)) else "ok"
        if ai_plan_call_count > 0 and ai_plan_ok_count == 0 and ai_plan_error_count >= ai_plan_call_count:
            exec_status = "error"
        self._write_ai_pen_test_usage_log(
            scene="ai_pen_test_exec",
            status=exec_status,
            provider=runtime_provider,
            model=runtime_model,
            profile=runtime_profile,
            request_text="AI渗透测试执行",
            reply_text=summary_text,
            elapsed_ms=elapsed_ms,
            usage=ai_plan_usage_total,
            meta={
                "task_id": self.task_id,
                "ai_pen_enable": ai_pen_enable,
                "mcp_enable": mcp_enable,
                "ai_planner_enable": ai_planner_enable,
                "mcp_max_tool_calls": mcp_max_tool_calls,
                "mcp_timeout_sec": mcp_timeout_sec,
                "external_enable": external_enable,
                "external_tools": external_tools,
                "external_timeout_sec": external_timeout_sec,
                "external_max_runs": external_max_runs,
                "external_tool_runs_total": external_tool_runs_total,
                "external_tool_hit_count": external_tool_hit_count,
                "ai_plan_max_cases": ai_plan_max_cases,
                "ai_plan_call_count": ai_plan_call_count,
                "ai_plan_ok_count": ai_plan_ok_count,
                "ai_plan_error_count": ai_plan_error_count,
                "ai_plan_skip_count": ai_plan_skip_count,
                "ai_plan_error_samples": ai_plan_error_samples[:6],
                "ai_plan_usage": dict(ai_plan_usage_total),
                "source_counter": source_counter,
                "knowledge_index_loaded": knowledge_loaded,
                "knowledge_index_path": knowledge_path,
                "knowledge_index_token_count": knowledge_index_token_count,
                "knowledge_hit_tokens": sorted(list(knowledge_hit_tokens_set))[:80],
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
