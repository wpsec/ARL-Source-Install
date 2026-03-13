"""
通用任务执行框架
"""
import time
import re
import os
from urllib.parse import urlparse
from bson import ObjectId
from app import utils
from app import services
from app.config import Config, normalize_dict_path_compat
from app.modules import CollectSource, WebSiteFetchStatus, WebSiteFetchOption
from app.services.nuclei_scan import nuclei_scan
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

        stat = utils.arl.task_statistic(self.task_id)

        logger.info("insert task stat")

        update = {"$set": {"statistic": stat}}

        utils.conn_db('task').update_one(query, update)

    def insert_finger_stat(self):
        finger_stat_map = utils.arl.gen_stat_finger_map(self.task_id)
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
    def __init__(self, task_id: str, sites: list, options: dict, scope_domain: list = None):
        self.task_id = task_id
        self.sites = sites  # ** 这个是用户提交的目标
        self.options = options
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

    @property
    def task_domain_set(self):
        if self._task_domain_set is None:
            self._task_domain_set = set(utils.arl.get_domain_by_id(self.task_id))

        return self._task_domain_set

    def site_identify(self):
        # ** 调用指纹识别
        self.web_analyze_map = services.web_analyze(self.available_sites)

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

        site_spider_result = services.site_spider_thread(entry_urls_list)
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
            page_map = services.page_fetch(spider_urls)
            for url in page_map:
                item = build_url_item(url, self.task_id, source=CollectSource.SITESPIDER)
                item.update(page_map[url])
                utils.conn_db('url').insert_one(item)

    def fetch_site(self):
        # ***站点信息获取***
        self.site_info_list = services.fetch_site(self.sites)
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
            pages = services.file_leak([site], file_leak_dict_words)
            for page in pages:
                item = page.dump_json()
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

        site_finger_map = {}
        query = {
            "task_id": self.task_id,
            "site": {"$in": poc_sites},
        }
        fields = {"site": 1, "finger": 1, "http_server": 1, "title": 1}
        for item in utils.conn_db('site').find(query, fields):
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

        nuclei_targets = []
        for site in poc_sites:
            nuclei_targets.append(
                {
                    "target": site,
                    "finger": site_finger_map.get(site, []),
                }
            )

        return nuclei_targets

    def nuclei_scan(self):
        nuclei_targets = self.build_nuclei_targets()
        finger_hit_count = 0
        for item in nuclei_targets:
            if item.get("finger"):
                finger_hit_count += 1

        logger.info(
            "start nuclei_scan, poc_sites:{} finger_hit:{}".format(
                len(nuclei_targets), finger_hit_count
            )
        )
        scan_results = nuclei_scan(nuclei_targets)
        for item in scan_results:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('nuclei_result').insert_one(item)

        logger.info("end nuclei_scan， result:{}".format(len(scan_results)))

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
        content = str(getattr(record, "content", "") or "").strip().lower()
        if not record_type and not content:
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

        sensitive_keywords = (
            "app_key",
            "api_key",
            "access_key",
            "secret_key",
            "client_secret",
            "private_key",
            "authorization: bearer",
            "password",
            "passwd",
            "token",
            "jwt",
        )
        for keyword in sensitive_keywords:
            if keyword in content:
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
        records = set(services.run_wih(self.sites))
        if records:
            trufflehog_records = set(services.run_trufflehog_js(self.sites, list(records)))
            if trufflehog_records:
                records |= trufflehog_records

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
        # *** 对站点进行基本信息的获取
        self.run_func(WebSiteFetchStatus.FETCH_SITE, self.fetch_site)

        """ *** 执行站点识别 """
        if self.options.get(WebSiteFetchOption.SITE_IDENTIFY):
            self.run_func(WebSiteFetchStatus.SITE_IDENTIFY, self.site_identify)

        """ *** 保存站点信息到数据库 """
        self.save_site_info()

        # 清空，节省内存
        self.site_info_list = []

        """ *** 站点截图 """
        if self.options.get(WebSiteFetchOption.SITE_CAPTURE):
            self.run_func(WebSiteFetchStatus.SITE_CAPTURE, self.site_screenshot)

        """ ***调用站点爬虫发现URL """
        if self.options.get(WebSiteFetchOption.SITE_SPIDER):
            self.update_page_url_set()
            self.run_func(WebSiteFetchStatus.SITE_SPIDER, self.site_spider)

        """ *** 对站点进行文件目录爆破 """
        if self.options.get(WebSiteFetchOption.FILE_LEAK):
            self.run_func(WebSiteFetchStatus.FILE_LEAK, self.file_leak)

        """ *** 对站点运行 nuclei """
        if self.options.get(WebSiteFetchOption.NUCLEI_SCAN):
            self.run_func(WebSiteFetchStatus.NUCLEI_SCAN, self.nuclei_scan)

        """ *** 对站点调用 WebInfoHunter """
        if self.options.get(WebSiteFetchOption.Info_Hunter):
            self.run_func(WebSiteFetchStatus.Info_Hunter, self.run_web_info_hunter)


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
