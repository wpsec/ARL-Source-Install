"""
通用任务执行框架
"""
import time
import re
import os
import json
import yaml
import subprocess
import base64
import hashlib
import hmac
import requests
from types import SimpleNamespace
from urllib.parse import urlparse, parse_qsl, urlencode, urlsplit, urlunsplit, urljoin
from bson import ObjectId
from pymongo.errors import NetworkTimeout, AutoReconnect, ServerSelectionTimeoutError
from app import utils
from app import services
from app.config import Config, normalize_dict_path_compat
from app.modules import CollectSource, WebSiteFetchStatus, WebSiteFetchOption
from app.services.nuclei_scan import nuclei_scan, NucleiScan
from app.services.afrog_scan import run_afrog_scan
from app.services.waf_guard import WAFSmartSkipGuard
from app.services.ai_pen_mcp_runtime import AiPenMcpRuntime, ToolSchema
from app.services.task_scope_guard import load_task_scope_context, host_in_scope, url_in_scope
from app.services import run_risk_cruising, BaseUpdateTask
logger = utils.get_logger()


# 任务类中一些相关公共类
class CommonTask(object):
    def __init__(self, task_id):
        self.task_id = task_id
        self._task_scope_context_cache = None

    def _get_task_scope_context(self, seed_sites=None, scope_domains=None):
        if isinstance(self._task_scope_context_cache, dict) and self._task_scope_context_cache:
            return self._task_scope_context_cache
        self._task_scope_context_cache = load_task_scope_context(
            task_id=self.task_id,
            seed_sites=seed_sites,
            scope_domains=scope_domains,
        )
        return self._task_scope_context_cache

    def _url_in_task_scope(self, value: str, seed_sites=None, scope_domains=None) -> bool:
        context = self._get_task_scope_context(seed_sites=seed_sites, scope_domains=scope_domains)
        return url_in_scope(value, context.get("allowed_hosts", []), context.get("allowed_flds", []))

    def _host_in_task_scope(self, value: str, seed_sites=None, scope_domains=None) -> bool:
        context = self._get_task_scope_context(seed_sites=seed_sites, scope_domains=scope_domains)
        return host_in_scope(value, context.get("allowed_hosts", []), context.get("allowed_flds", []))

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
    AI_PEN_MCP_RUNTIME_VERSION = "p0-local-v1"
    AI_PEN_TEST_AI_PLAN_MAX_CASES = 24
    AI_PEN_TEST_BODY_MAX = 8192
    AI_PEN_TEST_EVIDENCE_MAX = 280
    AI_PEN_TEST_ERROR_MAX = 180
    AI_PEN_TEST_REASON_MAX = 420
    AI_PEN_TEST_PAYLOAD_MAX = 220
    AI_PEN_TEST_REQUEST_PACKET_MAX = 2600
    AI_PEN_PRODUCT_HINT_MAX = 8
    AI_PEN_JS_REQUEST_WINDOW_SIZE = 800
    AI_PEN_JS_MAX_API_TARGETS = 20
    AI_PEN_TEST_SUPPORTED_PAYLOAD_TYPES = (
        "xss_probe",
        "sqli_probe",
        "cmdi_probe",
        "ssrf_probe",
        "ssti_probe",
        "xxe_probe",
        "weak_password_probe",
        "idor_probe",
        "api_doc_probe",
        "graphql_probe",
        "jwt_probe",
        "websocket_probe",
        "file_probe",
        "upload_probe",
        "config_probe",
        "replay",
    )
    AI_PEN_RUNTIME_TOOL_NAMES = (
        "http_fetch",
        "head_probe",
        "extract_links",
        "extract_forms",
        "extract_headers",
        "session_start",
        "session_request",
        "follow_redirect",
        "cookie_jar_update",
        "extract_csrf_token",
        "login_probe",
        "credential_probe",
        "detect_login_success",
        "logout_probe",
        "token_replay",
        "payload_probe",
        "xss_probe",
        "sqli_probe",
        "ssrf_probe",
        "ssti_probe",
        "xxe_probe",
        "cmdi_probe",
        "idor_probe",
        "api_doc_probe",
        "graphql_probe",
        "jwt_probe",
        "websocket_probe",
        "file_probe",
        "upload_probe",
        "config_probe",
    )
    AI_PEN_EXTERNAL_TOOL_REGISTRY = (
        "sqlmap",
        "httpx",
    )
    AI_PEN_EXTERNAL_TOOL_DIR_ENV_KEY = "ARL_AI_PEN_EXTERNAL_TOOL_DIR"
    AI_PEN_EXTERNAL_TOOL_DIR_REL_PATH = os.path.join("tools", "ai_pen_tools")
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
    AI_PEN_SUCCESS_STATUS_SET = {200, 201, 202, 203, 204, 206}
    AI_PEN_EXTRA_SURFACE_HINTS = {
        "api_doc_surface": ("swagger", "openapi", "api-docs", "postman", "knife4j", "redoc"),
        "graphql_surface": ("graphql", "graphiql", "graphql-playground", "apollo", "relay"),
        "js_bundler_app": ("_nuxt", "nuxt", "__nuxt__", "webpack", "__webpack_require__", "webpackjson", "__vite__"),
        "admin_office_portal": ("admin", "console", "dashboard", "backend", "manage", "panel", "oa", "office", "协同办公", "工作台", "审批", "流程"),
        "token_auth_flow": ("jwt", "bearer", "oauth", "openid", "access_token", "authorization", "id_token", "refresh_token"),
        "file_handling_surface": ("upload", "download", "attachment", "export", "template", "multipart", "avatar", "import", "附件", "上传", "下载", "导出", "模板"),
        "login_entry_surface": ("login", "signin", "sign-in", "sso", "cas", "passport", "认证", "登录", "统一身份认证", "单点登录"),
    }
    AI_PEN_CAPABILITY_PROFILES = {
        "api_doc_surface": {
            "priority": 100,
            "route_hint": "api_doc_structure",
            "preferred_payload_type": "api_doc_probe",
            "focus_paths": ["auth_paths", "sample_paths"],
            "focus_params": ["parameter_names"],
            "priority_actions": [
                "优先从 API 文档中筛选鉴权相关、对象ID风格、上传/下载接口",
                "优先围绕 securitySchemes、鉴权相关接口和高价值参数做低副作用验证",
            ],
        },
        "graphql_surface": {
            "priority": 96,
            "route_hint": "graphql_schema_context",
            "preferred_payload_type": "graphql_probe",
            "focus_paths": ["sample_paths", "auth_paths"],
            "focus_params": ["parameter_names"],
            "priority_actions": [
                "优先确认 GraphQL 入口是否真实可访问，再区分 introspection、playground 与鉴权边界",
                "若入口可用，优先保留 schema/operation 线索给渗透工程师继续黑盒深挖",
            ],
        },
        "admin_office_portal": {
            "priority": 90,
            "route_hint": "admin_portal_context",
            "preferred_payload_type": "replay",
            "focus_paths": ["auth_paths", "sample_paths"],
            "focus_params": ["parameter_names"],
            "priority_actions": [
                "优先关注管理后台、办公门户、工作流入口、文档暴露与文件处理能力",
                "若接口结构存在对象ID参数，优先安排越权/鉴权边界验证建议",
            ],
        },
        "js_bundler_app": {
            "priority": 88,
            "route_hint": "js_static_context",
            "preferred_payload_type": "replay",
            "focus_paths": ["sample_paths"],
            "focus_params": ["parameter_names"],
            "priority_actions": [
                "优先分析静态JS中提取出的接口、参数和鉴权线索，而不是只看构建产物关键词",
                "优先区分真实接口暴露与前端框架运行时代码噪声",
            ],
        },
        "token_auth_flow": {
            "priority": 84,
            "route_hint": "jwt_token_first",
            "preferred_payload_type": "jwt_probe",
            "focus_paths": ["auth_paths", "sample_paths"],
            "focus_params": ["parameter_names"],
            "priority_actions": [
                "优先确认 token 是否真实存在，再考虑 alg、签名方式与重放行为",
                "若 API 文档或 JS 提取接口包含 token/auth 参数，优先围绕这些入口做验证建议",
            ],
        },
        "file_handling_surface": {
            "priority": 82,
            "route_hint": "file_handling_context",
            "preferred_payload_type": "upload_probe",
            "focus_paths": ["sample_paths", "auth_paths"],
            "focus_params": ["parameter_names"],
            "priority_actions": [
                "优先区分发现文件处理入口与已证明任意文件读写，避免把导出/附件功能直接判成漏洞",
                "优先围绕 multipart 表单、下载响应头、导出/附件路径和文件参数做低副作用验证",
            ],
        },
        "login_entry_surface": {
            "priority": 80,
            "route_hint": "login_entry_context",
            "preferred_payload_type": "replay",
            "focus_paths": ["auth_paths", "sample_paths"],
            "focus_params": ["parameter_names"],
            "priority_actions": [
                "优先识别登录表单、验证码/风控线索、认证相关接口与运行时 token/session 路径",
                "优先补足黑盒登录前上下文，不将登录页本身直接判定为漏洞",
            ],
        },
    }
    AI_PEN_AUTH_PATH_KEYWORDS = ("login", "auth", "token", "oauth", "signin", "session", "user", "me", "current")
    AI_PEN_LOGIN_PAGE_KEYWORDS = ("login", "signin", "sign-in", "sso", "cas", "passport", "登录", "认证", "统一身份认证", "单点登录")
    AI_PEN_CAPTCHA_HINTS = ("captcha", "verifycode", "verification", "checkcode", "validatecode", "randcode", "yzm", "图形码", "验证码")
    AI_PEN_CSRF_FIELD_HINTS = ("csrf", "token", "_token", "authenticity", "xsrf", "nonce")
    AI_PEN_IDOR_SENSITIVE_MARKERS = (
        "email",
        "mobile",
        "phone",
        "username",
        "realname",
        "nickname",
        "tenant",
        "role",
        "permission",
        "isadmin",
        "address",
        "department",
        "orderno",
        "invoice",
    )
    AI_PEN_LOGIN_SUCCESS_KEYWORDS = (
        "login success",
        "logged in",
        "welcome",
        "dashboard",
        "sign out",
        "logout",
        "退出登录",
        "欢迎您",
        "控制台",
        "工作台",
        "后台首页",
    )
    AI_PEN_LOGIN_FAILURE_KEYWORDS = (
        "invalid password",
        "invalid username",
        "login failed",
        "incorrect password",
        "bad credentials",
        "wrong password",
        "authentication failed",
        "用户名或密码错误",
        "账号或密码错误",
        "密码错误",
        "登录失败",
        "认证失败",
    )
    AI_PEN_LOGIN_BLOCK_KEYWORDS = (
        "captcha",
        "验证码",
        "locked",
        "lockout",
        "too many attempts",
        "try again later",
        "账户锁定",
        "账号锁定",
        "频繁",
    )
    AI_PEN_MINIMAL_DEFAULT_CREDENTIALS = (
        ("admin", "admin"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("guest", "guest"),
        ("test", "test"),
    )
    AI_PEN_PRODUCT_DEFAULT_CREDENTIALS = {
        "rabbitmq": (("guest", "guest"),),
        "minio": (("minioadmin", "minioadmin"),),
        "grafana": (("admin", "admin"),),
        "nacos": (("nacos", "nacos"),),
        "tomcat": (("tomcat", "tomcat"),),
        "jenkins": (("admin", "admin"),),
    }
    AI_PEN_OBJECT_ID_PARAM_HINTS = {
        "id", "uid", "userid", "user_id", "memberid", "member_id", "accountid", "account_id",
        "customerid", "customer_id", "profileid", "profile_id", "tenantid", "tenant_id",
        "orgid", "org_id", "deptid", "dept_id", "employeeid", "employee_id",
    }
    AI_PEN_UPLOAD_HINTS = ("upload", "multipart", "file", "image", "avatar", "attachment", "import")
    AI_PEN_DOWNLOAD_HINTS = ("download", "export", "file", "attachment", "template", "report")
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
    _AI_PEN_EXTERNAL_TOOL_CACHE = {
        "path": "",
        "stamp": "",
        "tools": {},
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
        self.ai_pen_browser_intel_cache = {}
        self.ai_pen_js_context_cache = {}
        self.ai_pen_task_graph_context_cache = {}
        self._task_scope_context_cache = None

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

    def _get_task_scope_context(self):
        if isinstance(self._task_scope_context_cache, dict) and self._task_scope_context_cache:
            return self._task_scope_context_cache
        self._task_scope_context_cache = load_task_scope_context(
            task_id=self.task_id,
            seed_sites=self.sites,
            scope_domains=self.scope_domain,
        )
        return self._task_scope_context_cache

    def _url_in_task_scope(self, value: str) -> bool:
        context = self._get_task_scope_context()
        return url_in_scope(value, context.get("allowed_hosts", []), context.get("allowed_flds", []))

    def _host_in_task_scope(self, value: str) -> bool:
        context = self._get_task_scope_context()
        return host_in_scope(value, context.get("allowed_hosts", []), context.get("allowed_flds", []))

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
            if not self._scan_result_in_task_scope(item, target_keys=("target", "url")):
                continue
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
            product_labels = []
            for label_item in item.get("product_labels", []) if isinstance(item.get("product_labels"), list) else []:
                if not isinstance(label_item, dict):
                    continue
                label_name = str(label_item.get("name") or "").strip()
                if not label_name:
                    continue
                product_labels.append(
                    {
                        "name": label_name[:64],
                        "count": max(0, cls._safe_int_value(label_item.get("count"), 0)),
                    }
                )
                if len(product_labels) >= 8:
                    break
            vuln_types = []
            for vuln_item in item.get("vuln_types", []) if isinstance(item.get("vuln_types"), list) else []:
                if not isinstance(vuln_item, dict):
                    continue
                vuln_name = str(vuln_item.get("name") or "").strip()
                if not vuln_name:
                    continue
                vuln_types.append(
                    {
                        "name": vuln_name[:32],
                        "count": max(0, cls._safe_int_value(vuln_item.get("count"), 0)),
                    }
                )
                if len(vuln_types) >= 8:
                    break
            entry_paths = []
            for path_item in item.get("entry_paths", []) if isinstance(item.get("entry_paths"), list) else []:
                path_text = str(path_item or "").strip()
                if path_text:
                    entry_paths.append(path_text[:180])
                if len(entry_paths) >= 6:
                    break
            verify_actions = []
            for action_item in item.get("verify_actions", []) if isinstance(item.get("verify_actions"), list) else []:
                action_text = str(action_item or "").strip()
                if action_text:
                    verify_actions.append(action_text[:120])
                if len(verify_actions) >= 4:
                    break
            record_refs = []
            for ref_item in item.get("record_refs", []) if isinstance(item.get("record_refs"), list) else []:
                if not isinstance(ref_item, dict):
                    continue
                record_refs.append(
                    {
                        "source": str(ref_item.get("source") or "").strip()[:32],
                        "path": str(ref_item.get("path") or "").strip()[:220],
                        "title": str(ref_item.get("title") or "").strip()[:120],
                        "product_labels": [str(x or "").strip()[:64] for x in list(ref_item.get("product_labels", []) or [])[:3] if str(x or "").strip()],
                        "vuln_types": [str(x or "").strip()[:32] for x in list(ref_item.get("vuln_types", []) or [])[:6] if str(x or "").strip()],
                        "entry_paths": [str(x or "").strip()[:180] for x in list(ref_item.get("entry_paths", []) or [])[:4] if str(x or "").strip()],
                        "verify_actions": [str(x or "").strip()[:120] for x in list(ref_item.get("verify_actions", []) or [])[:4] if str(x or "").strip()],
                    }
                )
                if len(record_refs) >= 4:
                    break
            normalized_token_index[token] = {
                "count": max(0, count),
                "sources": normalized_sources,
                "samples": samples,
                "product_labels": product_labels,
                "vuln_types": vuln_types,
                "entry_paths": entry_paths,
                "verify_actions": verify_actions,
                "record_refs": record_refs,
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
            "hit_product_labels": [],
            "hit_vuln_types": [],
            "hit_entry_paths": [],
            "hit_verify_actions": [],
            "hit_record_refs": [],
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
        product_label_hits = []
        vuln_type_hits = []
        entry_path_hits = []
        verify_action_hits = []
        record_ref_hits = []
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
            for label_item in item.get("product_labels", []) if isinstance(item.get("product_labels"), list) else []:
                if not isinstance(label_item, dict):
                    continue
                label_name = str(label_item.get("name") or "").strip()
                if label_name and label_name not in product_label_hits:
                    product_label_hits.append(label_name[:64])
                if len(product_label_hits) >= 6:
                    break
            for vuln_item in item.get("vuln_types", []) if isinstance(item.get("vuln_types"), list) else []:
                if not isinstance(vuln_item, dict):
                    continue
                vuln_name = str(vuln_item.get("name") or "").strip()
                if vuln_name and vuln_name not in vuln_type_hits:
                    vuln_type_hits.append(vuln_name[:32])
                if len(vuln_type_hits) >= 6:
                    break
            for path_item in item.get("entry_paths", []) if isinstance(item.get("entry_paths"), list) else []:
                path_text = str(path_item or "").strip()
                if path_text and path_text not in entry_path_hits:
                    entry_path_hits.append(path_text[:180])
                if len(entry_path_hits) >= 6:
                    break
            for action_item in item.get("verify_actions", []) if isinstance(item.get("verify_actions"), list) else []:
                action_text = str(action_item or "").strip()
                if action_text and action_text not in verify_action_hits:
                    verify_action_hits.append(action_text[:120])
                if len(verify_action_hits) >= 4:
                    break
            for ref_item in item.get("record_refs", []) if isinstance(item.get("record_refs"), list) else []:
                if not isinstance(ref_item, dict):
                    continue
                ref_key = "{}|{}".format(str(ref_item.get("source") or "").strip(), str(ref_item.get("path") or "").strip())
                if ref_key and all(
                    "{}|{}".format(str(old.get("source") or "").strip(), str(old.get("path") or "").strip()) != ref_key
                    for old in record_ref_hits
                ):
                    record_ref_hits.append(ref_item)
                if len(record_ref_hits) >= 4:
                    break
            if len(matched_tokens) >= 12:
                break

        score = min(20, len(matched_tokens) * 2 + len(product_label_hits) + len(entry_path_hits))
        result["hit_tokens"] = matched_tokens
        result["hit_samples"] = sample_hits
        result["hit_product_labels"] = product_label_hits
        result["hit_vuln_types"] = vuln_type_hits
        result["hit_entry_paths"] = entry_path_hits
        result["hit_verify_actions"] = verify_action_hits
        result["hit_record_refs"] = record_ref_hits
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
            if not self._scan_result_in_task_scope(item, target_keys=("vuln_url", "target")):
                continue
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
            if not self._scan_result_in_task_scope(result, target_keys=("target",)):
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
            if not self._scan_result_in_task_scope(result, target_keys=("url",)):
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
    def _clip_multiline_text(value, max_len=220):
        text = str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
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
        agent_loop_enable = bool(config_obj.get("ai_pen_agent_loop_enable", ai_planner_enable and mcp_enable))
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
            "agent_loop_enable": agent_loop_enable,
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
        if any(token in merged for token in ("weak password", "default password", "default credential", "弱口令", "弱密码", "默认密码", "默认口令", "登录成功")):
            return "weak_password_probe"
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
    def _normalize_ai_pen_external_tools(cls, value, max_count=12):
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
            if not re.match(r"^[a-z0-9][a-z0-9_-]{0,63}$", tool):
                continue
            seen.add(tool)
            result.append(tool)
            if len(result) >= max_count:
                break
        return result

    @classmethod
    def _resolve_ai_pen_external_tool_dir_path(cls) -> str:
        env_dir = str(os.environ.get(cls.AI_PEN_EXTERNAL_TOOL_DIR_ENV_KEY, "") or "").strip()
        if env_dir:
            return os.path.abspath(env_dir)

        cfg_dir = str(getattr(Config, "AI_PEN_EXTERNAL_TOOL_DIR", "") or "").strip()
        if cfg_dir:
            return os.path.abspath(cfg_dir)

        current_dir = os.path.abspath(os.path.dirname(__file__))
        return os.path.abspath(
            os.path.join(current_dir, os.pardir, os.pardir, cls.AI_PEN_EXTERNAL_TOOL_DIR_REL_PATH)
        )

    @staticmethod
    def _parse_ai_pen_external_manifest_file(file_path: str):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                if str(file_path).lower().endswith(".json"):
                    return json.load(f)
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning("load ai pen external tool manifest failed path:{} err:{}".format(file_path, e))
            return None

    @classmethod
    def _normalize_ai_pen_external_manifest(cls, raw_item):
        if not isinstance(raw_item, dict):
            return {}

        tool_id = str(raw_item.get("id") or raw_item.get("tool_id") or "").strip().lower()
        if not tool_id or not re.match(r"^[a-z0-9][a-z0-9_-]{0,63}$", tool_id):
            return {}

        enabled = bool(raw_item.get("enabled", True))

        exec_obj = raw_item.get("exec") if isinstance(raw_item.get("exec"), dict) else {}
        exec_bin = str(exec_obj.get("bin") or raw_item.get("bin") or "").strip()

        args_template = exec_obj.get("args_template")
        if args_template is None:
            args_template = raw_item.get("args_template")
        if isinstance(args_template, str):
            args_template = [item for item in re.split(r"\s+", args_template.strip()) if item]
        elif not isinstance(args_template, list):
            args_template = []
        normalized_args = [str(item or "").strip() for item in args_template if str(item or "").strip()]

        timeout_sec = cls._safe_int_value(exec_obj.get("timeout_sec", raw_item.get("timeout_sec", 45)), 45)
        if timeout_sec < 5:
            timeout_sec = 5
        if timeout_sec > 300:
            timeout_sec = 300

        match_obj = raw_item.get("match") if isinstance(raw_item.get("match"), dict) else {}
        payload_types = cls._normalize_ai_pen_external_tools(match_obj.get("payload_types", []), max_count=24)
        risk_types = cls._normalize_ai_pen_external_tools(match_obj.get("risk_types", []), max_count=24)
        risk_keywords = []
        for keyword in match_obj.get("risk_keywords", []) if isinstance(match_obj.get("risk_keywords"), list) else []:
            kw = str(keyword or "").strip().lower()
            if kw and kw not in risk_keywords:
                risk_keywords.append(kw[:80])
            if len(risk_keywords) >= 48:
                break
        requires_query = bool(match_obj.get("requires_query", False))

        result_obj = raw_item.get("result") if isinstance(raw_item.get("result"), dict) else {}
        success_regex = []
        for pattern in result_obj.get("success_regex", []) if isinstance(result_obj.get("success_regex"), list) else []:
            p = str(pattern or "").strip()
            if p:
                success_regex.append(p[:240])
            if len(success_regex) >= 24:
                break
        negative_regex = []
        for pattern in result_obj.get("negative_regex", []) if isinstance(result_obj.get("negative_regex"), list) else []:
            p = str(pattern or "").strip()
            if p:
                negative_regex.append(p[:240])
            if len(negative_regex) >= 24:
                break

        hit_decision = cls._normalize_ai_pen_decision(result_obj.get("hit_decision"), default_value="verified")
        hit_confidence = cls._clamp_ai_pen_confidence(result_obj.get("hit_confidence"), 0.90)
        hit_reason = cls._clip_text(result_obj.get("hit_reason", ""), 120)

        negative_decision = cls._normalize_ai_pen_decision(
            result_obj.get("negative_decision"), default_value="likely_false_positive"
        )
        negative_confidence = cls._clamp_ai_pen_confidence(result_obj.get("negative_confidence"), 0.65)
        negative_reason = cls._clip_text(result_obj.get("negative_reason", ""), 120)

        verification_step = str(
            result_obj.get("verification_step") or "mcp_external_{}".format(tool_id)
        ).strip()[:64]
        config_bin_key = str(raw_item.get("config_bin_key") or "").strip()

        return {
            "id": tool_id,
            "enabled": enabled,
            "description": cls._clip_text(raw_item.get("description", ""), 240),
            "exec_bin": exec_bin,
            "args_template": normalized_args,
            "timeout_sec": timeout_sec,
            "match_payload_types": payload_types,
            "match_risk_types": risk_types,
            "match_risk_keywords": risk_keywords,
            "requires_query": requires_query,
            "success_regex": success_regex,
            "negative_regex": negative_regex,
            "hit_decision": hit_decision,
            "hit_confidence": hit_confidence,
            "hit_reason": hit_reason,
            "negative_decision": negative_decision,
            "negative_confidence": negative_confidence,
            "negative_reason": negative_reason,
            "verification_step": verification_step,
            "config_bin_key": config_bin_key,
        }

    @classmethod
    def _built_in_ai_pen_external_manifests(cls):
        builtin_items = [
            {
                "id": "sqlmap",
                "enabled": True,
                "description": "SQL 注入探测工具",
                "config_bin_key": "SQLMAP_BIN",
                "exec": {
                    "bin": "sqlmap",
                    "timeout_sec": 45,
                    "args_template": [
                        "-u", "{target_url}",
                        "--batch",
                        "--smart",
                        "--random-agent",
                        "--level", "1",
                        "--risk", "1",
                        "--threads", "1",
                        "--timeout", "10",
                        "--retries", "0",
                        "--disable-coloring",
                    ],
                },
                "match": {
                    "payload_types": ["sqli_probe"],
                    "risk_keywords": ["sqli", "sql"],
                    "requires_query": True,
                },
                "result": {
                    "success_regex": [
                        "is vulnerable",
                        "identified the following injection point",
                        "sql injection vulnerability",
                        "parameter ['\\\"]",
                        "injectable",
                    ],
                    "negative_regex": [
                        "all tested parameters do not appear to be injectable",
                        "does not seem to be injectable",
                        "not injectable",
                        "no parameter\\(s\\) found for testing",
                    ],
                    "hit_decision": "verified",
                    "hit_confidence": 0.94,
                    "hit_reason": "sqlmap 命中注入特征",
                    "negative_decision": "likely_false_positive",
                    "negative_confidence": 0.68,
                    "negative_reason": "sqlmap 未发现可注入参数",
                    "verification_step": "mcp_external_sqlmap",
                },
            },
            {
                "id": "httpx",
                "enabled": True,
                "description": "HTTP 协议特征探测工具",
                "config_bin_key": "HTTPX_BIN",
                "exec": {
                    "bin": "httpx",
                    "timeout_sec": 30,
                    "args_template": ["-u", "{target_url}", "-silent", "-status-code", "-title"],
                },
                "match": {
                    "payload_types": ["websocket_probe", "api_doc_probe"],
                    "risk_types": ["websocket", "api_doc"],
                    "risk_keywords": ["websocket", "api_doc", "swagger", "openapi", "api-docs"],
                },
                "result": {
                    "hit_decision": "needs_manual_review",
                    "hit_confidence": 0.72,
                    "verification_step": "mcp_external_httpx",
                },
            },
        ]

        normalized = {}
        for item in builtin_items:
            manifest = cls._normalize_ai_pen_external_manifest(item)
            if manifest and manifest.get("id"):
                normalized[manifest["id"]] = manifest
        return normalized

    @classmethod
    def _load_ai_pen_external_tool_manifests(cls):
        tool_dir = cls._resolve_ai_pen_external_tool_dir_path()
        file_paths = []
        if os.path.isdir(tool_dir):
            for name in sorted(os.listdir(tool_dir)):
                lower_name = str(name or "").lower()
                if not (lower_name.endswith(".yaml") or lower_name.endswith(".yml") or lower_name.endswith(".json")):
                    continue
                full_path = os.path.join(tool_dir, name)
                if os.path.isfile(full_path):
                    file_paths.append(full_path)

        stamp_items = [tool_dir]
        for path in file_paths:
            try:
                stat_obj = os.stat(path)
                stamp_items.append("{}:{}:{}".format(path, int(stat_obj.st_mtime), int(stat_obj.st_size)))
            except Exception:
                stamp_items.append("{}:0:0".format(path))
        stamp = "|".join(stamp_items)

        cache = cls._AI_PEN_EXTERNAL_TOOL_CACHE if isinstance(cls._AI_PEN_EXTERNAL_TOOL_CACHE, dict) else {}
        cached_tools = cache.get("tools")
        if cache.get("path") == tool_dir and cache.get("stamp") == stamp and isinstance(cached_tools, dict):
            return cached_tools, tool_dir

        manifests = cls._built_in_ai_pen_external_manifests()
        for file_path in file_paths:
            parsed = cls._parse_ai_pen_external_manifest_file(file_path)
            if parsed is None:
                continue
            items = parsed if isinstance(parsed, list) else [parsed]
            for raw_item in items:
                manifest = cls._normalize_ai_pen_external_manifest(raw_item)
                if not manifest:
                    continue
                if not manifest.get("enabled", True):
                    continue
                manifests[manifest.get("id")] = manifest

        cls._AI_PEN_EXTERNAL_TOOL_CACHE = {
            "path": tool_dir,
            "stamp": stamp,
            "tools": manifests,
        }
        return manifests, tool_dir

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

    @classmethod
    def _render_ai_pen_external_args(cls, args_template, context: dict):
        if not isinstance(args_template, list):
            return []
        safe_context = {}
        for key, value in (context or {}).items():
            safe_context[str(key)] = str(value or "")
        rendered = []
        for item in args_template:
            text = str(item or "").strip()
            if not text:
                continue
            try:
                next_text = text.format(**safe_context)
            except Exception:
                next_text = text
            if next_text:
                rendered.append(next_text)
        return rendered

    @staticmethod
    def _match_ai_pen_external_output_regex(output_text: str, patterns) -> bool:
        output = str(output_text or "")
        if not output or not isinstance(patterns, list):
            return False
        output_lower = output.lower()
        for pattern in patterns:
            text = str(pattern or "").strip()
            if not text:
                continue
            try:
                if re.search(text, output, flags=re.IGNORECASE):
                    return True
            except re.error:
                if text.lower() in output_lower:
                    return True
        return False

    @classmethod
    def _match_ai_pen_external_tool(
            cls,
            manifest: dict,
            *,
            risk_text: str,
            risk_name_text: str,
            payload_text: str,
            target_url: str,
    ) -> bool:
        payload_rules = manifest.get("match_payload_types", []) if isinstance(manifest, dict) else []
        if payload_rules and payload_text not in payload_rules:
            return False

        risk_rules = manifest.get("match_risk_types", []) if isinstance(manifest, dict) else []
        if risk_rules and risk_text not in risk_rules:
            return False

        keyword_rules = manifest.get("match_risk_keywords", []) if isinstance(manifest, dict) else []
        if keyword_rules:
            merged = "{} {} {}".format(risk_text, risk_name_text, payload_text).strip().lower()
            if not any(str(keyword or "").strip().lower() in merged for keyword in keyword_rules):
                return False

        if bool(manifest.get("requires_query", False)):
            parsed = urlsplit(target_url)
            if not str(parsed.query or "").strip():
                return False

        return True

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
            risk_name: str,
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

        manifests, manifest_dir = self._load_ai_pen_external_tool_manifests()
        if not manifests:
            return {
                "decision": base_decision,
                "confidence": base_confidence,
                "reason": "未加载到外部工具说明文件",
                "verification_step": "",
                "tool_trace": "external(skip_no_manifest)",
                "tool_runs": [],
                "tool_hit": False,
            }

        timeout_sec = self._safe_int_value(runtime_settings.get("external_timeout_sec"), 45)
        if timeout_sec < 5:
            timeout_sec = 5
        if timeout_sec > 300:
            timeout_sec = 300
        max_runs = self._safe_int_value(runtime_settings.get("external_max_runs"), 1)
        if max_runs < 1:
            max_runs = 1
        if max_runs > 8:
            max_runs = 8

        risk_text = str(risk_type or "").strip().lower()
        risk_name_text = str(risk_name or "").strip().lower()
        payload_text = str(payload_type or "").strip().lower()
        tool_trace_parts = []
        run_manifests = []
        for tool_name in allow_tools:
            manifest = manifests.get(tool_name) if isinstance(manifests, dict) else None
            if not isinstance(manifest, dict):
                tool_trace_parts.append("{}(skip_not_registered)".format(tool_name))
                continue
            if not self._match_ai_pen_external_tool(
                manifest,
                risk_text=risk_text,
                risk_name_text=risk_name_text,
                payload_text=payload_text,
                target_url=target_url,
            ):
                tool_trace_parts.append("{}(skip_not_matched)".format(tool_name))
                continue
            run_manifests.append(manifest)
            if len(run_manifests) >= max_runs:
                break

        if not run_manifests:
            return {
                "decision": base_decision,
                "confidence": base_confidence,
                "reason": "外部工具白名单未命中当前风险类型",
                "verification_step": "",
                "tool_trace": "external(skip_not_matched) @ {}".format(manifest_dir),
                "tool_runs": [],
                "tool_hit": False,
            }

        decision = self._normalize_ai_pen_decision(base_decision, default_value="needs_manual_review")
        confidence = self._clamp_ai_pen_confidence(base_confidence, 0.5)
        reason_parts = []
        tool_runs = []
        hit = False
        verification_step = ""

        command_context = {
            "target_url": target_url,
            "risk_type": risk_text,
            "risk_name": risk_name_text,
            "payload_type": payload_text,
            "task_id": self.task_id,
        }

        for manifest in run_manifests:
            tool_name = str(manifest.get("id") or "").strip().lower()
            if not tool_name:
                continue

            preferred_bin = str(manifest.get("exec_bin") or "").strip()
            cfg_bin_key = str(manifest.get("config_bin_key") or "").strip()
            if cfg_bin_key:
                cfg_bin_value = str(getattr(Config, cfg_bin_key, "") or "").strip()
                if cfg_bin_value:
                    preferred_bin = cfg_bin_value

            binary_path = self._resolve_executable_path(preferred_bin, tool_name)
            if not binary_path:
                tool_trace_parts.append("{}(skip_not_found)".format(tool_name))
                tool_runs.append({
                    "tool": tool_name,
                    "status": "skipped",
                    "message": "binary_not_found",
                    "elapsed_ms": 0,
                })
                continue

            args = self._render_ai_pen_external_args(manifest.get("args_template", []), command_context)
            command = [binary_path]
            command.extend(args)

            manifest_timeout = self._safe_int_value(manifest.get("timeout_sec", timeout_sec), timeout_sec)
            if manifest_timeout < 5:
                manifest_timeout = 5
            if manifest_timeout > timeout_sec:
                manifest_timeout = timeout_sec

            run_ret = self._run_external_command(command, timeout_sec=manifest_timeout)
            output_text = "{}\n{}".format(run_ret.get("stdout", ""), run_ret.get("stderr", ""))
            output_lower = output_text.lower()
            return_code = int(run_ret.get("return_code", -1) or -1)
            elapsed_ms = int(run_ret.get("elapsed_ms", 0) or 0)

            run_status = "ok" if bool(run_ret.get("ok")) else "error"
            run_message = "exit={}".format(return_code)
            positive_hit = False
            negative_hit = False
            if run_status == "ok":
                positive_hit = self._match_ai_pen_external_output_regex(
                    output_text, manifest.get("success_regex", [])
                )
                negative_hit = self._match_ai_pen_external_output_regex(
                    output_text, manifest.get("negative_regex", [])
                )

                if not positive_hit and tool_name == "httpx":
                    if payload_text == "websocket_probe" and (" 101 " in output_lower or "websocket" in output_lower):
                        positive_hit = True
                        run_message = "websocket_hint"
                    elif payload_text == "api_doc_probe" and any(
                        token in output_lower for token in ("swagger", "openapi", "api-docs")
                    ):
                        positive_hit = True
                        run_message = "api_doc_hint"

                if positive_hit:
                    next_decision = self._normalize_ai_pen_decision(
                        manifest.get("hit_decision"), default_value="verified"
                    )
                    if next_decision == "verified" or decision != "verified":
                        decision = next_decision
                    confidence = max(
                        confidence,
                        self._clamp_ai_pen_confidence(manifest.get("hit_confidence"), 0.90)
                    )
                    reason_text = self._clip_text(manifest.get("hit_reason", ""), 120)
                    if not reason_text:
                        reason_text = "{} 命中特征".format(tool_name)
                    reason_parts.append(reason_text)
                    verification_step = verification_step or str(manifest.get("verification_step") or "").strip()
                    run_message = run_message if run_message != "exit={}".format(return_code) else "positive"
                    hit = True
                elif negative_hit:
                    if decision != "verified":
                        decision = self._normalize_ai_pen_decision(
                            manifest.get("negative_decision"),
                            default_value="likely_false_positive",
                        )
                    confidence = max(
                        confidence,
                        self._clamp_ai_pen_confidence(manifest.get("negative_confidence"), 0.65)
                    )
                    reason_text = self._clip_text(manifest.get("negative_reason", ""), 120)
                    if not reason_text:
                        reason_text = "{} 未命中风险特征".format(tool_name)
                    reason_parts.append(reason_text)
                    verification_step = verification_step or str(manifest.get("verification_step") or "").strip()
                    run_message = "negative"
                else:
                    run_message = "inconclusive"
            else:
                run_message = self._clip_text(run_ret.get("stderr", ""), 100) or "error"

            tool_runs.append({
                "tool": tool_name,
                "status": run_status,
                "message": run_message,
                "elapsed_ms": elapsed_ms,
            })
            tool_trace_parts.append("{}({})".format(tool_name, run_message))

        if len(tool_runs) > self.AI_PEN_EXTERNAL_RESULT_MAX:
            tool_runs = tool_runs[: self.AI_PEN_EXTERNAL_RESULT_MAX]

        return {
            "decision": decision,
            "confidence": confidence,
            "reason": "；".join([item for item in reason_parts if item])[:220],
            "verification_step": verification_step,
            "tool_trace": " | ".join(tool_trace_parts)[:260] or "external(ok) @ {}".format(manifest_dir),
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
            "你是AI渗透测试助手，目标是做可控的二次验证与误报收敛，不是盲目利用。"
            "请优先遵守“上下文先行、证据驱动、PoC知识仅作提示不作证明”。"
            "请结合风险类型、URL、参数、响应特征、产品线索、知识命中与路由提示，"
            "评估该结果可信度并给出下一步验证建议。"
            "输出JSON对象，字段包含：decision/confidence/reason/payload_type/payload/evidence/next_actions。"
            "decision 仅允许 verified、likely_false_positive、needs_manual_review。"
            "若为静态JS场景，请区分硬编码字面量与变量拼接/本地存储噪声；"
            "若为API文档场景，请优先围绕文档结构、路径和参数做验证建议；"
            "若为文件处理场景，请区分发现上传/下载/导出入口与已证明任意文件读写；"
            "若为登录页场景，请区分发现认证入口与已证明存在认证缺陷；"
            "若证据不足，必须保持 needs_manual_review，禁止编造不存在的事实。"
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

    @classmethod
    def _collect_ai_pen_surface_hints(cls, candidate: dict, extra_text: str = ""):
        item = candidate if isinstance(candidate, dict) else {}
        raw_parts = [
            str(item.get("source_collection", "") or "").strip(),
            str(item.get("source_module", "") or "").strip(),
            str(item.get("risk_type", "") or "").strip(),
            str(item.get("risk_name", "") or "").strip(),
            str(item.get("target", "") or "").strip(),
            str(item.get("vuln_url", "") or "").strip(),
            str(item.get("evidence_seed", "") or "").strip(),
            " ".join([str(x or "").strip() for x in list(item.get("knowledge_hit_product_labels", []) or [])[:8]]),
            str(extra_text or "").strip(),
        ]
        raw_parts.extend([str(token or "").strip() for token in list(item.get("knowledge_hit_tokens", []) or [])[:24]])
        merged = " ".join([part for part in raw_parts if part]).strip().lower()
        if not merged:
            return []

        hints = []
        seen = set()

        def append_hint(name: str):
            hint = str(name or "").strip().lower()
            if not hint or hint in seen:
                return
            seen.add(hint)
            hints.append(hint)

        for canonical_name, alias_list in cls.AI_POC_ALIAS_HINTS.items():
            hint_tokens = [str(canonical_name or "").strip()] + list(alias_list or [])
            for token in hint_tokens:
                token_text = str(token or "").strip().lower()
                if token_text and token_text in merged:
                    append_hint(canonical_name)
                    break

        for canonical_name, alias_list in cls.AI_PEN_EXTRA_SURFACE_HINTS.items():
            for token in alias_list:
                token_text = str(token or "").strip().lower()
                if token_text and token_text in merged:
                    append_hint(canonical_name)
                    break

        return hints[: cls.AI_PEN_PRODUCT_HINT_MAX]

    @classmethod
    def _collect_ai_pen_product_hints(cls, candidate: dict, extra_text: str = ""):
        """
        兼容旧调用名，内部统一走通用 surface_hints。
        """
        return cls._collect_ai_pen_surface_hints(candidate, extra_text=extra_text)

    @classmethod
    def _build_ai_pen_route_hint(cls, candidate: dict):
        item = candidate if isinstance(candidate, dict) else {}
        target_url = str(item.get("vuln_url") or item.get("target") or "").strip()
        risk_type = str(item.get("risk_type", "") or "").strip().lower()
        api_surface_summary = item.get("api_surface_summary") if isinstance(item.get("api_surface_summary"), dict) else {}
        browser_surface_summary = item.get("browser_surface_summary") if isinstance(item.get("browser_surface_summary"), dict) else {}
        dom_form_summary = list(item.get("dom_form_summary", []) or [])
        page_title = str(browser_surface_summary.get("page_title") or "").strip().lower()
        page_url_text = str(browser_surface_summary.get("page_url") or target_url or "").strip().lower()

        if cls._is_js_asset_target(target_url):
            if risk_type == "sensitive_info":
                return "js_sensitive_context"
            if risk_type == "xss":
                return "js_dom_context"
            return "js_static_context"
        if risk_type == "login_surface":
            return "login_entry_context"
        if risk_type in {"file_upload", "file_read"}:
            return "file_handling_context"
        if risk_type == "api_doc":
            return "api_doc_structure"
        if risk_type == "graphql":
            return "graphql_schema_context"
        if risk_type == "jwt":
            return "jwt_token_first"
        if risk_type == "websocket":
            return "websocket_handshake"
        if risk_type == "idor":
            return "structured_id_mutation"
        if (
            cls._safe_int_value(api_surface_summary.get("upload_like_count"), 0) > 0
            or cls._safe_int_value(api_surface_summary.get("download_like_count"), 0) > 0
        ):
            return "file_handling_context"
        if any(token in page_title or token in page_url_text for token in cls.AI_PEN_LOGIN_PAGE_KEYWORDS):
            return "login_entry_context"
        for form_item in dom_form_summary:
            if not isinstance(form_item, dict):
                continue
            fields_text = str(form_item.get("fields") or "").strip().lower()
            has_password = str(form_item.get("has_password_input") or "").strip().lower() in {"1", "true", "yes"}
            if has_password or "password" in fields_text or "passwd" in fields_text:
                return "login_entry_context"
        if risk_type in {"sqli", "cmdi", "ssrf"}:
            return "low_side_effect_probe"
        return "http_replay_then_context"

    @staticmethod
    def _is_browser_intel_candidate_url(target_url: str):
        url_text = str(target_url or "").strip()
        if not url_text:
            return False
        if not WebSiteFetch._is_http_target(url_text):
            return False
        if WebSiteFetch._is_js_asset_target(url_text):
            return False

        try:
            parsed = urlsplit(url_text)
            path_text = str(parsed.path or "").strip().lower()
        except Exception:
            path_text = str(url_text or "").strip().lower()

        static_suffix = (
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".map", ".pdf", ".zip", ".rar", ".txt", ".json",
        )
        if path_text.endswith(static_suffix):
            return False
        return True

    @classmethod
    def _is_ai_pen_browser_intel_enabled(cls):
        return bool(getattr(Config, "AI_PEN_TEST_ENABLE", True)) and bool(getattr(Config, "BROWSER_INTEL_ENABLE", True))

    @classmethod
    def _browser_intel_static_context_sufficient(cls, candidate: dict):
        item = candidate if isinstance(candidate, dict) else {}
        api_surface_summary = item.get("api_surface_summary") if isinstance(item.get("api_surface_summary"), dict) else {}
        path_count = cls._safe_int_value(api_surface_summary.get("path_count"), 0)
        auth_path_count = cls._safe_int_value(api_surface_summary.get("auth_path_count"), 0)
        security_scheme_count = cls._safe_int_value(api_surface_summary.get("security_scheme_count"), 0)
        js_api_count = cls._safe_int_value(api_surface_summary.get("js_api_count"), 0)
        parameter_count = len(list(api_surface_summary.get("parameter_names", []) or []))

        if path_count >= 6:
            return True
        if auth_path_count >= 2 and security_scheme_count > 0:
            return True
        if js_api_count >= 6 and parameter_count >= 6:
            return True
        return False

    def _should_collect_ai_pen_browser_intel(self, candidate: dict):
        if not self._is_ai_pen_browser_intel_enabled():
            return False

        item = candidate if isinstance(candidate, dict) else {}
        target_url = str(item.get("vuln_url") or item.get("target") or "").strip()
        if not self._is_browser_intel_candidate_url(target_url):
            return False

        route_hint = str(item.get("route_hint") or self._build_ai_pen_route_hint(item) or "").strip().lower()
        source_collection = str(item.get("source_collection", "") or "").strip().lower()
        risk_type = str(item.get("risk_type", "") or "").strip().lower()
        if self._browser_intel_static_context_sufficient(item):
            return False

        if source_collection == "site":
            return True
        if route_hint in {"api_doc_structure", "jwt_token_first", "structured_id_mutation", "http_replay_then_context", "login_entry_context"}:
            return True
        return risk_type in {"api_doc", "jwt", "idor", "websocket", "login_surface"}

    def _collect_ai_pen_browser_intel(self, candidate: dict):
        item = candidate if isinstance(candidate, dict) else {}
        target_url = str(item.get("vuln_url") or item.get("target") or "").strip()
        if not target_url:
            return {}
        if not self._should_collect_ai_pen_browser_intel(item):
            return {}

        cache_key = str(target_url)
        if cache_key in self.ai_pen_browser_intel_cache:
            return dict(self.ai_pen_browser_intel_cache.get(cache_key) or {})

        current_count = len(self.ai_pen_browser_intel_cache)
        max_targets = max(1, int(getattr(Config, "BROWSER_INTEL_MAX_TARGETS", 8) or 8))
        if current_count >= max_targets:
            return {}

        if self.waf_guard:
            host = self.waf_guard._extract_host(target_url)
            if host and self.waf_guard.is_blocked_host(host):
                return {}

        try:
            result_map = services.run_browser_intel_scan([target_url], concurrency=1) or {}
            intel = result_map.get(target_url) if isinstance(result_map, dict) else {}
            normalized = intel if isinstance(intel, dict) else {}
            self.ai_pen_browser_intel_cache[cache_key] = normalized
            return dict(normalized)
        except Exception as e:
            logger.warning("task_id:{} collect ai_pen browser intel failed url:{} err:{}".format(self.task_id, target_url, e))
            return {}

    def _collect_ai_pen_js_context(self, candidate: dict, payload_type: str = ""):
        item = candidate if isinstance(candidate, dict) else {}
        target_url = str(item.get("vuln_url") or item.get("target") or "").strip()
        if not target_url or not self._is_js_asset_target(target_url):
            return {}

        evidence_seed = self._clip_text(item.get("evidence_seed", ""), self.AI_PEN_TEST_EVIDENCE_MAX)
        risk_type = str(item.get("risk_type", "") or "").strip()
        payload_type_text = str(payload_type or "").strip()
        cache_key = self._stable_hash(target_url, risk_type, payload_type_text, evidence_seed)
        if cache_key in self.ai_pen_js_context_cache:
            return dict(self.ai_pen_js_context_cache.get(cache_key) or {})

        if self.waf_guard:
            host = self.waf_guard._extract_host(target_url)
            if host and self.waf_guard.is_blocked_host(host):
                return {}

        try:
            resp = utils.http_req(
                target_url,
                "get",
                timeout=self.AI_PEN_TEST_FETCH_TIMEOUT,
                allow_redirects=True,
                waf_guard=self.waf_guard,
                waf_module="ai_pen_js_context",
            )
            header_obj = getattr(resp, "headers", {}) or {}
            if str(header_obj.get("X-ARL-WAF-SMART-SKIP", "")).strip() == "1":
                self.ai_pen_js_context_cache[cache_key] = {}
                return {}
            try:
                body_text = str(getattr(resp, "text", "") or "")
            except Exception:
                body_text = ""
        except Exception as e:
            logger.warning("task_id:{} collect ai_pen js context failed url:{} err:{}".format(self.task_id, target_url, e))
            self.ai_pen_js_context_cache[cache_key] = {}
            return {}

        summary = self._build_ai_pen_js_context_summary(
            target_url=target_url,
            body_text=body_text,
            headers=header_obj,
            evidence_seed=evidence_seed,
            risk_type=risk_type,
            payload_type=payload_type_text,
        )
        self.ai_pen_js_context_cache[cache_key] = dict(summary or {})
        return dict(summary or {})

    @classmethod
    def _select_ai_pen_capability_profile(cls, candidate: dict):
        item = candidate if isinstance(candidate, dict) else {}
        route_hint = str(item.get("route_hint") or cls._build_ai_pen_route_hint(item) or "").strip()
        api_surface_summary = item.get("api_surface_summary") if isinstance(item.get("api_surface_summary"), dict) else {}
        knowledge_products = [str(x or "").strip().lower() for x in list(item.get("knowledge_hit_product_labels", []) or []) if str(x or "").strip()]
        knowledge_vuln_types = [str(x or "").strip().lower() for x in list(item.get("knowledge_hit_vuln_types", []) or []) if str(x or "").strip()]
        surface_hints = [str(x or "").strip().lower() for x in list(item.get("surface_hints", []) or []) if str(x or "").strip()]
        risk_type = str(item.get("risk_type", "") or "").strip().lower()

        score_map = {}

        def bump(profile_name: str, score: int):
            if not profile_name:
                return
            score_map[profile_name] = score_map.get(profile_name, 0) + int(score or 0)

        for product in knowledge_products + surface_hints:
            if product in {"swagger", "openapi", "api_doc", "api_doc_surface"}:
                bump("api_doc_surface", 60)
            if product in {"graphql", "graphiql", "graphql_surface", "apollo"}:
                bump("graphql_surface", 58)
            if product in {"nuxt", "webpack", "js_bundler_app"}:
                bump("js_bundler_app", 45)
            if product in {"jwt", "token_auth_flow"}:
                bump("token_auth_flow", 50)
            if product in {"admin_office_portal", "oa", "office", "admin", "console", "dashboard", "portal"}:
                bump("admin_office_portal", 42)
            if product in {"file_handling_surface", "upload", "download", "attachment", "export", "template"}:
                bump("file_handling_surface", 38)
            if product in {"login_entry_surface", "login", "signin", "sso", "cas", "passport"}:
                bump("login_entry_surface", 40)

        if route_hint == "api_doc_structure":
            bump("api_doc_surface", 40)
        if route_hint == "graphql_schema_context":
            bump("graphql_surface", 38)
        if route_hint == "js_static_context":
            bump("js_bundler_app", 25)
        if route_hint == "jwt_token_first":
            bump("token_auth_flow", 35)
        if route_hint == "file_handling_context":
            bump("file_handling_surface", 40)
        if route_hint == "login_entry_context":
            bump("login_entry_surface", 42)

        if cls._safe_int_value(api_surface_summary.get("security_scheme_count"), 0) > 0:
            bump("api_doc_surface", 12)
            bump("graphql_surface", 8)
            bump("token_auth_flow", 8)
        if cls._safe_int_value(api_surface_summary.get("auth_path_count"), 0) > 0:
            bump("api_doc_surface", 10)
            bump("admin_office_portal", 10)
        if cls._safe_int_value(api_surface_summary.get("js_api_count"), 0) > 0:
            bump("js_bundler_app", 10)
        if cls._safe_int_value(api_surface_summary.get("object_id_like_count"), 0) > 0:
            bump("admin_office_portal", 8)
        if (
            cls._safe_int_value(api_surface_summary.get("upload_like_count"), 0) > 0
            or cls._safe_int_value(api_surface_summary.get("download_like_count"), 0) > 0
        ):
            bump("file_handling_surface", 36)

        for vuln_type in knowledge_vuln_types:
            if vuln_type in {"file_upload", "file_read", "fileleak"}:
                bump("file_handling_surface", 28)

        if risk_type == "jwt":
            bump("token_auth_flow", 30)
        if risk_type == "api_doc":
            bump("api_doc_surface", 30)
        if risk_type == "graphql":
            bump("graphql_surface", 32)
        if risk_type in {"file_upload", "file_read"}:
            bump("file_handling_surface", 32)
        if risk_type == "login_surface":
            bump("login_entry_surface", 32)

        best_name = ""
        best_score = 0
        for profile_name, profile in cls.AI_PEN_CAPABILITY_PROFILES.items():
            total_score = score_map.get(profile_name, 0) + int(profile.get("priority", 0) or 0)
            if total_score > best_score:
                best_name = profile_name
                best_score = total_score

        if not best_name:
            return {}

        capability_profile = dict(cls.AI_PEN_CAPABILITY_PROFILES.get(best_name) or {})
        capability_profile["name"] = best_name
        capability_profile["score"] = best_score
        if best_name == "file_handling_surface":
            upload_like_count = cls._safe_int_value(api_surface_summary.get("upload_like_count"), 0)
            download_like_count = cls._safe_int_value(api_surface_summary.get("download_like_count"), 0)
            if risk_type == "file_read" or download_like_count > upload_like_count:
                capability_profile["preferred_payload_type"] = "file_probe"
            else:
                capability_profile["preferred_payload_type"] = "upload_probe"
        return capability_profile

    def _call_ai_pen_planner(
        self,
        ai_config: dict,
        candidate: dict,
        runtime_settings: dict,
        prompt_content: str,
        agent_loop_context=None,
    ):
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
            "messages": [],
            "output": {},
        }
        agent_loop_ctx = agent_loop_context if isinstance(agent_loop_context, dict) else {}
        agent_loop_mode = bool(agent_loop_ctx)
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
            route_hint = self._build_ai_pen_route_hint(candidate)
            enriched_candidate = dict(candidate or {})
            enriched_candidate["route_hint"] = route_hint
            js_context_summary = self._collect_ai_pen_js_context(candidate, payload_type=default_payload_type)
            js_context_text = str(js_context_summary.get("summary_text", "") or "").strip()
            surface_hints = self._collect_ai_pen_surface_hints(candidate, extra_text=js_context_text)
            enriched_candidate["surface_hints"] = surface_hints
            capability_profile = self._select_ai_pen_capability_profile(enriched_candidate)
            inferred_tool_plan = self._infer_ai_pen_tool_plan(
                candidate=candidate,
                payload_type=default_payload_type,
                payload=default_payload,
                max_steps=max(2, self._safe_int_value(runtime_settings.get("max_tool_calls"), self.AI_PEN_TEST_MCP_MAX_TOOL_CALLS)),
            )
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
                "knowledge_hit_product_labels": list(candidate.get("knowledge_hit_product_labels", []) or [])[:8],
                "knowledge_hit_vuln_types": list(candidate.get("knowledge_hit_vuln_types", []) or [])[:8],
                "knowledge_hit_entry_paths": list(candidate.get("knowledge_hit_entry_paths", []) or [])[:8],
                "knowledge_hit_verify_actions": list(candidate.get("knowledge_hit_verify_actions", []) or [])[:6],
                "knowledge_hit_record_refs": list(candidate.get("knowledge_hit_record_refs", []) or [])[:4],
                "route_hint": route_hint,
                "surface_hints": surface_hints,
                "capability_profile": capability_profile,
                "browser_surface_summary": dict(candidate.get("browser_surface_summary") or {}) if isinstance(candidate.get("browser_surface_summary"), dict) else {},
                "runtime_api_calls": list(candidate.get("runtime_api_calls", []) or [])[:8],
                "dom_form_summary": list(candidate.get("dom_form_summary", []) or [])[:4],
                "task_ai_pen_graph_summary": dict(candidate.get("task_ai_pen_graph_summary") or {}) if isinstance(candidate.get("task_ai_pen_graph_summary"), dict) else {},
                "task_ai_pen_graph_context": dict(candidate.get("task_ai_pen_graph_context") or {}) if isinstance(candidate.get("task_ai_pen_graph_context"), dict) else {},
                "login_surface_summary": dict(candidate.get("login_surface_summary") or {}) if isinstance(candidate.get("login_surface_summary"), dict) else {},
                "js_context_summary": dict(js_context_summary or {}) if isinstance(js_context_summary, dict) else {},
                "js_context_snippet": self._clip_text(js_context_summary.get("context_snippet", ""), self.AI_PEN_TEST_EVIDENCE_MAX)
                if isinstance(js_context_summary, dict)
                else "",
                "inferred_tool_plan": list(inferred_tool_plan or []),
                "js_asset_target": bool(
                    self._is_js_asset_target(
                        str(candidate.get("vuln_url") or candidate.get("target") or "").strip()
                    )
                ),
                "default_payload_type": default_payload_type,
                "default_payload": default_payload,
                "mcp_enable": bool(runtime_settings.get("mcp_enable", True)),
                "mcp_max_tool_calls": self._safe_int_value(
                    runtime_settings.get("max_tool_calls"), self.AI_PEN_TEST_MCP_MAX_TOOL_CALLS
                ),
                "decision_guidelines": {
                    "verified": [
                        "真实暴露且结构明确的API文档",
                        "真实硬编码敏感值/凭据字面量",
                        "XSS 需具备可执行脚本/弹窗证据，而非仅关键词或静态链路",
                        "弱口令需具备可复现登录成功证据（账号+密码+成功响应）",
                        "SQL 注入需具备可复现利用证据（如报错注入/时间盲注/布尔盲注）",
                        "明确的JWT签名缺陷或弱密钥",
                        "明确的WebSocket握手成功",
                    ],
                    "needs_manual_review": [
                        "路线正确但证据尚未闭环",
                        "响应差异明显但鉴权或语义上下文不足",
                        "JS中出现source->sink链路但未完全确认可控性",
                        "发现上传/下载/导出/附件入口，但仅能证明文件处理能力，尚不能证明任意文件读写",
                        "发现登录入口、验证码或认证相关接口，但仅能证明存在认证测试面",
                    ],
                    "likely_false_positive": [
                        "仅命中关键词，没有真实字面量或结构性证据",
                        "构建产物/变量拼接/本地存储噪声",
                        "Swagger关键词存在但没有真实文档结构",
                    ],
                },
                "false_positive_focus": {
                    "js_sensitive_info": "区分硬编码字面量与 token+变量/localStorage/sessionStorage 噪声",
                    "dom_xss": "仅有 source->sink 不等于可利用，缺少可触发弹窗证据时应降权",
                    "weak_password": "必须有登录成功证据（账号/密码/成功响应），否则不判定为有效弱口令",
                    "sqli": "仅有关键字或响应差异不等于 SQL 注入成立，优先寻找报错/时间/布尔证据",
                    "api_doc": "URL包含swagger/openapi不等于真实文档暴露，优先看 paths/securitySchemes/参数结构",
                    "file_handling": "发现上传/下载/导出/附件入口不等于已证明任意文件读写，优先保守裁决并给出低副作用下一步",
                    "login_surface": "发现登录表单、验证码或 auth 接口不等于存在漏洞，优先整理黑盒认证面上下文与后续验证建议",
                },
                "supported_payload_types": list(self.AI_PEN_TEST_SUPPORTED_PAYLOAD_TYPES),
                "supported_tools": list(self.AI_PEN_RUNTIME_TOOL_NAMES),
                "output_schema": {
                    "decision": "verified|likely_false_positive|needs_manual_review",
                    "confidence": "0~1 float",
                    "reason": "string",
                    "payload_type": "xss_probe|sqli_probe|cmdi_probe|ssrf_probe|weak_password_probe|idor_probe|api_doc_probe|graphql_probe|jwt_probe|websocket_probe|upload_probe|replay",
                    "payload": "string",
                    "evidence": ["string"],
                    "next_actions": ["string"],
                    "tool_plan": [
                        {
                            "tool": "http_fetch|payload_probe|idor_probe|api_doc_probe|graphql_probe|jwt_probe|websocket_probe|session_start|login_probe|credential_probe|detect_login_success",
                            "params": {"url": "string", "method": "get|post", "allow_redirects": True, "headers": {"Header": "Value"}, "json_data": {"query": "string"}},
                            "summary": "string",
                        }
                    ],
                },
            }
            if agent_loop_mode:
                request_obj["agent_loop"] = {
                    "turn": self._safe_int_value(agent_loop_ctx.get("turn"), 0),
                    "max_turns": self._safe_int_value(agent_loop_ctx.get("max_turns"), 0),
                    "available_tools": list(agent_loop_ctx.get("available_tools", []) or [])[:8],
                    "seed_tool_plan_remaining": list(agent_loop_ctx.get("seed_tool_plan_remaining", []) or [])[:4],
                    "recent_tool_results": list(agent_loop_ctx.get("recent_tool_results", []) or [])[:4],
                    "last_tool_result": list(agent_loop_ctx.get("last_tool_result", []) or [])[:1],
                    "current_stop_reason": str(agent_loop_ctx.get("current_stop_reason", "") or "").strip(),
                }
                request_obj["supported_actions"] = ["tool_call", "final_decision", "manual_required"]
                request_obj["output_schema"] = {
                    "action": "tool_call|final_decision|manual_required",
                    "reason": "string",
                    "expected_signal": "string",
                    "stop_if": "string",
                    "tool_call": {
                        "tool": "http_fetch|payload_probe|idor_probe|api_doc_probe|graphql_probe|jwt_probe|websocket_probe|session_start|login_probe|credential_probe|detect_login_success",
                        "params": {"url": "string", "method": "get|post", "allow_redirects": True, "headers": {"Header": "Value"}, "json_data": {"query": "string"}},
                        "summary": "string",
                    },
                    "final_decision": {
                        "decision": "verified|likely_false_positive|needs_manual_review",
                        "confidence": "0~1 float",
                        "reason": "string",
                        "payload_type": "xss_probe|sqli_probe|cmdi_probe|ssrf_probe|weak_password_probe|idor_probe|api_doc_probe|graphql_probe|jwt_probe|websocket_probe|upload_probe|replay",
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
            if agent_loop_mode:
                system_prompt = (
                    "{}\n\n当前处于 Agent Loop 模式。"
                    "你必须在每一轮只做一个决定："
                    "1) 若需要继续验证，返回 action=tool_call，并只给出一个 tool_call；"
                    "2) 若证据已足够，返回 action=final_decision；"
                    "3) 若需要登录态、验证码处理、人工判断或预算已不适合继续，返回 action=manual_required。"
                    "禁止一次返回多个 tool_call。"
                    "tool_call 只能使用 supported_tools 中的工具，且不得越过当前 target/vuln_url 同任务范围。"
                    "final_decision.decision 只能是 verified/likely_false_positive/needs_manual_review。"
                    "仅返回 JSON 对象，不要 Markdown。"
                ).format(system_prompt)
            else:
                system_prompt = (
                    "{}\n\n输出要求：仅返回 JSON 对象，不要 Markdown；"
                    "decision 只能是 verified/likely_false_positive/needs_manual_review。"
                    "如果需要多轮验证，可返回 tool_plan，按顺序列出要调用的工具与 URL；"
                    "tool_plan 只能使用 supported_tools 中的工具，且不得越过当前 target/vuln_url 同任务范围。"
                ).format(system_prompt)
            conversation_messages = [
                {
                    "role": "system",
                    "content": self._clip_multiline_text(system_prompt, 3200),
                },
                {
                    "role": "user",
                    "content": self._clip_multiline_text(request_text, 3200),
                },
            ]
            result["messages"] = conversation_messages

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
            if result["reply_text"]:
                result["messages"] = conversation_messages + [
                    {
                        "role": "assistant",
                        "content": self._clip_multiline_text(result["reply_text"], 3200),
                    }
                ]
            if not call_ret.get("ok"):
                result["status"] = "error"
                result["message"] = str(call_ret.get("message", "") or "ai request failed")
                return result

            parsed = extract_json_obj(result["reply_text"])
            if not isinstance(parsed, dict):
                result["status"] = "error"
                result["message"] = "AI 返回格式不可解析"
                return result

            parsed_final = parsed.get("final_decision") if agent_loop_mode and isinstance(parsed.get("final_decision"), dict) else parsed
            ai_decision = self._normalize_ai_pen_decision(parsed_final.get("decision"), default_value="")
            ai_confidence = self._clamp_ai_pen_confidence(parsed_final.get("confidence"), 0.55)
            ai_actions = self._normalize_ai_poc_keywords(parsed_final.get("next_actions"), max_count=4)
            ai_payload_type = self._normalize_ai_pen_payload_type(
                parsed_final.get("payload_type"),
                fallback_type="",
            )
            if not ai_payload_type:
                ai_payload_type = self._infer_ai_pen_payload_type_from_actions(
                    ai_actions,
                    fallback_type=default_payload_type,
                )
            if not ai_payload_type:
                ai_payload_type = default_payload_type
            ai_payload = str(parsed_final.get("payload") or "").strip()[: self.AI_PEN_TEST_PAYLOAD_MAX]
            if not ai_payload and ai_payload_type and ai_payload_type != "replay":
                inferred_payload_type, inferred_payload = self._build_ai_pen_payload_hint(ai_payload_type, risk_name)
                if inferred_payload_type == ai_payload_type and inferred_payload:
                    ai_payload = str(inferred_payload)[: self.AI_PEN_TEST_PAYLOAD_MAX]
            ai_reason = self._clip_text(parsed_final.get("reason", "") or parsed.get("reason", ""), self.AI_PEN_TEST_REASON_MAX)
            ai_evidence = self._normalize_ai_poc_keywords(parsed_final.get("evidence"), max_count=8)
            ai_tool_plan = self._normalize_ai_pen_tool_plan(
                parsed.get("tool_plan"),
                default_url=str(candidate.get("vuln_url") or candidate.get("target") or "").strip(),
                max_steps=max(2, self._safe_int_value(runtime_settings.get("max_tool_calls"), self.AI_PEN_TEST_MCP_MAX_TOOL_CALLS)),
            )
            if not ai_tool_plan:
                ai_tool_plan = list(inferred_tool_plan or [])

            if agent_loop_mode:
                action = self._normalize_ai_pen_agent_action(
                    parsed.get("action"),
                    default_value="tool_call" if isinstance(parsed.get("tool_call"), dict) else "final_decision",
                )
                tool_call_obj = {}
                if isinstance(parsed.get("tool_call"), dict):
                    normalized_tool_calls = self._normalize_ai_pen_tool_plan(
                        [parsed.get("tool_call")],
                        default_url=str(candidate.get("vuln_url") or candidate.get("target") or "").strip(),
                        max_steps=1,
                    )
                    if normalized_tool_calls:
                        tool_call_obj = dict(normalized_tool_calls[0] or {})
                elif ai_tool_plan:
                    tool_call_obj = dict(ai_tool_plan[0] or {})
                final_decision_obj = {
                    "decision": ai_decision or "needs_manual_review",
                    "confidence": ai_confidence,
                    "reason": ai_reason,
                    "payload_type": ai_payload_type,
                    "payload": ai_payload,
                    "evidence": ai_evidence,
                    "next_actions": ai_actions,
                }
                result["ok"] = True
                result["status"] = "ok"
                result["message"] = ""
                result["output"] = {
                    "action": action,
                    "reason": ai_reason,
                    "expected_signal": self._clip_text(parsed.get("expected_signal", ""), 160),
                    "stop_if": self._clip_text(parsed.get("stop_if", ""), 160),
                    "tool_call": tool_call_obj,
                    "final_decision": final_decision_obj,
                    "decision": final_decision_obj["decision"],
                    "confidence": final_decision_obj["confidence"],
                    "payload_type": final_decision_obj["payload_type"],
                    "payload": final_decision_obj["payload"],
                    "evidence": list(final_decision_obj.get("evidence", []) or []),
                    "next_actions": list(final_decision_obj.get("next_actions", []) or []),
                }
                return result

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
                "tool_plan": ai_tool_plan,
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
        merged["ai_plan_tool_plan"] = []
        if not plan_ok:
            return merged

        ai_decision = self._normalize_ai_pen_decision(plan_output.get("decision"), default_value="")
        ai_confidence = self._clamp_ai_pen_confidence(plan_output.get("confidence"), 0.55)
        ai_reason = self._clip_text(plan_output.get("reason", ""), self.AI_PEN_TEST_REASON_MAX)
        ai_actions = self._normalize_ai_poc_keywords(plan_output.get("next_actions"), max_count=4)
        ai_tool_plan = self._normalize_ai_pen_tool_plan(
            plan_output.get("tool_plan"),
            default_url=str(merged.get("request_url") or merged.get("vuln_url") or merged.get("target") or "").strip(),
            max_steps=max(2, self.AI_PEN_TEST_MCP_MAX_TOOL_CALLS),
        )

        merged["ai_plan_reason"] = ai_reason
        merged["ai_plan_decision"] = ai_decision
        merged["ai_plan_confidence"] = ai_confidence
        merged["ai_plan_actions"] = ai_actions
        merged["ai_plan_tool_plan"] = ai_tool_plan

        base_decision = self._normalize_ai_pen_decision(merged.get("decision"), default_value="needs_manual_review")
        base_confidence = self._clamp_ai_pen_confidence(merged.get("confidence"), 0.5)
        status = str(merged.get("status", "ok") or "ok").strip().lower()
        risk_type_text = str(merged.get("risk_type", "") or "").strip().lower()
        payload_type_text = str(merged.get("payload_type", "") or "").strip().lower()
        xss_popup_proof = bool(merged.get("xss_popup_proof"))
        weak_password_login_proof = bool(merged.get("weak_password_login_proof"))
        sqli_proof_type = str(merged.get("sqli_proof_type", "") or "").strip().lower()

        if ai_reason:
            base_reason = str(merged.get("reason", "") or "").strip()
            if base_reason:
                merged["reason"] = "{}；AI研判：{}".format(base_reason, ai_reason)
            else:
                merged["reason"] = "AI研判：{}".format(ai_reason)

        if status != "ok" or not ai_decision:
            return merged

        proof_guard_reason = self._get_ai_pen_verified_proof_guard_reason(
            risk_type_text=risk_type_text,
            payload_type_text=payload_type_text,
            xss_popup_proof=xss_popup_proof,
            weak_password_login_proof=weak_password_login_proof,
            sqli_proof_type=sqli_proof_type,
        )
        if proof_guard_reason and base_decision == "verified":
            merged["decision"] = "needs_manual_review"
            merged["confidence"] = max(0.62, min(0.86, base_confidence))
            merged["reason"] = "{}；{}".format(str(merged.get("reason", "") or "").strip(), proof_guard_reason).strip("；")
            base_decision = "needs_manual_review"

        if proof_guard_reason and ai_decision == "verified":
            ai_decision = "needs_manual_review"
            merged["reason"] = "{}；{}".format(str(merged.get("reason", "") or "").strip(), proof_guard_reason).strip("；")

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
    def _get_ai_pen_verified_proof_guard_reason(
        risk_type_text: str,
        payload_type_text: str,
        xss_popup_proof: bool = False,
        weak_password_login_proof: bool = False,
        sqli_proof_type: str = "",
    ) -> str:
        if (str(risk_type_text or "").strip().lower() == "xss" or str(payload_type_text or "").strip().lower() == "xss_probe") and (not xss_popup_proof):
            return "XSS 缺少可触发弹窗的执行证据，禁止直接判定为 verified"
        if (
            str(risk_type_text or "").strip().lower() == "weak_password"
            or str(payload_type_text or "").strip().lower() == "weak_password_probe"
        ) and (not weak_password_login_proof):
            return "弱口令缺少登录成功证据，禁止直接判定为 verified"
        if (str(risk_type_text or "").strip().lower() == "sqli" or str(payload_type_text or "").strip().lower() == "sqli_probe") and str(sqli_proof_type or "").strip().lower() not in {
            "error_based",
            "time_based",
            "boolean_based",
            "external_tool",
        }:
            return "SQL 注入缺少可复现利用证据，禁止直接判定为 verified"
        return ""

    @staticmethod
    def _contains_sql_error_signature(text: str) -> bool:
        content = str(text or "").lower()
        if not content:
            return False
        patterns = (
            r"you have an error in your sql syntax",
            r"warning:\s*mysql",
            r"sql syntax.*mysql",
            r"sqlstate\[[0-9a-z]+\]",
            r"mysql_fetch",
            r"microsoft ole db provider for sql server",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"postgresql.*error",
            r"pg_query\(",
            r"ora-\d{5}",
            r"sqlite_error",
            r"near \".*\": syntax error",
            r"database error",
        )
        return any(re.search(pattern, content) for pattern in patterns)

    @classmethod
    def _detect_sqli_proof_type(cls, base_body: str, probe_body: str) -> str:
        probe_has_error = cls._contains_sql_error_signature(probe_body)
        if not probe_has_error:
            return ""
        base_has_error = cls._contains_sql_error_signature(base_body)
        if probe_has_error and (not base_has_error):
            return "error_based"
        return ""

    @staticmethod
    def _has_xss_popup_proof(payload: str, base_body: str, probe_body: str) -> bool:
        payload_text = str(payload or "").strip().lower()
        probe_text = str(probe_body or "").lower()
        base_text = str(base_body or "").lower()
        if not probe_text:
            return False

        popup_tokens = (
            "<script>alert(",
            "onerror=alert(",
            "onload=alert(",
            "javascript:alert(",
            "<svg/onload=alert(",
            "<img src=x onerror=alert(",
        )
        escaped_tokens = ("&lt;script", "&lt;svg", "&#x3c;script", "&#x3c;svg")

        has_popup_signature = any(token in probe_text for token in popup_tokens)
        has_escaped_only = (not has_popup_signature) and any(token in probe_text for token in escaped_tokens)
        if has_escaped_only:
            return False

        payload_reflected = bool(payload_text and payload_text in probe_text and payload_text not in base_text)
        marker_hit = any(token in probe_text and token not in base_text for token in popup_tokens)
        return payload_reflected and marker_hit

    @staticmethod
    def _has_weak_password_login_proof(evidence_seed: str, base_body: str, probe_body: str) -> bool:
        merged_text = " ".join(
            [
                str(evidence_seed or "").lower(),
                str(base_body or "").lower(),
                str(probe_body or "").lower(),
            ]
        )
        if not merged_text.strip():
            return False

        success_tokens = (
            "login success",
            "logged in",
            "authentication success",
            "auth success",
            "登录成功",
            "登陆成功",
            "认证成功",
            "弱口令验证成功",
            "default credential works",
            "账号密码正确",
        )
        credential_tokens = (
            "username",
            "password",
            "passwd",
            "credential",
            "账号",
            "密码",
            "admin/admin",
            "admin:admin",
            "root/root",
            "root:root",
        )
        return any(token in merged_text for token in success_tokens) and any(
            token in merged_text for token in credential_tokens
        )

    @staticmethod
    def _is_js_asset_target(target_url: str, headers=None):
        url_text = str(target_url or "").strip()
        if not url_text:
            return False

        try:
            parsed = urlsplit(url_text)
            path_text = str(parsed.path or "").strip().lower()
        except Exception:
            path_text = str(target_url or "").strip().lower()

        header_obj = headers if isinstance(headers, dict) else {}
        content_type = str(header_obj.get("Content-Type", "") or "").strip().lower()
        if "javascript" in content_type or "ecmascript" in content_type:
            return True
        if path_text.endswith((".js", ".mjs", ".cjs")):
            return True
        return any(token in path_text for token in ("/_nuxt/", "/static/js/", "/assets/")) and ".json" not in path_text

    @classmethod
    def _extract_js_context_snippet(cls, body_text: str, anchor_text: str = "", fallback_keywords=None):
        content = str(body_text or "")
        if not content:
            return ""

        candidates = []
        anchor = str(anchor_text or "").strip()
        if anchor:
            candidates.append(anchor)
            # 从证据片段里抽取更容易命中的关键 token，避免因前后文被裁剪导致无法定位。
            for token in re.findall(r"[A-Za-z0-9_./:+-]{6,80}", anchor):
                token_text = str(token or "").strip()
                if token_text and token_text not in candidates:
                    candidates.append(token_text)

        if isinstance(fallback_keywords, (list, tuple, set)):
            for item in fallback_keywords:
                token_text = str(item or "").strip()
                if token_text and token_text not in candidates:
                    candidates.append(token_text)

        content_lower = content.lower()
        for candidate in candidates:
            if len(candidate) < 4:
                continue
            idx = content_lower.find(candidate.lower())
            if idx < 0:
                continue
            start = max(0, idx - 140)
            end = min(len(content), idx + max(len(candidate), 32) + 140)
            return cls._clip_text(content[start:end], cls.AI_PEN_TEST_EVIDENCE_MAX)

        return cls._clip_text(content[: min(len(content), cls.AI_PEN_TEST_EVIDENCE_MAX)], cls.AI_PEN_TEST_EVIDENCE_MAX)

    @classmethod
    def _guess_js_component_hint(cls, target_url: str, body_text: str, context_snippet: str = ""):
        merged = "\n".join(
            [
                str(target_url or "").strip(),
                cls._clip_text(body_text, 4096),
                str(context_snippet or "").strip(),
            ]
        ).lower()
        if not merged.strip():
            return ""

        hint_rules = (
            (("getrouter", "getsearch", "createMatchSelector".lower(), "/umi.", "@@initialstate", "g_history"), "UMI/React Router 路由组件"),
            (("window.__nuxt__", "/_nuxt/", "nuxtlink", "useasyncdata"), "Nuxt 页面组件"),
            (("definecomponent(", "router-view", "vue-router", "createapp("), "Vue 页面组件"),
            (("react.", "reactdom", "usestate(", "useeffect(", "jsxruntime", "createelement("), "React 页面组件"),
            (("__webpack_require__", "webpackjson", "push(["), "Webpack 运行时模块"),
            (("__vite__", "import.meta.env", "/assets/"), "Vite 前端构建模块"),
        )
        for tokens, label in hint_rules:
            if any(token in merged for token in tokens):
                return label
        return ""

    @classmethod
    def _guess_js_application_hint(cls, target_url: str, body_text: str, context_snippet: str = ""):
        merged = "\n".join(
            [
                str(target_url or "").strip(),
                cls._clip_text(body_text, 4096),
                str(context_snippet or "").strip(),
            ]
        ).lower()
        if not merged.strip():
            return ""

        app_rules = (
            (("oauth", "openid", "token", "login", "signin", "passport", "sso", "cas", "auth"), "认证/登录应用"),
            (("admin", "dashboard", "console", "workbench", "manage", "permission", "tenant"), "管理后台应用"),
            (("upload", "download", "attachment", "export", "template", "report", "multipart"), "文件处理/导出应用"),
            (("user", "member", "profile", "account", "org", "dept"), "用户/组织应用"),
            (("order", "cart", "checkout", "pay", "refund", "invoice"), "交易/订单应用"),
            (("mail", "sms", "notify", "message", "push"), "消息通知应用"),
        )
        for tokens, label in app_rules:
            if any(token in merged for token in tokens):
                return label
        return ""

    @classmethod
    def _classify_js_secret_type(cls, secret_name: str, context_text: str = ""):
        name_text = str(secret_name or "").strip().lower()
        merged = "{} {}".format(name_text, str(context_text or "").strip().lower()).strip()
        if not merged:
            return ""

        cloud_tokens = ("oss", "s3", "cos", "minio", "obs", "aliyun", "aws", "qcloud", "tencent", "huawei")
        if "private_key" in name_text or "private-key" in name_text:
            return "非对称私钥"
        if "client_secret" in name_text or any(token in merged for token in ("oauth", "openid", "clientid", "client_id")):
            return "OAuth/OIDC 客户端密钥"
        if "access_key" in name_text or (("secret_key" in name_text or "secret-key" in name_text) and any(token in merged for token in cloud_tokens)):
            return "云访问密钥/对象存储凭据"
        if "api_key" in name_text or "app_key" in name_text:
            return "API 调用密钥"
        if "password" in name_text or "passwd" in name_text:
            return "账号口令"
        if "authorization" in name_text or "bearer" in merged or "jwt" in merged:
            return "认证令牌/签名密钥"
        if "token" in name_text:
            return "访问令牌/授权凭据"
        if "secret_key" in name_text or "secret-key" in name_text:
            if any(token in merged for token in ("sign", "signature", "hmac", "encrypt", "decrypt")):
                return "应用签名/加密密钥"
            return "应用级密钥"
        if "secret" in name_text:
            return "应用密钥/凭据"
        return "敏感凭据"

    @classmethod
    def _detect_js_header_noise(cls, evidence_seed: str, context_snippet: str):
        seed_lower = str(evidence_seed or "").strip().lower()
        snippet_lower = str(context_snippet or "").strip().lower()
        if not seed_lower and not snippet_lower:
            return ""

        header_token_map = (
            ("location", "Location"),
            ("set-cookie", "Set-Cookie"),
            ("content-type", "Content-Type"),
            ("content-disposition", "Content-Disposition"),
            ("x-powered-by", "X-Powered-By"),
            ("server", "Server"),
        )
        matched_label = ""
        for token, label in header_token_map:
            if token in seed_lower or token in snippet_lower:
                matched_label = label
                break
        if not matched_label:
            return ""

        js_signal = (
            bool(re.search(r"(?i)\b(function|const|let|var|return)\b", snippet_lower))
            or any(token in snippet_lower for token in ("getrouter", "getsearch", "creatematchselector", "__webpack_require__", "=>", "}}", "){", ";"))
            or bool(re.search(r"(?i)\b[a-z_$][a-z0-9_$]*\s*:\s*[a-z_$][a-z0-9_$]*\s*,", snippet_lower))
        )
        if js_signal:
            return matched_label
        return ""

    @classmethod
    def _build_ai_pen_js_context_summary(
        cls,
        target_url: str,
        body_text: str,
        headers=None,
        evidence_seed: str = "",
        risk_type: str = "",
        payload_type: str = "",
    ):
        if not cls._is_js_asset_target(target_url, headers=headers):
            return {}

        content = str(body_text or "")
        if not content:
            return {}

        content_lower = content.lower()
        try:
            path_lower = str(urlsplit(str(target_url or "").strip()).path or "").strip().lower()
        except Exception:
            path_lower = str(target_url or "").strip().lower()

        framework_like = any(
            token in content_lower
            for token in ("__webpack_require__", "webpackjson", "window.__nuxt__", "definecomponent(", "__vite__", "push([")
        ) or any(token in path_lower for token in ("/_nuxt/", ".chunk.", "/assets/", "/static/js/"))

        summary = {
            "framework_like": framework_like,
            "key_name": "",
            "key_type": "",
            "component_hint": "",
            "application_hint": "",
            "noise_kind": "",
            "noise_token": "",
            "context_snippet": "",
            "summary_text": "",
            "hardcoded_literal": False,
        }

        secret_pattern = re.compile(
            r"(?i)(api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|private[_-]?key|authorization|token|app[_-]?key|password|passwd)"
            r"\s*['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_./:=+~-]{16,256})['\"]"
        )
        secret_match = secret_pattern.search(content)
        if secret_match:
            secret_name = str(secret_match.group(1) or "").strip().lower()
            secret_value = str(secret_match.group(2) or "").strip()
            if secret_value and not secret_value.lower().startswith(("http://", "https://")) and "${" not in secret_value:
                summary["key_name"] = secret_name
                summary["hardcoded_literal"] = True
                summary["context_snippet"] = cls._extract_js_context_snippet(content, secret_match.group(0), fallback_keywords=[secret_name])
                summary["key_type"] = cls._classify_js_secret_type(secret_name, summary["context_snippet"] or content[:1024])

        if not summary["context_snippet"]:
            summary["context_snippet"] = cls._extract_js_context_snippet(
                content,
                evidence_seed,
                fallback_keywords=["secret", "token", "key", "authorization", "localstorage", "sessionstorage", "location", "router"],
            )

        context_snippet = str(summary.get("context_snippet", "") or "")
        context_lower = context_snippet.lower()
        summary["component_hint"] = cls._guess_js_component_hint(target_url, content, context_snippet)
        summary["application_hint"] = cls._guess_js_application_hint(target_url, content, context_snippet)

        header_noise_label = cls._detect_js_header_noise(evidence_seed, context_snippet)

        if not summary["hardcoded_literal"]:
            template_noise = (
                bool(re.search(r"(?i)(token|key|secret)\s*[:=]\s*['\"]?\s*\+", context_snippet))
                or "localstorage[" in context_lower
                or "sessionstorage[" in context_lower
                or "location.host" in context_lower
                or "webcustomize.title" in context_lower
            )
            if template_noise and not summary["noise_kind"]:
                summary["noise_kind"] = "secret_template_noise"

        if header_noise_label and not summary["noise_kind"]:
            summary["noise_kind"] = "header_keyword_in_bundle"
            summary["noise_token"] = header_noise_label

        summary_parts = []
        if summary["key_type"]:
            summary_parts.append("疑似{}".format(summary["key_type"]))
        if summary["key_name"]:
            summary_parts.append("变量={}".format(summary["key_name"]))
        if summary["component_hint"]:
            summary_parts.append("组件={}".format(summary["component_hint"]))
        if summary["application_hint"]:
            summary_parts.append("应用={}".format(summary["application_hint"]))
        if summary["noise_kind"] == "header_keyword_in_bundle":
            summary_parts.append("噪声=HTTP头关键字落在前端代码中")
        elif summary["noise_kind"] == "secret_template_noise":
            summary_parts.append("噪声=变量拼接/本地存储")
        elif framework_like:
            summary_parts.append("上下文=前端静态构建产物")
        summary["summary_text"] = cls._clip_text("；".join(summary_parts), cls.AI_PEN_TEST_REASON_MAX)
        return summary

    @classmethod
    def _analyze_ai_pen_js_context(cls, target_url: str, body_text: str, headers, risk_type: str, payload_type: str, evidence_seed: str):
        if not cls._is_js_asset_target(target_url, headers=headers):
            return {}

        content = str(body_text or "")
        if not content:
            return {}

        risk_type_text = str(risk_type or "").strip().lower()
        payload_type_text = str(payload_type or "").strip().lower()
        content_lower = content.lower()
        js_summary = cls._build_ai_pen_js_context_summary(
            target_url=target_url,
            body_text=content,
            headers=headers,
            evidence_seed=evidence_seed,
            risk_type=risk_type_text,
            payload_type=payload_type_text,
        )
        context_snippet = str(js_summary.get("context_snippet", "") or "")
        component_hint = str(js_summary.get("component_hint", "") or "").strip()
        application_hint = str(js_summary.get("application_hint", "") or "").strip()
        key_name = str(js_summary.get("key_name", "") or "").strip().lower()
        key_type = str(js_summary.get("key_type", "") or "").strip()
        noise_kind = str(js_summary.get("noise_kind", "") or "").strip().lower()
        noise_token = str(js_summary.get("noise_token", "") or "").strip()
        framework_like = bool(js_summary.get("framework_like"))
        bundle_hint = component_hint or "前端静态构建产物"

        def _with_summary(result: dict):
            ret = dict(result or {})
            ret["js_context_summary"] = dict(js_summary or {})
            return ret

        if risk_type_text == "sensitive_info":
            if bool(js_summary.get("hardcoded_literal")) and key_name:
                reason_parts = ["JS 上下文发现硬编码 {} 字面量".format(key_name)]
                if key_type:
                    reason_parts.append("疑似 {}".format(key_type))
                if component_hint:
                    reason_parts.append("组件线索指向 {}".format(component_hint))
                if application_hint:
                    reason_parts.append("应用线索指向 {}".format(application_hint))
                reason_text = "，".join(reason_parts)
                high_conf_tokens = ("private_key", "private-key", "client_secret", "secret_key", "access_key")
                high_conf_types = {"OAuth/OIDC 客户端密钥", "云访问密钥/对象存储凭据", "非对称私钥", "应用签名/加密密钥"}
                decision = "verified" if any(token in key_name for token in high_conf_tokens) or key_type in high_conf_types else "needs_manual_review"
                confidence = 0.90 if decision == "verified" else 0.78
                return _with_summary(
                    {
                        "decision": decision,
                        "confidence": confidence,
                        "reason": reason_text,
                        "context_snippet": context_snippet,
                        "tool_trace": "js_context(secret_literal)",
                    }
                )

            if noise_kind == "secret_template_noise":
                reason_text = "JS 上下文显示命中片段更像变量拼接或本地存储逻辑，未发现硬编码敏感值"
                if component_hint:
                    reason_text = "{}，当前代码更像 {}".format(reason_text, component_hint)
                return _with_summary(
                    {
                        "decision": "likely_false_positive",
                        "confidence": 0.80,
                        "reason": reason_text,
                        "context_snippet": context_snippet,
                        "tool_trace": "js_context(secret_noise)",
                    }
                )

        if risk_type_text == "xss" or payload_type_text == "xss_probe":
            sink_tokens = ("innerhtml", "outerhtml", "document.write", "insertadjacenthtml", ".html(", "eval(", "new function(", "srcdoc")
            source_tokens = (
                "location.search",
                "location.hash",
                "document.url",
                "document.cookie",
                "window.name",
                "localstorage",
                "sessionstorage",
                "postmessage",
            )
            has_sink = any(token in content_lower for token in sink_tokens)
            has_source = any(token in content_lower for token in source_tokens)
            if not context_snippet:
                context_snippet = cls._extract_js_context_snippet(content, evidence_seed, fallback_keywords=list(sink_tokens) + list(source_tokens))
            if has_sink and has_source:
                popup_tokens = ("alert(", "confirm(", "prompt(", "onerror=alert(", "onload=alert(", "javascript:alert(")
                has_popup_hint = any(token in content_lower for token in popup_tokens)
                if has_popup_hint:
                    return _with_summary(
                        {
                            "decision": "needs_manual_review",
                            "confidence": 0.72,
                            "reason": "JS 上下文存在 source->sink 且出现弹窗调用片段，建议在浏览器中复现可控输入链路",
                            "context_snippet": context_snippet,
                            "tool_trace": "js_context(dom_chain_popup_hint)",
                        }
                    )
                return _with_summary(
                    {
                        "decision": "likely_false_positive",
                        "confidence": 0.76,
                        "reason": "JS 上下文虽出现 source->sink，但缺少可触发弹窗的执行证据，当前不判定为可利用 XSS",
                        "context_snippet": context_snippet,
                        "tool_trace": "js_context(dom_chain)",
                    }
                )
            if (not has_sink) and framework_like:
                return _with_summary(
                    {
                        "decision": "likely_false_positive",
                        "confidence": 0.78,
                        "reason": "JS 上下文未发现危险 DOM sink，当前更像框架构建产物或静态加载代码",
                        "context_snippet": context_snippet,
                        "tool_trace": "js_context(dom_static)",
                    }
                )

        if noise_kind == "header_keyword_in_bundle":
            readable_header = noise_token or "Location/Header"
            reason_text = "证据显示这是 JavaScript 文件中的代码片段，{} 关键字落在前端代码键名/变量中，与 HTTP 响应头注入无关".format(readable_header)
            if component_hint:
                reason_text = "{}，组件线索指向 {}".format(reason_text, component_hint)
            if application_hint:
                reason_text = "{}，应用线索指向 {}".format(reason_text, application_hint)
            return _with_summary(
                {
                    "decision": "likely_false_positive",
                    "confidence": 0.86,
                    "reason": reason_text,
                    "context_snippet": context_snippet,
                    "tool_trace": "js_context(header_noise)",
                }
            )

        generic_probe_label = {
            "cmdi_probe": "命令执行",
            "sqli_probe": "SQL 注入",
            "ssrf_probe": "SSRF",
            "idor_probe": "越权",
            "replay": "HTTP 回放",
        }.get(payload_type_text) or {
            "cmdi": "命令执行",
            "sqli": "SQL 注入",
            "ssrf": "SSRF",
            "idor": "越权",
            "poc_scan": "PoC 命中",
            "unknown": "当前风险",
        }.get(risk_type_text, "当前风险")
        if framework_like and payload_type_text in {"cmdi_probe", "sqli_probe", "ssrf_probe", "idor_probe", "replay"}:
            reason_text = "目标返回 {}，当前证据更像前端静态代码片段命中，未形成 {} 的可利用证据".format(bundle_hint, generic_probe_label)
            if application_hint:
                reason_text = "{}，应用线索指向 {}".format(reason_text, application_hint)
            return _with_summary(
                {
                    "decision": "likely_false_positive",
                    "confidence": 0.78,
                    "reason": reason_text,
                    "context_snippet": context_snippet,
                    "tool_trace": "js_context(bundle_noise)",
                }
            )

        return {}

    @classmethod
    def _analyze_ai_pen_file_context(
        cls,
        target_url: str,
        body_text: str,
        headers,
        risk_type: str,
        payload_type: str,
        evidence_seed: str,
        api_surface_summary=None,
        browser_surface_summary=None,
        runtime_api_calls=None,
        dom_form_summary=None,
        probe_status=0,
        probe_headers=None,
        probe_body_text="",
        payload="",
    ):
        risk_type_text = str(risk_type or "").strip().lower()
        payload_type_text = str(payload_type or "").strip().lower()
        summary = api_surface_summary if isinstance(api_surface_summary, dict) else {}
        browser_summary = browser_surface_summary if isinstance(browser_surface_summary, dict) else {}
        runtime_calls = list(runtime_api_calls or [])
        forms = list(dom_form_summary or [])
        header_obj = headers if isinstance(headers, dict) else {}
        probe_header_obj = probe_headers if isinstance(probe_headers, dict) else {}

        upload_like_count = cls._safe_int_value(summary.get("upload_like_count"), 0)
        download_like_count = cls._safe_int_value(summary.get("download_like_count"), 0)
        if payload_type_text not in {"upload_probe", "file_probe"} and risk_type_text not in {"file_upload", "file_read"} and upload_like_count < 1 and download_like_count < 1:
            return {}

        content = str(body_text or "")
        content_lower = content.lower()
        content_type = str(header_obj.get("Content-Type", "") or "").strip().lower()
        content_disposition = str(header_obj.get("Content-Disposition", "") or "").strip().lower()
        active_header_obj = probe_header_obj if probe_header_obj else header_obj
        active_body_text = str(probe_body_text or content or "")
        active_body_lower = active_body_text.lower()
        active_content_type = str(active_header_obj.get("Content-Type", "") or "").strip().lower()
        active_content_disposition = str(active_header_obj.get("Content-Disposition", "") or "").strip().lower()
        probe_status_value = cls._safe_int_value(probe_status, 0)
        try:
            path_lower = str(urlsplit(str(target_url or "").strip()).path or "").strip().lower()
        except Exception:
            path_lower = str(target_url or "").strip().lower()

        sample_paths = [str(x or "").strip() for x in list(summary.get("sample_paths", []) or []) if str(x or "").strip()]
        runtime_paths = cls._extract_runtime_api_paths(runtime_calls)
        upload_path_hits = [item for item in sample_paths + runtime_paths if any(token in str(item).lower() for token in cls.AI_PEN_UPLOAD_HINTS)][:6]
        download_path_hits = [item for item in sample_paths + runtime_paths if any(token in str(item).lower() for token in cls.AI_PEN_DOWNLOAD_HINTS)][:6]

        file_form_hits = []
        multipart_form_hits = 0
        for item in forms:
            if not isinstance(item, dict):
                continue
            action_text = str(item.get("action") or "").strip()
            enctype_text = str(item.get("enctype") or "").strip().lower()
            has_file_input = str(item.get("has_file_input") or "").strip().lower() in {"1", "true", "yes"}
            field_text = str(item.get("fields") or "").strip().lower()
            if "multipart/form-data" in enctype_text:
                multipart_form_hits += 1
            if has_file_input or any(token in field_text for token in ("file", "image", "avatar", "attachment")):
                if action_text:
                    file_form_hits.append(action_text[:180])

        html_upload_signal = (
            'type="file"' in content_lower
            or "type='file'" in content_lower
            or "multipart/form-data" in content_lower
            or "el-upload" in content_lower
            or "uploadify" in content_lower
            or "dropzone" in content_lower
        )
        attachment_signal = "attachment" in content_disposition
        downloadable_content_signal = any(
            token in content_type
            for token in (
                "application/octet-stream",
                "application/pdf",
                "application/zip",
                "application/x-rar",
                "application/vnd.ms-excel",
                "application/vnd.openxmlformats-officedocument",
                "text/csv",
            )
        )
        active_attachment_signal = "attachment" in active_content_disposition
        active_downloadable_content_signal = any(
            token in active_content_type
            for token in (
                "application/octet-stream",
                "application/pdf",
                "application/zip",
                "application/x-rar",
                "application/vnd.ms-excel",
                "application/vnd.openxmlformats-officedocument",
                "text/csv",
            )
        )
        weak_path_signal = any(token in path_lower for token in cls.AI_PEN_UPLOAD_HINTS + cls.AI_PEN_DOWNLOAD_HINTS)
        upload_probe_filename = str(payload or "").strip().lower()
        upload_response_signal = (
            payload_type_text == "upload_probe"
            and cls._is_ai_pen_success_status(probe_status_value)
            and (
                (upload_probe_filename and upload_probe_filename in active_body_lower)
                or any(
                    token in active_body_lower
                    for token in (
                        '"success":true',
                        '"code":0',
                        '"uploaded"',
                        '"upload"',
                        '"fileurl"',
                        '"downloadurl"',
                        '"attachmentid"',
                        '"filepath"',
                    )
                )
                or (
                    "json" in active_content_type
                    and any(token in active_body_lower for token in ('"url"', '"path"', '"id"', '"name"'))
                )
                or bool(str(active_header_obj.get("Location", "") or "").strip())
            )
        )
        download_probe_signal = (
            payload_type_text == "file_probe"
            and cls._is_ai_pen_success_status(probe_status_value)
            and (active_attachment_signal or active_downloadable_content_signal)
        )

        fallback_keywords = list(cls.AI_PEN_UPLOAD_HINTS) + list(cls.AI_PEN_DOWNLOAD_HINTS) + ["multipart/form-data", "attachment", "type=file"]
        context_snippet = cls._extract_js_context_snippet(active_body_text or content, evidence_seed or payload, fallback_keywords=fallback_keywords)
        if not context_snippet:
            if file_form_hits:
                context_snippet = cls._clip_text("form_action={}".format(file_form_hits[0]), cls.AI_PEN_TEST_EVIDENCE_MAX)
            elif upload_path_hits:
                context_snippet = cls._clip_text("upload_path={}".format(upload_path_hits[0]), cls.AI_PEN_TEST_EVIDENCE_MAX)
            elif download_path_hits:
                context_snippet = cls._clip_text("download_path={}".format(download_path_hits[0]), cls.AI_PEN_TEST_EVIDENCE_MAX)
            elif active_attachment_signal or attachment_signal:
                context_snippet = cls._clip_text(active_content_disposition or content_disposition, cls.AI_PEN_TEST_EVIDENCE_MAX)
            elif active_downloadable_content_signal or downloadable_content_signal:
                context_snippet = cls._clip_text(active_content_type or content_type, cls.AI_PEN_TEST_EVIDENCE_MAX)

        if upload_response_signal:
            return {
                "decision": "verified",
                "confidence": 0.84,
                "reason": "无害静态文件上传探针返回成功特征，确认该接口可接收文件上传请求",
                "context_snippet": context_snippet,
                "tool_trace": "file_context(upload_verified)",
            }
        if download_probe_signal:
            return {
                "decision": "verified",
                "confidence": 0.82,
                "reason": "文件探针返回 attachment/binary 响应，确认该接口为下载/导出类文件接口",
                "context_snippet": context_snippet,
                "tool_trace": "file_context(download_verified)",
            }

        upload_signal_score = 0
        if upload_like_count > 0:
            upload_signal_score += 2
        if upload_path_hits:
            upload_signal_score += 2
        if file_form_hits:
            upload_signal_score += 3
        if multipart_form_hits > 0:
            upload_signal_score += 2
        if html_upload_signal:
            upload_signal_score += 2

        download_signal_score = 0
        if download_like_count > 0:
            download_signal_score += 2
        if download_path_hits:
            download_signal_score += 2
        if attachment_signal:
            download_signal_score += 3
        if downloadable_content_signal:
            download_signal_score += 2

        if download_signal_score >= 5:
            return {
                "decision": "needs_manual_review",
                "confidence": 0.80,
                "reason": "发现明确的下载/导出响应特征，建议继续围绕附件名、对象ID和导出参数做黑盒验证",
                "context_snippet": context_snippet,
                "tool_trace": "file_context(download_surface)",
            }
        if upload_signal_score >= 5:
            return {
                "decision": "needs_manual_review",
                "confidence": 0.78,
                "reason": "发现上传表单或 multipart 入口特征，建议继续围绕文件名、后缀、Content-Type 做低副作用验证",
                "context_snippet": context_snippet,
                "tool_trace": "file_context(upload_surface)",
            }
        if upload_signal_score >= 2 or download_signal_score >= 2 or weak_path_signal:
            return {
                "decision": "needs_manual_review",
                "confidence": 0.66,
                "reason": "发现文件处理相关路径或参数线索，但证据尚不足以证明存在任意文件读写风险",
                "context_snippet": context_snippet,
                "tool_trace": "file_context(file_hint)",
            }
        if risk_type_text in {"file_upload", "file_read"} or payload_type_text == "upload_probe":
            return {
                "decision": "likely_false_positive",
                "confidence": 0.62,
                "reason": "当前未观察到稳定的上传/下载/导出结构特征，仅凭现有线索不足以确认文件处理风险",
                "context_snippet": context_snippet,
                "tool_trace": "file_context(no_surface)",
            }
        return {}

    @classmethod
    def _analyze_ai_pen_login_surface(
        cls,
        target_url: str,
        risk_type: str,
        login_surface_summary=None,
    ):
        summary = login_surface_summary if isinstance(login_surface_summary, dict) else {}
        risk_type_text = str(risk_type or "").strip().lower()
        if risk_type_text != "login_surface" and not summary:
            return {}

        password_form_count = cls._safe_int_value(summary.get("password_form_count"), 0)
        captcha_form_count = cls._safe_int_value(summary.get("captcha_form_count"), 0)
        auth_runtime_call_count = cls._safe_int_value(summary.get("auth_runtime_call_count"), 0)
        auth_api_path_count = cls._safe_int_value(summary.get("auth_api_path_count"), 0)
        indicators = [str(item or "").strip() for item in list(summary.get("indicators", []) or []) if str(item or "").strip()]
        form_actions = [str(item or "").strip() for item in list(summary.get("form_actions", []) or []) if str(item or "").strip()]
        runtime_auth_paths = [str(item or "").strip() for item in list(summary.get("runtime_auth_paths", []) or []) if str(item or "").strip()]

        if password_form_count > 0 or auth_runtime_call_count > 0 or auth_api_path_count > 0 or indicators:
            reason_parts = ["发现登录入口或认证链路线索"]
            if password_form_count > 0:
                reason_parts.append("密码表单={}".format(password_form_count))
            if captcha_form_count > 0:
                reason_parts.append("验证码线索={}".format(captcha_form_count))
            if auth_runtime_call_count > 0:
                reason_parts.append("运行时认证接口={}".format(auth_runtime_call_count))
            if auth_api_path_count > 0:
                reason_parts.append("认证相关接口={}".format(auth_api_path_count))
            if form_actions:
                reason_parts.append("表单动作={}".format(",".join(form_actions[:2])))
            elif runtime_auth_paths:
                reason_parts.append("认证路径={}".format(",".join(runtime_auth_paths[:2])))
            return {
                "decision": "needs_manual_review",
                "confidence": 0.74 if (password_form_count > 0 or auth_runtime_call_count > 0) else 0.66,
                "reason": "；".join(reason_parts),
                "context_snippet": cls._clip_text(
                    ",".join(form_actions[:2] or runtime_auth_paths[:2] or indicators[:3]),
                    cls.AI_PEN_TEST_EVIDENCE_MAX,
                ),
                "tool_trace": "login_surface(context)",
            }

        if risk_type_text == "login_surface":
            return {
                "decision": "likely_false_positive",
                "confidence": 0.60,
                "reason": "当前未观察到稳定的登录表单、认证接口或验证码线索，暂不足以认定为有效登录入口",
                "context_snippet": cls._clip_text(str(target_url or ""), cls.AI_PEN_TEST_EVIDENCE_MAX),
                "tool_trace": "login_surface(no_signal)",
            }
        return {}

    @staticmethod
    def _extract_ai_pen_trace_method_and_url(tool_trace_parts, fallback_url: str):
        traces = tool_trace_parts if isinstance(tool_trace_parts, list) else []
        for item in reversed(traces):
            text = str(item or "").strip()
            if not text:
                continue
            match = re.search(
                r"\((get|post|put|patch|delete|head|options|trace|connect)\s*,\s*url=([^)]+)\)",
                text,
                re.I,
            )
            if not match:
                continue
            method_text = str(match.group(1) or "").strip().upper()
            url_text = str(match.group(2) or "").strip()
            if method_text and url_text:
                return method_text, url_text
        return "", str(fallback_url or "").strip()

    @classmethod
    def _infer_ai_pen_request_method(cls, payload_type: str, verification_step: str, tool_trace_parts, fallback="GET"):
        method_text, _ = cls._extract_ai_pen_trace_method_and_url(tool_trace_parts, "")
        if method_text:
            return method_text

        payload_text = str(payload_type or "").strip().lower()
        step_text = str(verification_step or "").strip().lower()
        if payload_text == "upload_probe":
            return "POST"
        if payload_text == "graphql_probe":
            return "POST"
        if payload_text == "websocket_probe":
            return "GET"
        if step_text.startswith("mcp_external_"):
            return "GET"
        return str(fallback or "GET").strip().upper() or "GET"

    @classmethod
    def _build_ai_pen_request_packet(
        cls,
        target_url: str,
        payload_type: str,
        payload: str,
        verification_step: str = "",
        tool_trace_parts=None,
    ):
        fallback_url = str(target_url or "").strip()
        trace_method, trace_url = cls._extract_ai_pen_trace_method_and_url(tool_trace_parts, fallback_url)
        method = cls._infer_ai_pen_request_method(
            payload_type=payload_type,
            verification_step=verification_step,
            tool_trace_parts=tool_trace_parts,
            fallback=trace_method or "GET",
        )
        request_url = str(trace_url or fallback_url).strip()
        if not request_url:
            return {
                "method": method,
                "url": "",
                "path": "/",
                "host": "",
                "headers": {},
                "body": "",
                "raw": "",
            }

        payload_text = str(payload or "").strip()
        payload_type_text = str(payload_type or "").strip().lower()
        method_upper = str(method or "GET").strip().upper()
        get_probe_types = {"xss_probe", "sqli_probe", "cmdi_probe", "ssrf_probe", "replay"}
        if method_upper == "GET" and payload_text and payload_type_text in get_probe_types:
            request_url = cls._build_probe_url_with_payload(request_url, payload_text)
        elif payload_type_text == "idor_probe":
            request_url = cls._build_idor_probe_url(request_url)

        parsed = None
        try:
            parsed = urlsplit(request_url)
        except Exception:
            parsed = None
        if (not parsed) or (not parsed.netloc and parsed.path):
            try:
                parsed = urlsplit("http://{}".format(str(request_url).lstrip("/")))
            except Exception:
                parsed = None

        scheme = str(getattr(parsed, "scheme", "") or "http").strip().lower()
        netloc = str(getattr(parsed, "netloc", "") or "").strip()
        host_text = netloc or str(getattr(parsed, "hostname", "") or "").strip()
        path_text = str(getattr(parsed, "path", "") or "").strip() or "/"
        query_text = str(getattr(parsed, "query", "") or "").strip()
        full_path = "{}?{}".format(path_text, query_text) if query_text else path_text
        safe_url = request_url
        if netloc:
            safe_url = urlunsplit((scheme, netloc, path_text, query_text, str(getattr(parsed, "fragment", "") or "")))

        headers = {
            "Host": host_text or "-",
            "User-Agent": "ARL-AI-Pen/1.0",
            "Accept": "*/*",
            "Connection": "close",
        }
        body_text = ""

        if payload_type_text == "jwt_probe" and payload_text:
            headers["Authorization"] = "Bearer {}".format(payload_text[:220])
        if payload_type_text == "websocket_probe":
            headers["Connection"] = "Upgrade"
            headers["Upgrade"] = "websocket"
            headers["Sec-WebSocket-Version"] = "13"
            headers["Sec-WebSocket-Key"] = "ArlAiPenProbe=="
        if payload_type_text == "api_doc_probe":
            headers["Accept"] = "application/json, */*"
        if payload_type_text == "graphql_probe":
            headers["Accept"] = "application/json, text/html;q=0.9, */*;q=0.8"

        if method_upper in {"POST", "PUT", "PATCH"}:
            if payload_type_text == "upload_probe":
                boundary = "----ARLAIPENBOUNDARY"
                headers["Content-Type"] = "multipart/form-data; boundary={}".format(boundary)
                if payload_text:
                    upload_content = payload_text
                else:
                    upload_content = "arl-ai-pen-probe"
                body_text = (
                    "--{0}\r\n"
                    "Content-Disposition: form-data; name=\"file\"; filename=\"probe.txt\"\r\n"
                    "Content-Type: text/plain\r\n\r\n"
                    "{1}\r\n"
                    "--{0}--\r\n"
                ).format(boundary, upload_content)
            elif payload_type_text == "graphql_probe":
                headers["Content-Type"] = "application/json"
                body_text = payload_text or '{"query":"query { __typename }"}'
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body_text = "arl_probe={}".format(payload_text or "probe")
            headers["Content-Length"] = str(len(body_text.encode("utf-8", "ignore")))

        packet_lines = ["{} {} HTTP/1.1".format(method_upper, full_path)]
        for key, value in headers.items():
            packet_lines.append("{}: {}".format(key, value))
        packet_lines.append("")
        if body_text:
            packet_lines.append(body_text)
        raw_packet = "\r\n".join(packet_lines)

        return {
            "method": method_upper,
            "url": safe_url,
            "path": full_path,
            "host": host_text,
            "headers": headers,
            "body": body_text,
            "raw": cls._clip_multiline_text(raw_packet, cls.AI_PEN_TEST_REQUEST_PACKET_MAX),
        }

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
    def _mutate_idor_like_value(value_text: str):
        text = str(value_text or "").strip()
        if not text:
            return {}

        if text.isdigit():
            next_number = str(int(text) + 1)
            if len(text) > 1 and text.startswith("0"):
                next_number = next_number.zfill(len(text))
            return {"value": next_number, "kind": "numeric"}

        if re.fullmatch(r"[0-9a-fA-F]{24}", text):
            last_char = text[-1].lower()
            next_char = "1" if last_char != "1" else "2"
            return {"value": "{}{}".format(text[:-1], next_char), "kind": "object_id"}

        if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", text):
            last_char = text[-1].lower()
            next_char = "1" if last_char != "1" else "2"
            return {"value": "{}{}".format(text[:-1], next_char), "kind": "uuid"}

        return {}

    @classmethod
    def _build_idor_probe_targets(cls, target_url: str, max_count=3):
        url_text = str(target_url or "").strip()
        if not url_text:
            return []

        try:
            parsed = urlsplit(url_text)
            query_items = parse_qsl(parsed.query, keep_blank_values=True)
            id_keys = {"id", "uid", "user_id", "userid", "account_id", "order_id", "doc_id"}
            targets = []
            seen = set()

            def append_target(next_url: str, mutation_key: str, mutation_from: str, mutation_to: str, mutation_kind: str):
                url_candidate = str(next_url or "").strip()
                if (not url_candidate) or url_candidate == url_text or url_candidate in seen:
                    return
                seen.add(url_candidate)
                targets.append(
                    {
                        "url": url_candidate,
                        "mutation_key": str(mutation_key or "").strip()[:64],
                        "mutation_from": str(mutation_from or "").strip()[:80],
                        "mutation_to": str(mutation_to or "").strip()[:80],
                        "mutation_kind": str(mutation_kind or "").strip()[:32],
                    }
                )

            if query_items:
                for index, (key, value) in enumerate(query_items):
                    key_text = str(key or "").strip().lower()
                    value_text = str(value or "").strip()
                    mutation = cls._mutate_idor_like_value(value_text)
                    if not mutation:
                        continue
                    if not ((key_text in id_keys) or key_text.endswith("_id") or key_text in cls.AI_PEN_OBJECT_ID_PARAM_HINTS):
                        continue
                    updated_items = list(query_items)
                    updated_items[index] = (key, mutation.get("value"))
                    updated_query = urlencode(updated_items, doseq=True)
                    append_target(
                        urlunsplit((parsed.scheme, parsed.netloc, parsed.path, updated_query, parsed.fragment)),
                        mutation_key=key,
                        mutation_from=value_text,
                        mutation_to=mutation.get("value", ""),
                        mutation_kind=mutation.get("kind", ""),
                    )
                    if len(targets) >= max(1, int(max_count or 1)):
                        return targets

            path_text = str(parsed.path or "")
            match = re.search(r"(\d+|[0-9a-fA-F]{24}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/?$)", path_text)
            if match:
                token_text = str(match.group(1) or "").strip()
                mutation = cls._mutate_idor_like_value(token_text)
                if mutation:
                    new_path = "{}{}{}".format(path_text[: match.start(1)], mutation.get("value", ""), path_text[match.end(1):])
                    append_target(
                        urlunsplit((parsed.scheme, parsed.netloc, new_path, parsed.query, parsed.fragment)),
                        mutation_key="path",
                        mutation_from=token_text,
                        mutation_to=mutation.get("value", ""),
                        mutation_kind=mutation.get("kind", ""),
                    )
            return targets[: max(1, int(max_count or 1))]
        except Exception:
            return []

    @classmethod
    def _build_idor_probe_url(cls, target_url: str):
        targets = cls._build_idor_probe_targets(target_url, max_count=1)
        if targets:
            return str(targets[0].get("url") or target_url).strip()
        return str(target_url or "").strip()

    @classmethod
    def _build_idor_diff_summary(cls, base_status: int, base_body: str, probe_status: int, probe_body: str, probe_target=None):
        target_obj = probe_target if isinstance(probe_target, dict) else {}
        base_text = str(base_body or "")
        probe_text = str(probe_body or "")
        base_lower = base_text.lower()
        probe_lower = probe_text.lower()
        sensitive_hits = []

        for marker in cls.AI_PEN_IDOR_SENSITIVE_MARKERS:
            marker_text = str(marker or "").strip().lower()
            if marker_text and (marker_text in probe_lower) and (marker_text not in base_lower):
                sensitive_hits.append(marker_text)
                if len(sensitive_hits) >= 6:
                    break

        status_changed = int(base_status or 0) != int(probe_status or 0)
        body_changed = bool(str(base_body or "")) != bool(str(probe_body or "")) or (str(base_body or "") != str(probe_body or ""))
        length_delta = abs(len(probe_text) - len(base_text))
        material_change = body_changed and (status_changed or length_delta >= 24 or bool(sensitive_hits))

        return {
            "mutation_key": str(target_obj.get("mutation_key") or "").strip(),
            "mutation_from": str(target_obj.get("mutation_from") or "").strip(),
            "mutation_to": str(target_obj.get("mutation_to") or "").strip(),
            "mutation_kind": str(target_obj.get("mutation_kind") or "").strip(),
            "status_changed": bool(status_changed),
            "body_changed": bool(body_changed),
            "length_delta": int(length_delta),
            "sensitive_hits": sensitive_hits[:6],
            "material_change": bool(material_change),
        }

    @classmethod
    def _format_idor_diff_summary_text(cls, summary: dict):
        if not isinstance(summary, dict) or not summary:
            return ""

        parts = []
        mutation_key = str(summary.get("mutation_key") or "").strip()
        mutation_from = str(summary.get("mutation_from") or "").strip()
        mutation_to = str(summary.get("mutation_to") or "").strip()
        mutation_kind = str(summary.get("mutation_kind") or "").strip()
        if mutation_key or mutation_from or mutation_to:
            parts.append(
                "mutation={}:{}->{}".format(
                    mutation_key or "id",
                    mutation_from or "-",
                    mutation_to or "-",
                )
            )
        if mutation_kind:
            parts.append("kind={}".format(mutation_kind))
        if bool(summary.get("status_changed")):
            parts.append("status_changed=1")
        if bool(summary.get("body_changed")):
            parts.append("body_changed=1")
        length_delta = cls._safe_int_value(summary.get("length_delta"), 0)
        if length_delta > 0:
            parts.append("length_delta={}".format(length_delta))
        sensitive_hits = [str(item or "").strip() for item in list(summary.get("sensitive_hits", []) or [])[:4] if str(item or "").strip()]
        if sensitive_hits:
            parts.append("fields={}".format(",".join(sensitive_hits)))
        return " | ".join(parts)

    @classmethod
    def _score_idor_diff_summary(cls, summary: dict):
        if not isinstance(summary, dict):
            return 0
        score = 0
        if bool(summary.get("status_changed")):
            score += 4
        if bool(summary.get("material_change")):
            score += 4
        if bool(summary.get("body_changed")):
            score += 2
        score += min(6, len(list(summary.get("sensitive_hits", []) or [])) * 2)
        length_delta = cls._safe_int_value(summary.get("length_delta"), 0)
        if length_delta >= 120:
            score += 2
        elif length_delta >= 32:
            score += 1
        return score

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
    def _build_graphql_probe_targets(target_url: str, max_count=4):
        url_text = str(target_url or "").strip()
        if not url_text:
            return []

        try:
            parsed = urlsplit(url_text)
            base = "{}://{}".format(parsed.scheme, parsed.netloc)
            lower_path = str(parsed.path or "").strip().lower()
            candidate_paths = []
            if lower_path and "graphql" in lower_path:
                candidate_paths.append(str(parsed.path or "").strip())
            candidate_paths.extend(
                [
                    "/graphql",
                    "/api/graphql",
                    "/graphql/console",
                    "/graphiql",
                    "/graphql-playground",
                ]
            )
            targets = []
            seen = set()
            for path in candidate_paths:
                path_text = str(path or "").strip()
                if not path_text:
                    continue
                full_url = "{}{}".format(base, path_text)
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
    def _looks_like_graphql_response(url_text: str, body_text: str, headers=None):
        url_lower = str(url_text or "").strip().lower()
        body_lower = str(body_text or "").strip().lower()
        header_obj = headers if isinstance(headers, dict) else {}
        content_type = str(header_obj.get("Content-Type", "") or "").strip().lower()

        if not body_lower and not content_type and not url_lower:
            return False

        json_markers = (
            '"__schema"',
            '"__typename"',
            '"querytype"',
            '"mutationtype"',
            'cannot query field',
            'graphql',
        )
        html_markers = (
            "graphiql",
            "graphql playground",
            "apollo sandbox",
            "graphql voyager",
        )
        if any(marker in body_lower for marker in json_markers):
            return True
        if '"errors"' in body_lower and "graphql" in url_lower:
            return True
        if any(marker in body_lower for marker in html_markers):
            return True
        if "graphql" in url_lower and any(token in content_type for token in ("json", "html", "graphql")):
            return True
        return False

    @classmethod
    def _extract_graphql_summary(cls, body_text: str):
        text = str(body_text or "").strip()
        if not text:
            return {}

        lower_text = text.lower()
        summary = {
            "mode": "unknown",
            "introspection_enabled": False,
            "error_count": 0,
            "top_level_keys": [],
        }

        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None

        if isinstance(parsed, dict):
            top_level_keys = [str(key or "").strip() for key in parsed.keys() if str(key or "").strip()]
            summary["top_level_keys"] = top_level_keys[:6]
            summary["error_count"] = len(parsed.get("errors", []) or []) if isinstance(parsed.get("errors"), list) else 0
            if isinstance(parsed.get("data"), dict):
                summary["mode"] = "json_data"
            elif summary["error_count"] > 0:
                summary["mode"] = "json_error"

            merged_json_text = json.dumps(parsed, ensure_ascii=False)[:4096].lower()
            if any(token in merged_json_text for token in ('"__schema"', '"querytype"', '"mutationtype"', '"subscriptiontype"')):
                summary["introspection_enabled"] = True
            elif '"__typename"' in merged_json_text:
                summary["mode"] = "typename"

            return summary

        if "graphiql" in lower_text:
            summary["mode"] = "graphiql"
        elif "graphql playground" in lower_text:
            summary["mode"] = "playground"
        elif "apollo sandbox" in lower_text:
            summary["mode"] = "apollo_sandbox"
        return summary

    @classmethod
    def _format_graphql_summary_text(cls, summary: dict):
        if not isinstance(summary, dict) or not summary:
            return ""

        parts = []
        mode_text = str(summary.get("mode") or "").strip()
        if mode_text:
            parts.append("mode={}".format(mode_text))
        if bool(summary.get("introspection_enabled")):
            parts.append("introspection=enabled")
        error_count = cls._safe_int_value(summary.get("error_count"), 0)
        if error_count > 0:
            parts.append("errors={}".format(error_count))
        top_level_keys = [str(item or "").strip() for item in list(summary.get("top_level_keys", []) or [])[:4] if str(item or "").strip()]
        if top_level_keys:
            parts.append("keys={}".format(",".join(top_level_keys)))
        return " | ".join(parts)

    @classmethod
    def _extract_api_doc_summary(cls, body_text: str):
        text = str(body_text or "").strip()
        if not text:
            return {}

        try:
            parsed = json.loads(text)
        except Exception:
            return {}

        if not isinstance(parsed, dict):
            return {}

        paths_obj = parsed.get("paths")
        if not isinstance(paths_obj, dict):
            return {}

        path_list = [str(key or "").strip() for key in list(paths_obj.keys()) if str(key or "").strip()]
        path_list = path_list[:120]
        sample_paths = path_list[:4]

        auth_keywords = ("login", "auth", "token", "oauth", "signin", "session", "user", "me", "current")
        auth_paths = []
        parameter_names = []
        parameter_seen = set()

        for path_text in path_list:
            path_lower = path_text.lower()
            if any(token in path_lower for token in auth_keywords):
                auth_paths.append(path_text)

            path_item = paths_obj.get(path_text)
            if not isinstance(path_item, dict):
                continue

            for op_obj in path_item.values():
                if not isinstance(op_obj, dict):
                    continue
                for parameter in op_obj.get("parameters", []) or []:
                    if not isinstance(parameter, dict):
                        continue
                    name_text = str(parameter.get("name") or "").strip()
                    if name_text and name_text not in parameter_seen:
                        parameter_seen.add(name_text)
                        parameter_names.append(name_text)
                        if len(parameter_names) >= 10:
                            break
                if len(parameter_names) >= 10:
                    break

                request_body = op_obj.get("requestBody")
                if isinstance(request_body, dict):
                    content_obj = request_body.get("content")
                    if isinstance(content_obj, dict):
                        for media_obj in content_obj.values():
                            if not isinstance(media_obj, dict):
                                continue
                            schema_obj = media_obj.get("schema")
                            if not isinstance(schema_obj, dict):
                                continue
                            props_obj = schema_obj.get("properties")
                            if not isinstance(props_obj, dict):
                                continue
                            for key in props_obj.keys():
                                key_text = str(key or "").strip()
                                if key_text and key_text not in parameter_seen:
                                    parameter_seen.add(key_text)
                                    parameter_names.append(key_text)
                                    if len(parameter_names) >= 10:
                                        break
                            if len(parameter_names) >= 10:
                                break
                        if len(parameter_names) >= 10:
                            break
            if len(parameter_names) >= 10:
                break

        components_obj = parsed.get("components")
        security_obj = components_obj.get("securitySchemes") if isinstance(components_obj, dict) else {}
        security_scheme_count = len(security_obj) if isinstance(security_obj, dict) else 0

        return {
            "path_count": len(path_list),
            "sample_paths": sample_paths,
            "auth_path_count": len(auth_paths),
            "auth_paths": auth_paths[:3],
            "parameter_names": parameter_names[:10],
            "security_scheme_count": int(security_scheme_count or 0),
        }

    @classmethod
    def _format_api_doc_summary_text(cls, summary: dict):
        if not isinstance(summary, dict) or not summary:
            return ""

        parts = []
        path_count = cls._safe_int_value(summary.get("path_count"), 0)
        if path_count > 0:
            parts.append("paths={}".format(path_count))
        auth_path_count = cls._safe_int_value(summary.get("auth_path_count"), 0)
        if auth_path_count > 0:
            parts.append("auth_paths={}".format(auth_path_count))
        security_scheme_count = cls._safe_int_value(summary.get("security_scheme_count"), 0)
        if security_scheme_count > 0:
            parts.append("securitySchemes={}".format(security_scheme_count))

        sample_paths = [str(item or "").strip() for item in list(summary.get("sample_paths", []) or [])[:3] if str(item or "").strip()]
        if sample_paths:
            parts.append("sample={}".format(",".join(sample_paths)))

        parameter_names = [str(item or "").strip() for item in list(summary.get("parameter_names", []) or [])[:6] if str(item or "").strip()]
        if parameter_names:
            parts.append("params={}".format(",".join(parameter_names)))

        return " | ".join(parts)

    @staticmethod
    def _extract_js_api_param_names(snippet: str):
        param_names = []
        seen = set()
        text = str(snippet or "")

        def append_name(name_text: str):
            name = str(name_text or "").strip()
            lowered = name.lower()
            if not name or lowered in seen:
                return
            if lowered in {
                "method", "headers", "body", "url", "type", "data", "params", "timeout",
                "responsetype", "mode", "credentials", "cache", "redirect", "signal",
                "content-type", "accept", "authorization",
            }:
                return
            seen.add(lowered)
            param_names.append(name)

        capture_patterns = (
            r"params\s*:\s*\{([^}]{1,300})\}",
            r"data\s*:\s*\{([^}]{1,300})\}",
            r"body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]{1,300})\}\s*\)",
            r"body\s*:\s*\{([^}]{1,300})\}",
            r"send\s*\(\s*JSON\.stringify\s*\(\s*\{([^}]{1,300})\}\s*\)\s*\)",
            r"new\s+URLSearchParams\s*\(\s*\{([^}]{1,300})\}\s*\)",
        )
        key_patterns = (
            r"[\"']([A-Za-z_][\w.-]{0,63})[\"']\s*:",
            r"\b([A-Za-z_][\w.-]{0,63})\s*:",
        )

        for pattern in capture_patterns:
            for match in re.finditer(pattern, text, flags=re.I | re.S):
                inner_text = str(match.group(1) or "")
                for key_pattern in key_patterns:
                    for inner_match in re.finditer(key_pattern, inner_text):
                        append_name(inner_match.group(1))

        for match in re.finditer(r"\.append\s*\(\s*[\"']([A-Za-z_][\w.-]{0,63})[\"']", text, flags=re.I):
            append_name(match.group(1))

        return param_names[:10]

    @staticmethod
    def _resolve_js_api_candidate_url(base_url: str, raw_url: str):
        candidate = str(raw_url or "").strip().strip("\"'`")
        if not candidate or "javascript:" in candidate.lower():
            return ""
        if any(mark in candidate for mark in ("${", "{{", "}}")):
            return ""

        base_parsed = urlsplit(str(base_url or "").strip())
        origin = "{}://{}".format(base_parsed.scheme, base_parsed.netloc) if base_parsed.scheme and base_parsed.netloc else ""
        if candidate.startswith(("http://", "https://")):
            return candidate
        if candidate.startswith("//") and base_parsed.scheme:
            return "{}:{}".format(base_parsed.scheme, candidate)
        if candidate.startswith(("./", "../", "/")):
            return urljoin("{}{}".format(origin, base_parsed.path or "/"), candidate)
        if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./?-]+$", candidate):
            return urljoin("{}/".format(origin) if origin else str(base_url or ""), candidate)
        return ""

    @classmethod
    def _normalize_js_api_target(cls, base_url: str, raw_url: str, method: str, params, source: str):
        resolved = cls._resolve_js_api_candidate_url(base_url, raw_url)
        if not cls._is_http_target(resolved):
            return {}

        param_names = []
        seen = set()

        def append_param(name_text):
            key_text = str(name_text or "").strip()
            lowered = key_text.lower()
            if not key_text or lowered in seen:
                return
            seen.add(lowered)
            param_names.append(key_text)

        try:
            parsed_query = str(urlsplit(resolved).query or "").strip()
            if parsed_query:
                for item in parsed_query.split("&"):
                    key_text = str(item.split("=", 1)[0] or "").strip()
                    append_param(key_text)
        except Exception:
            pass

        for item in list(params or []):
            append_param(item)

        method_name = str(method or "GET").strip().upper() or "GET"
        if method_name not in {"GET", "POST"}:
            return {}

        return {
            "method": method_name,
            "url": resolved,
            "params": param_names[:10],
            "source": str(source or "").strip() or "js_api_extract",
        }

    @classmethod
    def _extract_js_api_targets(cls, base_url: str, content: str):
        targets = []
        seen = set()
        merged_content = str(content or "")

        def request_window(start_index: int):
            start = max(0, int(start_index or 0))
            end = min(len(merged_content), start + 800)
            snippet = merged_content[start:end]
            close_candidates = []
            for token in (");", "})", "};", "\n\n"):
                pos = snippet.find(token)
                if pos >= 0:
                    close_candidates.append(pos + len(token))
            if close_candidates:
                snippet = snippet[: min(close_candidates)]
            return snippet

        def append_target(raw_url: str, method_name: str, params, source="js_api_extract"):
            target = cls._normalize_js_api_target(base_url, raw_url, method_name, params, source)
            if not target:
                return
            dedupe_key = "{}|{}|{}".format(
                str(target.get("method") or "").strip(),
                str(target.get("url") or "").strip(),
                ",".join(list(target.get("params", []) or [])),
            )
            if dedupe_key in seen:
                return
            seen.add(dedupe_key)
            targets.append(target)

        for match in re.finditer(r"fetch\s*\(\s*([\"'`])([^\"'`]+)\1", merged_content, flags=re.I):
            raw_url = str(match.group(2) or "").strip()
            window = request_window(match.start())
            method_match = re.search(r"method\s*:\s*[\"']([A-Za-z]+)[\"']", window, flags=re.I)
            method_name = str(method_match.group(1) or "GET").strip().upper() if method_match else "GET"
            append_target(raw_url, method_name, cls._extract_js_api_param_names(window))

        for match in re.finditer(r"axios\.(get|post|put|delete|patch)\s*\(\s*([\"'`])([^\"'`]+)\2", merged_content, flags=re.I):
            method_name = str(match.group(1) or "GET").strip().upper()
            raw_url = str(match.group(3) or "").strip()
            window = request_window(match.start())
            append_target(raw_url, method_name, cls._extract_js_api_param_names(window))

        for match in re.finditer(r"\$\.ajax\s*\(\s*\{", merged_content, flags=re.I):
            window = request_window(match.start())
            url_match = re.search(r"url\s*:\s*([\"'`])([^\"'`]+)\1", window, flags=re.I)
            if not url_match:
                continue
            method_match = re.search(r"(?:type|method)\s*:\s*[\"']([A-Za-z]+)[\"']", window, flags=re.I)
            method_name = str(method_match.group(1) or "GET").strip().upper() if method_match else "GET"
            append_target(str(url_match.group(2) or "").strip(), method_name, cls._extract_js_api_param_names(window))

        for match in re.finditer(r"\.open\s*\(\s*([\"'])(GET|POST|PUT|PATCH|DELETE)\1\s*,\s*([\"'`])([^\"'`]+)\3", merged_content, flags=re.I):
            method_name = str(match.group(2) or "GET").strip().upper()
            raw_url = str(match.group(4) or "").strip()
            window = request_window(match.start())
            append_target(raw_url, method_name, cls._extract_js_api_param_names(window))

        targets.sort(key=lambda item: (-len(item.get("params", [])), str(item.get("url", "") or "")))
        return targets[:20]

    @classmethod
    def _build_api_surface_summary(cls, api_doc_summary=None, js_api_targets=None):
        doc_summary = api_doc_summary if isinstance(api_doc_summary, dict) else {}
        js_targets = list(js_api_targets or [])

        parameter_names = []
        parameter_seen = set()
        auth_paths = [str(item or "").strip() for item in list(doc_summary.get("auth_paths", []) or []) if str(item or "").strip()]
        sample_interfaces = []

        auth_like_count = cls._safe_int_value(doc_summary.get("auth_path_count"), 0)
        object_id_like_count = 0
        upload_like_count = 0
        download_like_count = 0

        for item in js_targets:
            if not isinstance(item, dict):
                continue
            method_name = str(item.get("method") or "GET").strip().upper()
            url_text = str(item.get("url") or "").strip()
            params = [str(param or "").strip() for param in list(item.get("params", []) or []) if str(param or "").strip()]
            source_text = str(item.get("source") or "").strip()
            path_text = str(urlsplit(url_text).path or "").strip()
            path_lower = path_text.lower()

            if any(token in path_lower for token in cls.AI_PEN_AUTH_PATH_KEYWORDS):
                auth_like_count += 1
                if path_text and path_text not in auth_paths:
                    auth_paths.append(path_text)
            if any(param.lower() in cls.AI_PEN_OBJECT_ID_PARAM_HINTS or param.lower().endswith("_id") for param in params):
                object_id_like_count += 1
            if any(token in path_lower for token in cls.AI_PEN_UPLOAD_HINTS) or any("file" in param.lower() for param in params):
                upload_like_count += 1
            if any(token in path_lower for token in cls.AI_PEN_DOWNLOAD_HINTS):
                download_like_count += 1

            for param in params:
                lowered = param.lower()
                if lowered not in parameter_seen:
                    parameter_seen.add(lowered)
                    parameter_names.append(param)

            if len(sample_interfaces) < 6:
                sample_interfaces.append(
                    {
                        "method": method_name,
                        "path": path_text or url_text,
                        "params": params[:6],
                        "source": source_text or "js_api_extract",
                    }
                )

        path_count = max(cls._safe_int_value(doc_summary.get("path_count"), 0), len(js_targets))
        security_scheme_count = cls._safe_int_value(doc_summary.get("security_scheme_count"), 0)
        if any(token.lower() in {"authorization", "token"} for token in parameter_seen):
            security_scheme_count = max(security_scheme_count, 1)

        sample_paths = [str(item or "").strip() for item in list(doc_summary.get("sample_paths", []) or []) if str(item or "").strip()]
        if not sample_paths:
            sample_paths = [str(item.get("path") or "").strip() for item in sample_interfaces if str(item.get("path") or "").strip()]

        return {
            "path_count": path_count,
            "sample_paths": sample_paths[:6],
            "auth_path_count": auth_like_count,
            "auth_paths": auth_paths[:6],
            "parameter_names": parameter_names[:12] or list(doc_summary.get("parameter_names", []) or [])[:12],
            "security_scheme_count": security_scheme_count,
            "object_id_like_count": object_id_like_count,
            "upload_like_count": upload_like_count,
            "download_like_count": download_like_count,
            "js_api_count": len(js_targets),
            "sample_interfaces": sample_interfaces[:6],
            "source_types": [item for item in ["api_doc" if doc_summary else "", "js" if js_targets else ""] if item],
        }

    @classmethod
    def _format_api_surface_summary_text(cls, summary: dict):
        if not isinstance(summary, dict) or not summary:
            return ""

        parts = []
        for key_name, alias in (
            ("path_count", "paths"),
            ("auth_path_count", "auth_paths"),
            ("security_scheme_count", "securitySchemes"),
            ("object_id_like_count", "object_id"),
            ("upload_like_count", "upload"),
            ("download_like_count", "download"),
            ("js_api_count", "js_api"),
        ):
            value = cls._safe_int_value(summary.get(key_name), 0)
            if value > 0:
                parts.append("{}={}".format(alias, value))

        sample_paths = [str(item or "").strip() for item in list(summary.get("sample_paths", []) or [])[:3] if str(item or "").strip()]
        if sample_paths:
            parts.append("sample={}".format(",".join(sample_paths)))

        parameter_names = [str(item or "").strip() for item in list(summary.get("parameter_names", []) or [])[:6] if str(item or "").strip()]
        if parameter_names:
            parts.append("params={}".format(",".join(parameter_names)))

        return " | ".join(parts)

    @staticmethod
    def _extract_form_field_names(dom_form_summary):
        results = []
        seen = set()
        for item in dom_form_summary or []:
            if not isinstance(item, dict):
                continue
            fields_text = str(item.get("fields") or "").strip()
            if not fields_text:
                continue
            for field_name in fields_text.split(","):
                text = str(field_name or "").strip()
                lowered = text.lower()
                if not text or lowered in seen:
                    continue
                seen.add(lowered)
                results.append(text)
                if len(results) >= 12:
                    return results
        return results

    @staticmethod
    def _extract_html_attr_value(raw_text: str, attr_name: str):
        text = str(raw_text or "")
        attr = str(attr_name or "").strip()
        if not text or not attr:
            return ""

        pattern = r'(?is)\b{}\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))'.format(re.escape(attr))
        match = re.search(pattern, text)
        if not match:
            return ""
        for group_id in (1, 2, 3):
            value = str(match.group(group_id) or "").strip()
            if value:
                return value
        return ""

    @classmethod
    def _extract_html_login_form_candidate(cls, target_url: str, body_text: str):
        content = str(body_text or "")
        if not content:
            return {}

        best_form = {}
        best_score = -1
        for match in re.finditer(r"(?is)<form\b([^>]*)>(.*?)</form>", content):
            attrs_text = str(match.group(1) or "")
            inner_html = str(match.group(2) or "")
            action_text = cls._extract_html_attr_value(attrs_text, "action")
            method_text = cls._extract_html_attr_value(attrs_text, "method").lower() or "post"
            enctype_text = cls._extract_html_attr_value(attrs_text, "enctype").lower()
            merged_form_text = "{} {}".format(attrs_text, inner_html).lower()

            visible_fields = []
            hidden_fields = {}
            username_field = ""
            password_field = ""
            csrf_field = ""
            captcha_required = False
            score = 0

            if any(token in merged_form_text for token in cls.AI_PEN_LOGIN_PAGE_KEYWORDS):
                score += 2

            for input_match in re.finditer(r"(?is)<input\b([^>]*)>", inner_html):
                input_attrs = str(input_match.group(1) or "")
                field_name = cls._extract_html_attr_value(input_attrs, "name") or cls._extract_html_attr_value(input_attrs, "id")
                field_type = (cls._extract_html_attr_value(input_attrs, "type") or "text").strip().lower() or "text"
                field_value = cls._extract_html_attr_value(input_attrs, "value")
                lowered_name = str(field_name or "").strip().lower()

                if field_type == "password":
                    password_field = field_name or password_field or "password"
                    score += 5
                    continue

                if field_type == "hidden":
                    if field_name:
                        hidden_fields[field_name] = field_value[:180]
                        if any(token in lowered_name for token in cls.AI_PEN_CSRF_FIELD_HINTS):
                            csrf_field = field_name
                    continue

                if field_name:
                    visible_fields.append(field_name)
                    if (not username_field) and any(token in lowered_name for token in ("user", "name", "account", "login", "email", "mobile", "phone")):
                        username_field = field_name
                    if any(token in lowered_name for token in cls.AI_PEN_CAPTCHA_HINTS):
                        captcha_required = True

            if password_field and (not username_field):
                for field_name in visible_fields:
                    lowered_name = str(field_name or "").strip().lower()
                    if any(token in lowered_name for token in ("user", "name", "account", "login", "email", "mobile", "phone")):
                        username_field = field_name
                        break

            if captcha_required:
                score -= 1
            if action_text:
                score += 1

            if password_field and score > best_score:
                best_score = score
                best_form = {
                    "login_url": str(target_url or "").strip(),
                    "submit_url": urljoin(str(target_url or "").strip(), action_text) if action_text else str(target_url or "").strip(),
                    "form_action": action_text,
                    "method": method_text,
                    "enctype": enctype_text,
                    "username_field": username_field or "username",
                    "password_field": password_field or "password",
                    "csrf_field": csrf_field,
                    "captcha_required": bool(captcha_required),
                    "hidden_fields": hidden_fields,
                    "fields": visible_fields[:12],
                }
        return best_form

    @classmethod
    def _build_ai_pen_login_probe_context(
        cls,
        target_url: str,
        body_text: str = "",
        dom_form_summary=None,
        login_surface_summary=None,
    ):
        dom_forms = list(dom_form_summary or [])
        summary = login_surface_summary if isinstance(login_surface_summary, dict) else {}
        html_form = cls._extract_html_login_form_candidate(target_url, body_text)

        form_actions = [str(item or "").strip() for item in list(summary.get("form_actions", []) or []) if str(item or "").strip()]
        summary_fields = cls._extract_form_field_names(dom_forms)
        has_password_form = bool(html_form.get("password_field")) or cls._safe_int_value(summary.get("password_form_count"), 0) > 0
        captcha_required = bool(html_form.get("captcha_required")) or cls._safe_int_value(summary.get("captcha_form_count"), 0) > 0

        candidate_fields = []
        for field_name in list(html_form.get("fields", []) or []) + summary_fields:
            field_text = str(field_name or "").strip()
            if field_text and field_text not in candidate_fields:
                candidate_fields.append(field_text)

        def pick_field(existing_value: str, default_value: str, keywords):
            if str(existing_value or "").strip():
                return str(existing_value or "").strip()
            for field_name in candidate_fields:
                lowered_name = field_name.lower()
                if any(token in lowered_name for token in keywords):
                    return field_name
            return default_value

        username_field = pick_field(html_form.get("username_field"), "username", ("user", "name", "account", "login", "email", "mobile", "phone"))
        password_field = pick_field(html_form.get("password_field"), "password", ("password", "passwd", "pwd"))
        csrf_field = pick_field(html_form.get("csrf_field"), "", cls.AI_PEN_CSRF_FIELD_HINTS)

        login_url = str(target_url or "").strip()
        submit_url = str(html_form.get("submit_url") or "").strip()
        form_action = str(html_form.get("form_action") or "").strip()
        method_text = str(html_form.get("method") or "").strip().lower() or "post"
        enctype_text = str(html_form.get("enctype") or "").strip().lower()
        hidden_fields = dict(html_form.get("hidden_fields") or {}) if isinstance(html_form.get("hidden_fields"), dict) else {}

        if not submit_url and form_actions:
            form_action = str(form_actions[0] or "").strip()
            submit_url = urljoin(login_url, form_action)
        if not submit_url and has_password_form:
            submit_url = login_url

        if not has_password_form or not submit_url:
            return {}

        return {
            "login_url": login_url,
            "submit_url": submit_url,
            "form_action": form_action,
            "method": method_text,
            "enctype": enctype_text,
            "username_field": username_field,
            "password_field": password_field,
            "csrf_field": csrf_field,
            "captcha_required": bool(captcha_required),
            "hidden_fields": hidden_fields,
            "fields": candidate_fields[:12],
        }

    @classmethod
    def _extract_html_upload_form_candidate(cls, target_url: str, body_text: str):
        content = str(body_text or "")
        if not content:
            return {}

        best_form = {}
        best_score = -1
        for match in re.finditer(r"(?is)<form\b([^>]*)>(.*?)</form>", content):
            attrs_text = str(match.group(1) or "")
            inner_html = str(match.group(2) or "")
            action_text = cls._extract_html_attr_value(attrs_text, "action")
            method_text = cls._extract_html_attr_value(attrs_text, "method").lower() or "post"
            enctype_text = cls._extract_html_attr_value(attrs_text, "enctype").lower()
            hidden_fields = {}
            file_field = ""
            field_names = []
            score = 0

            if "multipart/form-data" in enctype_text:
                score += 3

            for input_match in re.finditer(r"(?is)<input\b([^>]*)>", inner_html):
                input_attrs = str(input_match.group(1) or "")
                field_name = cls._extract_html_attr_value(input_attrs, "name") or cls._extract_html_attr_value(input_attrs, "id")
                field_type = (cls._extract_html_attr_value(input_attrs, "type") or "text").strip().lower() or "text"
                field_value = cls._extract_html_attr_value(input_attrs, "value")
                lowered_name = str(field_name or "").strip().lower()

                if field_type == "hidden" and field_name:
                    hidden_fields[field_name] = field_value[:180]
                    continue
                if field_name:
                    field_names.append(field_name)
                if field_type == "file" or any(token in lowered_name for token in ("file", "image", "avatar", "attachment")):
                    file_field = field_name or file_field or "file"
                    score += 5

            if file_field and score > best_score:
                best_score = score
                best_form = {
                    "probe_type": "upload",
                    "probe_url": urljoin(str(target_url or "").strip(), action_text) if action_text else str(target_url or "").strip(),
                    "submit_url": urljoin(str(target_url or "").strip(), action_text) if action_text else str(target_url or "").strip(),
                    "form_action": action_text,
                    "method": method_text,
                    "enctype": enctype_text,
                    "file_field": file_field or "file",
                    "hidden_fields": hidden_fields,
                    "fields": field_names[:12],
                }
        return best_form

    @classmethod
    def _build_ai_pen_file_probe_context(
        cls,
        target_url: str,
        risk_type: str = "",
        body_text: str = "",
        api_surface_summary=None,
        dom_form_summary=None,
    ):
        url_text = str(target_url or "").strip()
        risk_type_text = str(risk_type or "").strip().lower()
        summary = api_surface_summary if isinstance(api_surface_summary, dict) else {}
        forms = list(dom_form_summary or [])
        upload_form = cls._extract_html_upload_form_candidate(url_text, body_text)

        file_form_hits = []
        for form_item in forms:
            if not isinstance(form_item, dict):
                continue
            action_text = str(form_item.get("action") or "").strip()
            enctype_text = str(form_item.get("enctype") or "").strip().lower()
            has_file_input = str(form_item.get("has_file_input") or "").strip().lower() in {"1", "true", "yes"}
            fields = [str(field or "").strip() for field in str(form_item.get("fields") or "").split(",") if str(field or "").strip()]
            if has_file_input or "multipart/form-data" in enctype_text:
                file_field = "file"
                for field_name in fields:
                    lowered_name = field_name.lower()
                    if any(token in lowered_name for token in ("file", "image", "avatar", "attachment")):
                        file_field = field_name
                        break
                file_form_hits.append(
                    {
                        "probe_type": "upload",
                        "probe_url": urljoin(url_text, action_text) if action_text else url_text,
                        "submit_url": urljoin(url_text, action_text) if action_text else url_text,
                        "form_action": action_text,
                        "method": str(form_item.get("method") or "post").strip().lower() or "post",
                        "enctype": enctype_text,
                        "file_field": file_field,
                        "hidden_fields": {},
                        "fields": fields[:12],
                    }
                )

        if upload_form:
            return upload_form
        if file_form_hits:
            return file_form_hits[0]

        try:
            path_lower = str(urlsplit(url_text).path or "").strip().lower()
        except Exception:
            path_lower = url_text.lower()

        upload_like_count = cls._safe_int_value(summary.get("upload_like_count"), 0)
        download_like_count = cls._safe_int_value(summary.get("download_like_count"), 0)
        if risk_type_text == "file_upload" or upload_like_count > 0 or any(token in path_lower for token in cls.AI_PEN_UPLOAD_HINTS):
            return {
                "probe_type": "upload",
                "probe_url": url_text,
                "submit_url": url_text,
                "method": "post",
                "enctype": "multipart/form-data",
                "file_field": "file",
                "hidden_fields": {},
                "fields": ["file"],
            }

        if risk_type_text == "file_read" or download_like_count > 0 or any(token in path_lower for token in cls.AI_PEN_DOWNLOAD_HINTS):
            return {
                "probe_type": "download",
                "probe_url": url_text,
                "method": "get",
            }

        return {}

    @classmethod
    def _parse_ai_pen_payload_credentials(cls, payload: str):
        payload_text = str(payload or "").strip()
        if not payload_text:
            return {}

        username = ""
        password = ""
        for key, value in parse_qsl(payload_text, keep_blank_values=True):
            key_text = str(key or "").strip().lower()
            value_text = str(value or "").strip()
            if not value_text:
                continue
            if (not username) and any(token == key_text or token in key_text for token in ("username", "user", "account", "login", "email")):
                username = value_text
            elif (not password) and any(token == key_text or token in key_text for token in ("password", "passwd", "pwd")):
                password = value_text
        if username and password:
            return {"username": username, "password": password}
        return {}

    @classmethod
    def _build_ai_pen_minimal_default_credentials(cls, candidate: dict = None, payload: str = "", max_count: int = 3):
        item = candidate if isinstance(candidate, dict) else {}
        result = []
        seen = set()

        def append_pair(username: str, password: str, source: str):
            user_text = str(username or "").strip()
            pass_text = str(password or "").strip()
            if not user_text or not pass_text:
                return
            cache_key = "{}\0{}".format(user_text, pass_text)
            if cache_key in seen:
                return
            seen.add(cache_key)
            result.append(
                {
                    "username": user_text[:80],
                    "password": pass_text[:80],
                    "source": str(source or "").strip()[:48],
                }
            )

        payload_credentials = cls._parse_ai_pen_payload_credentials(payload)
        if payload_credentials:
            append_pair(payload_credentials.get("username"), payload_credentials.get("password"), "payload_hint")

        merged_text = " ".join(
            [
                str(item.get("target") or "").strip().lower(),
                str(item.get("risk_name") or "").strip().lower(),
                " ".join([str(x or "").strip().lower() for x in list(item.get("knowledge_hit_tokens", []) or [])[:16]]),
                " ".join([str(x or "").strip().lower() for x in list(item.get("knowledge_hit_product_labels", []) or [])[:8]]),
                " ".join([str(x or "").strip().lower() for x in list(item.get("surface_hints", []) or [])[:8]]),
            ]
        ).strip()
        for product_name, credential_pairs in cls.AI_PEN_PRODUCT_DEFAULT_CREDENTIALS.items():
            if product_name in merged_text:
                for username, password in credential_pairs:
                    append_pair(username, password, "product_default")
                    if len(result) >= max(1, int(max_count or 1)):
                        return result[: max(1, int(max_count or 1))]

        for username, password in cls.AI_PEN_MINIMAL_DEFAULT_CREDENTIALS:
            append_pair(username, password, "minimal_default")
            if len(result) >= max(1, int(max_count or 1)):
                break
        return result[: max(1, int(max_count or 1))]

    @classmethod
    def _analyze_ai_pen_login_success(cls, login_url: str, response_summary, base_body_text: str = ""):
        response_obj = response_summary if isinstance(response_summary, dict) else {}
        headers = response_obj.get("headers") if isinstance(response_obj.get("headers"), dict) else {}
        body_text = str(response_obj.get("body_text") or "").strip()
        body_lower = body_text.lower()
        base_lower = str(base_body_text or "").strip().lower()
        final_url = str(response_obj.get("url") or login_url or "").strip()
        history_urls = [str(item or "").strip() for item in list(response_obj.get("history_urls", []) or []) if str(item or "").strip()]
        cookie_names = [str(item or "").strip() for item in list(response_obj.get("cookie_names", []) or []) if str(item or "").strip()]
        location_value = str(headers.get("Location") or headers.get("location") or "").strip()

        try:
            login_path = str(urlsplit(str(login_url or "")).path or "").strip().lower()
        except Exception:
            login_path = str(login_url or "").strip().lower()
        try:
            final_path = str(urlsplit(final_url).path or "").strip().lower()
        except Exception:
            final_path = final_url.lower()

        login_like_tokens = cls.AI_PEN_LOGIN_PAGE_KEYWORDS
        if any(token in body_lower and token not in base_lower for token in cls.AI_PEN_LOGIN_BLOCK_KEYWORDS):
            return {
                "success": False,
                "blocked": True,
                "reason": "登录流程出现验证码或锁定提示，默认停止弱口令验证",
                "final_url": final_url,
            }

        if any(token in body_lower and token not in base_lower for token in cls.AI_PEN_LOGIN_FAILURE_KEYWORDS):
            return {
                "success": False,
                "blocked": False,
                "reason": "登录响应出现失败提示，当前凭证未验证通过",
                "final_url": final_url,
            }

        if any(token in body_lower and token not in base_lower for token in cls.AI_PEN_LOGIN_SUCCESS_KEYWORDS):
            return {
                "success": True,
                "blocked": False,
                "reason": "登录响应出现成功/进入后台关键词",
                "final_url": final_url,
            }

        if location_value:
            resolved_location = urljoin(final_url or login_url, location_value)
            try:
                location_path = str(urlsplit(resolved_location).path or "").strip().lower()
            except Exception:
                location_path = resolved_location.lower()
            if location_path and location_path != login_path and not any(token in location_path for token in login_like_tokens):
                return {
                    "success": True,
                    "blocked": False,
                    "reason": "登录后发生非登录页跳转",
                    "final_url": resolved_location,
                }

        if history_urls and final_path and final_path != login_path and not any(token in final_path for token in login_like_tokens):
            return {
                "success": True,
                "blocked": False,
                "reason": "登录后进入非登录页路径",
                "final_url": final_url,
            }

        if cookie_names and final_path and final_path != login_path and not any(token in final_path for token in login_like_tokens):
            if any(token in " ".join(cookie_names).lower() for token in ("session", "auth", "token", "jwt", "sid")):
                return {
                    "success": True,
                    "blocked": False,
                    "reason": "登录后获得鉴权 Cookie 且页面已离开登录路径",
                    "final_url": final_url,
                }

        return {
            "success": False,
            "blocked": False,
            "reason": "未观察到稳定的登录成功信号",
            "final_url": final_url,
        }

    @staticmethod
    def _extract_runtime_api_paths(runtime_api_calls):
        results = []
        seen = set()
        for item in runtime_api_calls or []:
            if not isinstance(item, dict):
                continue
            url_text = str(item.get("url") or "").strip()
            if not url_text:
                continue
            try:
                parsed = urlsplit(url_text)
                path_text = "{}{}".format(str(parsed.path or "").strip(), ("?" + parsed.query) if parsed.query else "")
            except Exception:
                path_text = url_text
            if path_text and path_text not in seen:
                seen.add(path_text)
                results.append(path_text[:180])
            if len(results) >= 8:
                break
        return results

    @classmethod
    def _build_ai_pen_intel_layers_summary(cls, candidate: dict):
        item = candidate if isinstance(candidate, dict) else {}
        api_surface_summary = item.get("api_surface_summary") if isinstance(item.get("api_surface_summary"), dict) else {}
        browser_surface_summary = item.get("browser_surface_summary") if isinstance(item.get("browser_surface_summary"), dict) else {}
        runtime_api_calls = list(item.get("runtime_api_calls", []) or [])
        dom_form_summary = list(item.get("dom_form_summary", []) or [])
        knowledge_hit_tokens = [str(x or "").strip() for x in list(item.get("knowledge_hit_tokens", []) or []) if str(x or "").strip()]
        knowledge_entry_paths = [str(x or "").strip() for x in list(item.get("knowledge_hit_entry_paths", []) or []) if str(x or "").strip()]
        knowledge_vuln_types = [str(x or "").strip() for x in list(item.get("knowledge_hit_vuln_types", []) or []) if str(x or "").strip()]
        parameter_names = [str(x or "").strip() for x in list(api_surface_summary.get("parameter_names", []) or []) if str(x or "").strip()]
        browser_role = str(browser_surface_summary.get("source_role") or "").strip()

        static_layer = {
            "context_ready": bool(cls._browser_intel_static_context_sufficient(item)),
            "api_path_count": cls._safe_int_value(api_surface_summary.get("path_count"), 0),
            "auth_path_count": cls._safe_int_value(api_surface_summary.get("auth_path_count"), 0),
            "security_scheme_count": cls._safe_int_value(api_surface_summary.get("security_scheme_count"), 0),
            "js_api_count": cls._safe_int_value(api_surface_summary.get("js_api_count"), 0),
            "param_count": len(parameter_names[:24]),
        }
        runtime_layer = {
            "used": bool(runtime_api_calls or dom_form_summary or browser_surface_summary),
            "role": browser_role[:64],
            "runtime_api_count": min(16, len(runtime_api_calls)),
            "dom_form_count": min(8, len(dom_form_summary)),
            "script_count": cls._safe_int_value(browser_surface_summary.get("script_count"), 0),
        }
        knowledge_layer = {
            "token_count": min(24, len(knowledge_hit_tokens)),
            "entry_path_count": min(16, len(knowledge_entry_paths)),
            "vuln_type_count": min(12, len(knowledge_vuln_types)),
        }

        active_layers = ["static_surface"]
        if knowledge_layer["token_count"] or knowledge_layer["entry_path_count"] or knowledge_layer["vuln_type_count"]:
            active_layers.append("knowledge_index")
        if runtime_layer["used"]:
            active_layers.append("browser_runtime")

        return {
            "active_layers": active_layers,
            "static_layer": static_layer,
            "runtime_layer": runtime_layer,
            "knowledge_layer": knowledge_layer,
        }

    @classmethod
    def _build_ai_pen_login_surface_summary(cls, candidate: dict):
        item = candidate if isinstance(candidate, dict) else {}
        browser_surface_summary = item.get("browser_surface_summary") if isinstance(item.get("browser_surface_summary"), dict) else {}
        api_surface_summary = item.get("api_surface_summary") if isinstance(item.get("api_surface_summary"), dict) else {}
        runtime_api_calls = list(item.get("runtime_api_calls", []) or [])
        dom_form_summary = list(item.get("dom_form_summary", []) or [])

        page_title = str(browser_surface_summary.get("page_title") or "").strip()
        page_url = str(browser_surface_summary.get("page_url") or item.get("target") or item.get("vuln_url") or "").strip()
        merged_text = " ".join(
            [
                page_title.lower(),
                page_url.lower(),
                str(item.get("risk_name") or "").strip().lower(),
                str(item.get("evidence_seed") or "").strip().lower(),
            ]
        ).strip()

        auth_form_count = 0
        password_form_count = 0
        captcha_form_count = 0
        form_actions = []
        password_fields = []
        captcha_fields = []
        seen_actions = set()
        seen_password_fields = set()
        seen_captcha_fields = set()

        for form_item in dom_form_summary:
            if not isinstance(form_item, dict):
                continue
            action_text = str(form_item.get("action") or "").strip()
            fields = [str(field or "").strip() for field in str(form_item.get("fields") or "").split(",") if str(field or "").strip()]
            lower_fields = [field.lower() for field in fields]
            has_password = str(form_item.get("has_password_input") or "").strip().lower() in {"1", "true", "yes"} or any(
                token in lower_fields for token in ("password", "passwd", "pwd")
            )
            has_captcha = str(form_item.get("has_captcha_hint") or "").strip().lower() in {"1", "true", "yes"} or any(
                any(keyword in field for keyword in cls.AI_PEN_CAPTCHA_HINTS) for field in lower_fields
            )
            if has_password:
                password_form_count += 1
                auth_form_count += 1
            if has_captcha:
                captcha_form_count += 1
            if has_password or has_captcha:
                if action_text and action_text not in seen_actions:
                    seen_actions.add(action_text)
                    form_actions.append(action_text[:180])
            for field in fields:
                lowered = field.lower()
                if lowered in {"password", "passwd", "pwd"} and lowered not in seen_password_fields:
                    seen_password_fields.add(lowered)
                    password_fields.append(field[:60])
                if any(keyword in lowered for keyword in cls.AI_PEN_CAPTCHA_HINTS) and lowered not in seen_captcha_fields:
                    seen_captcha_fields.add(lowered)
                    captcha_fields.append(field[:60])

        runtime_auth_paths = []
        runtime_captcha_paths = []
        seen_runtime_auth = set()
        seen_runtime_captcha = set()
        for path_text in cls._extract_runtime_api_paths(runtime_api_calls):
            lowered = str(path_text or "").strip().lower()
            if not lowered:
                continue
            if any(token in lowered for token in cls.AI_PEN_AUTH_PATH_KEYWORDS) and lowered not in seen_runtime_auth:
                seen_runtime_auth.add(lowered)
                runtime_auth_paths.append(path_text[:180])
            if any(token in lowered for token in cls.AI_PEN_CAPTCHA_HINTS) and lowered not in seen_runtime_captcha:
                seen_runtime_captcha.add(lowered)
                runtime_captcha_paths.append(path_text[:180])

        auth_api_paths = [str(item or "").strip()[:180] for item in list(api_surface_summary.get("auth_paths", []) or []) if str(item or "").strip()]
        login_page_hint = any(token in merged_text for token in cls.AI_PEN_LOGIN_PAGE_KEYWORDS)

        indicators = []
        if login_page_hint:
            indicators.append("login_keyword")
        if password_form_count > 0:
            indicators.append("password_form")
        if captcha_form_count > 0 or runtime_captcha_paths:
            indicators.append("captcha_hint")
        if runtime_auth_paths:
            indicators.append("auth_runtime_api")
        if auth_api_paths:
            indicators.append("auth_api_surface")

        return {
            "page_title": page_title[:160],
            "page_url": page_url[:240],
            "login_page_hint": bool(login_page_hint),
            "auth_form_count": int(auth_form_count),
            "password_form_count": int(password_form_count),
            "captcha_form_count": int(captcha_form_count),
            "auth_runtime_call_count": len(runtime_auth_paths),
            "auth_api_path_count": len(auth_api_paths),
            "form_actions": form_actions[:6],
            "runtime_auth_paths": runtime_auth_paths[:6],
            "runtime_captcha_paths": runtime_captcha_paths[:4],
            "auth_api_paths": auth_api_paths[:6],
            "password_fields": password_fields[:6],
            "captcha_fields": captcha_fields[:6],
            "indicators": indicators[:8],
        }

    @classmethod
    def _build_ai_pen_graph_summary(cls, candidate: dict):
        item = candidate if isinstance(candidate, dict) else {}
        api_surface_summary = item.get("api_surface_summary") if isinstance(item.get("api_surface_summary"), dict) else {}
        runtime_api_calls = list(item.get("runtime_api_calls", []) or [])
        dom_form_summary = list(item.get("dom_form_summary", []) or [])
        knowledge_entry_paths = [str(x or "").strip() for x in list(item.get("knowledge_hit_entry_paths", []) or []) if str(x or "").strip()]
        knowledge_vuln_types = [str(x or "").strip() for x in list(item.get("knowledge_hit_vuln_types", []) or []) if str(x or "").strip()]
        intel_layers = cls._build_ai_pen_intel_layers_summary(item)

        top_paths = []
        seen_paths = set()
        for path_text in (
            list(api_surface_summary.get("sample_paths", []) or [])
            + cls._extract_runtime_api_paths(runtime_api_calls)
            + knowledge_entry_paths
        ):
            text = str(path_text or "").strip()
            if not text or text in seen_paths:
                continue
            seen_paths.add(text)
            top_paths.append(text[:180])
            if len(top_paths) >= 8:
                break

        top_params = []
        seen_params = set()
        for name_text in (
            list(api_surface_summary.get("parameter_names", []) or [])
            + cls._extract_form_field_names(dom_form_summary)
        ):
            text = str(name_text or "").strip()
            lowered = text.lower()
            if not text or lowered in seen_params:
                continue
            seen_params.add(lowered)
            top_params.append(text[:80])
            if len(top_params) >= 12:
                break

        auth_cluster = {
            "auth_path_count": cls._safe_int_value(api_surface_summary.get("auth_path_count"), 0),
            "security_scheme_count": cls._safe_int_value(api_surface_summary.get("security_scheme_count"), 0),
            "top_auth_paths": [str(x or "").strip()[:180] for x in list(api_surface_summary.get("auth_paths", []) or [])[:4] if str(x or "").strip()],
        }
        object_ref_cluster = {
            "object_id_like_count": cls._safe_int_value(api_surface_summary.get("object_id_like_count"), 0),
            "object_ref_params": [text for text in top_params if text.lower().endswith("_id") or text.lower() in cls.AI_PEN_OBJECT_ID_PARAM_HINTS][:6],
        }
        file_cluster = {
            "upload_like_count": cls._safe_int_value(api_surface_summary.get("upload_like_count"), 0),
            "download_like_count": cls._safe_int_value(api_surface_summary.get("download_like_count"), 0),
        }

        node_count = 0
        for value in (
            1 if str(item.get("target") or item.get("vuln_url") or "").strip() else 0,
            len(top_paths),
            len(top_params),
            min(8, len(runtime_api_calls)),
            min(6, len(dom_form_summary)),
            min(6, len(knowledge_vuln_types)),
        ):
            node_count += int(value or 0)

        edge_count = min(
            32,
            max(0, len(top_paths) - 1)
            + max(0, len(top_params) - 1)
            + min(12, len(runtime_api_calls))
            + min(8, len(dom_form_summary)),
        )

        return {
            "node_count": node_count,
            "edge_count": edge_count,
            "top_paths": top_paths,
            "top_params": top_params,
            "auth_cluster": auth_cluster,
            "object_ref_cluster": object_ref_cluster,
            "file_cluster": file_cluster,
            "browser_runtime_call_count": min(16, len(runtime_api_calls)),
            "dom_form_count": min(8, len(dom_form_summary)),
            "knowledge_vuln_types": knowledge_vuln_types[:6],
            "intel_layers": intel_layers,
        }

    @classmethod
    def _build_task_ai_pen_graph_context(cls, candidates):
        candidate_list = [item for item in list(candidates or []) if isinstance(item, dict)]
        source_counter = {}
        route_counter = {}
        layer_counter = {}
        feature_presence = {
            "auth_surface_candidates": 0,
            "object_ref_candidates": 0,
            "file_candidates": 0,
            "browser_runtime_candidates": 0,
            "knowledge_guided_candidates": 0,
            "login_surface_candidates": 0,
        }

        top_paths = []
        top_params = []
        auth_paths = []
        runtime_targets = []
        knowledge_vuln_types = []
        seen_paths = set()
        seen_params = set()
        seen_auth_paths = set()
        seen_runtime_targets = set()
        seen_vuln_types = set()

        def _append_limited(target_list, seen_set, raw_value, max_count=8, lower=False, clip=180):
            text = str(raw_value or "").strip()
            if not text:
                return
            cache_key = text.lower() if lower else text
            if cache_key in seen_set:
                return
            seen_set.add(cache_key)
            target_list.append(text[:clip])

        def _build_top_counts(counter_obj: dict, max_count=6):
            results = []
            for name_text, count in sorted(counter_obj.items(), key=lambda item: (-int(item[1] or 0), str(item[0]))):
                name = str(name_text or "").strip()
                if not name:
                    continue
                results.append({"name": name, "count": int(count or 0)})
                if len(results) >= max_count:
                    break
            return results

        for item in candidate_list:
            source_name = str(item.get("source_collection", "") or "").strip().lower() or "unknown"
            source_counter[source_name] = source_counter.get(source_name, 0) + 1

            route_hint = str(item.get("route_hint") or cls._build_ai_pen_route_hint(item) or "").strip()
            if route_hint:
                route_counter[route_hint] = route_counter.get(route_hint, 0) + 1

            graph_summary = item.get("task_ai_pen_graph_summary") if isinstance(item.get("task_ai_pen_graph_summary"), dict) else {}
            if not graph_summary:
                graph_summary = cls._build_ai_pen_graph_summary(item)

            for layer_name in list(graph_summary.get("intel_layers", {}).get("active_layers", []) or []):
                layer_text = str(layer_name or "").strip()
                if layer_text:
                    layer_counter[layer_text] = layer_counter.get(layer_text, 0) + 1

            for path_text in list(graph_summary.get("top_paths", []) or []):
                _append_limited(top_paths, seen_paths, path_text, max_count=12, clip=180)
                if len(top_paths) >= 12:
                    break
            for param_text in list(graph_summary.get("top_params", []) or []):
                _append_limited(top_params, seen_params, param_text, max_count=16, lower=True, clip=80)
                if len(top_params) >= 16:
                    break
            for auth_path in list(graph_summary.get("auth_cluster", {}).get("top_auth_paths", []) or []):
                _append_limited(auth_paths, seen_auth_paths, auth_path, max_count=8, clip=180)
                if len(auth_paths) >= 8:
                    break
            for vuln_type in list(graph_summary.get("knowledge_vuln_types", []) or []):
                _append_limited(knowledge_vuln_types, seen_vuln_types, vuln_type, max_count=8, lower=True, clip=60)
                if len(knowledge_vuln_types) >= 8:
                    break

            browser_surface_summary = item.get("browser_surface_summary") if isinstance(item.get("browser_surface_summary"), dict) else {}
            runtime_target = str(
                browser_surface_summary.get("page_url")
                or item.get("target")
                or item.get("vuln_url")
                or ""
            ).strip()
            if runtime_target and (
                browser_surface_summary
                or list(item.get("runtime_api_calls", []) or [])
                or list(item.get("dom_form_summary", []) or [])
            ):
                _append_limited(runtime_targets, seen_runtime_targets, runtime_target, max_count=6, clip=220)

            auth_cluster = graph_summary.get("auth_cluster") if isinstance(graph_summary.get("auth_cluster"), dict) else {}
            object_cluster = graph_summary.get("object_ref_cluster") if isinstance(graph_summary.get("object_ref_cluster"), dict) else {}
            file_cluster = graph_summary.get("file_cluster") if isinstance(graph_summary.get("file_cluster"), dict) else {}
            if cls._safe_int_value(auth_cluster.get("auth_path_count"), 0) > 0 or cls._safe_int_value(auth_cluster.get("security_scheme_count"), 0) > 0:
                feature_presence["auth_surface_candidates"] += 1
            if cls._safe_int_value(object_cluster.get("object_id_like_count"), 0) > 0:
                feature_presence["object_ref_candidates"] += 1
            if (
                cls._safe_int_value(file_cluster.get("upload_like_count"), 0) > 0
                or cls._safe_int_value(file_cluster.get("download_like_count"), 0) > 0
            ):
                feature_presence["file_candidates"] += 1
            if cls._safe_int_value(graph_summary.get("browser_runtime_call_count"), 0) > 0 or cls._safe_int_value(graph_summary.get("dom_form_count"), 0) > 0:
                feature_presence["browser_runtime_candidates"] += 1
            if list(item.get("knowledge_hit_tokens", []) or []) or list(item.get("knowledge_hit_entry_paths", []) or []):
                feature_presence["knowledge_guided_candidates"] += 1
            login_surface_summary = item.get("login_surface_summary") if isinstance(item.get("login_surface_summary"), dict) else {}
            if not login_surface_summary:
                login_surface_summary = cls._build_ai_pen_login_surface_summary(item)
            if (
                bool(login_surface_summary.get("login_page_hint"))
                or cls._safe_int_value(login_surface_summary.get("password_form_count"), 0) > 0
                or cls._safe_int_value(login_surface_summary.get("auth_runtime_call_count"), 0) > 0
            ):
                feature_presence["login_surface_candidates"] += 1

        return {
            "candidate_count": len(candidate_list),
            "source_mix": _build_top_counts(source_counter, max_count=6),
            "route_mix": _build_top_counts(route_counter, max_count=6),
            "layer_mix": _build_top_counts(layer_counter, max_count=4),
            "top_paths": top_paths[:12],
            "top_params": top_params[:16],
            "auth_paths": auth_paths[:8],
            "runtime_targets": runtime_targets[:6],
            "knowledge_vuln_types": knowledge_vuln_types[:8],
            "feature_presence": feature_presence,
        }

    def _get_task_ai_pen_graph_context(self, candidates):
        if isinstance(self.ai_pen_task_graph_context_cache, dict) and self.ai_pen_task_graph_context_cache:
            return dict(self.ai_pen_task_graph_context_cache)
        context = self._build_task_ai_pen_graph_context(candidates)
        self.ai_pen_task_graph_context_cache = dict(context or {})
        return dict(self.ai_pen_task_graph_context_cache)

    @staticmethod
    def _extract_js_api_param_names(snippet: str):
        param_names = []
        seen = set()
        text = str(snippet or "")

        def append_name(name_text: str):
            name = str(name_text or "").strip()
            lowered = name.lower()
            if not name or lowered in seen:
                return
            if lowered in {
                "method", "headers", "body", "url", "type", "data", "params", "timeout",
                "responsetype", "mode", "credentials", "cache", "redirect", "signal",
                "content-type", "accept", "authorization",
            }:
                return
            seen.add(lowered)
            param_names.append(name)

        capture_patterns = (
            r"params\s*:\s*\{([^}]{1,300})\}",
            r"data\s*:\s*\{([^}]{1,300})\}",
            r"body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]{1,300})\}\s*\)",
            r"body\s*:\s*\{([^}]{1,300})\}",
            r"send\s*\(\s*JSON\.stringify\s*\(\s*\{([^}]{1,300})\}\s*\)\s*\)",
            r"new\s+URLSearchParams\s*\(\s*\{([^}]{1,300})\}\s*\)",
        )
        key_patterns = (
            r"[\"']([A-Za-z_][\w.-]{0,63})[\"']\s*:",
            r"\b([A-Za-z_][\w.-]{0,63})\s*:",
        )

        for pattern in capture_patterns:
            for match in re.finditer(pattern, text, flags=re.I | re.S):
                inner_text = str(match.group(1) or "")
                for key_pattern in key_patterns:
                    for inner_match in re.finditer(key_pattern, inner_text):
                        append_name(inner_match.group(1))

        for match in re.finditer(r"\.append\s*\(\s*[\"']([A-Za-z_][\w.-]{0,63})[\"']", text, flags=re.I):
            append_name(match.group(1))

        return param_names[:10]

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
        if any(
            token in merged
            for token in (
                "weak password",
                "weakpass",
                "default password",
                "default credential",
                "弱口令",
                "弱密码",
                "默认口令",
                "默认密码",
            )
        ):
            return "weak_password"
        if "idor" in merged or "越权" in merged or "horizontal" in merged or "vertical" in merged:
            return "idor"
        if "ssrf" in merged:
            return "ssrf"
        if "ssti" in merged or ("template" in merged and "inject" in merged):
            return "ssti"
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
        if any(token in merged for token in ("actuator/env", "configprops", "mappings", "beans", "conditions", "loggers")):
            return "sensitive_info"
        if "upload" in merged or "文件上传" in merged:
            return "file_upload"
        if "read" in merged or "download" in merged or "traversal" in merged or "文件读取" in merged:
            return "file_read"
        if "websocket" in merged or "ws://" in merged or "wss://" in merged:
            return "websocket"
        if "graphql" in merged or "graphiql" in merged:
            return "graphql"
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
        if any(
            token in merged
            for token in (
                "weak password",
                "weakpass",
                "default password",
                "default credential",
                "弱口令",
                "弱密码",
                "默认口令",
                "默认密码",
            )
        ):
            return "weak_password_probe", "username=admin&password=admin"
        if "cmd" in merged or "command" in merged:
            return "cmdi_probe", ";id"
        if "jwt" in merged:
            return "jwt_probe", '{"alg":"none"}'
        if "ssrf" in merged:
            return "ssrf_probe", "http://127.0.0.1/"
        if "ssti" in merged or ("template" in merged and "inject" in merged):
            return "ssti_probe", "{{7*7}}"
        if "xxe" in merged or "xml external" in merged:
            return "xxe_probe", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>'
        if "idor" in merged or "越权" in merged:
            return "idor_probe", "id=1 -> id=2"
        if "graphql" in merged or "graphiql" in merged:
            return "graphql_probe", '{"query":"query { __typename }"}'
        if "swagger" in merged or "openapi" in merged or "postman" in merged or "api_doc" in merged:
            return "api_doc_probe", "/v3/api-docs"
        if any(
            token in merged
            for token in (
                "actuator/env",
                "configprops",
                "mappings",
                "beans",
                "conditions",
                "loggers",
                "heapdump",
                "prometheus",
                "metrics",
                "env",
                "配置",
                "环境",
                "诊断",
                "管理",
                "敏感信息",
            )
        ):
            return "config_probe", ""
        if "websocket" in merged or "socket.io" in merged or "sockjs" in merged:
            return "websocket_probe", "ws_handshake"
        if "upload" in merged or "文件上传" in merged:
            return "upload_probe", "arl-safe-upload.txt"
        if any(token in merged for token in ("download", "export", "attachment", "template", "文件读取", "导出", "附件", "模板")):
            return "file_probe", ""
        return "replay", ""

    @classmethod
    def _is_ai_pen_success_status(cls, status_code) -> bool:
        return cls._safe_int_value(status_code, 0) in cls.AI_PEN_SUCCESS_STATUS_SET

    @classmethod
    def _build_ai_pen_high_value_url_candidate(
        cls,
        source_collection: str,
        source_id,
        target_url: str,
        status_code=0,
        title_text: str = "",
        source_text: str = "",
        site_url: str = "",
        content_length=0,
    ):
        raw_url = str(target_url or "").strip()
        if not cls._is_http_target(raw_url):
            return None

        lower_url = raw_url.lower()
        title_lower = str(title_text or "").strip().lower()
        source_lower = str(source_text or "").strip().lower()
        site_text = str(site_url or "").strip()
        status_value = cls._safe_int_value(status_code, 0)
        success_like = cls._is_ai_pen_success_status(status_value)
        privileged_like = status_value in {401, 403}

        if status_value in {404, 500, 502, 503, 504}:
            return None

        matched_keywords = []
        risk_type = ""
        risk_name = ""
        severity = "info"
        priority_score = 0
        high_value_reason = ""

        api_doc_tokens = (
            "/v3/api-docs",
            "/v2/api-docs",
            "/api-docs",
            "/swagger-resources",
            "/swagger-ui",
            "/openapi",
            "/redoc",
            "/knife4j",
            "/postman",
        )
        graphql_tokens = (
            "/graphql",
            "/api/graphql",
            "/graphiql",
            "/graphql-playground",
            "/graphql/console",
        )
        config_tokens = (
            "/actuator/env",
            "/api/actuator/env",
            "/env",
            "/actuator/configprops",
            "/configprops",
            "/actuator/beans",
            "/actuator/mappings",
            "/actuator/conditions",
            "/actuator/heapdump",
            "/heapdump",
            "/actuator/loggers",
        )
        manage_tokens = (
            "/actuator",
            "/jolokia",
            "/druid",
            "/prometheus",
            "/metrics",
            "/mappings",
            "/beans",
            "/conditions",
            "/loggers",
        )
        auth_tokens = (
            "/login",
            "/signin",
            "/sign-in",
            "/sso",
            "/cas",
            "/passport",
            "/oauth",
            "/token",
            "/auth/login",
            "/api/login",
            "/connect/token",
        )
        file_surface_tokens = (
            "/upload",
            "/import",
            "/download",
            "/export",
            "/attachment",
            "/template",
            "/avatar",
            "/report",
        )
        file_tokens = (
            "/.env",
            "/.git/config",
            "/application.yml",
            "/application.yaml",
            "/bootstrap.yml",
            "/bootstrap.yaml",
            "/application-prod.yml",
            "/application-dev.yml",
            "/web.config",
            "/config.php",
        )

        if any(token in lower_url for token in api_doc_tokens) or any(token in title_lower for token in ("swagger", "openapi", "knife4j", "redoc")):
            matched_keywords = [token for token in api_doc_tokens if token in lower_url][:4] or ["api-docs"]
            risk_type = "api_doc"
            risk_name = "高价值接口说明/Schema端点"
            severity = "high" if success_like else "medium"
            priority_score = 60 if success_like else 28
            high_value_reason = "api_doc_endpoint"
        elif any(token in lower_url for token in graphql_tokens) or any(token in title_lower for token in ("graphql", "graphiql", "apollo")):
            matched_keywords = [token for token in graphql_tokens if token in lower_url][:4] or ["graphql"]
            risk_type = "graphql"
            risk_name = "高价值 GraphQL 入口"
            severity = "high" if success_like else "medium"
            priority_score = 58 if success_like else 28
            high_value_reason = "graphql_endpoint"
        elif any(token in lower_url for token in config_tokens):
            matched_keywords = [token for token in config_tokens if token in lower_url][:4]
            risk_type = "sensitive_info"
            risk_name = "高价值配置/环境信息端点"
            severity = "high" if success_like else "medium"
            priority_score = 64 if success_like else 30
            high_value_reason = "config_env_endpoint"
        elif any(token in lower_url for token in manage_tokens):
            matched_keywords = [token for token in manage_tokens if token in lower_url][:4]
            risk_type = "sensitive_info"
            risk_name = "高价值管理/诊断端点"
            severity = "high" if success_like else "medium"
            priority_score = 52 if success_like else 24
            high_value_reason = "manage_debug_endpoint"
        elif any(token in lower_url for token in file_surface_tokens):
            matched_keywords = [token for token in file_surface_tokens if token in lower_url][:4]
            if any(token in lower_url for token in ("/upload", "/import", "/avatar")):
                risk_type = "file_upload"
            else:
                risk_type = "file_read"
            risk_name = "高价值文件处理入口"
            severity = "medium" if success_like else "low"
            priority_score = 42 if success_like else 18
            high_value_reason = "file_surface_endpoint"
        elif any(token in lower_url for token in auth_tokens):
            matched_keywords = [token for token in auth_tokens if token in lower_url][:4]
            risk_type = "login_surface"
            risk_name = "高价值认证入口"
            severity = "medium" if success_like else "low"
            priority_score = 38 if success_like else 16
            high_value_reason = "auth_entry_endpoint"
        elif any(token in lower_url for token in file_tokens):
            matched_keywords = [token for token in file_tokens if token in lower_url][:4]
            risk_type = "sensitive_info"
            risk_name = "高价值敏感文件/配置端点"
            severity = "high" if success_like else "medium"
            priority_score = 58 if success_like else 26
            high_value_reason = "sensitive_file_endpoint"

        if not risk_type:
            return None
        if not success_like and not privileged_like:
            return None

        evidence_parts = ["url={}".format(raw_url[:180])]
        if title_text:
            evidence_parts.append("title={}".format(str(title_text)[:90]))
        if site_text:
            evidence_parts.append("site={}".format(site_text[:120]))
        if source_lower:
            evidence_parts.append("source={}".format(source_lower[:48]))
        if status_value:
            evidence_parts.append("status={}".format(status_value))
        if content_length:
            evidence_parts.append("content_length={}".format(cls._safe_int_value(content_length, 0)))
        if matched_keywords:
            evidence_parts.append("keywords={}".format(",".join(matched_keywords[:4])))

        return {
            "source_collection": str(source_collection or "").strip(),
            "source_id": source_id,
            "source_module": str(source_text or source_collection or "").strip().lower(),
            "target": raw_url,
            "vuln_url": raw_url,
            "risk_type": risk_type,
            "risk_name": risk_name,
            "severity": severity,
            "evidence_seed": " | ".join(evidence_parts),
            "status_code_hint": status_value,
            "priority_score": priority_score,
            "high_value_target": True,
            "high_value_reason": high_value_reason,
        }

    @classmethod
    def _looks_like_sensitive_config_response(cls, url_text: str, body_text: str, headers=None):
        lower_url = str(url_text or "").strip().lower()
        if not lower_url:
            return False
        if not any(
            token in lower_url
            for token in (
                "/actuator/env",
                "/api/actuator/env",
                "/env",
                "/actuator/configprops",
                "/configprops",
                "/actuator/beans",
                "/actuator/mappings",
                "/actuator/conditions",
                "/actuator/heapdump",
                "/heapdump",
                "/actuator/loggers",
            )
        ):
            return False
        if any(token in lower_url for token in ("/actuator/health", "/health", "/actuator/info", "/info")):
            return False

        header_obj = headers if isinstance(headers, dict) else {}
        content_type = str(header_obj.get("Content-Type", "") or "").strip().lower()
        text = str(body_text or "").strip()
        lower_text = text.lower()

        if any(token in lower_url for token in ("/heapdump", "/actuator/heapdump")):
            return any(token in content_type for token in ("application/octet-stream", "application/x-hprof"))

        if not text or text[:1] not in "{[":
            return False

        markers = (
            "propertysources",
            "activeprofiles",
            "applicationconfig:",
            "systemproperties",
            "local.server.port",
            "spring.datasource",
            "\"contexts\"",
            "\"beans\"",
            "\"mappings\"",
            "\"conditions\"",
            "\"loggers\"",
        )
        return any(marker in lower_text for marker in markers)

    @classmethod
    def _extract_sensitive_config_summary(cls, body_text: str):
        text = str(body_text or "").strip()
        if not text:
            return ""
        lower_text = text.lower()
        summary_parts = []
        if "propertysources" in lower_text:
            summary_parts.append("propertySources")
        if "activeprofiles" in lower_text:
            summary_parts.append("activeProfiles")
        if "systemproperties" in lower_text:
            summary_parts.append("systemProperties")
        if "\"beans\"" in lower_text:
            summary_parts.append("beans")
        if "\"mappings\"" in lower_text:
            summary_parts.append("mappings")
        if "\"conditions\"" in lower_text:
            summary_parts.append("conditions")
        if "\"loggers\"" in lower_text:
            summary_parts.append("loggers")
        if "spring.datasource" in lower_text:
            summary_parts.append("spring.datasource")
        return cls._clip_text(",".join(summary_parts[:6]), cls.AI_PEN_TEST_EVIDENCE_MAX)

    @classmethod
    def _normalize_ai_pen_tool_plan(cls, value, default_url: str = "", max_steps: int = 4):
        if not isinstance(value, list):
            return []

        steps = []
        seen = set()
        allowed_tools = set(cls.AI_PEN_RUNTIME_TOOL_NAMES)
        allowed_methods = {"get", "post", "put", "patch", "delete", "head", "options"}
        safe_default_url = str(default_url or "").strip()

        for item in value:
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("tool") or item.get("name") or "").strip()
            if tool_name not in allowed_tools:
                continue

            params = {}
            raw_params = item.get("params")
            if isinstance(raw_params, dict):
                params.update(raw_params)
            for key in (
                "url",
                "method",
                "allow_redirects",
                "headers",
                "cookies",
                "session_key",
                "prepare_url",
                "login_url",
                "form_data",
                "json_data",
                "file_field",
                "file_name",
                "file_content",
                "file_content_type",
            ):
                if key not in params and key in item:
                    params[key] = item.get(key)

            url_text = str(params.get("url") or safe_default_url).strip()
            if not url_text:
                continue
            method_text = str(params.get("method") or "").strip().lower()
            if method_text and method_text not in allowed_methods:
                method_text = ""
            allow_redirects = params.get("allow_redirects")
            headers_obj = params.get("headers") if isinstance(params.get("headers"), dict) else {}
            safe_headers = {}
            for header_key, header_value in headers_obj.items():
                key_text = str(header_key or "").strip()
                if not key_text:
                    continue
                safe_headers[key_text] = str(header_value or "")[:240]

            summary = str(item.get("summary") or item.get("reason") or item.get("goal") or "").strip()[:120]
            step = {
                "tool": tool_name,
                "params": {
                    "url": url_text,
                },
                "summary": summary,
            }
            if method_text:
                step["params"]["method"] = method_text
            if isinstance(allow_redirects, bool):
                step["params"]["allow_redirects"] = allow_redirects
            if safe_headers:
                step["params"]["headers"] = safe_headers
            cookies_obj = params.get("cookies") if isinstance(params.get("cookies"), dict) else {}
            safe_cookies = {}
            for cookie_key, cookie_value in cookies_obj.items():
                key_text = str(cookie_key or "").strip()
                if not key_text:
                    continue
                safe_cookies[key_text[:80]] = str(cookie_value or "")[:240]
            if safe_cookies:
                step["params"]["cookies"] = safe_cookies
            session_key = str(params.get("session_key") or "").strip()
            if session_key:
                step["params"]["session_key"] = session_key[:64]
            prepare_url = str(params.get("prepare_url") or "").strip()
            if prepare_url:
                step["params"]["prepare_url"] = prepare_url[:240]
            login_url = str(params.get("login_url") or "").strip()
            if login_url:
                step["params"]["login_url"] = login_url[:240]
            form_data_obj = params.get("form_data") if isinstance(params.get("form_data"), dict) else {}
            safe_form_data = {}
            for form_key, form_value in form_data_obj.items():
                key_text = str(form_key or "").strip()
                if not key_text:
                    continue
                safe_form_data[key_text[:64]] = str(form_value or "")[:180]
            if safe_form_data:
                step["params"]["form_data"] = safe_form_data
            json_data_obj = params.get("json_data") if isinstance(params.get("json_data"), dict) else {}
            safe_json_data = {}
            for json_key, json_value in json_data_obj.items():
                key_text = str(json_key or "").strip()
                if not key_text:
                    continue
                if isinstance(json_value, (dict, list)):
                    value_text = cls._clip_text(json.dumps(json_value, ensure_ascii=False), 400)
                else:
                    value_text = str(json_value or "")[:240]
                safe_json_data[key_text[:64]] = value_text
            if safe_json_data:
                step["params"]["json_data"] = safe_json_data
            for field_name in ("file_field", "file_name", "file_content", "file_content_type"):
                field_value = str(params.get(field_name) or "").strip()
                if field_value:
                    step["params"][field_name] = field_value[:180]

            cache_key = json.dumps(step, ensure_ascii=False, sort_keys=True)
            if cache_key in seen:
                continue
            seen.add(cache_key)
            steps.append(step)
            if len(steps) >= max(1, int(max_steps or 1)):
                break
        return steps

    @classmethod
    def _infer_ai_pen_tool_plan(cls, candidate: dict, payload_type: str, payload: str, max_steps: int = 4):
        item = candidate if isinstance(candidate, dict) else {}
        target_url = str(item.get("vuln_url") or item.get("target") or "").strip()
        if not target_url:
            return []

        plan = []
        payload_type_text = str(payload_type or "").strip().lower()
        lower_target = target_url.lower()

        if payload_type_text == "api_doc_probe":
            for doc_url in cls._build_api_doc_probe_targets(target_url, max_count=max_steps):
                plan.append(
                    {
                        "tool": "api_doc_probe",
                        "params": {
                            "url": doc_url,
                            "method": "get",
                            "allow_redirects": True,
                        },
                        "summary": "多轮探测 API 文档入口",
                    }
                )
            return cls._normalize_ai_pen_tool_plan(plan, default_url=target_url, max_steps=max_steps)

        if payload_type_text == "graphql_probe":
            for graphql_url in cls._build_graphql_probe_targets(target_url, max_count=max_steps):
                plan.append(
                    {
                        "tool": "graphql_probe",
                        "params": {
                            "url": graphql_url,
                            "method": "post",
                            "allow_redirects": True,
                            "headers": {
                                "Content-Type": "application/json",
                                "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
                            },
                            "json_data": {
                                "query": "query { __typename }",
                            },
                        },
                        "summary": "低副作用确认 GraphQL 入口",
                    }
                )
            return cls._normalize_ai_pen_tool_plan(plan, default_url=target_url, max_steps=max_steps)

        if payload_type_text in {"file_probe", "upload_probe"}:
            file_probe_context = cls._build_ai_pen_file_probe_context(
                target_url=target_url,
                risk_type=str(item.get("risk_type") or ""),
                body_text="",
                api_surface_summary=item.get("api_surface_summary"),
                dom_form_summary=item.get("dom_form_summary"),
            )
            probe_type = str(file_probe_context.get("probe_type") or "").strip().lower()
            if payload_type_text == "upload_probe" or probe_type == "upload":
                plan.append(
                    {
                        "tool": "upload_probe",
                        "params": {
                            "url": str(file_probe_context.get("probe_url") or target_url),
                            "method": "post",
                            "allow_redirects": True,
                            "form_data": dict(file_probe_context.get("hidden_fields") or {}),
                            "file_field": str(file_probe_context.get("file_field") or "file"),
                            "file_name": str(payload or "arl-safe-upload.txt")[:80],
                            "file_content": "ARL_SAFE_UPLOAD_PROBE",
                            "file_content_type": "text/plain",
                        },
                        "summary": "无害静态文件上传探针",
                    }
                )
            elif payload_type_text == "file_probe" or probe_type == "download":
                plan.append(
                    {
                        "tool": "file_probe",
                        "params": {
                            "url": str(file_probe_context.get("probe_url") or target_url),
                            "method": "get",
                            "allow_redirects": True,
                        },
                        "summary": "文件下载/导出接口确认探针",
                    }
                )
            return cls._normalize_ai_pen_tool_plan(plan, default_url=target_url, max_steps=max_steps)

        if payload_type_text == "config_probe" or any(
            token in lower_target
            for token in (
                "/actuator/env",
                "/api/actuator/env",
                "/env",
                "/actuator/configprops",
                "/configprops",
                "/actuator/beans",
                "/actuator/mappings",
                "/actuator/conditions",
                "/actuator/loggers",
            )
        ):
            plan.append(
                {
                    "tool": "config_probe",
                    "params": {
                        "url": target_url,
                        "method": "get",
                        "allow_redirects": True,
                    },
                    "summary": "复测高价值配置/环境端点",
                }
            )
            return cls._normalize_ai_pen_tool_plan(plan, default_url=target_url, max_steps=max_steps)

        if payload_type_text == "websocket_probe":
            ws_url = cls._build_websocket_handshake_url(target_url)
            if ws_url:
                plan.append(
                    {
                        "tool": "websocket_probe",
                        "params": {
                            "url": ws_url,
                            "method": "get",
                            "allow_redirects": False,
                            "headers": {
                                "Connection": "Upgrade",
                                "Upgrade": "websocket",
                                "Sec-WebSocket-Version": "13",
                                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                            },
                        },
                        "summary": "复测 WebSocket 握手入口",
                    }
                )
        elif payload_type_text == "jwt_probe":
            plan.append(
                {
                    "tool": "jwt_probe",
                    "params": {
                        "url": target_url,
                        "method": "get",
                        "allow_redirects": True,
                    },
                    "summary": "复测 JWT 鉴权入口",
                }
            )
        return cls._normalize_ai_pen_tool_plan(plan, default_url=target_url, max_steps=max_steps)

    @classmethod
    def _build_ai_pen_fallback_tool_plan(
        cls,
        target_url: str,
        payload_type: str,
        payload: str,
        max_steps: int = 4,
        candidate: dict = None,
        body_text: str = "",
        dom_form_summary=None,
        login_surface_summary=None,
    ):
        url_text = str(target_url or "").strip()
        payload_type_text = str(payload_type or "").strip().lower()
        payload_text = str(payload or "").strip()
        if not url_text:
            return []

        plan = []
        if payload_type_text in {"xss_probe", "sqli_probe", "cmdi_probe", "ssrf_probe", "ssti_probe", "xxe_probe", "replay"} and payload_text:
            probe_url = cls._build_probe_url_with_payload(url_text, payload_text)
            if probe_url and probe_url != url_text:
                probe_tool_name = "payload_probe" if payload_type_text == "replay" else payload_type_text
                plan.append(
                    {
                        "tool": probe_tool_name,
                        "params": {
                            "url": probe_url,
                            "method": "get",
                            "allow_redirects": True,
                        },
                        "summary": "fallback payload 探针重放",
                    }
                )
        elif payload_type_text == "idor_probe":
            idor_targets = cls._build_idor_probe_targets(url_text, max_count=max_steps)
            for target in idor_targets:
                idor_url = str(target.get("url") or "").strip()
                if not idor_url or idor_url == url_text:
                    continue
                plan.append(
                    {
                        "tool": "idor_probe",
                        "params": {
                            "url": idor_url,
                            "method": "get",
                            "allow_redirects": True,
                        },
                        "summary": "fallback IDOR 参数变异探针 {}".format(
                            cls._format_idor_diff_summary_text(
                                {
                                    "mutation_key": target.get("mutation_key"),
                                    "mutation_from": target.get("mutation_from"),
                                    "mutation_to": target.get("mutation_to"),
                                    "mutation_kind": target.get("mutation_kind"),
                                }
                            ) or ""
                        ).strip(),
                    }
                )
                if len(plan) >= max(1, int(max_steps or 1)):
                    break
        elif payload_type_text == "api_doc_probe":
            for doc_url in cls._build_api_doc_probe_targets(url_text, max_count=max_steps):
                plan.append(
                    {
                        "tool": "api_doc_probe",
                        "params": {
                            "url": doc_url,
                            "method": "get",
                            "allow_redirects": True,
                        },
                        "summary": "fallback API 文档路径探测",
                    }
                )
        elif payload_type_text == "graphql_probe":
            for graphql_url in cls._build_graphql_probe_targets(url_text, max_count=max_steps):
                plan.append(
                    {
                        "tool": "graphql_probe",
                        "params": {
                            "url": graphql_url,
                            "method": "post",
                            "allow_redirects": True,
                            "headers": {
                                "Content-Type": "application/json",
                                "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
                            },
                            "json_data": {
                                "query": "query { __typename }",
                            },
                        },
                        "summary": "fallback GraphQL 入口探测",
                    }
                )
        elif payload_type_text in {"file_probe", "upload_probe"}:
            file_probe_context = cls._build_ai_pen_file_probe_context(
                target_url=url_text,
                risk_type=str(candidate.get("risk_type") or "") if isinstance(candidate, dict) else "",
                body_text=body_text,
                api_surface_summary=candidate.get("api_surface_summary") if isinstance(candidate, dict) else None,
                dom_form_summary=dom_form_summary,
            )
            probe_type = str(file_probe_context.get("probe_type") or "").strip().lower()
            if payload_type_text == "upload_probe" or probe_type == "upload":
                plan.append(
                    {
                        "tool": "upload_probe",
                        "params": {
                            "url": str(file_probe_context.get("probe_url") or url_text),
                            "method": "post",
                            "allow_redirects": True,
                            "form_data": dict(file_probe_context.get("hidden_fields") or {}),
                            "file_field": str(file_probe_context.get("file_field") or "file"),
                            "file_name": str(payload_text or "arl-safe-upload.txt")[:80],
                            "file_content": "ARL_SAFE_UPLOAD_PROBE",
                            "file_content_type": "text/plain",
                        },
                        "summary": "fallback 无害静态文件上传探针",
                    }
                )
            elif payload_type_text == "file_probe" or probe_type == "download":
                plan.append(
                    {
                        "tool": "file_probe",
                        "params": {
                            "url": str(file_probe_context.get("probe_url") or url_text),
                            "method": "get",
                            "allow_redirects": True,
                        },
                        "summary": "fallback 文件下载/导出接口确认探针",
                    }
                )
        elif payload_type_text == "config_probe":
            plan.append(
                {
                    "tool": "config_probe",
                    "params": {
                        "url": url_text,
                        "method": "get",
                        "allow_redirects": True,
                    },
                    "summary": "fallback 配置/环境暴露探针",
                }
            )
        elif payload_type_text == "weak_password_probe":
            login_context = cls._build_ai_pen_login_probe_context(
                target_url=url_text,
                body_text=body_text,
                dom_form_summary=dom_form_summary,
                login_surface_summary=login_surface_summary,
            )
            if login_context and (not bool(login_context.get("captcha_required"))):
                credential_candidates = cls._build_ai_pen_minimal_default_credentials(
                    candidate=candidate,
                    payload=payload_text,
                    max_count=1,
                )
                if credential_candidates:
                    credential_item = credential_candidates[0]
                    form_data = dict(login_context.get("hidden_fields") or {})
                    form_data[str(login_context.get("username_field") or "username")] = str(credential_item.get("username") or "")
                    form_data[str(login_context.get("password_field") or "password")] = str(credential_item.get("password") or "")
                    if max(1, int(max_steps or 1)) >= 4:
                        plan.append(
                            {
                                "tool": "session_start",
                                "params": {
                                    "url": str(login_context.get("login_url") or url_text),
                                    "session_key": "weak_password",
                                    "method": "get",
                                    "allow_redirects": True,
                                },
                                "summary": "fallback 初始化弱口令验证会话",
                            }
                        )
                    if max(1, int(max_steps or 1)) >= 3:
                        plan.append(
                            {
                                "tool": "extract_csrf_token",
                                "params": {
                                    "url": str(login_context.get("login_url") or url_text),
                                    "session_key": "weak_password",
                                    "method": "get",
                                    "allow_redirects": True,
                                },
                                "summary": "fallback 提取 CSRF Token",
                            }
                        )
                    plan.append(
                        {
                            "tool": "credential_probe",
                            "params": {
                                "url": str(login_context.get("submit_url") or url_text),
                                "prepare_url": str(login_context.get("login_url") or url_text),
                                "login_url": str(login_context.get("login_url") or url_text),
                                "session_key": "weak_password",
                                "method": str(login_context.get("method") or "post"),
                                "allow_redirects": True,
                                "form_data": form_data,
                            },
                            "summary": "fallback 默认口令低副作用验证",
                        }
                    )
                    if max(1, int(max_steps or 1)) > 1:
                        plan.append(
                            {
                                "tool": "detect_login_success",
                                "params": {
                                    "url": str(login_context.get("submit_url") or url_text),
                                    "login_url": str(login_context.get("login_url") or url_text),
                                    "session_key": "weak_password",
                                },
                                "summary": "fallback 登录成功判定",
                            }
                        )
        elif payload_type_text == "websocket_probe":
            ws_probe_url = cls._build_websocket_handshake_url(url_text)
            if ws_probe_url:
                plan.append(
                    {
                        "tool": "websocket_probe",
                        "params": {
                            "url": ws_probe_url,
                            "method": "get",
                            "allow_redirects": False,
                            "headers": {
                                "Connection": "Upgrade",
                                "Upgrade": "websocket",
                                "Sec-WebSocket-Version": "13",
                                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                            },
                        },
                        "summary": "fallback WebSocket 握手探针",
                    }
                )
        return cls._normalize_ai_pen_tool_plan(plan, default_url=url_text, max_steps=max_steps)

    @staticmethod
    def _normalize_ai_pen_agent_action(value: str, default_value="manual_required"):
        action = str(value or "").strip().lower()
        if action in {"tool_call", "final_decision", "manual_required"}:
            return action
        return str(default_value or "manual_required").strip().lower() or "manual_required"

    @classmethod
    def _summarize_ai_pen_tool_results_for_agent(cls, tool_results, max_items: int = 4):
        result = []
        items = list(tool_results or [])
        for item in items[-max(1, int(max_items or 1)):]:
            if not isinstance(item, dict):
                continue
            result_item = item.get("result") if isinstance(item.get("result"), dict) else {}
            response_obj = result_item.get("response") if isinstance(result_item.get("response"), dict) else {}
            summary = {
                "turn": cls._safe_int_value(item.get("turn"), 0),
                "tool": str(item.get("tool") or "").strip()[:48],
                "status": str(item.get("status") or "").strip()[:24],
                "message": cls._clip_text(item.get("message") or result_item.get("message") or "", 120),
            }
            if response_obj:
                response_summary = {
                    "url": str(response_obj.get("url") or "").strip()[:220],
                    "status_code": cls._safe_int_value(response_obj.get("status_code"), 0),
                    "body_excerpt": cls._clip_text(response_obj.get("body_text") or "", 260),
                }
                header_obj = response_obj.get("headers") if isinstance(response_obj.get("headers"), dict) else {}
                selected_headers = {}
                for header_name in ("Content-Type", "Location", "Upgrade", "WWW-Authenticate"):
                    header_value = str(header_obj.get(header_name, "") or "").strip()
                    if header_value:
                        selected_headers[header_name] = header_value[:180]
                if selected_headers:
                    response_summary["headers"] = selected_headers
                summary["response"] = response_summary
            result.append(summary)
        return result

    @classmethod
    def _collect_ai_pen_runtime_observation(cls, result_items, evidence_seed: str, js_api_targets=None):
        observation = {
            "trace_parts": [],
            "tool_counts": {},
            "responses": [],
            "probe_status": 0,
            "probe_url": "",
            "probe_headers": {},
            "probe_body_excerpt": "",
            "probe_body_md5": "",
            "evidence_hit": False,
            "api_doc_hit": False,
            "api_doc_hit_url": "",
            "api_doc_summary": {},
            "api_surface_summary": {},
            "graphql_hit": False,
            "graphql_hit_url": "",
            "graphql_summary": {},
            "config_exposure_hit": False,
            "config_exposure_url": "",
            "config_exposure_summary": "",
            "websocket_upgrade_hit": False,
            "websocket_upgrade_hint": False,
            "login_success_hit": False,
            "login_success_reason": "",
            "login_blocked_reason": "",
            "error": "",
        }
        if not result_items:
            return observation

        for item in result_items:
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("tool", "") or "").strip()
            status_text = str(item.get("status", "") or "").strip().lower()
            result_obj = item.get("result") if isinstance(item.get("result"), dict) else {}
            response_obj = result_obj.get("response") if isinstance(result_obj.get("response"), dict) else {}
            url_text = str(response_obj.get("url", "") or "").strip()
            if tool_name:
                observation["tool_counts"][tool_name] = int(observation["tool_counts"].get(tool_name, 0) or 0) + 1
            summary_text = "agent_plan({},{})".format(tool_name or "-", status_text or "unknown")
            if url_text:
                summary_text = "agent_plan({},status={},url={})".format(tool_name or "-", status_text or "unknown", url_text[:220])
            observation["trace_parts"].append(summary_text)

            if status_text != "ok":
                if not observation["error"]:
                    observation["error"] = cls._clip_text(
                        item.get("message") or result_obj.get("message") or "",
                        cls.AI_PEN_TEST_ERROR_MAX,
                    )
                continue

            if not url_text:
                continue

            status_code = int(response_obj.get("status_code", 0) or 0)
            headers = dict(response_obj.get("headers") or {}) if isinstance(response_obj.get("headers"), dict) else {}
            body_excerpt = str(response_obj.get("body_text", "") or "")[: cls.AI_PEN_TEST_BODY_MAX]
            body_md5 = str(response_obj.get("body_md5", "") or "").strip()
            if body_excerpt and not body_md5:
                body_md5 = hashlib.md5(body_excerpt.encode("utf-8", "ignore")).hexdigest()
            response_summary = {
                "tool": tool_name,
                "url": url_text,
                "status_code": status_code,
                "headers": headers,
                "body_text": body_excerpt,
                "body_md5": body_md5,
            }
            observation["responses"].append(response_summary)
            if len(observation["responses"]) > 8:
                observation["responses"] = observation["responses"][-8:]

            if not observation["probe_status"]:
                observation["probe_status"] = status_code
            if url_text:
                observation["probe_url"] = url_text
            if headers:
                observation["probe_headers"] = dict(headers)
            if body_excerpt:
                observation["probe_body_excerpt"] = body_excerpt
            if body_md5:
                observation["probe_body_md5"] = body_md5
            if cls._contains_evidence(evidence_seed, body_excerpt):
                observation["evidence_hit"] = True

            if cls._looks_like_api_doc_response(url_text, body_excerpt, headers):
                observation["api_doc_hit"] = True
                observation["api_doc_hit_url"] = url_text
                observation["api_doc_summary"] = cls._extract_api_doc_summary(body_excerpt)
                observation["api_surface_summary"] = cls._build_api_surface_summary(
                    api_doc_summary=observation["api_doc_summary"],
                    js_api_targets=js_api_targets or [],
                )

            if cls._looks_like_graphql_response(url_text, body_excerpt, headers):
                observation["graphql_hit"] = True
                observation["graphql_hit_url"] = url_text
                observation["graphql_summary"] = cls._extract_graphql_summary(body_excerpt)

            if cls._looks_like_sensitive_config_response(url_text, body_excerpt, headers):
                observation["config_exposure_hit"] = True
                observation["config_exposure_url"] = url_text
                observation["config_exposure_summary"] = cls._extract_sensitive_config_summary(body_excerpt)

            ws_upgrade_header = str(headers.get("Upgrade", "") or "").strip().lower()
            ws_version_hint = str(headers.get("Sec-WebSocket-Version", "") or "").strip()
            if tool_name == "websocket_probe":
                if status_code == 101 and "websocket" in ws_upgrade_header:
                    observation["websocket_upgrade_hit"] = True
                elif status_code in (400, 426) and ("websocket" in ws_upgrade_header or ws_version_hint):
                    observation["websocket_upgrade_hint"] = True

            if tool_name == "detect_login_success":
                analysis_obj = result_obj.get("analysis") if isinstance(result_obj.get("analysis"), dict) else {}
                if bool(analysis_obj.get("success")):
                    observation["login_success_hit"] = True
                    observation["login_success_reason"] = cls._clip_text(
                        analysis_obj.get("reason", ""),
                        cls.AI_PEN_TEST_REASON_MAX,
                    )
                elif bool(analysis_obj.get("blocked")) and not observation["login_blocked_reason"]:
                    observation["login_blocked_reason"] = cls._clip_text(
                        analysis_obj.get("reason", ""),
                        cls.AI_PEN_TEST_REASON_MAX,
                    )

        return observation

    def _execute_ai_pen_tool_plan(
        self,
        runtime,
        runtime_context: dict,
        tool_plan,
        target_url: str,
        evidence_seed: str,
        js_api_targets=None,
    ):
        plan_items = list(tool_plan or [])
        if not plan_items:
            return self._collect_ai_pen_runtime_observation([], evidence_seed=evidence_seed, js_api_targets=js_api_targets)

        start_idx = len(list(getattr(runtime, "tool_results", []) or []))
        runtime.run_plan(plan_items, context=runtime_context)
        result_items = list(getattr(runtime, "tool_results", []) or [])[start_idx:]
        return self._collect_ai_pen_runtime_observation(
            result_items,
            evidence_seed=evidence_seed,
            js_api_targets=js_api_targets,
        )

    def _execute_ai_pen_agent_loop(
        self,
        runtime,
        runtime_context: dict,
        candidate: dict,
        runtime_settings: dict,
        ai_config: dict,
        prompt_content: str,
        initial_tool_plan,
        target_url: str,
        evidence_seed: str,
        js_api_targets=None,
    ):
        seed_steps = list(initial_tool_plan or [])
        observation = self._collect_ai_pen_runtime_observation([], evidence_seed=evidence_seed, js_api_targets=js_api_targets)
        if not ai_config:
            return observation

        trace_start = len(list(getattr(runtime, "agent_trace", []) or []))
        result_start = len(list(getattr(runtime, "tool_results", []) or []))
        runtime_settings_obj = runtime_settings if isinstance(runtime_settings, dict) else {}

        def _decide_next(state: dict):
            state_obj = state if isinstance(state, dict) else {}
            turn_id = self._safe_int_value(state_obj.get("turn"), 0)
            tool_results = list(state_obj.get("tool_results", []) or [])
            last_tool_result = state_obj.get("last_tool_result") if isinstance(state_obj.get("last_tool_result"), dict) else {}

            if turn_id == 1 and seed_steps:
                return {
                    "action": "tool_call",
                    "reason": "沿用初始 AI 规划作为 Agent 首轮动作",
                    "expected_signal": "先补目标低副作用上下文，再决定是否继续",
                    "tool_call": dict(seed_steps.pop(0) or {}),
                }

            agent_loop_context = {
                "turn": turn_id,
                "max_turns": self._safe_int_value(state_obj.get("max_turns"), 0),
                "available_tools": list(state_obj.get("available_tools", []) or []),
                "seed_tool_plan_remaining": list(seed_steps or [])[:4],
                "recent_tool_results": self._summarize_ai_pen_tool_results_for_agent(tool_results, max_items=4),
                "last_tool_result": self._summarize_ai_pen_tool_results_for_agent([last_tool_result], max_items=1),
                "current_stop_reason": str(getattr(runtime, "stop_reason", "") or "").strip(),
            }
            planner_ret = self._call_ai_pen_planner(
                ai_config=ai_config,
                candidate=candidate,
                runtime_settings=runtime_settings_obj,
                prompt_content=prompt_content,
                agent_loop_context=agent_loop_context,
            )
            output = planner_ret.get("output") if isinstance(planner_ret.get("output"), dict) else {}
            planner_status = str(planner_ret.get("status", "") or "").strip().lower()
            planner_ok = bool(planner_ret.get("ok")) and planner_status == "ok"
            if planner_ok:
                action = self._normalize_ai_pen_agent_action(
                    output.get("action"),
                    default_value="tool_call" if isinstance(output.get("tool_call"), dict) else "final_decision",
                )
                tool_call = output.get("tool_call") if isinstance(output.get("tool_call"), dict) else {}
                final_decision = output.get("final_decision") if isinstance(output.get("final_decision"), dict) else {}
                if action == "tool_call" and tool_call:
                    return {
                        "action": "tool_call",
                        "reason": str(output.get("reason") or "").strip(),
                        "expected_signal": str(output.get("expected_signal") or "").strip(),
                        "stop_if": str(output.get("stop_if") or "").strip(),
                        "tool_call": tool_call,
                    }
                if action in {"final_decision", "manual_required"}:
                    return {
                        "action": action,
                        "reason": str(output.get("reason") or "").strip(),
                        "expected_signal": str(output.get("expected_signal") or "").strip(),
                        "stop_if": str(output.get("stop_if") or "").strip(),
                        "final_decision": final_decision,
                    }

            if seed_steps:
                return {
                    "action": "tool_call",
                    "reason": "Agent 未给出可执行动作，回退到剩余 seed tool plan",
                    "tool_call": dict(seed_steps.pop(0) or {}),
                }

            return {
                "action": "manual_required",
                "reason": self._clip_text(planner_ret.get("message", "") or "agent_loop_no_action", 160),
                "final_decision": {
                    "decision": "needs_manual_review",
                    "confidence": 0.6,
                    "reason": self._clip_text(
                        planner_ret.get("message", "") or "Agent 未返回可执行动作，当前停止自动验证",
                        self.AI_PEN_TEST_REASON_MAX,
                    ),
                    "payload_type": "",
                    "payload": "",
                    "evidence": [],
                    "next_actions": [],
                },
            }

        runtime_result = runtime.run_agent_loop(_decide_next, context=runtime_context)
        result_items = list(getattr(runtime, "tool_results", []) or [])[result_start:]
        observation = self._collect_ai_pen_runtime_observation(
            result_items,
            evidence_seed=evidence_seed,
            js_api_targets=js_api_targets,
        )
        trace_items = list(getattr(runtime, "agent_trace", []) or [])[trace_start:]
        for item in trace_items:
            if not isinstance(item, dict):
                continue
            if str(item.get("action", "") or "").strip() != "agent_turn":
                continue
            action_text = self._normalize_ai_pen_agent_action(item.get("decision"), default_value="manual_required")
            tool_text = str(item.get("tool", "") or "").strip()
            summary_text = "agent_turn(action={})".format(action_text)
            if tool_text:
                summary_text = "agent_turn(action={},tool={})".format(action_text, tool_text[:48])
            observation["trace_parts"].append(summary_text)
        observation["trace_parts"].append(
            "agent_loop(stop={})".format(str(runtime_result.get("stop_reason", "") or "final_decision").strip())
        )
        observation["final_decision"] = (
            dict(runtime_result.get("final_output") or {})
            if isinstance(runtime_result.get("final_output"), dict)
            else {}
        )
        observation["stop_reason"] = str(runtime_result.get("stop_reason", "") or "").strip()
        return observation

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
                if self._is_http_target(target) and not self._url_in_task_scope(target):
                    continue
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
                if self._is_http_target(preferred_url) and not self._url_in_task_scope(preferred_url):
                    continue
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
                if self._is_http_target(target) and not self._url_in_task_scope(target):
                    continue
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
            login_keywords = self.AI_PEN_LOGIN_PAGE_KEYWORDS
            site_cursor = utils.conn_db("site").find(
                {"task_id": self.task_id},
                {"_id": 1, "site": 1, "title": 1, "http_server": 1, "finger": 1, "status": 1},
                max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
            ).limit(self.AI_PEN_TEST_SOURCE_LIMIT)
            for row in site_cursor:
                site_url = str(row.get("site", "") or "").strip()
                if not self._is_http_target(site_url):
                    continue
                if not self._url_in_task_scope(site_url):
                    continue

                status_code = int(row.get("status", 0) or 0)
                high_value_candidate = self._build_ai_pen_high_value_url_candidate(
                    source_collection="site",
                    source_id=row.get("_id"),
                    target_url=site_url,
                    status_code=status_code,
                    title_text=str(row.get("title", "") or "").strip(),
                    source_text="site",
                    site_url=site_url,
                )
                if high_value_candidate:
                    _append_candidate(high_value_candidate)
                    continue

                title_text = str(row.get("title", "") or "").strip()
                server_text = str(row.get("http_server", "") or "").strip()
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
                elif any(keyword in merged_text for keyword in login_keywords):
                    matched_keywords = [keyword for keyword in login_keywords if keyword in merged_text][:4]
                    risk_type = "login_surface"
                    risk_name = "站点疑似登录入口"
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
                        "status_code_hint": status_code,
                        "priority_score": 18 if self._is_ai_pen_success_status(status_code) else (8 if status_code in {401, 403} else 0),
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
            login_keywords = self.AI_PEN_LOGIN_PAGE_KEYWORDS
            url_cursor = utils.conn_db("url").find(
                {"task_id": self.task_id},
                {"_id": 1, "url": 1, "title": 1, "status_code": 1, "source": 1},
                max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
            ).limit(self.AI_PEN_TEST_SOURCE_LIMIT)
            for row in url_cursor:
                raw_url = str(row.get("url", "") or "").strip()
                if not self._is_http_target(raw_url):
                    continue
                if not self._url_in_task_scope(raw_url):
                    continue

                title_text = str(row.get("title", "") or "").strip()
                source_text = str(row.get("source", "") or "").strip().lower()
                status_code = int(row.get("status_code", 0) or 0)
                high_value_candidate = self._build_ai_pen_high_value_url_candidate(
                    source_collection="url",
                    source_id=row.get("_id"),
                    target_url=raw_url,
                    status_code=status_code,
                    title_text=title_text,
                    source_text=source_text or "url",
                )
                if high_value_candidate:
                    _append_candidate(high_value_candidate)
                    continue

                lower_url = raw_url.lower()
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
                elif any(keyword in lower_url or keyword in title_text.lower() for keyword in login_keywords):
                    matched_keywords = [
                        keyword for keyword in login_keywords
                        if keyword in lower_url or keyword in title_text.lower()
                    ][:4]
                    risk_type = "login_surface"
                    risk_name = "URL疑似登录入口"
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
                        "status_code_hint": status_code,
                        "priority_score": 22 if self._is_ai_pen_success_status(status_code) else (10 if status_code in {401, 403} else 0),
                    }
                )
        except Exception as e:
            logger.warning("task_id:{} build ai_pen candidates from url failed err:{}".format(self.task_id, e))

        # 6) 目录扫描(fileleak)：优先提取状态码 200 的高价值端点/敏感文件。
        try:
            fileleak_cursor = utils.conn_db("fileleak").find(
                {"task_id": self.task_id},
                {"_id": 1, "url": 1, "site": 1, "title": 1, "status_code": 1, "content_length": 1},
                max_time_ms=Config.MONGO_SOCKET_TIMEOUT_MS,
            ).limit(self.AI_PEN_TEST_SOURCE_LIMIT)
            for row in fileleak_cursor:
                raw_url = str(row.get("url", "") or "").strip()
                if not self._is_http_target(raw_url):
                    continue
                if not self._url_in_task_scope(raw_url):
                    continue
                status_code = int(row.get("status_code", 0) or 0)
                candidate = self._build_ai_pen_high_value_url_candidate(
                    source_collection="fileleak",
                    source_id=row.get("_id"),
                    target_url=raw_url,
                    status_code=status_code,
                    title_text=str(row.get("title", "") or "").strip(),
                    source_text="fileleak",
                    site_url=str(row.get("site", "") or "").strip(),
                    content_length=row.get("content_length", 0),
                )
                if candidate:
                    _append_candidate(candidate)
        except Exception as e:
            logger.warning("task_id:{} build ai_pen candidates from fileleak failed err:{}".format(self.task_id, e))

        def _risk_score(item):
            score = 0
            risk_type = str(item.get("risk_type", "") or "").lower()
            severity = str(item.get("severity", "") or "").lower()
            if str(item.get("source_collection", "") or "") == "nuclei_result":
                score += 15
            elif str(item.get("source_collection", "") or "") == "fileleak":
                score += 12
            elif str(item.get("source_collection", "") or "") in {"site", "url"}:
                score += 5
            if self._is_http_target(item.get("vuln_url", "")):
                score += 20
            if str(item.get("evidence_seed", "") or "").strip():
                score += 8
            status_code = self._safe_int_value(item.get("status_code_hint"), 0)
            if self._is_ai_pen_success_status(status_code):
                score += 14
            elif status_code in {401, 403}:
                score += 6
            elif status_code >= 500 or status_code == 404:
                score -= 8
            if bool(item.get("high_value_target")):
                score += 24
            score += self._safe_int_value(item.get("priority_score"), 0)
            if severity in ("critical", "high"):
                score += 12
            elif severity == "medium":
                score += 6
            if any(
                keyword in risk_type
                for keyword in (
                    "xss",
                    "sql",
                    "sqli",
                    "command",
                    "cmdi",
                    "jwt",
                    "ssrf",
                    "ssti",
                    "xxe",
                    "idor",
                    "upload",
                    "file_read",
                    "api_doc",
                    "websocket",
                    "sensitive",
                    "config",
                )
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

    def _verify_ai_pen_candidate(self, candidate: dict, mcp_settings=None, ai_plan=None, planner_context=None):
        settings = mcp_settings if isinstance(mcp_settings, dict) else {}
        plan_obj = ai_plan if isinstance(ai_plan, dict) else {}
        planner_context_obj = planner_context if isinstance(planner_context, dict) else {}
        mcp_enable = bool(settings.get("mcp_enable", True))
        agent_loop_enable = bool(settings.get("agent_loop_enable", False)) and bool(planner_context_obj.get("ai_config"))
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
        risk_type_text = self._normalize_risk_type(risk_type, default_value="unknown")
        risk_name = str(candidate.get("risk_name", "") or "").strip()
        evidence_seed = self._clip_text(candidate.get("evidence_seed", ""), self.AI_PEN_TEST_EVIDENCE_MAX)
        browser_surface_summary = dict(candidate.get("browser_surface_summary") or {}) if isinstance(candidate.get("browser_surface_summary"), dict) else {}
        runtime_api_calls = list(candidate.get("runtime_api_calls", []) or [])[:16]
        dom_form_summary = list(candidate.get("dom_form_summary", []) or [])[:8]
        task_ai_pen_graph_summary = dict(candidate.get("task_ai_pen_graph_summary") or {}) if isinstance(candidate.get("task_ai_pen_graph_summary"), dict) else {}
        task_ai_pen_graph_context = dict(candidate.get("task_ai_pen_graph_context") or {}) if isinstance(candidate.get("task_ai_pen_graph_context"), dict) else {}
        login_surface_summary = dict(candidate.get("login_surface_summary") or {}) if isinstance(candidate.get("login_surface_summary"), dict) else {}
        payload_type, payload = self._build_ai_pen_payload_hint(risk_type, risk_name)
        route_hint = str(candidate.get("route_hint") or self._build_ai_pen_route_hint(candidate) or "").strip()
        capability_candidate = dict(candidate or {})
        capability_candidate["route_hint"] = route_hint
        capability_profile = self._select_ai_pen_capability_profile(capability_candidate)
        ai_plan_payload_type = self._normalize_ai_pen_payload_type(plan_obj.get("payload_type"), fallback_type=payload_type)
        ai_plan_payload = str(plan_obj.get("payload", "") or "").strip()[: self.AI_PEN_TEST_PAYLOAD_MAX]
        if ai_plan_payload_type:
            payload_type = ai_plan_payload_type
        if ai_plan_payload:
            payload = ai_plan_payload
        ai_plan_tool_plan = self._normalize_ai_pen_tool_plan(
            plan_obj.get("tool_plan"),
            default_url=target_url,
            max_steps=max(2, max_tool_calls),
        )
        if not ai_plan_tool_plan:
            ai_plan_tool_plan = self._infer_ai_pen_tool_plan(
                candidate=candidate,
                payload_type=payload_type,
                payload=payload,
                max_steps=max(2, max_tool_calls),
            )
        tool_plan_preview_parts = []
        for step_item in list(ai_plan_tool_plan or [])[:4]:
            if not isinstance(step_item, dict):
                continue
            tool_name = str(step_item.get("tool") or "").strip() or "unknown"
            step_url = str(dict(step_item.get("params") or {}).get("url") or "").strip()
            if step_url:
                tool_plan_preview_parts.append("{}@{}".format(tool_name, step_url[:90]))
            else:
                tool_plan_preview_parts.append(tool_name)
        is_xss_case = (risk_type_text == "xss") or (str(payload_type or "").strip().lower() == "xss_probe")
        is_sqli_case = (risk_type_text == "sqli") or (str(payload_type or "").strip().lower() == "sqli_probe")
        is_weak_password_case = (risk_type_text == "weak_password") or (
            str(payload_type or "").strip().lower() == "weak_password_probe"
        )
        runtime_timeout_sec = self._safe_int_value(
            settings.get("timeout_sec"),
            self.AI_PEN_TEST_MCP_TIMEOUT_SEC,
        )
        if runtime_timeout_sec < 1:
            runtime_timeout_sec = self.AI_PEN_TEST_MCP_TIMEOUT_SEC
        logger.info(
            "task_id:{} ai_pen verify start source={}:{} target:{} risk_type:{} payload_type:{} route_hint:{} capability:{} "
            "mcp:{} agent_loop:{} max_tool_calls:{} tool_plan_steps:{} tool_plan_preview:{}".format(
                self.task_id,
                str(candidate.get("source_collection", "") or "").strip()[:40] or "-",
                str(candidate.get("source_id", "") or "").strip()[:32] or "-",
                target_url[:180],
                risk_type_text,
                payload_type,
                route_hint[:48],
                str(capability_profile.get("name", "") or "").strip()[:48] or "-",
                "on" if mcp_enable else "off",
                "on" if agent_loop_enable else "off",
                max_tool_calls,
                len(list(ai_plan_tool_plan or [])),
                self._clip_text(",".join(tool_plan_preview_parts) or "-", 260),
            )
        )

        # 使用统一 MCP Runtime 管理探针调用审计，避免仅依赖 tool_trace 字符串回填。
        runtime = AiPenMcpRuntime(
            max_turns=max_tool_calls,
            max_tool_calls=max_tool_calls,
            timeout_sec=runtime_timeout_sec,
            runtime_version=self.AI_PEN_MCP_RUNTIME_VERSION,
        )
        runtime_context = {
            "task_id": str(self.task_id or ""),
            "target_url": target_url,
            "risk_type": risk_type_text,
            "risk_name": risk_name,
        }

        common_input_schema = {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "allow_redirects": {"type": "boolean"},
                "headers": {"type": "object"},
                "cookies": {"type": "object"},
                "session_key": {"type": "string"},
                "prepare_url": {"type": "string"},
                "login_url": {"type": "string"},
                "form_data": {"type": "object"},
                "json_data": {"type": "object"},
                "file_field": {"type": "string"},
                "file_name": {"type": "string"},
                "file_content": {"type": "string"},
                "file_content_type": {"type": "string"},
            },
            "required": ["url"],
        }
        session_store = {}

        def _build_runtime_response(resp, req_url: str, req_method: str, session_obj=None):
            status_code = int(getattr(resp, "status_code", 0) or 0)
            response_headers = {}
            raw_headers = getattr(resp, "headers", {}) or {}
            if hasattr(raw_headers, "items"):
                for header_key, header_value in raw_headers.items():
                    key_text = str(header_key or "").strip()
                    if not key_text:
                        continue
                    response_headers[key_text] = str(header_value or "")[:240]
            try:
                body_text = str(getattr(resp, "text", "") or "")
            except Exception:
                body_text = ""
            body_excerpt = body_text[: self.AI_PEN_TEST_BODY_MAX]
            body_md5 = hashlib.md5(body_excerpt.encode("utf-8", "ignore")).hexdigest() if body_excerpt else ""

            history_urls = []
            history_status_codes = []
            for history_item in list(getattr(resp, "history", []) or [])[:4]:
                history_url = str(getattr(history_item, "url", "") or "").strip()
                if history_url:
                    history_urls.append(history_url[:220])
                history_status_codes.append(int(getattr(history_item, "status_code", 0) or 0))

            cookie_names = []
            seen_cookie_names = set()
            cookie_jar = getattr(session_obj, "cookies", None)
            if cookie_jar is not None and hasattr(cookie_jar, "keys"):
                for cookie_name in list(cookie_jar.keys())[:8]:
                    name_text = str(cookie_name or "").strip()
                    lowered_name = name_text.lower()
                    if not name_text or lowered_name in seen_cookie_names:
                        continue
                    seen_cookie_names.add(lowered_name)
                    cookie_names.append(name_text[:60])

            return {
                "status": "ok",
                "message": "ok",
                "response": {
                    "request_url": req_url,
                    "url": str(getattr(resp, "url", "") or req_url or ""),
                    "method": str(req_method or "").strip().lower(),
                    "status_code": status_code,
                    "headers": response_headers,
                    "body_text": body_excerpt,
                    "body_md5": body_md5,
                    "history_urls": history_urls,
                    "history_status_codes": history_status_codes,
                    "cookie_names": cookie_names,
                },
            }

        def _prepare_runtime_request(
            req_url,
            req_method="get",
            allow_redirects=True,
            headers=None,
            cookies=None,
            form_data=None,
            json_data=None,
            file_field="",
            file_name="",
            file_content="",
            file_content_type="",
        ):
            headers_obj = dict(headers or {}) if isinstance(headers, dict) else {}
            headers_obj.setdefault("User-Agent", "Mozilla/5.0")
            headers_obj.setdefault("Cache-Control", "max-age=0")

            if self.waf_guard:
                should_skip, detail = self.waf_guard.should_skip(req_url, module="ai_pen_test")
                if should_skip:
                    return {}, self.waf_guard.build_skip_response(req_url, detail)

                headers_obj, waf_delay, _ = self.waf_guard.prepare_request(
                    req_url,
                    module="ai_pen_test",
                    method=req_method,
                    headers=headers_obj,
                )
                if waf_delay > 0:
                    time.sleep(waf_delay)

            request_kwargs = {
                "verify": False,
                "timeout": timeout_tuple,
                "allow_redirects": bool(allow_redirects),
                "headers": headers_obj,
            }
            if isinstance(form_data, dict) and form_data:
                request_kwargs["data"] = form_data
            if isinstance(json_data, dict) and json_data:
                request_kwargs["json"] = json_data
            if isinstance(cookies, dict) and cookies:
                safe_cookies = {}
                for cookie_key, cookie_value in cookies.items():
                    key_text = str(cookie_key or "").strip()
                    if not key_text:
                        continue
                    safe_cookies[key_text[:80]] = str(cookie_value or "")[:240]
                if safe_cookies:
                    request_kwargs["cookies"] = safe_cookies
            upload_field = str(file_field or "").strip()
            if upload_field:
                request_kwargs["files"] = {
                    upload_field: (
                        str(file_name or "arl-safe-upload.txt")[:120],
                        str(file_content or "ARL_SAFE_UPLOAD_PROBE"),
                        str(file_content_type or "text/plain")[:80],
                    )
                }

            if Config.PROXY_URL:
                request_kwargs["proxies"] = {
                    "https": Config.PROXY_URL,
                    "http": Config.PROXY_URL,
                }
            else:
                request_kwargs["proxies"] = {"http": None, "https": None}
            return request_kwargs, None

        def _execute_runtime_request(
            req_url,
            req_method="get",
            allow_redirects=True,
            headers=None,
            cookies=None,
            form_data=None,
            json_data=None,
            file_field="",
            file_name="",
            file_content="",
            file_content_type="",
            session_key="",
        ):
            if not req_url:
                return {"status": "error", "message": "missing_url", "response": {}}

            req_method = str(req_method or "get").strip().lower() or "get"
            request_kwargs, skip_response = _prepare_runtime_request(
                req_url=req_url,
                req_method=req_method,
                allow_redirects=allow_redirects,
                headers=headers,
                cookies=cookies,
                form_data=form_data,
                json_data=json_data,
                file_field=file_field,
                file_name=file_name,
                file_content=file_content,
                file_content_type=file_content_type,
            )
            if skip_response is not None:
                session_obj = None
                if session_key:
                    session_obj = dict(session_store.get(session_key) or {}).get("session")
                return _build_runtime_response(skip_response, req_url, req_method, session_obj=session_obj)

            session_obj = None
            if session_key:
                session_bucket = session_store.setdefault(
                    str(session_key or "").strip() or "default",
                    {"session": requests.Session(), "last_response": {}},
                )
                session_obj = session_bucket["session"]
                resp = session_obj.request(req_method, req_url, **request_kwargs)
            else:
                resp = requests.request(req_method, req_url, **request_kwargs)

            if self.waf_guard:
                self.waf_guard.observe_response(req_url, resp, module="ai_pen_test")

            result = _build_runtime_response(resp, req_url, req_method, session_obj=session_obj)
            if session_key:
                session_store[str(session_key or "").strip() or "default"]["last_response"] = dict(result.get("response") or {})
            return result

        def _build_runtime_http_executor(default_method="get", default_allow_redirects=True):
            def _executor(_context, params):
                params_obj = params if isinstance(params, dict) else {}
                req_url = str(params_obj.get("url") or "").strip()
                req_method = str(params_obj.get("method") or default_method or "get").strip().lower() or "get"
                allow_redirects = params_obj.get("allow_redirects")
                if not isinstance(allow_redirects, bool):
                    allow_redirects = bool(default_allow_redirects)
                req_headers = params_obj.get("headers")
                req_headers_obj = req_headers if isinstance(req_headers, dict) else {}
                req_cookies = params_obj.get("cookies")
                req_cookies_obj = req_cookies if isinstance(req_cookies, dict) else {}
                session_key = str(params_obj.get("session_key") or "").strip()
                form_data = params_obj.get("form_data") if isinstance(params_obj.get("form_data"), dict) else {}
                json_data = params_obj.get("json_data") if isinstance(params_obj.get("json_data"), dict) else {}
                file_field = str(params_obj.get("file_field") or "").strip()
                file_name = str(params_obj.get("file_name") or "").strip()
                file_content = str(params_obj.get("file_content") or "").strip()
                file_content_type = str(params_obj.get("file_content_type") or "").strip()
                prepare_url = str(params_obj.get("prepare_url") or "").strip()

                if not req_url:
                    return {"status": "error", "message": "missing_url", "response": {}}

                try:
                    if prepare_url and session_key:
                        _execute_runtime_request(
                            req_url=prepare_url,
                            req_method="get",
                            allow_redirects=True,
                            headers=req_headers_obj,
                            cookies=req_cookies_obj,
                            session_key=session_key,
                        )
                        prepared_response = dict(session_store.get(session_key, {}).get("last_response") or {})
                        prepared_body = str(prepared_response.get("body_text") or "")
                        prepared_context = self._build_ai_pen_login_probe_context(
                            target_url=prepare_url,
                            body_text=prepared_body,
                        )
                        if prepared_context:
                            merged_form_data = dict(prepared_context.get("hidden_fields") or {})
                            merged_form_data.update(form_data)
                            form_data = merged_form_data
                            if req_method == "get":
                                req_method = str(prepared_context.get("method") or req_method).strip().lower() or req_method
                            if not req_url:
                                req_url = str(prepared_context.get("submit_url") or prepare_url)

                    return _execute_runtime_request(
                        req_url=req_url,
                        req_method=req_method,
                        allow_redirects=allow_redirects,
                        headers=req_headers_obj,
                        cookies=req_cookies_obj,
                        form_data=form_data,
                        json_data=json_data,
                        file_field=file_field,
                        file_name=file_name,
                        file_content=file_content,
                        file_content_type=file_content_type,
                        session_key=session_key,
                    )
                except Exception as req_exc:
                    return {
                        "status": "error",
                        "message": self._clip_text(req_exc, self.AI_PEN_TEST_ERROR_MAX),
                        "response": {},
                    }

            return _executor

        def _build_detect_login_success_executor():
            def _executor(_context, params):
                params_obj = params if isinstance(params, dict) else {}
                session_key = str(params_obj.get("session_key") or "").strip() or "default"
                login_url = str(params_obj.get("login_url") or params_obj.get("url") or "").strip()
                session_bucket = session_store.get(session_key) if isinstance(session_store.get(session_key), dict) else {}
                last_response = dict(session_bucket.get("last_response") or {})
                if not last_response:
                    return {
                        "status": "error",
                        "message": "missing_login_response",
                        "response": {},
                        "analysis": {},
                    }

                analysis = self._analyze_ai_pen_login_success(
                    login_url=login_url,
                    response_summary=last_response,
                )
                return {
                    "status": "ok",
                    "message": str(analysis.get("reason") or "").strip(),
                    "response": last_response,
                    "analysis": analysis,
                }

            return _executor

        def _build_extract_csrf_executor():
            def _executor(_context, params):
                params_obj = params if isinstance(params, dict) else {}
                req_url = str(params_obj.get("url") or params_obj.get("prepare_url") or params_obj.get("login_url") or "").strip()
                session_key = str(params_obj.get("session_key") or "").strip() or "default"
                req_headers = params_obj.get("headers") if isinstance(params_obj.get("headers"), dict) else {}
                if not req_url:
                    return {"status": "error", "message": "missing_url", "response": {}, "analysis": {}}

                runtime_ret = _execute_runtime_request(
                    req_url=req_url,
                    req_method="get",
                    allow_redirects=True,
                    headers=req_headers,
                    session_key=session_key,
                )
                status_text = str(runtime_ret.get("status", "") or "").strip().lower()
                response_obj = dict(runtime_ret.get("response") or {}) if isinstance(runtime_ret.get("response"), dict) else {}
                if status_text != "ok":
                    return {
                        "status": status_text or "error",
                        "message": str(runtime_ret.get("message") or "csrf_prepare_failed"),
                        "response": response_obj,
                        "analysis": {},
                    }

                body_text = str(response_obj.get("body_text", "") or "")
                login_context = self._build_ai_pen_login_probe_context(
                    target_url=req_url,
                    body_text=body_text,
                )
                hidden_fields = dict(login_context.get("hidden_fields") or {})
                csrf_field = str(login_context.get("csrf_field") or "").strip()
                csrf_value = str(hidden_fields.get(csrf_field) or "")[:180] if csrf_field else ""
                analysis = {
                    "csrf_field": csrf_field,
                    "csrf_value": csrf_value,
                    "submit_url": str(login_context.get("submit_url") or req_url),
                    "method": str(login_context.get("method") or "post").lower(),
                    "captcha_required": bool(login_context.get("captcha_required")),
                    "hidden_fields": hidden_fields,
                }
                return {
                    "status": "ok",
                    "message": "csrf_extracted" if csrf_field else "csrf_not_found",
                    "response": response_obj,
                    "analysis": analysis,
                }

            return _executor

        def _build_extract_links_executor():
            def _executor(_context, params):
                params_obj = params if isinstance(params, dict) else {}
                req_url = str(params_obj.get("url") or "").strip()
                req_headers = params_obj.get("headers") if isinstance(params_obj.get("headers"), dict) else {}
                if not req_url:
                    return {"status": "error", "message": "missing_url", "response": {}, "analysis": {}}
                runtime_ret = _execute_runtime_request(
                    req_url=req_url,
                    req_method="get",
                    allow_redirects=True,
                    headers=req_headers,
                )
                status_text = str(runtime_ret.get("status", "") or "").strip().lower()
                response_obj = dict(runtime_ret.get("response") or {}) if isinstance(runtime_ret.get("response"), dict) else {}
                if status_text != "ok":
                    return {
                        "status": status_text or "error",
                        "message": str(runtime_ret.get("message") or "extract_links_failed"),
                        "response": response_obj,
                        "analysis": {},
                    }
                body_text = str(response_obj.get("body_text", "") or "")
                links = []
                seen_links = set()
                for match in re.finditer(r'(?is)\bhref\s*=\s*["\']([^"\']+)["\']', body_text):
                    href_value = str(match.group(1) or "").strip()
                    if not href_value:
                        continue
                    abs_link = urljoin(req_url, href_value)
                    if abs_link in seen_links:
                        continue
                    seen_links.add(abs_link)
                    links.append(abs_link[:220])
                    if len(links) >= 30:
                        break
                return {
                    "status": "ok",
                    "message": "extract_links_ok",
                    "response": response_obj,
                    "analysis": {
                        "link_count": len(links),
                        "links": links,
                    },
                }

            return _executor

        def _build_extract_forms_executor():
            def _executor(_context, params):
                params_obj = params if isinstance(params, dict) else {}
                req_url = str(params_obj.get("url") or "").strip()
                req_headers = params_obj.get("headers") if isinstance(params_obj.get("headers"), dict) else {}
                if not req_url:
                    return {"status": "error", "message": "missing_url", "response": {}, "analysis": {}}
                runtime_ret = _execute_runtime_request(
                    req_url=req_url,
                    req_method="get",
                    allow_redirects=True,
                    headers=req_headers,
                )
                status_text = str(runtime_ret.get("status", "") or "").strip().lower()
                response_obj = dict(runtime_ret.get("response") or {}) if isinstance(runtime_ret.get("response"), dict) else {}
                if status_text != "ok":
                    return {
                        "status": status_text or "error",
                        "message": str(runtime_ret.get("message") or "extract_forms_failed"),
                        "response": response_obj,
                        "analysis": {},
                    }
                body_text = str(response_obj.get("body_text", "") or "")
                forms = []
                for match in re.finditer(r"(?is)<form\b([^>]*)>(.*?)</form>", body_text):
                    attrs_text = str(match.group(1) or "")
                    inner_text = str(match.group(2) or "")
                    action_text = self._extract_html_attr_value(attrs_text, "action")
                    method_text = self._extract_html_attr_value(attrs_text, "method") or "get"
                    enctype_text = self._extract_html_attr_value(attrs_text, "enctype")
                    forms.append(
                        {
                            "action": urljoin(req_url, action_text) if action_text else req_url,
                            "method": method_text.lower(),
                            "enctype": enctype_text.lower(),
                            "has_password_input": bool(re.search(r'(?is)<input\b[^>]*\btype\s*=\s*["\']password["\']', inner_text)),
                            "has_file_input": bool(re.search(r'(?is)<input\b[^>]*\btype\s*=\s*["\']file["\']', inner_text)),
                        }
                    )
                    if len(forms) >= 12:
                        break
                return {
                    "status": "ok",
                    "message": "extract_forms_ok",
                    "response": response_obj,
                    "analysis": {
                        "form_count": len(forms),
                        "forms": forms,
                    },
                }

            return _executor

        def _build_extract_headers_executor():
            def _executor(_context, params):
                params_obj = params if isinstance(params, dict) else {}
                req_url = str(params_obj.get("url") or "").strip()
                req_headers = params_obj.get("headers") if isinstance(params_obj.get("headers"), dict) else {}
                if not req_url:
                    return {"status": "error", "message": "missing_url", "response": {}, "analysis": {}}
                runtime_ret = _execute_runtime_request(
                    req_url=req_url,
                    req_method="head",
                    allow_redirects=True,
                    headers=req_headers,
                )
                status_text = str(runtime_ret.get("status", "") or "").strip().lower()
                response_obj = dict(runtime_ret.get("response") or {}) if isinstance(runtime_ret.get("response"), dict) else {}
                if status_text != "ok":
                    return {
                        "status": status_text or "error",
                        "message": str(runtime_ret.get("message") or "extract_headers_failed"),
                        "response": response_obj,
                        "analysis": {},
                    }
                header_obj = dict(response_obj.get("headers") or {}) if isinstance(response_obj.get("headers"), dict) else {}
                focus_headers = {}
                for key_name in ("Content-Type", "Content-Length", "Server", "X-Powered-By", "Location", "Set-Cookie"):
                    value_text = str(header_obj.get(key_name, "") or "").strip()
                    if value_text:
                        focus_headers[key_name] = value_text[:180]
                return {
                    "status": "ok",
                    "message": "extract_headers_ok",
                    "response": response_obj,
                    "analysis": {
                        "header_count": len(header_obj),
                        "focus_headers": focus_headers,
                    },
                }

            return _executor

        def _build_cookie_jar_update_executor():
            def _executor(_context, params):
                params_obj = params if isinstance(params, dict) else {}
                session_key = str(params_obj.get("session_key") or "").strip() or "default"
                cookie_map = {}
                if isinstance(params_obj.get("cookies"), dict):
                    cookie_map.update(params_obj.get("cookies") or {})
                if isinstance(params_obj.get("form_data"), dict):
                    cookie_map.update(params_obj.get("form_data") or {})
                if isinstance(params_obj.get("json_data"), dict):
                    cookie_map.update(params_obj.get("json_data") or {})
                if not cookie_map:
                    return {"status": "error", "message": "missing_cookies", "response": {}, "analysis": {}}

                session_bucket = session_store.setdefault(
                    session_key,
                    {"session": requests.Session(), "last_response": {}},
                )
                session_obj = session_bucket["session"]
                changed_names = []
                for cookie_key, cookie_value in cookie_map.items():
                    key_text = str(cookie_key or "").strip()
                    if not key_text:
                        continue
                    session_obj.cookies.set(key_text[:80], str(cookie_value or "")[:240])
                    changed_names.append(key_text[:80])
                    if len(changed_names) >= 20:
                        break
                response_obj = dict(session_bucket.get("last_response") or {}) if isinstance(session_bucket.get("last_response"), dict) else {}
                return {
                    "status": "ok",
                    "message": "cookie_jar_updated",
                    "response": response_obj,
                    "analysis": {
                        "session_key": session_key,
                        "cookie_count": len(list(session_obj.cookies.keys())),
                        "updated_cookie_names": changed_names,
                    },
                }

            return _executor

        runtime.register_tool(
            ToolSchema(
                name="http_fetch",
                description="基础 HTTP 获取探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="head_probe",
                description="基础 HEAD 请求探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="head", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="extract_links",
                description="提取页面链接关系",
                input_schema=common_input_schema,
                execute=_build_extract_links_executor(),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="extract_forms",
                description="提取页面表单结构",
                input_schema=common_input_schema,
                execute=_build_extract_forms_executor(),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="extract_headers",
                description="提取关键响应头",
                input_schema=common_input_schema,
                execute=_build_extract_headers_executor(),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="session_start",
                description="初始化登录会话",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="session_request",
                description="会话内请求执行器",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="follow_redirect",
                description="跟随重定向获取最终页面",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="cookie_jar_update",
                description="更新会话 Cookie Jar",
                input_schema=common_input_schema,
                execute=_build_cookie_jar_update_executor(),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="extract_csrf_token",
                description="提取登录页 CSRF token",
                input_schema=common_input_schema,
                execute=_build_extract_csrf_executor(),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="login_probe",
                description="登录页探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="credential_probe",
                description="默认口令登录探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="post", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="detect_login_success",
                description="登录成功/阻断判定",
                input_schema=common_input_schema,
                execute=_build_detect_login_success_executor(),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="logout_probe",
                description="退出登录状态探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="token_replay",
                description="认证令牌重放探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="payload_probe",
                description="Payload 探针请求",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="xss_probe",
                description="XSS 探针请求",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="sqli_probe",
                description="SQLi 探针请求",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="ssrf_probe",
                description="SSRF 探针请求",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="ssti_probe",
                description="SSTI 探针请求",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="xxe_probe",
                description="XXE 探针请求",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="cmdi_probe",
                description="命令注入探针请求",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="idor_probe",
                description="IDOR 参数变异探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="api_doc_probe",
                description="API 文档发现探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="graphql_probe",
                description="GraphQL 入口确认探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="post", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="config_probe",
                description="配置/环境暴露探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="jwt_probe",
                description="JWT 鉴权探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="websocket_probe",
                description="WebSocket 握手探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=False),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="file_probe",
                description="文件下载/导出接口确认探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="get", default_allow_redirects=True),
            )
        )
        runtime.register_tool(
            ToolSchema(
                name="upload_probe",
                description="无害静态文件上传探针",
                input_schema=common_input_schema,
                execute=_build_runtime_http_executor(default_method="post", default_allow_redirects=True),
            )
        )

        def _runtime_http_req(tool_name, req_url, summary="", method="get", allow_redirects=True, headers=None):
            params = {
                "url": str(req_url or "").strip(),
                "method": str(method or "get").strip().lower() or "get",
                "allow_redirects": bool(allow_redirects),
            }
            if isinstance(headers, dict) and headers:
                params["headers"] = headers
            call_ret = runtime.invoke(
                tool_name=tool_name,
                params=params,
                context=runtime_context,
                summary=summary,
            )
            result_obj = call_ret.get("result") if isinstance(call_ret, dict) else {}
            if not isinstance(result_obj, dict):
                result_obj = {}
            status_text = str(call_ret.get("status", "") or result_obj.get("status", "") or "ok").strip().lower()
            if status_text == "blocked":
                raise RuntimeError("{} blocked by runtime budget".format(tool_name))
            if status_text == "error":
                err_text = str(result_obj.get("message") or call_ret.get("message") or "").strip()
                raise RuntimeError(err_text or "{} failed".format(tool_name))
            response_obj = result_obj.get("response") if isinstance(result_obj.get("response"), dict) else {}
            return SimpleNamespace(
                status_code=int(response_obj.get("status_code", 0) or 0),
                headers=dict(response_obj.get("headers") or {}),
                text=str(response_obj.get("body_text", "") or ""),
                url=str(response_obj.get("url", "") or req_url or ""),
            )

        def _with_runtime_artifacts(base_payload, trace_parts, current_status, current_decision, runtime_result=None):
            payload_obj = dict(base_payload or {})
            trace_list = trace_parts if isinstance(trace_parts, list) else []
            runtime_obj = runtime_result if isinstance(runtime_result, dict) else {}
            if not runtime_obj:
                runtime_obj = AiPenMcpRuntime.build_artifacts_from_tool_trace(
                    tool_trace_parts=trace_list,
                    max_tool_calls=max_tool_calls,
                    timeout_sec=runtime_timeout_sec,
                    status=current_status,
                    decision=current_decision,
                    runtime_version=self.AI_PEN_MCP_RUNTIME_VERSION,
                )
            current_stop_reason = str(runtime_obj.get("stop_reason", "") or "").strip()
            if not current_stop_reason or current_stop_reason == "final_decision":
                if str(current_status or "").strip().lower() == "error":
                    runtime_obj["stop_reason"] = "error"
                elif str(current_status or "").strip().lower() == "skipped":
                    runtime_obj["stop_reason"] = "manual_required"
                elif str(current_decision or "").strip().lower() == "needs_manual_review":
                    runtime_obj["stop_reason"] = "manual_required"
                else:
                    runtime_obj["stop_reason"] = current_stop_reason or "final_decision"
            payload_obj["agent_trace"] = list(runtime_obj.get("agent_trace", []) or [])
            payload_obj["tool_calls"] = list(runtime_obj.get("tool_calls", []) or [])
            payload_obj["tool_results"] = list(runtime_obj.get("tool_results", []) or [])
            payload_obj["stop_reason"] = str(runtime_obj.get("stop_reason", "") or "")
            payload_obj["budget_used"] = dict(runtime_obj.get("budget_used") or {})
            payload_obj["runtime_version"] = str(runtime_obj.get("runtime_version", "") or "")
            request_packet_obj = self._build_ai_pen_request_packet(
                target_url=target_url,
                payload_type=str(payload_obj.get("payload_type", "") or payload_type),
                payload=str(payload_obj.get("payload", "") or payload),
                verification_step=str(payload_obj.get("verification_step", "") or ""),
                tool_trace_parts=trace_list,
            )
            payload_obj["request_method"] = str(request_packet_obj.get("method", "") or "").strip()
            payload_obj["request_url"] = str(request_packet_obj.get("url", "") or "").strip()
            payload_obj["request_path"] = str(request_packet_obj.get("path", "") or "").strip()
            payload_obj["request_headers"] = (
                dict(request_packet_obj.get("headers") or {})
                if isinstance(request_packet_obj.get("headers"), dict)
                else {}
            )
            payload_obj["request_body"] = str(request_packet_obj.get("body", "") or "").strip()
            payload_obj["request_packet"] = self._clip_multiline_text(
                request_packet_obj.get("raw", ""),
                self.AI_PEN_TEST_REQUEST_PACKET_MAX,
            )
            return payload_obj

        if not self._is_http_target(target_url):
            return _with_runtime_artifacts({
                "status": "skipped",
                "decision": "needs_manual_review",
                "confidence": 0.35,
                "reason": "缺少可访问的 HTTP 目标，当前阶段仅完成上下文归档",
                "risk_type": risk_type_text,
                "payload_type": payload_type,
                "payload": payload,
                "verification_step": "collect_context_only",
                "evidence_snippet": evidence_seed,
                "http_status": 0,
                "response_hash_diff": "",
                "xss_popup_proof": False,
                "sqli_proof_type": "",
                "weak_password_login_proof": False,
                "api_doc_summary": {},
                "api_surface_summary": {},
                "browser_surface_summary": browser_surface_summary,
                "runtime_api_calls": runtime_api_calls,
                "dom_form_summary": dom_form_summary,
                "task_ai_pen_graph_summary": task_ai_pen_graph_summary,
                "task_ai_pen_graph_context": task_ai_pen_graph_context,
                "login_surface_summary": login_surface_summary,
                "route_hint": route_hint,
                "capability_profile": capability_profile if isinstance(capability_profile, dict) else {},
                "tool_trace": "collect_context_only",
                "external_tool_runs": [],
                "external_tool_hit": False,
            }, ["collect_context_only"], "skipped", "needs_manual_review")

        tool_trace_parts = []
        if plan_obj:
            plan_trace_parts = []
            if str(plan_obj.get("decision", "") or "").strip():
                plan_trace_parts.append("decision={}".format(str(plan_obj.get("decision", "")).strip()))
            if payload_type:
                plan_trace_parts.append("payload_type={}".format(payload_type))
            if payload:
                plan_trace_parts.append("payload={}".format(str(payload)[:80]))
            if ai_plan_tool_plan:
                plan_trace_parts.append("tool_plan_steps={}".format(len(ai_plan_tool_plan)))
            if plan_trace_parts:
                tool_trace_parts.append("ai_plan({})".format(",".join(plan_trace_parts)))
        try:
            response = _runtime_http_req(
                "http_fetch",
                target_url,
                summary="基础页面获取",
                method="get",
                allow_redirects=True,
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
                return _with_runtime_artifacts({
                    "status": "skipped",
                    "decision": "needs_manual_review",
                    "confidence": 0.32,
                    "reason": " | ".join(reason_parts),
                    "risk_type": risk_type_text,
                    "payload_type": payload_type,
                    "payload": payload,
                    "verification_step": "waf_smart_skip",
                    "evidence_snippet": evidence_seed,
                    "http_status": status_code,
                    "response_hash_diff": "",
                    "xss_popup_proof": False,
                    "sqli_proof_type": "",
                    "weak_password_login_proof": False,
                    "api_doc_summary": {},
                    "api_surface_summary": {},
                    "browser_surface_summary": browser_surface_summary,
                    "runtime_api_calls": runtime_api_calls,
                    "dom_form_summary": dom_form_summary,
                    "task_ai_pen_graph_summary": task_ai_pen_graph_summary,
                    "task_ai_pen_graph_context": task_ai_pen_graph_context,
                    "login_surface_summary": login_surface_summary,
                    "route_hint": route_hint,
                    "capability_profile": capability_profile if isinstance(capability_profile, dict) else {},
                    "tool_trace": "http_fetch(skip_by_waf,url={})".format(target_url[:220]),
                    "external_tool_runs": [],
                    "external_tool_hit": False,
                }, ["http_fetch(skip_by_waf,url={})".format(target_url[:220])], "skipped", "needs_manual_review", runtime_result=runtime.build_result())

            body_text = ""
            try:
                body_text = str(getattr(response, "text", "") or "")
            except Exception:
                body_text = ""
            js_api_targets = self._extract_js_api_targets(target_url, body_text) if self._is_js_asset_target(target_url, headers=header_obj) else []

            base_body_excerpt = body_text[: self.AI_PEN_TEST_BODY_MAX]
            base_body_md5 = hashlib.md5(base_body_excerpt.encode("utf-8", "ignore")).hexdigest() if base_body_excerpt else ""
            evidence_hit = self._contains_evidence(evidence_seed, base_body_excerpt)
            login_probe_context = self._build_ai_pen_login_probe_context(
                target_url=target_url,
                body_text=body_text,
                dom_form_summary=dom_form_summary,
                login_surface_summary=login_surface_summary,
            )
            idor_probe_targets = self._build_idor_probe_targets(target_url, max_count=max(2, max_tool_calls))

            probe_status = 0
            probe_url = ""
            probe_headers = {}
            probe_body_excerpt = ""
            probe_body_md5 = ""
            payload_reflect_hit = False
            idor_diff_hit = False
            idor_probe_count = 0
            idor_probe_responses = []
            idor_diff_summary = {}
            api_doc_hit = False
            api_doc_hit_url = ""
            api_doc_probe_count = 0
            config_probe_count = 0
            api_doc_summary = {}
            api_surface_summary = self._build_api_surface_summary(api_doc_summary=api_doc_summary, js_api_targets=js_api_targets)
            graphql_hit = False
            graphql_hit_url = ""
            graphql_summary = {}
            config_exposure_hit = False
            config_exposure_url = ""
            config_exposure_summary = ""
            jwt_token_found = ""
            jwt_alg_text = ""
            jwt_alg_none_hit = False
            jwt_none_probe_hit = False
            jwt_weak_secret = ""
            websocket_upgrade_hit = False
            websocket_upgrade_hint = False
            credential_probe_count = 0
            login_success_hit = False
            login_success_reason = ""
            login_blocked_reason = ""
            agent_loop_final_decision = {}
            agent_loop_stop_reason = ""
            probe_error = ""
            payload_probe_types = {"xss_probe", "sqli_probe", "cmdi_probe", "ssrf_probe", "ssti_probe", "xxe_probe", "replay"}

            if mcp_enable and len(runtime.tool_calls) < max_tool_calls and (ai_plan_tool_plan or agent_loop_enable):
                if agent_loop_enable:
                    plan_observation = self._execute_ai_pen_agent_loop(
                        runtime=runtime,
                        runtime_context=runtime_context,
                        candidate=candidate,
                        runtime_settings=settings,
                        ai_config=planner_context_obj.get("ai_config") if isinstance(planner_context_obj.get("ai_config"), dict) else {},
                        prompt_content=str(planner_context_obj.get("prompt_content", "") or ""),
                        initial_tool_plan=ai_plan_tool_plan,
                        target_url=target_url,
                        evidence_seed=evidence_seed,
                        js_api_targets=js_api_targets,
                    )
                else:
                    plan_observation = self._execute_ai_pen_tool_plan(
                        runtime=runtime,
                        runtime_context=runtime_context,
                        tool_plan=ai_plan_tool_plan,
                        target_url=target_url,
                        evidence_seed=evidence_seed,
                        js_api_targets=js_api_targets,
                    )
                tool_trace_parts.extend(list(plan_observation.get("trace_parts", []) or []))
                probe_status = int(plan_observation.get("probe_status", 0) or 0) or probe_status
                probe_url = str(plan_observation.get("probe_url", "") or "") or probe_url
                probe_headers = dict(plan_observation.get("probe_headers") or {}) or probe_headers
                probe_body_excerpt = str(plan_observation.get("probe_body_excerpt", "") or "") or probe_body_excerpt
                probe_body_md5 = str(plan_observation.get("probe_body_md5", "") or "") or probe_body_md5
                idor_probe_responses.extend(
                    [
                        dict(item or {})
                        for item in list(plan_observation.get("responses", []) or [])
                        if isinstance(item, dict) and str(item.get("tool") or "").strip() == "idor_probe"
                    ]
                )
                evidence_hit = bool(plan_observation.get("evidence_hit")) or evidence_hit
                api_doc_hit = bool(plan_observation.get("api_doc_hit")) or api_doc_hit
                api_doc_hit_url = str(plan_observation.get("api_doc_hit_url", "") or "") or api_doc_hit_url
                if isinstance(plan_observation.get("api_doc_summary"), dict) and plan_observation.get("api_doc_summary"):
                    api_doc_summary = dict(plan_observation.get("api_doc_summary") or {})
                if isinstance(plan_observation.get("api_surface_summary"), dict) and plan_observation.get("api_surface_summary"):
                    api_surface_summary = dict(plan_observation.get("api_surface_summary") or {})
                graphql_hit = bool(plan_observation.get("graphql_hit")) or graphql_hit
                graphql_hit_url = str(plan_observation.get("graphql_hit_url", "") or "") or graphql_hit_url
                if isinstance(plan_observation.get("graphql_summary"), dict) and plan_observation.get("graphql_summary"):
                    graphql_summary = dict(plan_observation.get("graphql_summary") or {})
                api_doc_probe_count += self._safe_int_value(
                    dict(plan_observation.get("tool_counts") or {}).get("api_doc_probe"),
                    0,
                )
                config_probe_count += self._safe_int_value(
                    dict(plan_observation.get("tool_counts") or {}).get("config_probe"),
                    0,
                )
                idor_probe_count += self._safe_int_value(
                    dict(plan_observation.get("tool_counts") or {}).get("idor_probe"),
                    0,
                )
                config_exposure_hit = bool(plan_observation.get("config_exposure_hit")) or config_exposure_hit
                config_exposure_url = str(plan_observation.get("config_exposure_url", "") or "") or config_exposure_url
                config_exposure_summary = str(plan_observation.get("config_exposure_summary", "") or "") or config_exposure_summary
                websocket_upgrade_hit = bool(plan_observation.get("websocket_upgrade_hit")) or websocket_upgrade_hit
                websocket_upgrade_hint = bool(plan_observation.get("websocket_upgrade_hint")) or websocket_upgrade_hint
                credential_probe_count += self._safe_int_value(
                    dict(plan_observation.get("tool_counts") or {}).get("credential_probe"),
                    0,
                )
                login_success_hit = bool(plan_observation.get("login_success_hit")) or login_success_hit
                login_success_reason = str(plan_observation.get("login_success_reason", "") or "") or login_success_reason
                login_blocked_reason = str(plan_observation.get("login_blocked_reason", "") or "") or login_blocked_reason
                if isinstance(plan_observation.get("final_decision"), dict) and plan_observation.get("final_decision"):
                    agent_loop_final_decision = dict(plan_observation.get("final_decision") or {})
                agent_loop_stop_reason = str(plan_observation.get("stop_reason", "") or "").strip()
                if (not probe_error) and str(plan_observation.get("error", "") or "").strip():
                    probe_error = self._clip_text(plan_observation.get("error", ""), self.AI_PEN_TEST_ERROR_MAX)
                payload_text = str(payload or "").strip().lower()
                if payload_text and payload_type in payload_probe_types and len(payload_text) >= 6 and payload_text in str(probe_body_excerpt or "").lower():
                    payload_reflect_hit = True
                logger.info(
                    "task_id:{} ai_pen verify main_plan target:{} payload_type:{} stop_reason:{} probe_status:{} "
                    "tool_counts:{} evidence_hit:{} api_doc_hit:{} graphql_hit:{} idor_resp:{} error:{}".format(
                        self.task_id,
                        target_url[:180],
                        payload_type,
                        agent_loop_stop_reason or "-",
                        probe_status,
                        self._clip_text(
                            json.dumps(dict(plan_observation.get("tool_counts") or {}), ensure_ascii=False, sort_keys=True),
                            180,
                        ),
                        int(bool(evidence_hit)),
                        int(bool(api_doc_hit)),
                        int(bool(graphql_hit)),
                        len(idor_probe_responses),
                        self._clip_text(probe_error, 120) if probe_error else "-",
                    )
                )
            tool_calls = len(list(runtime.tool_calls or []))
            if mcp_enable and tool_calls < max_tool_calls and agent_loop_stop_reason not in {"final_decision", "manual_required"}:
                if payload_type == "jwt_probe":
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
                                jwt_resp = _runtime_http_req(
                                    "jwt_probe",
                                    target_url,
                                    summary="JWT none token 重放",
                                    method="get",
                                    allow_redirects=True,
                                    headers=jwt_headers,
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
                else:
                    remain_calls = max(1, max_tool_calls - tool_calls)
                    fallback_tool_plan = self._build_ai_pen_fallback_tool_plan(
                        target_url=target_url,
                        payload_type=payload_type,
                        payload=payload,
                        max_steps=remain_calls,
                        candidate=candidate,
                        body_text=body_text,
                        dom_form_summary=dom_form_summary,
                        login_surface_summary=login_surface_summary,
                    )
                    if fallback_tool_plan:
                        fallback_observation = self._execute_ai_pen_tool_plan(
                            runtime=runtime,
                            runtime_context=runtime_context,
                            tool_plan=fallback_tool_plan,
                            target_url=target_url,
                            evidence_seed=evidence_seed,
                            js_api_targets=js_api_targets,
                        )
                        tool_calls = len(list(runtime.tool_calls or []))
                        tool_trace_parts.extend(list(fallback_observation.get("trace_parts", []) or []))
                        probe_status = int(fallback_observation.get("probe_status", 0) or 0) or probe_status
                        probe_url = str(fallback_observation.get("probe_url", "") or "") or probe_url
                        probe_headers = dict(fallback_observation.get("probe_headers") or {}) or probe_headers
                        probe_body_excerpt = str(fallback_observation.get("probe_body_excerpt", "") or "") or probe_body_excerpt
                        probe_body_md5 = str(fallback_observation.get("probe_body_md5", "") or "") or probe_body_md5
                        idor_probe_responses.extend(
                            [
                                dict(item or {})
                                for item in list(fallback_observation.get("responses", []) or [])
                                if isinstance(item, dict) and str(item.get("tool") or "").strip() == "idor_probe"
                            ]
                        )
                        evidence_hit = bool(fallback_observation.get("evidence_hit")) or evidence_hit
                        api_doc_hit = bool(fallback_observation.get("api_doc_hit")) or api_doc_hit
                        api_doc_hit_url = str(fallback_observation.get("api_doc_hit_url", "") or "") or api_doc_hit_url
                        if isinstance(fallback_observation.get("api_doc_summary"), dict) and fallback_observation.get("api_doc_summary"):
                            api_doc_summary = dict(fallback_observation.get("api_doc_summary") or {})
                        if isinstance(fallback_observation.get("api_surface_summary"), dict) and fallback_observation.get("api_surface_summary"):
                            api_surface_summary = dict(fallback_observation.get("api_surface_summary") or {})
                        graphql_hit = bool(fallback_observation.get("graphql_hit")) or graphql_hit
                        graphql_hit_url = str(fallback_observation.get("graphql_hit_url", "") or "") or graphql_hit_url
                        if isinstance(fallback_observation.get("graphql_summary"), dict) and fallback_observation.get("graphql_summary"):
                            graphql_summary = dict(fallback_observation.get("graphql_summary") or {})
                        api_doc_probe_count += self._safe_int_value(
                            dict(fallback_observation.get("tool_counts") or {}).get("api_doc_probe"),
                            0,
                        )
                        config_probe_count += self._safe_int_value(
                            dict(fallback_observation.get("tool_counts") or {}).get("config_probe"),
                            0,
                        )
                        idor_probe_count += self._safe_int_value(
                            dict(fallback_observation.get("tool_counts") or {}).get("idor_probe"),
                            0,
                        )
                        config_exposure_hit = bool(fallback_observation.get("config_exposure_hit")) or config_exposure_hit
                        config_exposure_url = str(fallback_observation.get("config_exposure_url", "") or "") or config_exposure_url
                        config_exposure_summary = str(fallback_observation.get("config_exposure_summary", "") or "") or config_exposure_summary
                        websocket_upgrade_hit = bool(fallback_observation.get("websocket_upgrade_hit")) or websocket_upgrade_hit
                        websocket_upgrade_hint = bool(fallback_observation.get("websocket_upgrade_hint")) or websocket_upgrade_hint
                        credential_probe_count += self._safe_int_value(
                            dict(fallback_observation.get("tool_counts") or {}).get("credential_probe"),
                            0,
                        )
                        login_success_hit = bool(fallback_observation.get("login_success_hit")) or login_success_hit
                        login_success_reason = str(fallback_observation.get("login_success_reason", "") or "") or login_success_reason
                        login_blocked_reason = str(fallback_observation.get("login_blocked_reason", "") or "") or login_blocked_reason
                        if (not probe_error) and str(fallback_observation.get("error", "") or "").strip():
                            probe_error = self._clip_text(fallback_observation.get("error", ""), self.AI_PEN_TEST_ERROR_MAX)
                        payload_text = str(payload or "").strip().lower()
                        if payload_text and payload_type in payload_probe_types and len(payload_text) >= 6 and payload_text in str(probe_body_excerpt or "").lower():
                            payload_reflect_hit = True
                        logger.info(
                            "task_id:{} ai_pen verify fallback_plan target:{} payload_type:{} probe_status:{} "
                            "tool_counts:{} evidence_hit:{} api_doc_hit:{} graphql_hit:{} idor_resp:{} error:{}".format(
                                self.task_id,
                                target_url[:180],
                                payload_type,
                                probe_status,
                                self._clip_text(
                                    json.dumps(dict(fallback_observation.get("tool_counts") or {}), ensure_ascii=False, sort_keys=True),
                                    180,
                                ),
                                int(bool(evidence_hit)),
                                int(bool(api_doc_hit)),
                                int(bool(graphql_hit)),
                                len(idor_probe_responses),
                                self._clip_text(probe_error, 120) if probe_error else "-",
                            )
                        )
                    elif payload_type == "weak_password_probe" and login_probe_context:
                        if bool(login_probe_context.get("captcha_required")):
                            tool_trace_parts.append("weak_password_probe(skip_captcha)")
                        else:
                            tool_trace_parts.append("weak_password_probe(skip_no_credential)")
                    elif payload_type == "idor_probe":
                        tool_trace_parts.append("idor_probe(skip_no_mutation)")
                    elif payload_type == "api_doc_probe":
                        tool_trace_parts.append("api_doc_probe(skip_no_target)")
                    elif payload_type == "graphql_probe":
                        tool_trace_parts.append("graphql_probe(skip_no_target)")
                    elif payload_type == "websocket_probe":
                        tool_trace_parts.append("websocket_probe(skip_invalid_target)")
                    elif payload_type == "weak_password_probe":
                        tool_trace_parts.append("weak_password_probe(skip_no_login_form)")

            decision = "needs_manual_review"
            confidence = 0.56
            reason = "目标可访问，已完成 HTTP 验证"
            xss_popup_proof = False
            sqli_proof_type = ""
            weak_password_login_proof = False
            if is_xss_case:
                xss_popup_proof = self._has_xss_popup_proof(payload, base_body_excerpt, probe_body_excerpt)
            if is_sqli_case:
                sqli_proof_type = self._detect_sqli_proof_type(base_body_excerpt, probe_body_excerpt or base_body_excerpt)
            if payload_type == "idor_probe" and idor_probe_responses:
                best_idor_score = -1
                for response_item in idor_probe_responses:
                    probe_url_text = str(response_item.get("url") or "").strip()
                    matching_target = None
                    for target in idor_probe_targets:
                        if str(target.get("url") or "").strip() == probe_url_text:
                            matching_target = target
                            break
                    candidate_summary = self._build_idor_diff_summary(
                        base_status=status_code,
                        base_body=base_body_excerpt,
                        probe_status=self._safe_int_value(response_item.get("status_code"), 0),
                        probe_body=str(response_item.get("body_text", "") or ""),
                        probe_target=matching_target or {},
                    )
                    candidate_score = self._score_idor_diff_summary(candidate_summary)
                    if candidate_score > best_idor_score:
                        best_idor_score = candidate_score
                        idor_diff_summary = dict(candidate_summary or {})
                        probe_status = self._safe_int_value(response_item.get("status_code"), 0) or probe_status
                        probe_url = probe_url_text or probe_url
                        probe_headers = dict(response_item.get("headers") or {}) if isinstance(response_item.get("headers"), dict) else probe_headers
                        probe_body_excerpt = str(response_item.get("body_text", "") or "") or probe_body_excerpt
                        probe_body_md5 = str(response_item.get("body_md5", "") or "") or probe_body_md5
                idor_diff_hit = bool(idor_diff_summary.get("material_change"))
                logger.info(
                    "task_id:{} ai_pen idor summary target:{} probes:{} best_score:{} diff_hit:{} summary:{}".format(
                        self.task_id,
                        target_url[:180],
                        len(idor_probe_responses),
                        best_idor_score,
                        int(bool(idor_diff_hit)),
                        self._clip_text(self._format_idor_diff_summary_text(idor_diff_summary), 220) or "-",
                    )
                )
            if is_weak_password_case:
                if credential_probe_count > 0 and not login_success_hit:
                    login_analysis = self._analyze_ai_pen_login_success(
                        login_url=str(login_probe_context.get("login_url") or target_url),
                        response_summary={
                            "url": probe_url or target_url,
                            "headers": probe_headers,
                            "body_text": probe_body_excerpt,
                        },
                        base_body_text=base_body_excerpt,
                    )
                    login_success_hit = bool(login_analysis.get("success")) or login_success_hit
                    login_success_reason = str(login_analysis.get("reason", "") or "") or login_success_reason
                    if (not login_blocked_reason) and bool(login_analysis.get("blocked")):
                        login_blocked_reason = str(login_analysis.get("reason", "") or "")

                weak_password_login_proof = bool(login_success_hit) or self._has_weak_password_login_proof(
                    evidence_seed,
                    base_body_excerpt,
                    probe_body_excerpt,
                )

            if is_xss_case and xss_popup_proof:
                decision = "verified"
                confidence = 0.90
                reason = "XSS 探针命中可执行弹窗特征，具备可利用证据"
            elif is_xss_case and payload_reflect_hit:
                decision = "likely_false_positive"
                confidence = 0.68
                reason = "仅发现 payload 回显，缺少可触发弹窗的执行证据"
            elif is_xss_case and self._is_js_asset_target(target_url, headers=header_obj):
                decision = "likely_false_positive"
                confidence = 0.74
                reason = "目标为静态 JS 资源，当前未验证到可执行弹窗链路"
            elif is_weak_password_case and weak_password_login_proof:
                decision = "verified"
                confidence = 0.91
                reason = login_success_reason or "命中账号/口令与登录成功证据，弱口令可复现"
            elif is_weak_password_case and login_blocked_reason:
                decision = "needs_manual_review"
                confidence = 0.64
                reason = login_blocked_reason
            elif is_weak_password_case and bool(login_probe_context.get("captcha_required")) and credential_probe_count < 1:
                decision = "needs_manual_review"
                confidence = 0.62
                reason = "登录入口存在验证码或风控线索，默认未执行弱口令验证"
            elif is_weak_password_case and credential_probe_count < 1:
                decision = "needs_manual_review"
                confidence = 0.60
                reason = "未识别到可稳定复用的登录表单/认证入口，当前未执行默认口令验证"
            elif is_weak_password_case:
                decision = "likely_false_positive"
                confidence = 0.70
                reason = "默认口令验证未命中登录成功信号，当前不判定为可利用弱口令"
            elif is_sqli_case and sqli_proof_type == "error_based":
                decision = "verified"
                confidence = 0.88
                reason = "探针触发 SQL 报错注入特征，可复现"
            elif is_sqli_case and (probe_body_md5 and base_body_md5 and probe_body_md5 != base_body_md5):
                decision = "needs_manual_review"
                confidence = 0.72
                reason = "SQL 探针前后响应差异明显，疑似布尔/时间盲注，需人工复核"
            elif evidence_hit and not (is_xss_case or is_sqli_case or is_weak_password_case):
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
                api_surface_summary_text = self._format_api_surface_summary_text(api_surface_summary)
                if api_surface_summary_text:
                    reason = "{}；接口结构：{}".format(reason, api_surface_summary_text)
            elif payload_type == "graphql_probe" and graphql_hit:
                decision = "verified"
                confidence = 0.84
                reason = "发现可访问 GraphQL 入口 {}".format((graphql_hit_url or target_url)[:180])
                graphql_summary_text = self._format_graphql_summary_text(graphql_summary)
                if graphql_summary_text:
                    reason = "{}；GraphQL结构：{}".format(reason, graphql_summary_text)
            elif config_exposure_hit:
                decision = "verified"
                confidence = 0.87
                reason = "发现公开高价值配置/环境端点 {}".format((config_exposure_url or target_url)[:180])
                if config_exposure_summary:
                    reason = "{}；配置摘要：{}".format(reason, config_exposure_summary)
            elif payload_reflect_hit:
                decision = "needs_manual_review"
                confidence = 0.74
                reason = "Payload 在响应中回显，疑似存在可利用注入点"
            elif payload_type == "idor_probe" and idor_diff_hit:
                decision = "needs_manual_review"
                confidence = 0.80 if list(idor_diff_summary.get("sensitive_hits", []) or []) else 0.76
                reason = "对象引用参数变异后响应差异明显，疑似存在越权风险"
                idor_summary_text = self._format_idor_diff_summary_text(idor_diff_summary)
                if idor_summary_text:
                    reason = "{}；差异摘要：{}".format(reason, idor_summary_text)
            elif payload_type != "idor_probe" and probe_body_md5 and base_body_md5 and probe_body_md5 != base_body_md5:
                decision = "needs_manual_review"
                confidence = 0.66
                reason = "Payload 探针前后响应差异明显，建议人工复核"
            elif payload_type == "idor_probe" and idor_probe_count > 0:
                decision = "likely_false_positive"
                confidence = 0.60
                reason = "已尝试 {} 个对象引用变异，暂未观察到稳定的访问控制差异".format(idor_probe_count)
            elif payload_type == "api_doc_probe" and api_doc_probe_count > 0 and not api_doc_hit:
                decision = "likely_false_positive"
                confidence = 0.60
                reason = "已探测 {} 个常见 API 文档端点，暂未命中暴露特征".format(api_doc_probe_count)
            elif payload_type == "config_probe" and config_probe_count > 0 and not config_exposure_hit:
                decision = "likely_false_positive"
                confidence = 0.60
                reason = "已探测 {} 个配置/环境端点，暂未命中高价值暴露特征".format(config_probe_count)
            elif payload_type == "graphql_probe":
                decision = "likely_false_positive"
                confidence = 0.60
                reason = "已尝试 GraphQL 最小探针，暂未观察到稳定的 GraphQL 入口响应"
            elif status_code >= 500 or status_code == 404:
                decision = "likely_false_positive"
                confidence = 0.66
                reason = "目标返回异常状态码 {}，当前证据不足".format(status_code)
            elif status_code in (401, 403):
                decision = "needs_manual_review"
                confidence = 0.48
                reason = "目标受访问控制保护（{}），建议结合登录态复核".format(status_code)

            agent_decision = self._normalize_ai_pen_decision(agent_loop_final_decision.get("decision"), default_value="")
            agent_confidence = self._clamp_ai_pen_confidence(agent_loop_final_decision.get("confidence"), 0.55)
            agent_reason = self._clip_text(agent_loop_final_decision.get("reason", ""), self.AI_PEN_TEST_REASON_MAX)
            agent_proof_guard_reason = self._get_ai_pen_verified_proof_guard_reason(
                risk_type_text=risk_type_text,
                payload_type_text=payload_type,
                xss_popup_proof=xss_popup_proof,
                weak_password_login_proof=weak_password_login_proof,
                sqli_proof_type=sqli_proof_type,
            )
            if decision == "needs_manual_review" and agent_decision == "verified" and agent_confidence >= 0.9 and not agent_proof_guard_reason:
                decision = "verified"
                confidence = max(confidence, min(0.94, agent_confidence * 0.9))
            elif decision == "needs_manual_review" and agent_decision in {"needs_manual_review", "likely_false_positive"}:
                decision = agent_decision
                confidence = max(confidence, min(0.88, agent_confidence))
            if agent_reason:
                reason = "{}；Agent裁决：{}".format(reason, agent_reason) if reason else "Agent裁决：{}".format(agent_reason)
            if agent_decision == "verified" and agent_proof_guard_reason:
                reason = "{}；{}".format(reason, agent_proof_guard_reason).strip("；")

            js_context_summary = {}
            evidence_snippet = evidence_seed
            if not evidence_snippet:
                evidence_source = probe_body_excerpt or base_body_excerpt
                evidence_snippet = self._clip_text(evidence_source, self.AI_PEN_TEST_EVIDENCE_MAX)
            if payload_type == "api_doc_probe" or js_api_targets:
                api_surface_summary_text = self._format_api_surface_summary_text(api_surface_summary)
                if api_surface_summary_text:
                    evidence_snippet = self._clip_text(api_surface_summary_text, self.AI_PEN_TEST_EVIDENCE_MAX)

            js_context_ret = self._analyze_ai_pen_js_context(
                target_url=target_url,
                body_text=body_text,
                headers=header_obj,
                risk_type=risk_type,
                payload_type=payload_type,
                evidence_seed=evidence_seed,
            )
            if isinstance(js_context_ret, dict) and js_context_ret:
                js_trace = str(js_context_ret.get("tool_trace", "") or "").strip()
                if js_trace:
                    tool_trace_parts.append(js_trace)
                js_context_snippet = self._clip_text(
                    js_context_ret.get("context_snippet", ""),
                    self.AI_PEN_TEST_EVIDENCE_MAX,
                )
                js_context_summary = dict(js_context_ret.get("js_context_summary") or {}) if isinstance(js_context_ret.get("js_context_summary"), dict) else {}
                if js_context_snippet:
                    evidence_snippet = js_context_snippet
                js_reason = self._clip_text(js_context_ret.get("reason", ""), self.AI_PEN_TEST_REASON_MAX)
                js_decision = self._normalize_ai_pen_decision(js_context_ret.get("decision"), default_value="")
                if js_decision:
                    if js_reason:
                        if decision == "verified" and js_decision in {"likely_false_positive", "needs_manual_review"}:
                            reason = "目标可访问，已完成 HTTP 验证；JS上下文：{}".format(js_reason)
                        else:
                            reason = "{}；JS上下文：{}".format(reason, js_reason) if reason else "JS上下文：{}".format(js_reason)
                    decision = js_decision
                    confidence = self._clamp_ai_pen_confidence(js_context_ret.get("confidence"), confidence)
                elif js_reason:
                    reason = "{}；JS上下文：{}".format(reason, js_reason) if reason else "JS上下文：{}".format(js_reason)

            file_context_ret = self._analyze_ai_pen_file_context(
                target_url=target_url,
                body_text=body_text,
                headers=header_obj,
                risk_type=risk_type,
                payload_type=payload_type,
                evidence_seed=evidence_seed,
                api_surface_summary=api_surface_summary,
                browser_surface_summary=browser_surface_summary,
                runtime_api_calls=runtime_api_calls,
                dom_form_summary=dom_form_summary,
            )
            if isinstance(file_context_ret, dict) and file_context_ret:
                file_trace = str(file_context_ret.get("tool_trace", "") or "").strip()
                if file_trace:
                    tool_trace_parts.append(file_trace)
                file_context_snippet = self._clip_text(
                    file_context_ret.get("context_snippet", ""),
                    self.AI_PEN_TEST_EVIDENCE_MAX,
                )
                if file_context_snippet:
                    evidence_snippet = file_context_snippet
                file_reason = self._clip_text(file_context_ret.get("reason", ""), self.AI_PEN_TEST_REASON_MAX)
                if file_reason:
                    reason = "{}；文件处理上下文：{}".format(reason, file_reason) if reason else "文件处理上下文：{}".format(file_reason)
                file_decision = self._normalize_ai_pen_decision(file_context_ret.get("decision"), default_value="")
                if file_decision:
                    decision = file_decision
                    confidence = self._clamp_ai_pen_confidence(file_context_ret.get("confidence"), confidence)

            login_context_ret = self._analyze_ai_pen_login_surface(
                target_url=target_url,
                risk_type=risk_type,
                login_surface_summary=login_surface_summary,
            )
            if isinstance(login_context_ret, dict) and login_context_ret:
                login_trace = str(login_context_ret.get("tool_trace", "") or "").strip()
                if login_trace:
                    tool_trace_parts.append(login_trace)
                login_context_snippet = self._clip_text(
                    login_context_ret.get("context_snippet", ""),
                    self.AI_PEN_TEST_EVIDENCE_MAX,
                )
                if login_context_snippet:
                    evidence_snippet = login_context_snippet
                login_reason = self._clip_text(login_context_ret.get("reason", ""), self.AI_PEN_TEST_REASON_MAX)
                if login_reason:
                    reason = "{}；登录面上下文：{}".format(reason, login_reason) if reason else "登录面上下文：{}".format(login_reason)
                login_decision = self._normalize_ai_pen_decision(login_context_ret.get("decision"), default_value="")
                if login_decision:
                    decision = login_decision
                    confidence = self._clamp_ai_pen_confidence(login_context_ret.get("confidence"), confidence)

            if probe_error:
                reason = "{}；探针异常：{}".format(reason, probe_error)
            reason = self._clip_text(reason, self.AI_PEN_TEST_REASON_MAX)

            verification_step = "http_fetch_replay"
            if agent_loop_enable and agent_loop_stop_reason:
                verification_step = "mcp_agent_loop"
            elif mcp_enable and max_tool_calls > 1 and payload_type == "idor_probe":
                verification_step = "mcp_idor_probe"
            elif mcp_enable and max_tool_calls > 1 and payload_type == "api_doc_probe":
                verification_step = "mcp_api_doc_probe"
            elif mcp_enable and max_tool_calls > 1 and payload_type == "graphql_probe":
                verification_step = "mcp_graphql_probe"
            elif mcp_enable and max_tool_calls > 1 and payload_type == "jwt_probe":
                verification_step = "mcp_jwt_probe"
            elif mcp_enable and max_tool_calls > 1 and payload_type == "websocket_probe":
                verification_step = "mcp_websocket_probe"
            elif mcp_enable and max_tool_calls > 1 and payload_type == "upload_probe":
                verification_step = "mcp_file_probe"
            elif mcp_enable and max_tool_calls > 1 and payload_type == "config_probe":
                verification_step = "mcp_config_probe"
            elif mcp_enable and max_tool_calls > 1:
                verification_step = "mcp_http_probe"

            response_hash_diff = base_body_md5
            if probe_body_md5:
                response_hash_diff = "base:{} | probe:{}".format(base_body_md5[:16], probe_body_md5[:16])
            if payload_type == "api_doc_probe" and api_doc_hit_url:
                response_hash_diff = "{} | api_doc:{}".format(response_hash_diff, api_doc_hit_url[:120]).strip(" |")
            api_surface_summary_text = self._format_api_surface_summary_text(api_surface_summary)
            if api_surface_summary_text:
                response_hash_diff = "{} | {}".format(response_hash_diff, api_surface_summary_text[:180]).strip(" |")

            external_ret = self._run_ai_pen_external_tools(
                target_url=target_url,
                risk_type=risk_type,
                risk_name=risk_name,
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

            if is_sqli_case and bool(external_ret.get("tool_hit")) and decision == "verified":
                sqli_proof_type = "external_tool"

            proof_guard_reason = self._get_ai_pen_verified_proof_guard_reason(
                risk_type_text=risk_type_text,
                payload_type_text=payload_type,
                xss_popup_proof=xss_popup_proof,
                weak_password_login_proof=weak_password_login_proof,
                sqli_proof_type=sqli_proof_type,
            )
            if decision == "verified" and proof_guard_reason:
                decision = "needs_manual_review"
                confidence = max(0.62, min(0.86, confidence))
                reason = "{}；{}".format(reason, proof_guard_reason).strip("；")

            logger.info(
                "task_id:{} ai_pen verify done target:{} payload_type:{} decision:{} confidence:{:.4f} step:{} http_status:{} "
                "tool_calls:{} idor_probe_count:{} api_doc_probe_count:{} config_probe_count:{} external_hit:{} stop_reason:{} reason:{}".format(
                    self.task_id,
                    target_url[:180],
                    payload_type,
                    decision,
                    float(confidence or 0.0),
                    verification_step,
                    probe_status or status_code,
                    len(list(runtime.tool_calls or [])),
                    idor_probe_count,
                    api_doc_probe_count,
                    config_probe_count,
                    int(bool(external_ret.get("tool_hit"))),
                    agent_loop_stop_reason or "-",
                    self._clip_text(reason, 220),
                )
            )

            return _with_runtime_artifacts({
                "status": "ok",
                "decision": decision,
                "confidence": confidence,
                "reason": reason,
                "risk_type": risk_type_text,
                "payload_type": payload_type,
                "payload": payload,
                "verification_step": verification_step,
                "evidence_snippet": evidence_snippet,
                "http_status": probe_status or status_code,
                "response_hash_diff": response_hash_diff,
                "xss_popup_proof": xss_popup_proof,
                "sqli_proof_type": sqli_proof_type,
                "weak_password_login_proof": weak_password_login_proof,
                "api_doc_summary": api_doc_summary if isinstance(api_doc_summary, dict) else {},
                "api_surface_summary": api_surface_summary if isinstance(api_surface_summary, dict) else {},
                "browser_surface_summary": browser_surface_summary,
                "runtime_api_calls": runtime_api_calls,
                "dom_form_summary": dom_form_summary,
                "js_context_summary": js_context_summary if isinstance(js_context_summary, dict) else {},
                "task_ai_pen_graph_summary": task_ai_pen_graph_summary,
                "task_ai_pen_graph_context": task_ai_pen_graph_context,
                "login_surface_summary": login_surface_summary,
                "route_hint": route_hint,
                "capability_profile": capability_profile if isinstance(capability_profile, dict) else {},
                "tool_trace": " | ".join(tool_trace_parts)[:500],
                "external_tool_runs": list(external_ret.get("tool_runs", []) or [])[: self.AI_PEN_EXTERNAL_RESULT_MAX],
                "external_tool_hit": bool(external_ret.get("tool_hit")),
            }, tool_trace_parts, "ok", decision, runtime_result=runtime.build_result())
        except Exception as e:
            logger.warning(
                "task_id:{} ai_pen verify exception target:{} payload_type:{} err:{}".format(
                    self.task_id,
                    target_url[:180],
                    str(payload_type or "").strip()[:48],
                    self._clip_text(e, self.AI_PEN_TEST_ERROR_MAX),
                )
            )
            return _with_runtime_artifacts({
                "status": "error",
                "decision": "needs_manual_review",
                "confidence": 0.30,
                "reason": "HTTP 验证失败: {}".format(self._clip_text(e, self.AI_PEN_TEST_ERROR_MAX)),
                "risk_type": risk_type_text,
                "payload_type": payload_type,
                "payload": payload,
                "verification_step": "http_fetch_replay",
                "evidence_snippet": evidence_seed,
                "http_status": 0,
                "response_hash_diff": "",
                "xss_popup_proof": False,
                "sqli_proof_type": "",
                "weak_password_login_proof": False,
                "api_doc_summary": {},
                "api_surface_summary": {},
                "browser_surface_summary": browser_surface_summary,
                "runtime_api_calls": runtime_api_calls,
                "dom_form_summary": dom_form_summary,
                "js_context_summary": {},
                "task_ai_pen_graph_summary": task_ai_pen_graph_summary,
                "task_ai_pen_graph_context": task_ai_pen_graph_context,
                "login_surface_summary": login_surface_summary,
                "route_hint": route_hint,
                "capability_profile": capability_profile if isinstance(capability_profile, dict) else {},
                "tool_trace": "http_fetch(error,url={})".format(target_url[:220]),
                "external_tool_runs": [],
                "external_tool_hit": False,
            }, ["http_fetch(error,url={})".format(target_url[:220])], "error", "needs_manual_review", runtime_result=runtime.build_result())

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
            candidate["knowledge_hit_product_labels"] = list(hit_info.get("hit_product_labels", []) or [])
            candidate["knowledge_hit_vuln_types"] = list(hit_info.get("hit_vuln_types", []) or [])
            candidate["knowledge_hit_entry_paths"] = list(hit_info.get("hit_entry_paths", []) or [])
            candidate["knowledge_hit_verify_actions"] = list(hit_info.get("hit_verify_actions", []) or [])
            candidate["knowledge_hit_record_refs"] = list(hit_info.get("hit_record_refs", []) or [])
            browser_intel = self._collect_ai_pen_browser_intel(candidate)
            candidate["browser_surface_summary"] = dict(browser_intel.get("browser_surface_summary") or {}) if isinstance(browser_intel.get("browser_surface_summary"), dict) else {}
            candidate["runtime_api_calls"] = list(browser_intel.get("runtime_api_calls", []) or [])[:16]
            candidate["dom_form_summary"] = list(browser_intel.get("dom_form_summary", []) or [])[:8]
            candidate["task_ai_pen_graph_summary"] = self._build_ai_pen_graph_summary(candidate)
            candidate["login_surface_summary"] = self._build_ai_pen_login_surface_summary(candidate)
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

        # 有知识命中的候选优先进入执行窗口；同分时继续按高价值与状态优先级排序。
        candidates.sort(
            key=lambda item: (
                -int(item.get("knowledge_score", 0) or 0),
                -int(item.get("priority_score", 0) or 0),
                str(item.get("source_collection", "")),
                str(item.get("source_id", "")),
            )
        )
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
        task_ai_pen_graph_context = self._get_task_ai_pen_graph_context(selected_candidates)
        for candidate in selected_candidates:
            candidate["task_ai_pen_graph_context"] = dict(task_ai_pen_graph_context or {})
        selected_preview = []
        for candidate in selected_candidates[:6]:
            selected_preview.append(
                "{}:{}:{}@{}".format(
                    str(candidate.get("source_collection", "") or "").strip()[:16] or "unknown",
                    str(candidate.get("risk_type", "") or "").strip()[:18] or "unknown",
                    str(candidate.get("payload_type", "") or "").strip()[:18] or "auto",
                    str(candidate.get("target") or candidate.get("vuln_url") or "").strip()[:80],
                )
            )
        logger.info(
            "task_id:{} ai_pen candidate window total:{} selected:{} max_cases:{} preview:{}".format(
                self.task_id,
                len(candidates),
                len(selected_candidates),
                max_cases,
                self._clip_text(",".join(selected_preview) or "-", 420),
            )
        )

        saved_count = 0
        verified_count = 0
        false_positive_count = 0
        error_count = 0
        external_tool_runs_total = 0
        external_tool_hit_count = 0

        collection = utils.conn_db("ai_pen_test_result")
        for candidate_index, candidate in enumerate(selected_candidates, start=1):
            candidate_target = str(candidate.get("vuln_url") or candidate.get("target") or "").strip()
            logger.info(
                "task_id:{} ai_pen candidate start {}/{} source={}:{} target:{} risk_type:{} risk_name:{} "
                "priority:{} knowledge_score:{}".format(
                    self.task_id,
                    candidate_index,
                    len(selected_candidates),
                    str(candidate.get("source_collection", "") or "").strip()[:24] or "-",
                    str(candidate.get("source_id", "") or "").strip()[:32] or "-",
                    candidate_target[:180],
                    str(candidate.get("risk_type", "") or "").strip()[:32] or "-",
                    str(candidate.get("risk_name", "") or "").strip()[:48] or "-",
                    self._safe_int_value(candidate.get("priority_score"), 0),
                    self._safe_int_value(candidate.get("knowledge_score"), 0),
                )
            )
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
            ai_plan_status = str(ai_plan_result.get("status", "skipped") or "skipped").strip().lower()
            ai_plan_message = self._clip_text(ai_plan_result.get("message", ""), 120)
            ai_plan_output = ai_plan_result.get("output") if isinstance(ai_plan_result.get("output"), dict) else {}
            ai_plan_tool_steps = len(list(ai_plan_output.get("tool_plan", []) or []))
            logger.info(
                "task_id:{} ai_pen candidate planner {}/{} status:{} ok:{} payload_type:{} tool_steps:{} message:{}".format(
                    self.task_id,
                    candidate_index,
                    len(selected_candidates),
                    ai_plan_status,
                    int(bool(ai_plan_result.get("ok"))),
                    str(ai_plan_output.get("payload_type", "") or "").strip()[:32] or "-",
                    ai_plan_tool_steps,
                    ai_plan_message or "-",
                )
            )

            verify_result = self._verify_ai_pen_candidate(
                candidate,
                mcp_settings=runtime_settings,
                ai_plan=ai_plan_output,
                planner_context={
                    "ai_config": ai_config,
                    "prompt_content": ai_prompt_content,
                },
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
                logger.warning(
                    "task_id:{} ai_pen candidate skip save {}/{} source={}:{} missing source identifier".format(
                        self.task_id,
                        candidate_index,
                        len(selected_candidates),
                        source_collection[:24] or "-",
                        str(candidate.get("source_id", "") or "").strip()[:32] or "-",
                    )
                )
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
                "request_method": str(verify_result.get("request_method", "") or "").strip(),
                "request_url": str(verify_result.get("request_url", "") or "").strip(),
                "request_path": str(verify_result.get("request_path", "") or "").strip(),
                "request_headers": dict(verify_result.get("request_headers") or {}) if isinstance(verify_result.get("request_headers"), dict) else {},
                "request_body": self._clip_multiline_text(verify_result.get("request_body", ""), self.AI_PEN_TEST_REQUEST_PACKET_MAX),
                "request_packet": self._clip_multiline_text(verify_result.get("request_packet", ""), self.AI_PEN_TEST_REQUEST_PACKET_MAX),
                "verification_step": str(verify_result.get("verification_step", "") or "").strip(),
                "evidence_snippet": str(verify_result.get("evidence_snippet", "") or "").strip(),
                "http_status": int(verify_result.get("http_status", 0) or 0),
                "response_hash_diff": str(verify_result.get("response_hash_diff", "") or "").strip(),
                "api_doc_summary": dict(verify_result.get("api_doc_summary") or {}) if isinstance(verify_result.get("api_doc_summary"), dict) else {},
                "api_surface_summary": dict(verify_result.get("api_surface_summary") or {}) if isinstance(verify_result.get("api_surface_summary"), dict) else {},
                "browser_surface_summary": dict(verify_result.get("browser_surface_summary") or {}) if isinstance(verify_result.get("browser_surface_summary"), dict) else {},
                "runtime_api_calls": list(verify_result.get("runtime_api_calls", []) or [])[:16],
                "dom_form_summary": list(verify_result.get("dom_form_summary", []) or [])[:8],
                "js_context_summary": dict(verify_result.get("js_context_summary") or {}) if isinstance(verify_result.get("js_context_summary"), dict) else {},
                "task_ai_pen_graph_summary": dict(verify_result.get("task_ai_pen_graph_summary") or {}) if isinstance(verify_result.get("task_ai_pen_graph_summary"), dict) else {},
                "task_ai_pen_graph_context": dict(verify_result.get("task_ai_pen_graph_context") or {}) if isinstance(verify_result.get("task_ai_pen_graph_context"), dict) else {},
                "login_surface_summary": dict(verify_result.get("login_surface_summary") or {}) if isinstance(verify_result.get("login_surface_summary"), dict) else {},
                "route_hint": str(verify_result.get("route_hint", "") or "").strip(),
                "capability_profile": dict(verify_result.get("capability_profile") or {}) if isinstance(verify_result.get("capability_profile"), dict) else {},
                "decision": decision,
                "confidence": float("{:.4f}".format(confidence)),
                "reason": str(verify_result.get("reason", "") or "").strip(),
                "status": status,
                "model": record_model,
                "provider": record_provider,
                "profile": record_profile,
                "knowledge_hit_tokens": list(candidate.get("knowledge_hit_tokens", []) or []),
                "knowledge_hit_samples": list(candidate.get("knowledge_hit_samples", []) or []),
                "knowledge_hit_product_labels": list(candidate.get("knowledge_hit_product_labels", []) or []),
                "knowledge_hit_vuln_types": list(candidate.get("knowledge_hit_vuln_types", []) or []),
                "knowledge_hit_entry_paths": list(candidate.get("knowledge_hit_entry_paths", []) or []),
                "knowledge_hit_verify_actions": list(candidate.get("knowledge_hit_verify_actions", []) or []),
                "knowledge_hit_record_refs": list(candidate.get("knowledge_hit_record_refs", []) or [])[:4],
                "tool_trace": str(verify_result.get("tool_trace", "") or "").strip(),
                "agent_trace": list(verify_result.get("agent_trace", []) or [])[:16],
                "tool_calls": list(verify_result.get("tool_calls", []) or [])[:16],
                "tool_results": list(verify_result.get("tool_results", []) or [])[:16],
                "stop_reason": str(verify_result.get("stop_reason", "") or "").strip(),
                "budget_used": dict(verify_result.get("budget_used") or {}) if isinstance(verify_result.get("budget_used"), dict) else {},
                "runtime_version": str(verify_result.get("runtime_version", "") or "").strip(),
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
                "ai_plan_tool_plan": list(verify_result.get("ai_plan_tool_plan", []) or [])[:8],
                "ai_plan_request": self._clip_text(ai_plan_result.get("request_text", ""), 2600),
                "ai_plan_reply": self._clip_text(ai_plan_result.get("reply_text", ""), 2600),
                "ai_plan_messages": list(ai_plan_result.get("messages", []) or [])[:8],
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
            logger.info(
                "task_id:{} ai_pen candidate done {}/{} source={}:{} decision:{} status:{} confidence:{:.4f} "
                "verification_step:{} payload_type:{} http_status:{} tool_calls:{} external_hit:{} ai_plan_status:{}".format(
                    self.task_id,
                    candidate_index,
                    len(selected_candidates),
                    source_collection[:24],
                    str(source_id)[:32],
                    decision,
                    status,
                    confidence,
                    str(verify_result.get("verification_step", "") or "").strip()[:48] or "-",
                    str(verify_result.get("payload_type", "") or "").strip()[:32] or "-",
                    self._safe_int_value(verify_result.get("http_status"), 0),
                    len(list(verify_result.get("tool_calls", []) or [])),
                    int(bool(external_tool_hit)),
                    ai_plan_status,
                )
            )

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
        urls = [url for url in get_url_by_task_id(self.task_id) if self._url_in_task_scope(url)]
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

    def _extract_scope_urls_from_wih_record(self, record) -> list:
        record_type = str(getattr(record, "recordType", "") or "").strip().lower()
        content = str(getattr(record, "content", "") or "").strip()
        source = str(getattr(record, "source", "") or "").strip()
        site = str(getattr(record, "site", "") or "").strip()
        candidates = []
        for value in (content, source, site):
            if self._is_http_url(value) and value not in candidates:
                candidates.append(value)

        if record_type == "page_form":
            match = re.match(r"^\s*([A-Za-z]+)\s+(\S+?)(?:\s+\[([^\]]*)\])?\s*$", content)
            if match:
                action_url = str(match.group(2) or "").strip()
                if self._is_http_url(action_url) and action_url not in candidates:
                    candidates.append(action_url)
        elif record_type == "api_doc_endpoint":
            match = re.match(r"^\s*([A-Za-z]+)\s+(\S+)\s*$", content)
            if match:
                endpoint_url = str(match.group(2) or "").strip()
                if self._is_http_url(endpoint_url) and endpoint_url not in candidates:
                    candidates.append(endpoint_url)

        return candidates

    def _wih_record_in_task_scope(self, record) -> bool:
        for value in self._extract_scope_urls_from_wih_record(record):
            if not self._url_in_task_scope(value):
                return False

        record_type = str(getattr(record, "recordType", "") or "").strip().lower()
        content = str(getattr(record, "content", "") or "").strip()
        if record_type == "domain" and content:
            return self._host_in_task_scope(content)
        return True

    def _scan_result_in_task_scope(self, result: dict, target_keys=None) -> bool:
        item = result if isinstance(result, dict) else {}
        keys = list(target_keys or ("target", "url", "vuln_url"))
        for key in keys:
            value = str(item.get(key, "") or "").strip()
            if not value:
                continue
            if self._is_http_url(value):
                return self._url_in_task_scope(value)
            return self._host_in_task_scope(value)
        return False

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
        if not self._wih_record_in_task_scope(record):
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
        if self._is_http_url(target) and not self._url_in_task_scope(target):
            return None
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
            if not self._wih_record_in_task_scope(record):
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
