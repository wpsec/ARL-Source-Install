"""AI-POC 预扫描决策服务。

功能说明：
- 收集站点上下文、规则索引与批次计划，调用模型生成 Nuclei tags / Afrog keywords
- 决策结果写回 task.ai_poc_runtime，由 Nuclei/Afrog stage service 消费
- 保留 WebSiteFetch 上的同名兼容入口与常量别名；失败降级由任务侧
  _handle_ai_poc_stage_degrade 处理，不改变 pass-through 语义
"""

import json
import os
import re
import time

from bson.objectid import ObjectId

from app import utils
from app.config import Config
from app.modules import WebSiteFetchOption
from app.utils.log_safety import safe_error_text


logger = utils.get_logger()


class AIPocPlannerService(object):
    """AI-POC 扫描计划：上下文收集、模型调用与决策落地。"""

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
    PENETRATION_FEATURES_TEMP_DISABLED = True
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

    # 索引文件按 path+mtime 缓存；缺初始化会在索引命中时抛 AttributeError（上批重构丢失，迁移时恢复）。
    _AI_POC_INDEX_CACHE = {
        "path": "",
        "mtime": 0.0,
        "data": {},
    }
    AI_POC_INDEX_REL_PATH = os.path.join("docker", "ai", "sop", "poc_index.json")
    AI_POC_INDEX_REL_PATH_LEGACY = os.path.join("docker", "ai", "poc-index", "poc_index.json")

    def __init__(self, task, utils_module=None):
        self.task = task
        self.utils = utils_module or utils

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
            logger.warning("task_id:{} load ai runtime config failed err:{}".format(self.task.task_id, safe_error_text(e)))
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

        cache = getattr(cls, "_AI_POC_INDEX_CACHE", None)
        if not isinstance(cache, dict):
            cache = {}
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
            logger.warning("load ai poc index failed path:{} err:{}".format(index_path, safe_error_text(e)))
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
                    {"task_id": self.task.task_id},
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
                logger.warning("task_id:{} collect ai_poc url context failed err:{}".format(self.task.task_id, safe_error_text(e)))

            try:
                cursor = utils.conn_db("wih").find(
                    {"task_id": self.task.task_id},
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
                logger.warning("task_id:{} collect ai_poc wih context failed err:{}".format(self.task.task_id, safe_error_text(e)))

        site_contexts = []
        query = {"task_id": self.task.task_id, "site": {"$in": poc_sites}}
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
            logger.warning("task_id:{} collect ai_poc site context failed err:{}".format(self.task.task_id, safe_error_text(e)))

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
                "task_id": str(self.task.task_id),
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
            logger.warning("task_id:{} write ai_poc usage log failed err:{}".format(self.task.task_id, safe_error_text(e)))

    def run_ai_poc_scan_plan(self):
        """
        AI-POC 预扫描决策：
        - 开关关闭或模型不可用：保持现有扫描行为（pass-through）。
        - 开关开启且 AI 成功：将决策注入 nuclei/afrog 扫描参数。
        """
        self.task.ai_poc_runtime = {
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

        nuclei_enabled = bool(self.task.options.get(WebSiteFetchOption.NUCLEI_SCAN))
        afrog_enabled = bool(self.task.options.get(WebSiteFetchOption.AFROG_SCAN))
        if not (nuclei_enabled or afrog_enabled):
            return

        t1 = time.time()
        ai_config = self._load_ai_runtime_config()
        ai_poc_scan_enable = bool(ai_config.get("ai_poc_scan_enable", True))

        nuclei_targets = self.task.build_nuclei_targets() if nuclei_enabled else []
        nuclei_finger_hit = 0
        for item in nuclei_targets:
            if item.get("finger"):
                nuclei_finger_hit += 1

        nuclei_plan = self.task._preview_nuclei_batch_plan(nuclei_targets) if nuclei_enabled else {
            "batch_count": 0,
            "auto_scan_batch_count": 0,
            "tag_sample": [],
            "all_tags": [],
        }

        afrog_target_count = len(self.task.poc_sites) if afrog_enabled else 0
        afrog_pocs_dir = str(getattr(Config, "AFROG_POCS_DIR", "") or "").strip()
        afrog_poc_count = self._count_yaml_files(afrog_pocs_dir) if afrog_enabled else 0

        context_payload = self._collect_ai_poc_context(sorted(self.task.poc_sites))
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
                    self.task.ai_poc_runtime["nuclei_scan_profile"] = {
                        "name": "ai-poc",
                        "force_tags": applied_nuclei_tags,
                    }
                if afrog_enabled and ai_afrog_keywords:
                    applied_afrog_keywords = ai_afrog_keywords
                    self.task.ai_poc_runtime["afrog_keywords"] = ",".join(applied_afrog_keywords)
                if afrog_enabled and ai_afrog_severity:
                    applied_afrog_severity = ai_afrog_severity
                    self.task.ai_poc_runtime["afrog_severity"] = applied_afrog_severity

                if applied_nuclei_tags or applied_afrog_keywords or applied_afrog_severity:
                    run_mode = "ai_applied"
                    self.task.ai_poc_runtime["enabled"] = True
                else:
                    run_mode = "ai_no_action"
            else:
                run_mode = "ai_{}".format(ai_status or "error")

        self.task.ai_poc_runtime["mode"] = run_mode
        self.task.ai_poc_runtime["confidence"] = ai_confidence
        self.task.ai_poc_runtime["reason"] = ai_reason
        self.task.ai_poc_runtime["evidence"] = ai_evidence
        self.task.ai_poc_runtime["raw_ai_reply"] = ai_reply_text[:2200]

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
        logger.info("task_id:{} ai_poc_scan plan {}".format(self.task.task_id, detail_text))

        elapsed = time.time() - t1
        self.task._result_writer.update_one(
            "task",
            {"_id": ObjectId(self.task.task_id)},
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
            "task_id": str(self.task.task_id),
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

