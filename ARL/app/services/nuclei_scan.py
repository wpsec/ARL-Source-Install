"""
Nuclei漏洞扫描
"""
import copy
import difflib
import json
import os
import os.path
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict

from app.config import Config
from app import utils


logger = utils.get_logger()


class NucleiScan(object):
    """
    Nuclei 扫描执行器

    支持两种目标输入格式：
    1. ["http://a.com", "https://b.com:8443"]
    2. [{"target": "http://a.com", "finger": ["wordpress", "nginx"]}, ...]
    """

    DEFAULT_FINGER_TAG_MAP = {
        "wordpress": ["wordpress"],
        "drupal": ["drupal"],
        "joomla": ["joomla"],
        "thinkphp": ["thinkphp"],
        "laravel": ["laravel"],
        "struts": ["struts", "apache"],
        "spring": ["spring"],
        "tomcat": ["tomcat", "apache"],
        "weblogic": ["weblogic", "oracle"],
        "jboss": ["jboss"],
        "nginx": ["nginx"],
        "apache": ["apache"],
        "iis": ["iis", "microsoft"],
        "jenkins": ["jenkins"],
        "gitlab": ["gitlab"],
        "jira": ["jira", "atlassian"],
        "confluence": ["confluence", "atlassian"],
        "kibana": ["kibana"],
        "elasticsearch": ["elasticsearch"],
        "redis": ["redis"],
        "docker": ["docker"],
        "kubernetes": ["kubernetes"],
    }
    # 常见产品别名到 nuclei tags 的映射，用于补足指纹命名差异。
    FINGER_ALIAS_TAG_MAP = {
        "esa": ["esafenet"],
        "aliyunoss": ["alibaba", "bucket", "oss", "exposure", "misconfig"],
        "apache tomcat": ["tomcat", "apache", "java"],
        "tomcat": ["tomcat", "java"],
        "spring boot": ["spring", "springboot", "java", "actuator"],
        "springcloud": ["spring", "java"],
        "weblogic": ["weblogic", "oracle", "java"],
        "websphere": ["websphere", "ibm", "java"],
        "jboss": ["jboss", "java"],
        "jetty": ["jetty", "java"],
        "struts": ["struts", "java", "apache"],
        "nginx": ["nginx"],
        "openresty": ["nginx", "lua"],
        "tengine": ["nginx"],
        "apache http server": ["apache"],
        "iis": ["iis", "microsoft"],
        "microsoft iis": ["iis", "microsoft"],
        "jenkins": ["jenkins"],
        "gitlab": ["gitlab"],
        "jira": ["jira", "atlassian"],
        "confluence": ["confluence", "atlassian"],
        "grafana": ["grafana"],
        "kibana": ["kibana", "elasticsearch"],
        "elasticsearch": ["elasticsearch"],
        "rabbitmq": ["rabbitmq", "default-login", "panel"],
        "nacos": ["nacos", "default-login", "unauth"],
        "harbor": ["harbor", "default-login", "panel"],
        "minio": ["minio", "default-login"],
        "redis": ["redis", "unauth"],
        "mysql": ["mysql", "default-login"],
        "mongodb": ["mongodb", "unauth"],
        "kubernetes dashboard": ["kubernetes", "dashboard", "unauth"],
        "consul": ["consul", "unauth"],
    }
    # tag 家族扩展，低权重补全，不会走全模板。
    TAG_FAMILY_EXPANSION = {
        "tomcat": ["java"],
        "spring": ["java", "actuator"],
        "springboot": ["spring", "java", "actuator"],
        "weblogic": ["java", "oracle"],
        "jboss": ["java"],
        "jetty": ["java"],
        "apache": ["http"],
        "nginx": ["http"],
        "iis": ["http", "microsoft"],
        "jenkins": ["default-login"],
        "grafana": ["default-login"],
        "gitlab": ["default-login"],
        "harbor": ["default-login"],
        "rabbitmq": ["default-login", "panel"],
        "nacos": ["default-login", "unauth"],
        "kubernetes": ["dashboard"],
    }
    # 默认兜底标签过于单薄时，补一组高价值“通用漏洞”标签。
    SMART_BASELINE_TAGS = ["cve", "exposure", "misconfig", "default-login", "unauth", "panel"]
    MAX_TAGS_PER_TARGET = 18
    # 指纹模糊匹配的内置高精度阈值（不开放配置，降低误匹配引发的无效扫描）。
    FINGER_FUZZY_MATCH_ENABLE = True
    FINGER_FUZZY_MATCH_THRESHOLD = 85
    FINGER_FUZZY_MIN_TOKEN_COVERAGE = 60
    _TEMPLATE_TAG_INDEX_CACHE = {}
    # 通用噪声词，避免从指纹文本中推导出过于泛化的 tag。
    FINGER_TOKEN_STOPWORDS = {
        "www", "web", "http", "https", "server", "service", "system", "platform",
        "application", "app", "cloud", "default", "admin", "login", "portal",
        "console", "dashboard", "test", "dev", "uat", "prod", "beta", "alpha",
        "version", "community", "enterprise", "open", "source", "edition",
    }

    def __init__(self, targets: list):
        self.targets = self._normalize_targets(targets)
        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()
        self.file_rand_str = rand_str

        self.tmp_path = tmp_path
        self.tmp_target_files = []
        self.tmp_result_files = []
        # 为每次扫描创建独立的 nuclei 运行时目录，避免共享 ~/.config/nuclei 产生并发污染
        self.nuclei_runtime_root = os.path.join(self.tmp_path, "nuclei_runtime_{}".format(rand_str))
        self.nuclei_runtime_config_dir = os.path.join(self.nuclei_runtime_root, "nuclei")
        self.nuclei_runtime_ignore_file = os.path.join(self.nuclei_runtime_config_dir, ".nuclei-ignore")
        self.dns_policy_cache = {}

        self.nuclei_bin_path = Config.NUCLEI_BIN
        self.nuclei_template_dir = Config.NUCLEI_TEMPLATE_DIR
        self.nuclei_auto_scan = bool(Config.NUCLEI_AUTO_SCAN)
        self.nuclei_default_tags = Config.NUCLEI_DEFAULT_TAGS
        self.nuclei_finger_fuzzy_match_enable = bool(self.FINGER_FUZZY_MATCH_ENABLE)
        self.nuclei_finger_fuzzy_match_threshold = int(self.FINGER_FUZZY_MATCH_THRESHOLD)
        self.nuclei_finger_fuzzy_match_min_token_coverage = int(self.FINGER_FUZZY_MIN_TOKEN_COVERAGE)
        if self.nuclei_finger_fuzzy_match_threshold < 60:
            self.nuclei_finger_fuzzy_match_threshold = 60
        if self.nuclei_finger_fuzzy_match_threshold > 95:
            self.nuclei_finger_fuzzy_match_threshold = 95
        if self.nuclei_finger_fuzzy_match_min_token_coverage < 0:
            self.nuclei_finger_fuzzy_match_min_token_coverage = 0
        if self.nuclei_finger_fuzzy_match_min_token_coverage > 100:
            self.nuclei_finger_fuzzy_match_min_token_coverage = 100

        self.nuclei_finger_tag_map = copy.deepcopy(self.DEFAULT_FINGER_TAG_MAP)
        self._load_custom_finger_tag_map()
        self.template_tag_set = set()

        # 在nuclei 2.9.1 中 将-json 参数改成了 -jsonl 参数。
        self.nuclei_json_flag = None

    @staticmethod
    def _normalize_targets(targets):
        """
        统一目标格式并去重，确保后续流程使用同一数据结构
        """
        target_map = {}
        for item in targets:
            target = ""
            finger = []
            if isinstance(item, str):
                target = item.strip()
            elif isinstance(item, dict):
                target = str(item.get("target", "")).strip()
                finger_data = item.get("finger", [])
                if isinstance(finger_data, list):
                    for x in finger_data:
                        finger_name = str(x).strip().lower()
                        if finger_name:
                            finger.append(finger_name)

            if not target:
                continue

            old_fingers = target_map.get(target, set())
            old_fingers.update(finger)
            target_map[target] = old_fingers

        target_items = []
        for target in sorted(target_map.keys()):
            target_items.append({
                "target": target,
                "finger": sorted(target_map[target]),
            })

        return target_items

    def _load_custom_finger_tag_map(self):
        """
        加载用户自定义指纹映射，覆盖默认映射
        """
        mapping = Config.NUCLEI_FINGER_TAG_MAP
        if not isinstance(mapping, dict):
            return

        for key, value in mapping.items():
            map_key = str(key).strip().lower()
            if not map_key:
                continue

            if not isinstance(value, list):
                continue

            tags = []
            for tag in value:
                tag = str(tag).strip().lower()
                if tag:
                    tags.append(tag)

            if tags:
                self.nuclei_finger_tag_map[map_key] = tags

    def _check_json_flag(self):
        """
        检查 nuclei 支持的 json 输出参数

        说明：
        - 不能直接执行 `nuclei -json/-jsonl` 做探测，部分版本会因缺少目标返回非 0
        - 通过 `-h` 帮助文本判断兼容参数更稳定
        """
        try:
            command = [self.nuclei_bin_path, "-h"]
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            help_text = ""
            if pro.stdout:
                help_text += pro.stdout.decode("utf-8", errors="ignore")
            if pro.stderr:
                help_text += "\n" + pro.stderr.decode("utf-8", errors="ignore")
            help_text = help_text.lower()
        except Exception as e:
            logger.warning("nuclei help probe failed: {}".format(e))
            help_text = ""

        if "-jsonl" in help_text:
            self.nuclei_json_flag = "-jsonl"
            return True
        if "-json" in help_text:
            self.nuclei_json_flag = "-json"
            return True

        logger.warning("nuclei json flag check failed, only -json/-jsonl are supported")
        return False

    def _delete_file(self):
        tmp_files = self.tmp_target_files + self.tmp_result_files
        for file_path in tmp_files:
            try:
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning(e)

        try:
            if os.path.isdir(self.nuclei_runtime_root):
                shutil.rmtree(self.nuclei_runtime_root)
        except Exception as e:
            logger.warning("delete nuclei runtime dir failed {}".format(e))

    def _resolve_template_dir(self):
        """
        校验模板目录，目录不可用时降级为 nuclei 默认模板目录
        """
        nuclei_template_dir = str(self.nuclei_template_dir).strip()
        if not nuclei_template_dir:
            self.nuclei_template_dir = ""
            return

        if os.path.isdir(nuclei_template_dir):
            self.nuclei_template_dir = nuclei_template_dir
            return

        # 兼容目录布局差异：
        # - 旧路径: /code/tools/nuclei-templates
        # - 新路径: /code/tools/nuclei/nuclei-templates
        compat_candidates = []
        normalized_dir = nuclei_template_dir.rstrip("/")
        if normalized_dir.endswith("/nuclei-templates"):
            compat_candidates.append(normalized_dir[:-len("/nuclei-templates")] + "/nuclei/nuclei-templates")
        compat_candidates.append(os.path.join("/code/tools/nuclei", "nuclei-templates"))

        for candidate in compat_candidates:
            candidate = str(candidate).strip()
            if not candidate:
                continue
            if os.path.isdir(candidate):
                logger.warning(
                    "nuclei template dir not found: {}, use compatible path: {}".format(
                        nuclei_template_dir, candidate
                    )
                )
                self.nuclei_template_dir = candidate
                return

        logger.warning(
            "nuclei template dir not found: {}, fallback to nuclei default templates".format(
                nuclei_template_dir
            )
        )
        self.nuclei_template_dir = ""

    def _log_template_summary(self):
        """
        记录模板目录摘要，便于排查“扫描 0 结果”问题
        """
        if not self.nuclei_template_dir:
            logger.info("nuclei template dir: use default")
            return

        yaml_count = 0
        try:
            for root, _, files in os.walk(self.nuclei_template_dir):
                for file_name in files:
                    if file_name.endswith(".yaml") or file_name.endswith(".yml"):
                        yaml_count += 1
        except Exception as e:
            logger.warning("count nuclei templates failed: {}".format(e))
            return

        logger.info(
            "nuclei template dir:{} templates:{}".format(
                self.nuclei_template_dir, yaml_count
            )
        )
        if yaml_count == 0:
            logger.warning(
                "nuclei template dir has zero templates: {}".format(self.nuclei_template_dir)
            )

    @staticmethod
    def _default_nuclei_ignore_content():
        """
        生成默认 .nuclei-ignore 内容（YAML 格式）
        """
        return (
            "# auto generated by arl-ti\n"
            "# keep minimal defaults to avoid heavy templates by default\n"
            "tags:\n"
            "  - fuzz\n"
            "  - dos\n"
            "files: []\n"
        )

    @staticmethod
    def _is_nuclei_ignore_valid(file_path):
        """
        检查 .nuclei-ignore 是否为可用内容
        """
        try:
            if not os.path.exists(file_path):
                return False

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if not content or not content.strip():
                return False

            # 过滤空行和注释后至少包含 tags/files 关键节点
            lines = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                lines.append(line.lower())

            if not lines:
                return False

            content_low = "\n".join(lines)
            if "tags:" in content_low or "files:" in content_low:
                return True
        except Exception:
            return False

        return False

    @staticmethod
    def _write_file_atomic(file_path, content):
        """
        原子写文件，避免并发读写下出现空文件/半文件
        """
        parent_dir = os.path.dirname(file_path)
        fd, temp_file = tempfile.mkstemp(prefix=".nuclei-ignore.", dir=parent_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_file, file_path)
            os.chmod(file_path, 0o644)
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def _prepare_nuclei_runtime(self, force_rewrite=False):
        """
        准备 nuclei 运行时目录，避免首次运行因缺失/空 .nuclei-ignore 直接失败
        """
        config_root = self.nuclei_runtime_root
        nuclei_config_dir = self.nuclei_runtime_config_dir
        ignore_file = self.nuclei_runtime_ignore_file
        try:
            os.makedirs(nuclei_config_dir, mode=0o755, exist_ok=True)
            rewrite_reason = ""
            should_write = bool(force_rewrite)
            if should_write:
                rewrite_reason = "force"
            elif not self._is_nuclei_ignore_valid(ignore_file):
                should_write = True
                rewrite_reason = "invalid_or_empty"

            if should_write:
                self._write_file_atomic(ignore_file, self._default_nuclei_ignore_content())

            logger.info(
                "nuclei runtime prepared xdg_config_home={} config_dir={} ignore_file={} rewrite={} reason={}".format(
                    config_root,
                    nuclei_config_dir,
                    ignore_file,
                    str(should_write).lower(),
                    rewrite_reason or "keep",
                )
            )
        except Exception as e:
            # 不中断扫描流程，交由 nuclei 自身报错处理
            logger.warning("prepare nuclei runtime failed {}".format(e))

    def check_have_nuclei(self) -> bool:
        self.nuclei_bin_path = utils.resolve_executable(self.nuclei_bin_path)
        if not self.nuclei_bin_path:
            logger.warning("not found nuclei binary, set ARL.NUCLEI_BIN or ARL_NUCLEI_BIN")
            return False

        command = [self.nuclei_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                return True
        except Exception as e:
            logger.debug("{}".format(str(e)))

        return False

    def _gen_target_file(self, target_list: list, file_name: str):
        with open(file_name, "w") as f:
            for domain in target_list:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + "\n")

    def _gen_tmp_file_path(self, prefix: str, index: int, suffix: str):
        return os.path.join(
            self.tmp_path,
            "{}_{}_{}.{}".format(prefix, self.file_rand_str, index, suffix),
        )

    @staticmethod
    def _normalize_text(value):
        """
        统一文本格式，便于指纹与 tag 的鲁棒匹配。
        """
        text = str(value or "").strip().lower()
        if not text:
            return ""

        text = re.sub(r"[\[\]\(\)\{\}/\\|,:;=_+]+", " ", text)
        text = re.sub(r"[^a-z0-9.\-\s]", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @classmethod
    def _tokenize_text(cls, value):
        """
        从文本中提取可用于匹配的 token。
        """
        text = cls._normalize_text(value)
        if not text:
            return []

        tokens = []
        for token in text.split():
            token = token.strip(".-")
            if len(token) < 3:
                continue
            if token.isdigit():
                continue
            if token in cls.FINGER_TOKEN_STOPWORDS:
                continue
            tokens.append(token)

        return tokens

    @staticmethod
    def _split_tag_text(tag_text):
        """
        拆分 tags 字符串，兼容 `a,b`、`[a,b]`、`- a` 等写法。
        """
        raw = str(tag_text or "").strip()
        if not raw:
            return []

        raw = raw.strip("[]").replace('"', "").replace("'", "")
        items = []
        for token in re.split(r"[,\s]+", raw):
            token = re.sub(r"[^a-z0-9._-]", "", token.strip().lower())
            if not token:
                continue
            if token in {"true", "false", "null", "none"}:
                continue
            items.append(token)
        return items

    @staticmethod
    def _compact_text(value):
        """
        紧凑化文本，仅保留字母和数字，用于 fuzzy 相似度计算。
        """
        return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())

    @staticmethod
    def _sequence_ratio(left, right):
        """
        计算两个字符串的序列相似度。
        """
        l_text = str(left or "")
        r_text = str(right or "")
        if not l_text or not r_text:
            return 0.0
        return float(difflib.SequenceMatcher(None, l_text, r_text).ratio())

    def _calc_fuzzy_match_score(self, finger_name, map_key):
        """
        计算指纹与映射键的 fuzzy 分数和关键指标。
        """
        f_norm = self._normalize_text(finger_name)
        k_norm = self._normalize_text(map_key)
        if not f_norm or not k_norm:
            return 0.0, 0.0, 0.0

        f_tokens = set(self._tokenize_text(f_norm))
        k_tokens = set(self._tokenize_text(k_norm))
        token_coverage = 0.0
        token_jaccard = 0.0
        if k_tokens:
            inter = f_tokens & k_tokens
            # 优先看 key token 的覆盖率，避免“碰到 1 个词就算命中”。
            token_coverage = float(len(inter)) / float(len(k_tokens))

            # 补充“词片段包含”覆盖，提升 springboot/spring boot 之类命中率。
            partial_hit = 0
            f_token_list = list(f_tokens)
            for k_token in k_tokens:
                if len(k_token) < 4:
                    continue
                for f_token in f_token_list:
                    if len(f_token) < 4:
                        continue
                    if k_token in f_token or f_token in k_token:
                        partial_hit += 1
                        break

            if partial_hit > 0:
                partial_coverage = float(partial_hit) / float(len(k_tokens))
                token_coverage = max(token_coverage, partial_coverage)

            union = f_tokens | k_tokens
            if union:
                token_jaccard = float(len(inter)) / float(len(union))

        compact_ratio = self._sequence_ratio(self._compact_text(f_norm), self._compact_text(k_norm))
        norm_ratio = self._sequence_ratio(f_norm, k_norm)
        score = (
            compact_ratio * 0.45
            + norm_ratio * 0.20
            + token_coverage * 0.25
            + token_jaccard * 0.10
        )
        return score, token_coverage, compact_ratio

    def _match_mapping_key(self, finger_name, map_key):
        """
        指纹键匹配规则：优先严格匹配，再按阈值进行高精度 fuzzy 匹配。
        """
        f_raw = str(finger_name or "").strip().lower()
        k_raw = str(map_key or "").strip().lower()
        if not f_raw or not k_raw:
            return False, 0.0

        f_norm = self._normalize_text(f_raw)
        k_norm = self._normalize_text(k_raw)
        if not f_norm or not k_norm:
            return False, 0.0

        # 精确匹配（含紧凑格式）
        if f_raw == k_raw or f_norm == k_norm:
            return True, 1.0
        if self._compact_text(f_norm) == self._compact_text(k_norm):
            return True, 1.0

        f_tokens = set(self._tokenize_text(f_norm))
        k_tokens = set(self._tokenize_text(k_norm))
        if not f_tokens or not k_tokens:
            return False, 0.0

        # token 严格子集命中，优先作为高置信匹配。
        if k_tokens.issubset(f_tokens):
            return True, 1.0
        # 单 token 场景只接受精确 token 命中，避免误扫。
        if len(k_tokens) == 1 and len(f_tokens & k_tokens) == 1:
            return True, 1.0

        if not self.nuclei_finger_fuzzy_match_enable:
            return False, 0.0

        score, token_coverage, compact_ratio = self._calc_fuzzy_match_score(f_norm, k_norm)
        threshold = float(self.nuclei_finger_fuzzy_match_threshold) / 100.0
        min_coverage = float(self.nuclei_finger_fuzzy_match_min_token_coverage) / 100.0

        # 单 token 映射默认更严格，避免短词误匹配放大扫描范围。
        if len(k_tokens) == 1:
            threshold = max(threshold, 0.88)
            if len(next(iter(k_tokens), "")) < 5:
                threshold = max(threshold, 0.92)
            min_coverage = max(min_coverage, 0.0)

        if score >= threshold and token_coverage >= min_coverage:
            return True, score

        # 对于连写词（如 springboot）给一个高阈值补充通道。
        if compact_ratio >= 0.94 and score >= max(threshold, 0.86):
            return True, score

        return False, score

    def _load_template_tag_index(self):
        """
        从模板目录抽取 tags 索引，用于指纹 token 的自动补全。
        """
        self.template_tag_set = set()
        template_dir = str(self.nuclei_template_dir or "").strip()
        if not template_dir or not os.path.isdir(template_dir):
            return

        cache_tags = self._TEMPLATE_TAG_INDEX_CACHE.get(template_dir)
        if isinstance(cache_tags, set):
            self.template_tag_set = cache_tags.copy()
            return

        tag_set = set()
        try:
            for root, _, files in os.walk(template_dir):
                for file_name in files:
                    if not (file_name.endswith(".yaml") or file_name.endswith(".yml")):
                        continue

                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read(8192)
                    except Exception:
                        continue

                    in_tags_block = False
                    tags_indent = 0
                    for line in content.splitlines():
                        stripped = line.strip()
                        if not stripped:
                            continue

                        indent = len(line) - len(line.lstrip())
                        line_low = stripped.lower()

                        if in_tags_block:
                            if indent <= tags_indent:
                                in_tags_block = False
                            elif stripped.startswith("-"):
                                for tag in self._split_tag_text(stripped[1:]):
                                    tag_set.add(tag)
                                continue
                            else:
                                continue

                        if line_low.startswith("tags:"):
                            for tag in self._split_tag_text(stripped[5:]):
                                tag_set.add(tag)
                            in_tags_block = True
                            tags_indent = indent

            self._TEMPLATE_TAG_INDEX_CACHE[template_dir] = tag_set.copy()
            self.template_tag_set = tag_set
            logger.info(
                "nuclei template tags indexed dir:{} tags:{}".format(template_dir, len(tag_set))
            )
        except Exception as e:
            logger.warning("build nuclei template tag index failed: {}".format(e))

    def _infer_tags_by_template_tokens(self, finger_name):
        """
        当显式映射未命中时，基于模板 tag 索引做轻量推断。
        """
        if not self.template_tag_set:
            return []

        inferred = set()
        for token in self._tokenize_text(finger_name):
            if token in self.template_tag_set:
                inferred.add(token)

        return sorted(inferred)

    def _match_alias_tags(self, finger_name):
        """
        通过别名映射补齐 tags。
        """
        out_scores = {}
        for alias_key, alias_tags in self.FINGER_ALIAS_TAG_MAP.items():
            matched, score = self._match_mapping_key(finger_name, alias_key)
            if not matched:
                continue
            tag_score = 5 + int(round(max(0.0, min(1.0, score)) * 3))
            for tag in alias_tags:
                tag_name = str(tag).strip().lower()
                if not tag_name:
                    continue
                old = out_scores.get(tag_name, 0)
                out_scores[tag_name] = max(old, tag_score)
        return out_scores

    def _add_tag_scores(self, score_map, tags, score):
        """
        给 tags 打分，后续按分数截断，保证“尽量多命中”且不盲扫。
        """
        if not isinstance(tags, (list, tuple, set)):
            return

        for tag in tags:
            tag_name = str(tag).strip().lower()
            if not tag_name:
                continue

            # 若已建立模板 tag 索引，仅保留真实存在的 tag，减少无效参数。
            if self.template_tag_set and tag_name not in self.template_tag_set:
                continue
            score_map[tag_name] += int(score)

    def _expand_family_tags(self, tags):
        """
        按标签家族做低权重扩展，提升覆盖率。
        """
        expanded = set()
        for tag in tags:
            for extra in self.TAG_FAMILY_EXPANSION.get(tag, []):
                extra_name = str(extra).strip().lower()
                if not extra_name:
                    continue
                if self.template_tag_set and extra_name not in self.template_tag_set:
                    continue
                expanded.add(extra_name)
        return sorted(expanded)

    def _build_fallback_tags(self):
        """
        构建兜底标签：
        - 保留用户默认配置
        - 当默认仅为 cve（或空）时，补充高价值通用标签
        """
        tags = set(self._split_tag_text(self.nuclei_default_tags))
        if not tags:
            tags = set(self.SMART_BASELINE_TAGS)
        elif tags == {"cve"}:
            tags.update(self.SMART_BASELINE_TAGS)

        if self.template_tag_set:
            tags = {x for x in tags if x in self.template_tag_set}

        if not tags:
            tags = {"cve"}

        return ",".join(sorted(tags))

    def _build_finger_tags(self, finger_list: list):
        """
        根据指纹名称映射 nuclei tags
        """
        tag_score_map = Counter()
        for finger in finger_list:
            finger_name = str(finger).strip().lower()
            if not finger_name:
                continue

            match_flag = False
            for map_key, tags in self.nuclei_finger_tag_map.items():
                matched, score = self._match_mapping_key(finger_name, map_key)
                if not matched:
                    continue
                match_flag = True
                mapping_score = 6 + int(round(max(0.0, min(1.0, score)) * 4))
                self._add_tag_scores(tag_score_map, tags, score=mapping_score)

            alias_tag_scores = self._match_alias_tags(finger_name)
            if alias_tag_scores:
                match_flag = True
                for alias_tag, alias_score in alias_tag_scores.items():
                    self._add_tag_scores(tag_score_map, [alias_tag], score=alias_score)

            # 显式映射未命中时，尝试依据模板 tag 做自动补全。
            if not match_flag:
                self._add_tag_scores(
                    tag_score_map,
                    self._infer_tags_by_template_tokens(finger_name),
                    score=4,
                )

        # 对已命中的核心 tag 做家族扩展（低权重）。
        core_tags = list(tag_score_map.keys())
        self._add_tag_scores(tag_score_map, self._expand_family_tags(core_tags), score=2)

        # 按分数和字典序排序并截断，避免无边界增长。
        sorted_tags = sorted(tag_score_map.items(), key=lambda x: (-x[1], x[0]))
        out_tags = [x[0] for x in sorted_tags[: self.MAX_TAGS_PER_TARGET]]
        return out_tags

    def _build_target_batches(self):
        """
        根据指纹标签构建批次：
        - 命中指纹映射：按 tags 分组，使用 -tags 定向扫描
        - 未命中映射：走自动扫描(-as)或默认标签兜底
        """
        fallback_tags = self._build_fallback_tags()
        tags_target_map = defaultdict(set)
        fallback_targets = set()
        unmatched_finger_counter = Counter()

        for item in self.targets:
            target = item["target"]
            finger_list = item.get("finger", [])
            finger_tags = self._build_finger_tags(finger_list)

            if finger_tags:
                key = ",".join(finger_tags)
                tags_target_map[key].add(target)
            else:
                fallback_targets.add(target)
                for finger in finger_list:
                    finger_key = self._normalize_text(finger)
                    if finger_key:
                        unmatched_finger_counter[finger_key] += 1

        target_batches = []
        for tags in sorted(tags_target_map.keys()):
            target_batches.append(
                {
                    "targets": sorted(tags_target_map[tags]),
                    "tags": tags,
                    "auto_scan": False,
                    "batch_type": "fingerprint",
                }
            )

        if fallback_targets:
            target_batches.append(
                {
                    "targets": sorted(fallback_targets),
                    "tags": fallback_tags,
                    "auto_scan": self.nuclei_auto_scan,
                    "batch_type": "fallback",
                }
            )

        # 所有目标都未构建到批次时，兜底执行一次
        if not target_batches and self.targets:
            target_batches.append(
                {
                    "targets": [item["target"] for item in self.targets],
                    "tags": fallback_tags,
                    "auto_scan": self.nuclei_auto_scan,
                    "batch_type": "default",
                }
            )

        if unmatched_finger_counter:
            top_items = unmatched_finger_counter.most_common(12)
            top_text = "; ".join(["{}({})".format(name, count) for name, count in top_items])
            logger.info(
                "nuclei unmatched finger top:{} total_unique:{}".format(
                    top_text, len(unmatched_finger_counter)
                )
            )

        return target_batches

    def _filter_targets_by_dns_policy(self):
        """
        扫描前进行 DNS 漂移校验，避免请求被系统 DNS 解析到非预期地址
        """
        if not self.targets:
            return

        keep_targets = []
        skip_count = 0
        for item in self.targets:
            target = item.get("target", "")
            allow_scan, policy_detail = utils.check_dns_policy_for_url(target, cache_map=self.dns_policy_cache)
            if not allow_scan:
                skip_count += 1
                logger.info(
                    "skip nuclei target by dns policy target:{} reason:{} resolver_ips:{} system_ips:{}".format(
                        target,
                        policy_detail.get("reason", ""),
                        policy_detail.get("resolver_ips", []),
                        policy_detail.get("system_ips", []),
                    )
                )
                continue

            keep_targets.append(item)

        if skip_count > 0:
            logger.info(
                "nuclei dns policy filter skip:{} keep:{}".format(skip_count, len(keep_targets))
            )

        self.targets = keep_targets

    def dump_result(self) -> list:
        results = []
        for result_file in self.tmp_result_files:
            if not os.path.exists(result_file):
                continue

            with open(result_file, "r") as f:
                while True:
                    line = f.readline()
                    if not line:
                        break

                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    item = {
                        "template_url": data.get("template-url", ""),
                        "template_id": data.get("template-id", ""),
                        "vuln_name": data.get("info", {}).get("name", ""),
                        "vuln_severity": data.get("info", {}).get("severity", ""),
                        "vuln_url": data.get("matched-at", ""),
                        "curl_command": data.get("curl-command", ""),
                        "target": data.get("host", "")
                    }
                    results.append(item)

        return results

    def _build_base_command(self, target_file: str, result_file: str):
        """
        构建 nuclei 基础命令（不含扫描模式参数）
        """
        rate_limit = int(getattr(Config, "NUCLEI_RATE_LIMIT", 8) or 8)
        concurrency = int(getattr(Config, "NUCLEI_CONCURRENCY", 4) or 4)
        bulk_size = int(getattr(Config, "NUCLEI_BULK_SIZE", 5) or 5)
        if rate_limit < 1:
            rate_limit = 1
        if concurrency < 1:
            concurrency = 1
        if bulk_size < 1:
            bulk_size = 1

        command = [
            self.nuclei_bin_path,
            "-duc",
            "-severity low,medium,high,critical",
            "-type http",
            "-l {}".format(target_file),
            "-rl {}".format(rate_limit),
            "-c {}".format(concurrency),
            "-bs {}".format(bulk_size),
            self.nuclei_json_flag,  # 在nuclei 2.9.1 中将 -json 改成了 -jsonl 参数
            "-stats",
            "-stats-interval 60",
            "-o {}".format(result_file),
        ]

        # 指定内部模板库目录
        if self.nuclei_template_dir:
            command.append("-t {}".format(self.nuclei_template_dir))

        return command

    @staticmethod
    def _decode_output(raw_bytes):
        if not raw_bytes:
            return ""
        return raw_bytes.decode("utf-8", errors="ignore").strip()

    @staticmethod
    def _result_file_size(file_path):
        try:
            return os.path.getsize(file_path) if os.path.exists(file_path) else 0
        except Exception:
            return 0

    @staticmethod
    def _calc_exec_timeout(target_count: int):
        exec_timeout = int(getattr(Config, "NUCLEI_EXEC_TIMEOUT_SEC", 96 * 60 * 60) or 96 * 60 * 60)
        per_target_timeout = int(getattr(Config, "NUCLEI_SINGLE_TARGET_TIMEOUT_SEC", 0) or 0)

        if exec_timeout < 60:
            exec_timeout = 60
        if target_count < 1:
            target_count = 1

        if per_target_timeout > 0:
            if per_target_timeout < 60:
                per_target_timeout = 60
            exec_timeout = min(exec_timeout, per_target_timeout * target_count)

        return exec_timeout

    @staticmethod
    def _calc_effective_targets_per_batch(target_count: int):
        """
        计算本轮实际分批大小。

        规则：
        - 当 NUCLEI_TARGETS_PER_BATCH > 1 时，严格按用户配置执行
        - 当 NUCLEI_TARGETS_PER_BATCH <= 1 时启用自动批次：
          1) 参考 nuclei 并发能力（c * bs）
          2) 受超时预算约束（exec_timeout / per_target_timeout）
          3) 最终不超过当前批次目标数
        """
        if target_count < 1:
            return 1

        configured_chunk = int(getattr(Config, "NUCLEI_TARGETS_PER_BATCH", 1) or 1)
        if configured_chunk > 1:
            return min(configured_chunk, target_count)

        concurrency = int(getattr(Config, "NUCLEI_CONCURRENCY", 4) or 4)
        bulk_size = int(getattr(Config, "NUCLEI_BULK_SIZE", 5) or 5)
        if concurrency < 1:
            concurrency = 1
        if bulk_size < 1:
            bulk_size = 1

        # 以 nuclei 并发吞吐能力作为自动批次上限，避免单目标串行导致慢扫描。
        perf_budget = max(1, concurrency * bulk_size)

        exec_timeout = int(getattr(Config, "NUCLEI_EXEC_TIMEOUT_SEC", 96 * 60 * 60) or 96 * 60 * 60)
        if exec_timeout < 60:
            exec_timeout = 60
        per_target_timeout = int(getattr(Config, "NUCLEI_SINGLE_TARGET_TIMEOUT_SEC", 0) or 0)
        timeout_budget = target_count
        if per_target_timeout > 0:
            if per_target_timeout < 60:
                per_target_timeout = 60
            timeout_budget = max(1, int(exec_timeout / per_target_timeout))

        chunk_size = min(target_count, perf_budget, timeout_budget)
        if chunk_size < 1:
            chunk_size = 1
        return chunk_size

    def _run_nuclei_command(self, command: list, batch_type: str, stage: str, result_file: str, target_count: int = 1):
        """
        执行 nuclei 命令并输出统一日志
        """
        timeout_sec = self._calc_exec_timeout(target_count=target_count)

        logger.info(
            "nuclei command stage={} batch={} targets={} timeout={}s cmd={}".format(
                stage, batch_type, target_count, timeout_sec, " ".join(command)
            )
        )
        env = os.environ.copy()
        env["XDG_CONFIG_HOME"] = self.nuclei_runtime_root
        try:
            completed = utils.exec_system(
                command,
                timeout=timeout_sec,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env
            )
        except subprocess.TimeoutExpired as e:
            stdout_text = self._decode_output(getattr(e, "stdout", b""))
            stderr_text = self._decode_output(getattr(e, "stderr", b""))
            result_size = self._result_file_size(result_file)
            logger.warning(
                "nuclei run timeout stage={} batch={} timeout={}s result_file_size={} stderr={} stdout={}".format(
                    stage, batch_type, timeout_sec, result_size, stderr_text[:800], stdout_text[:800]
                )
            )
            return {
                "returncode": 124,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "result_size": result_size,
            }
        except Exception as e:
            logger.warning(
                "nuclei run exception stage={} batch={} error={}".format(stage, batch_type, e)
            )
            return {
                "returncode": 1,
                "stdout": "",
                "stderr": str(e),
                "result_size": self._result_file_size(result_file),
            }

        stdout_text = self._decode_output(completed.stdout)
        stderr_text = self._decode_output(completed.stderr)
        result_size = self._result_file_size(result_file)

        logger.info(
            "nuclei stage={} batch={} rc={} result_file_size={}".format(
                stage, batch_type, completed.returncode, result_size
            )
        )
        if completed.returncode != 0:
            logger.warning(
                "nuclei run failed stage={} batch={} rc={} stderr={} stdout={}".format(
                    stage, batch_type, completed.returncode, stderr_text[:800], stdout_text[:800]
                )
            )

        return {
            "returncode": completed.returncode,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "result_size": result_size,
        }

    def exec_nuclei(self, batch: dict, index: int):
        target_file = self._gen_tmp_file_path("nuclei_target", index, "txt")
        result_file = self._gen_tmp_file_path("nuclei_result", index, "json")
        self.tmp_target_files.append(target_file)
        self.tmp_result_files.append(result_file)
        batch_targets = batch.get("targets", [])
        self._gen_target_file(batch_targets, target_file)
        target_count = len(batch_targets)

        # 按批次类型选择参数
        # 1) fingerprint: 仅运行匹配到的 tags
        # 2) fallback/default: 优先 -as；若 -as 执行失败或无有效模板，再回退默认 tags
        command = self._build_base_command(target_file=target_file, result_file=result_file)

        logger.info(
            "nuclei batch={} targets={} tags={} auto_scan={}".format(
                batch.get("batch_type"),
                len(batch.get("targets", [])),
                batch.get("tags", ""),
                batch.get("auto_scan", False),
            )
        )
        batch_type = str(batch.get("batch_type", "default"))
        fallback_tags = str(batch.get("tags", "")).strip()

        if batch.get("auto_scan"):
            auto_result = self._run_nuclei_command(
                command=command + ["-as"],
                batch_type=batch_type,
                stage="auto-scan",
                result_file=result_file,
                target_count=target_count,
            )
            auto_output_lower = "{}\n{}".format(auto_result.get("stderr", ""), auto_result.get("stdout", "")).lower()
            if auto_result["returncode"] != 0 and (
                "could not parse nuclei-ignore file" in auto_output_lower
                or "could not read nuclei-ignore file" in auto_output_lower
            ):
                logger.warning(
                    "nuclei auto-scan detected invalid .nuclei-ignore, try rewrite and retry once"
                )
                self._prepare_nuclei_runtime(force_rewrite=True)
                auto_result = self._run_nuclei_command(
                    command=command + ["-as"],
                    batch_type=batch_type,
                    stage="auto-scan-retry",
                    result_file=result_file,
                    target_count=target_count,
                )
                auto_output_lower = "{}\n{}".format(
                    auto_result.get("stderr", ""),
                    auto_result.get("stdout", "")
                ).lower()

            stderr_lower = auto_result.get("stderr", "").lower()
            auto_need_fallback = False
            if auto_result["returncode"] != 0:
                auto_need_fallback = True
            elif "could not find any templates with tech tag" in stderr_lower:
                auto_need_fallback = True
            elif "no templates found for scan" in auto_output_lower:
                auto_need_fallback = True

            if auto_need_fallback and fallback_tags:
                logger.info(
                    "nuclei auto-scan fallback to tags, batch={} tags={}".format(
                        batch_type, fallback_tags
                    )
                )
                self._run_nuclei_command(
                    command=command + ["-tags {}".format(fallback_tags)],
                    batch_type=batch_type,
                    stage="tags-fallback",
                    result_file=result_file,
                    target_count=target_count,
                )
            return

        if fallback_tags:
            self._run_nuclei_command(
                command=command + ["-tags {}".format(fallback_tags)],
                batch_type=batch_type,
                stage="tags",
                result_file=result_file,
                target_count=target_count,
            )
            return

        # 禁止回退到全模板扫描，避免内部任务被全量模板拖慢
        self._run_nuclei_command(
            command=command + ["-tags cve"],
            batch_type=batch_type,
            stage="tags-default",
            result_file=result_file,
            target_count=target_count,
        )

    @staticmethod
    def _split_targets(targets: list, chunk_size: int):
        if chunk_size < 1:
            chunk_size = 1

        for index in range(0, len(targets), chunk_size):
            yield targets[index:index + chunk_size]

    def _split_batch_targets(self, batch: dict):
        targets = list(batch.get("targets", []))
        if not targets:
            return []

        chunk_size = self._calc_effective_targets_per_batch(target_count=len(targets))

        out_batches = []
        for part in self._split_targets(targets, chunk_size):
            new_batch = dict(batch)
            new_batch["targets"] = part
            out_batches.append(new_batch)

        logger.info(
            "nuclei split batch={} input_targets={} chunk_size={} split_count={}".format(
                batch.get("batch_type", "default"),
                len(targets),
                chunk_size,
                len(out_batches),
            )
        )

        return out_batches

    def exec_scan_batches(self):
        target_batches = self._build_target_batches()
        run_index = 1
        for batch in target_batches:
            split_batches = self._split_batch_targets(batch)
            for split_batch in split_batches:
                if not split_batch.get("targets"):
                    continue
                self.exec_nuclei(batch=split_batch, index=run_index)
                run_index += 1

    def run(self):
        if not self.targets:
            return []

        self._filter_targets_by_dns_policy()
        if not self.targets:
            logger.info("nuclei targets all skipped by dns policy")
            return []

        if not self.check_have_nuclei():
            logger.warning("not found nuclei")
            return []

        self._resolve_template_dir()
        self._log_template_summary()
        self._load_template_tag_index()
        self._prepare_nuclei_runtime()

        if not self._check_json_flag():
            return []

        try:
            self.exec_scan_batches()
            results = self.dump_result()
        finally:
            # 删除临时文件
            self._delete_file()

        logger.info("nuclei scan finish result:{}".format(len(results)))

        return results


def nuclei_scan(targets: list):
    if not targets:
        return []

    n = NucleiScan(targets=targets)
    return n.run()
