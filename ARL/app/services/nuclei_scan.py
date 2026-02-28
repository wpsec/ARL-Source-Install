"""
Nuclei漏洞扫描
"""
import copy
import json
import os
import os.path
import subprocess
from collections import defaultdict

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

    def __init__(self, targets: list):
        self.targets = self._normalize_targets(targets)
        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()
        self.file_rand_str = rand_str

        self.tmp_path = tmp_path
        self.tmp_target_files = []
        self.tmp_result_files = []

        self.nuclei_bin_path = Config.NUCLEI_BIN
        self.nuclei_template_dir = Config.NUCLEI_TEMPLATE_DIR
        self.nuclei_auto_scan = bool(Config.NUCLEI_AUTO_SCAN)
        self.nuclei_default_tags = Config.NUCLEI_DEFAULT_TAGS

        self.nuclei_finger_tag_map = copy.deepcopy(self.DEFAULT_FINGER_TAG_MAP)
        self._load_custom_finger_tag_map()

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

    def _prepare_nuclei_runtime(self, force_rewrite=False):
        """
        准备 nuclei 运行时目录，避免首次运行因缺失/空 .nuclei-ignore 直接失败
        """
        config_root = os.environ.get("XDG_CONFIG_HOME")
        if not config_root:
            config_root = os.path.join(os.path.expanduser("~"), ".config")

        nuclei_config_dir = os.path.join(config_root, "nuclei")
        ignore_file = os.path.join(nuclei_config_dir, ".nuclei-ignore")
        try:
            os.makedirs(nuclei_config_dir, mode=0o755, exist_ok=True)

            should_write = force_rewrite
            if not should_write:
                if not os.path.exists(ignore_file):
                    should_write = True
                else:
                    try:
                        should_write = os.path.getsize(ignore_file) <= 0
                    except Exception:
                        should_write = True

            if should_write:
                with open(ignore_file, "w", encoding="utf-8") as f:
                    f.write(self._default_nuclei_ignore_content())

            logger.info(
                "nuclei runtime prepared config_dir={} ignore_file={} rewrite={}".format(
                    nuclei_config_dir, ignore_file, str(should_write).lower()
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

    def _build_finger_tags(self, finger_list: list):
        """
        根据指纹名称映射 nuclei tags
        """
        finger_tags = set()
        for finger in finger_list:
            finger_name = str(finger).strip().lower()
            if not finger_name:
                continue

            for map_key, tags in self.nuclei_finger_tag_map.items():
                if map_key in finger_name:
                    for tag in tags:
                        tag_name = str(tag).strip().lower()
                        if tag_name:
                            finger_tags.add(tag_name)

        return sorted(finger_tags)

    def _build_target_batches(self):
        """
        根据指纹标签构建批次：
        - 命中指纹映射：按 tags 分组，使用 -tags 定向扫描
        - 未命中映射：走自动扫描(-as)或默认标签兜底
        """
        tags_target_map = defaultdict(set)
        fallback_targets = set()

        for item in self.targets:
            target = item["target"]
            finger_list = item.get("finger", [])
            finger_tags = self._build_finger_tags(finger_list)

            if finger_tags:
                key = ",".join(finger_tags)
                tags_target_map[key].add(target)
            else:
                fallback_targets.add(target)

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
                    "tags": str(self.nuclei_default_tags).strip(),
                    "auto_scan": self.nuclei_auto_scan,
                    "batch_type": "fallback",
                }
            )

        # 所有目标都未构建到批次时，兜底执行一次
        if not target_batches and self.targets:
            target_batches.append(
                {
                    "targets": [item["target"] for item in self.targets],
                    "tags": str(self.nuclei_default_tags).strip(),
                    "auto_scan": self.nuclei_auto_scan,
                    "batch_type": "default",
                }
            )

        return target_batches

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
        command = [
            self.nuclei_bin_path,
            "-duc",
            "-severity low,medium,high,critical",
            "-type http",
            "-l {}".format(target_file),
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

    def _run_nuclei_command(self, command: list, batch_type: str, stage: str, result_file: str):
        """
        执行 nuclei 命令并输出统一日志
        """
        logger.info("nuclei command stage={} batch={} cmd={}".format(stage, batch_type, " ".join(command)))
        completed = utils.exec_system(
            command,
            timeout=96 * 60 * 60,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

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
        self._gen_target_file(batch["targets"], target_file)

        # 按批次类型选择参数
        # 1) fingerprint: 仅运行匹配到的 tags
        # 2) fallback/default: 优先 -as；若 -as 没有有效模板或结果为空，再回退默认 tags
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
            )
            auto_output_lower = "{}\n{}".format(auto_result.get("stderr", ""), auto_result.get("stdout", "")).lower()
            if auto_result["returncode"] != 0 and "could not parse nuclei-ignore file" in auto_output_lower:
                logger.warning(
                    "nuclei auto-scan detected invalid .nuclei-ignore, try rewrite and retry once"
                )
                self._prepare_nuclei_runtime(force_rewrite=True)
                auto_result = self._run_nuclei_command(
                    command=command + ["-as"],
                    batch_type=batch_type,
                    stage="auto-scan-retry",
                    result_file=result_file,
                )

            stderr_lower = auto_result.get("stderr", "").lower()
            auto_need_fallback = False
            if auto_result["returncode"] != 0:
                auto_need_fallback = True
            elif auto_result["result_size"] <= 0 and fallback_tags:
                auto_need_fallback = True
            elif "could not find any templates with tech tag" in stderr_lower:
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
                )
            return

        if fallback_tags:
            self._run_nuclei_command(
                command=command + ["-tags {}".format(fallback_tags)],
                batch_type=batch_type,
                stage="tags",
                result_file=result_file,
            )
            return

        # 禁止回退到全模板扫描，避免内部任务被全量模板拖慢
        self._run_nuclei_command(
            command=command + ["-tags cve"],
            batch_type=batch_type,
            stage="tags-default",
            result_file=result_file,
        )

    def exec_scan_batches(self):
        target_batches = self._build_target_batches()
        for index, batch in enumerate(target_batches, start=1):
            if not batch.get("targets"):
                continue
            self.exec_nuclei(batch=batch, index=index)

    def run(self):
        if not self.targets:
            return []

        if not self.check_have_nuclei():
            logger.warning("not found nuclei")
            return []

        self._resolve_template_dir()
        self._log_template_summary()
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
