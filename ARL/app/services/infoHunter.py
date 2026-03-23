"""
信息收集和处理
"""
from typing import List
from app import utils
from app.config import Config
import os
import json
import subprocess
import hashlib
import re
from urllib.parse import urlparse
from app.modules import WihRecord
from .url_candidate_filter import (
    has_route_template_markers,
    is_js_resource_path,
    is_non_js_static_resource_path,
    is_noise_single_segment_path,
    strip_route_method_suffix,
)

logger = utils.get_logger()

_EMAIL_STATIC_SUFFIXES = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "ico",
    "bmp",
    "css",
    "js",
    "map",
    "woff",
    "woff2",
    "ttf",
    "eot",
}
_PATH_NOISE_SINGLE_SEGMENTS = {
    "svg",
    "post",
    "var",
    "return",
    "undefined",
    "template",
    "license",
    "textarea",
    "span",
    "h1",
    "h2",
    "h3",
    "dtd",
    "compiler-dom",
    "ietf",
}
_PATH_SHORT_ALLOWLIST = {
    "api",
    "app",
    "cms",
    "doc",
    "docs",
    "rpc",
    "sdk",
    "sms",
    "sso",
    "uaa",
}
_HOST_LIKE_SEGMENT_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$")
_PATH_CODE_MARKER_RE = re.compile(
    r"(?i)(?:\.test\(|\.exec\(|parseint|parsefloat|math\.|offsetwidth|offsetheight|"
    r"function\.prototype|object\.prototype|number\.isfinite|regexp\(|substr\(|substring\(|"
    r"starting_with\(|django_value|xhtml\+xml|android/gi|iphone|msie|lark)"
)


class InfoHunter(object):
    # 从JS中收集，子域名，AK SK 等信息
    def __init__(self, sites: list):
        self.sites = set(sites)

        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        # wih 目标文件
        self.wih_target_path = os.path.join(tmp_path, "wih_target_{}.txt".format(rand_str))

        # wih 结果文件
        self.wih_result_path = os.path.join(tmp_path, "wih_result_{}.json".format(rand_str))

        self.wih_bin_path = self._resolve_wih_binary()
        self.wih_timeout_sec = int(getattr(Config, "WIH_TIMEOUT_SEC", 2 * 60 * 60) or (2 * 60 * 60))
        self.wih_concurrency = int(getattr(Config, "WIH_CONCURRENCY", 6) or 6)
        self.wih_concurrency_per_site = int(getattr(Config, "WIH_CONCURRENCY_PER_SITE", 2) or 2)
        if self.wih_timeout_sec < 60:
            self.wih_timeout_sec = 60
        if self.wih_concurrency < 1:
            self.wih_concurrency = 1
        if self.wih_concurrency_per_site < 1:
            self.wih_concurrency_per_site = 1
        self._help_text = None

    @staticmethod
    def _should_keep_plain_content(record_type: str, content: str) -> bool:
        record_type = str(record_type or "").strip().lower()
        content = str(content or "").strip().lower()
        if record_type in {"domain_url", "ip_url", "path_url", "urlfinder_url", "urlfinder_js"}:
            return True
        return content.startswith("http://") or content.startswith("https://")

    @staticmethod
    def _is_js_source(source: str, site: str) -> bool:
        source_text = str(source or "").strip()
        site_text = str(site or "").strip()
        if not source_text:
            return False
        parsed = urlparse(source_text)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            if is_js_resource_path(parsed.path or ""):
                return True
        return bool(site_text and source_text != site_text and source_text.endswith((".js", ".mjs")))

    @staticmethod
    def _should_keep_email_content(content: str) -> bool:
        text = str(content or "").strip()
        if "@" not in text:
            return False

        domain = text.rsplit("@", 1)[-1].strip().lower().rstrip(".")
        if "." not in domain:
            return False

        suffix = domain.rsplit(".", 1)[-1]
        if suffix in _EMAIL_STATIC_SUFFIXES:
            return False

        if re.search(r"(?i)@(1x|2x|3x|4x|5x)(?:-[a-f0-9]{4,})?\.[a-z0-9]{2,10}$", text):
            return False

        return True

    @staticmethod
    def _is_host_like_path_segment(segment: str) -> bool:
        text = str(segment or "").strip().lower().rstrip(".")
        if not text:
            return False
        if text.startswith("localhost"):
            return True
        if _HOST_LIKE_SEGMENT_RE.match(text):
            return True
        if ":" in text:
            host_part = text.split(":", 1)[0].strip()
            if host_part and utils.is_valid_domain(host_part):
                return True
        return utils.is_valid_domain(text)

    @staticmethod
    def _should_keep_path_content(content: str, source: str, site: str) -> bool:
        path_text = strip_route_method_suffix(str(content or "").strip())
        if not path_text or not path_text.startswith("/"):
            return False
        if len(path_text) > 180:
            return False
        if any(token in path_text for token in ("\r", "\n", "\t", "\\", " ")):
            return False
        if has_route_template_markers(path_text):
            return False
        if is_js_resource_path(path_text) or is_non_js_static_resource_path(path_text):
            return False
        if _PATH_CODE_MARKER_RE.search(path_text):
            return False

        raw_text = path_text.strip("/")
        if not raw_text:
            return False

        first_segment = raw_text.split("/", 1)[0].strip()
        if InfoHunter._is_host_like_path_segment(first_segment):
            return False

        is_js_source = InfoHunter._is_js_source(source, site)
        if is_js_source and any(token in path_text for token in ("(", ")", ",", "=", "$")):
            return False

        if "/" not in raw_text:
            lowered = raw_text.lower()
            if is_noise_single_segment_path(path_text):
                return False
            if lowered.isdigit():
                return False
            if lowered in _PATH_NOISE_SINGLE_SEGMENTS:
                return False
            if is_js_source and len(lowered) <= 3 and lowered not in _PATH_SHORT_ALLOWLIST:
                return False

        return True

    @staticmethod
    def _normalize_record_content(record_type: str, content: str, source: str = "", site: str = "") -> str:
        normalized_type = str(record_type or "").strip().lower()
        text = str(content or "").strip()
        if not normalized_type or not text:
            return ""

        if normalized_type == "email":
            return text if InfoHunter._should_keep_email_content(text) else ""

        if normalized_type == "path":
            normalized_path = strip_route_method_suffix(text)
            return normalized_path if InfoHunter._should_keep_path_content(normalized_path, source, site) else ""

        return text

    @staticmethod
    def _resolve_wih_binary() -> str:
        # 优先使用本地/挂载目录下的“成品二进制”，其次回退到镜像内编译产物。
        candidates = [
            "/code/tools/wih/wih",
            "/code/tools/wih/wihscan",
            "/code/tools/wih/bin/wih",
            "/code/tools/wih/bin/wihscan",
            "wihscan",
            "wih",
        ]
        for candidate in candidates:
            binary_path = utils.resolve_executable(candidate)
            if binary_path:
                return binary_path
        return "wih"

    def _get_target_file(self):
        with open(self.wih_target_path, "w") as f:
            for site in self.sites:
                site = str(site or "").strip()
                if site:
                    f.write(site + "\n")

    def _delete_file(self):
        try:
            os.unlink(self.wih_target_path)
            # 删除结果临时文件
            if os.path.exists(self.wih_result_path):
                os.unlink(self.wih_result_path)
        except Exception as e:
            logger.warning(e)

    def _load_help_text(self) -> str:
        if self._help_text is not None:
            return self._help_text

        try:
            output = utils.check_output([self.wih_bin_path, "-h"], timeout=2 * 60, stderr=subprocess.STDOUT)
            self._help_text = str(output or b"", "utf-8", errors="ignore")
        except Exception:
            self._help_text = ""

        return self._help_text

    def _supports_flag(self, flag_text: str) -> bool:
        return flag_text in self._load_help_text()

    @staticmethod
    def _resolve_rule_path() -> str:
        configured_path = str(getattr(Config, "WIH_RULE_PATH", "") or "").strip()
        if configured_path and os.path.isfile(configured_path):
            return configured_path

        if configured_path:
            logger.warning("wih rule path not found: {}, fallback to built-in/default".format(configured_path))

        return ""

    def _build_command(self, minimal=False) -> list:
        command = [
            self.wih_bin_path,
            "-J",
            "-o",
            self.wih_result_path,
            "-t",
            self.wih_target_path,
        ]

        if minimal:
            return command

        rule_path = self._resolve_rule_path()
        if rule_path:
            command.extend(["-r", rule_path])

        # 兼容不同 WIH 版本参数差异：仅在帮助信息里检测到时才追加。
        if self._supports_flag("--concurrency"):
            command.extend(["--concurrency", str(self.wih_concurrency)])
        elif self._supports_flag("-c"):
            command.extend(["-c", str(self.wih_concurrency)])

        if self._supports_flag("--log-level"):
            command.extend(["--log-level", "zero"])
        elif self._supports_flag("-v"):
            command.extend(["-v", "zero"])

        if self._supports_flag("--concurrency-per-site"):
            command.extend(["--concurrency-per-site", str(self.wih_concurrency_per_site)])

        if self._supports_flag("--disable-ak-sk-output"):
            command.append("--disable-ak-sk-output")

        proxy_url = str(getattr(Config, "PROXY_URL", "") or "").strip()
        if proxy_url:
            if self._supports_flag("--proxy"):
                command.extend(["--proxy", proxy_url])
            elif self._supports_flag("-x"):
                command.extend(["-x", proxy_url])

        return command

    def exec_wih(self):
        command = self._build_command(minimal=False)
        logger.info(
            "run wih command timeout:{}s concurrency:{} per_site:{} cmd:{}".format(
                self.wih_timeout_sec,
                self.wih_concurrency,
                self.wih_concurrency_per_site,
                " ".join(command),
            )
        )
        completed = utils.exec_system(
            command,
            timeout=self.wih_timeout_sec,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if completed.returncode == 0:
            return True

        stderr_text = completed.stderr.decode("utf-8", errors="ignore").strip() if completed.stderr else ""
        stdout_text = completed.stdout.decode("utf-8", errors="ignore").strip() if completed.stdout else ""
        logger.warning(
            "wih command failed rc={} stderr={} stdout={}".format(
                completed.returncode, stderr_text[:500], stdout_text[:500]
            )
        )

        # 失败后回退最小参数集，兼容历史二进制或参数差异。
        fallback_command = self._build_command(minimal=True)
        logger.info("retry wih command (minimal): {}".format(" ".join(fallback_command)))
        fallback_completed = utils.exec_system(
            fallback_command,
            timeout=self.wih_timeout_sec,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if fallback_completed.returncode == 0:
            return True

        fb_stderr = fallback_completed.stderr.decode("utf-8", errors="ignore").strip() if fallback_completed.stderr else ""
        fb_stdout = fallback_completed.stdout.decode("utf-8", errors="ignore").strip() if fallback_completed.stdout else ""
        logger.warning(
            "wih minimal command failed rc={} stderr={} stdout={}".format(
                fallback_completed.returncode, fb_stderr[:500], fb_stdout[:500]
            )
        )
        return False

    def check_have_wih(self) -> bool:
        command = [self.wih_bin_path, "--version"]
        try:
            completed = utils.exec_system(
                command,
                timeout=2 * 60,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if completed.returncode != 0:
                return False

            output_text = completed.stdout.decode("utf-8", errors="ignore").strip() if completed.stdout else ""
            normalized = output_text.lower()
            if output_text and (
                "version" in normalized or normalized.startswith("v") or normalized[0].isdigit()
            ):
                return True
            # 某些旧版二进制 --version 无输出，回退校验 -h。
            help_text = self._load_help_text()
            if help_text and ("webinfohunter" in help_text.lower() or "wih" in help_text.lower()):
                return True
        except Exception as e:
            logger.debug("{}".format(str(e)))

        return False

    def dump_result(self) -> list:
        results = []
        total_items = 0
        invalid_items = 0
        filtered_items = 0

        # 检查结果文件是否存在
        if not os.path.exists(self.wih_result_path):
            logger.warning("wih result file not found: {}".format(self.wih_result_path))
            return results

        with open(self.wih_result_path, "r", encoding="utf-8", errors="ignore") as f:
            raw_text = str(f.read() or "").strip()

        payload_items = []
        if not raw_text:
            payload_items = []
        elif raw_text.startswith("["):
            try:
                payload = json.loads(raw_text)
                if isinstance(payload, list):
                    payload_items = payload
                elif isinstance(payload, dict):
                    payload_items = [payload]
            except Exception as e:
                logger.debug("parse wih json array failed err:{}".format(e))
                payload_items = []
        else:
            for line in raw_text.splitlines():
                line = str(line or "").strip()
                if not line:
                    continue
                try:
                    payload_items.append(json.loads(line))
                except Exception as e:
                    invalid_items += 1
                    logger.debug("skip invalid wih json line err:{} line:{}".format(e, line[:200]))

        for data in payload_items:
            total_items += 1
            if not isinstance(data, dict):
                invalid_items += 1
                continue

            site = str(data.get("target") or data.get("url") or data.get("site") or "").strip()
            if not site:
                invalid_items += 1
                continue

            records = data.get("records")
            if not isinstance(records, list):
                records = data.get("result")
            if not isinstance(records, list):
                records = data.get("results")
            if not isinstance(records, list):
                continue

            for item in records:
                if not isinstance(item, dict):
                    continue

                record_type = str(item.get("id") or item.get("type") or item.get("name") or "").strip()
                raw_content = str(item.get("content") or item.get("value") or item.get("match") or "").strip()
                source = str(item.get("source") or item.get("from") or site or "").strip()
                content = self._normalize_record_content(record_type, raw_content, source=source, site=site)
                if not record_type or not content:
                    filtered_items += 1
                    continue

                tag_text = str(item.get("tag") or item.get("rule") or "").strip()
                hash_needs_refresh = content != raw_content
                if tag_text and str(record_type or "").strip().lower() != "path" and \
                        (not self._should_keep_plain_content(record_type, content)):
                    content = "{} ({})".format(content, tag_text)
                    hash_needs_refresh = True

                hash_value = item.get("hash", item.get("fnv_hash"))
                try:
                    if hash_needs_refresh:
                        raise ValueError("refresh normalized hash")
                    hash_value = int(hash_value)
                except Exception:
                    hash_text = "{}|{}|{}|{}".format(record_type, content, source, site)
                    hash_digest = hashlib.md5(hash_text.encode("utf-8", errors="ignore")).hexdigest()
                    hash_value = int(hash_digest[:16], 16)

                record_dict = {
                    "record_type": record_type,
                    "content": content,
                    "source": source,
                    "site": site,
                    "fnv_hash": hash_value,
                }
                results.append(WihRecord(**record_dict))

        logger.info(
            "wih parsed result file:{} payload_items:{} invalid_items:{} filtered_items:{} records:{} bin:{}".format(
                self.wih_result_path, total_items, invalid_items, filtered_items, len(results), self.wih_bin_path
            )
        )
        return results

    def run(self):
        if not self.check_have_wih():
            logger.warning("not found webInfoHunter binary")
            return []

        self._get_target_file()
        if not self.exec_wih():
            self._delete_file()
            return []
        results = self.dump_result()
        self._delete_file()

        return results


def run_wih(sites: List[str]) -> List[WihRecord]:
    logger.info("run webInfoHunter, sites: {}".format(len(sites)))
    hunter = InfoHunter(sites)
    results = hunter.run()

    logger.info("webInfoHunter result: {}".format(len(results)))

    return results
