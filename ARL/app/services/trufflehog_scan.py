"""
TruffleHog JS 泄露扫描服务

功能说明：
- 基于 WIH 已发现的 JS 源 URL 进行二次秘密扫描
- 调用 trufflehog filesystem 模式，输出 JSON 结果
- 结果转换为 WihRecord，复用现有 wih 表进行统一展示与导出

设计原则：
- 默认禁用在线验证（--no-verification），降低外连和误触风险
- 结果默认原文入库，便于排查定位
- 二进制不存在/执行失败时仅记录日志，不中断主扫描流程
"""
import json
import os
import re
import shutil
import subprocess
from typing import Dict, List, Set
from urllib.parse import urlparse

from app import utils
from app.config import Config
from app.modules import WihRecord

logger = utils.get_logger()
DNS_POLICY_CACHE = {}


class TrufflehogJSScanner:
    """
    TruffleHog JS 扫描执行器
    """

    def __init__(self, sites: List[str], wih_records: List[WihRecord], waf_guard=None):
        self.sites = list(sites or [])
        self.wih_records = list(wih_records or [])
        self.waf_guard = waf_guard
        self.trufflehog_bin = str(getattr(Config, "TRUFFLEHOG_BIN", "trufflehog") or "trufflehog")
        self.no_verification = bool(getattr(Config, "TRUFFLEHOG_NO_VERIFICATION", True))
        self.result_types = str(getattr(Config, "TRUFFLEHOG_RESULTS", "verified,unknown,unverified") or "").strip()
        self.max_files = int(getattr(Config, "TRUFFLEHOG_JS_MAX_FILES", 80) or 80)
        self.scan_timeout = int(getattr(Config, "TRUFFLEHOG_JS_TIMEOUT_SEC", 900) or 900)
        self.max_file_bytes = int(getattr(Config, "TRUFFLEHOG_JS_MAX_FILE_BYTES", 512 * 1024) or (512 * 1024))

        if self.max_files < 1:
            self.max_files = 1
        if self.scan_timeout < 30:
            self.scan_timeout = 30
        if self.max_file_bytes < 1024:
            self.max_file_bytes = 1024

        self.tmp_root = Config.TMP_PATH
        self.rand = utils.random_choices(10)
        self.scan_dir = os.path.join(self.tmp_root, "trufflehog_js_{}".format(self.rand))
        self.file_source_map: Dict[str, str] = {}

    def _cleanup(self):
        try:
            shutil.rmtree(self.scan_dir, ignore_errors=True)
        except Exception as e:
            logger.debug("cleanup trufflehog tmp dir failed {}".format(e))

    def check_have_trufflehog(self) -> bool:
        self.trufflehog_bin = utils.resolve_executable(self.trufflehog_bin)
        if not self.trufflehog_bin:
            logger.info(
                "not found trufflehog binary, put it in tools/TruffleHog/trufflehog or set ARL_TRUFFLEHOG_BIN"
            )
            return False

        try:
            pro = subprocess.run(
                [self.trufflehog_bin, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=8,
                check=False,
            )
            if pro.returncode == 0:
                return True
        except Exception as e:
            logger.warning("check trufflehog binary failed {} {}".format(self.trufflehog_bin, e))

        return False

    @staticmethod
    def _is_http_url(value: str) -> bool:
        text = str(value or "").strip()
        return text.startswith("http://") or text.startswith("https://")

    @staticmethod
    def _is_js_url(value: str) -> bool:
        text = str(value or "").strip().lower()
        if not text:
            return False
        if ".js" in text:
            return True

        path = urlparse(text).path.lower()
        return path.endswith(".js")

    @staticmethod
    def _extract_host(value: str) -> str:
        """
        从 URL / host 文本中提取主机名（小写、去尾点）。
        """
        text = str(value or "").strip()
        if not text:
            return ""

        parsed = urlparse(text)
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if host:
            return host

        # 兼容无 scheme 的 host[:port] 文本
        parsed = urlparse("//{}".format(text))
        return str(parsed.hostname or "").strip().lower().rstrip(".")

    def _collect_allowed_hosts(self) -> Set[str]:
        """
        仅允许扫描当前任务目标站点（域名/IP）来源的 JS。
        """
        hosts: Set[str] = set()
        for site in self.sites:
            host = self._extract_host(site)
            if host:
                hosts.add(host)
        return hosts

    def _collect_js_urls(self) -> List[str]:
        js_urls: Set[str] = set()

        for record in self.wih_records:
            source = str(getattr(record, "source", "") or "").strip()
            if self._is_http_url(source) and self._is_js_url(source):
                js_urls.add(source)

            content = str(getattr(record, "content", "") or "").strip()
            if self._is_http_url(content) and self._is_js_url(content):
                js_urls.add(content)

        if not js_urls:
            logger.info("trufflehog js scan skip, not found js source from wih records")
            return []

        allowed_hosts = self._collect_allowed_hosts()
        if not allowed_hosts:
            logger.info("trufflehog js scan skip, not found allowed hosts from current target sites")
            return []

        filtered_js_urls: Set[str] = set()
        skipped = 0
        for js_url in js_urls:
            js_host = self._extract_host(js_url)
            if js_host and js_host in allowed_hosts:
                filtered_js_urls.add(js_url)
            else:
                skipped += 1

        if skipped > 0:
            logger.info(
                "trufflehog js host filter applied, allowed_hosts:{} kept:{} skipped:{}".format(
                    len(allowed_hosts),
                    len(filtered_js_urls),
                    skipped,
                )
            )

        if not filtered_js_urls:
            logger.info("trufflehog js scan skip, all js sources are out of current target hosts")
            return []

        js_url_list = sorted(filtered_js_urls)
        if len(js_url_list) > self.max_files:
            js_url_list = js_url_list[: self.max_files]

        return js_url_list

    @staticmethod
    def _safe_site_from_url(url: str) -> str:
        try:
            parsed = urlparse(str(url))
            if parsed.scheme and parsed.netloc:
                return "{}://{}".format(parsed.scheme, parsed.netloc)
        except Exception:
            pass
        return ""

    def _download_js_files(self, js_urls: List[str]) -> int:
        os.makedirs(self.scan_dir, exist_ok=True)

        saved_count = 0
        for index, js_url in enumerate(js_urls):
            allow_scan, policy_detail = utils.check_dns_policy_for_url(js_url, cache_map=DNS_POLICY_CACHE)
            if not allow_scan:
                logger.info(
                    "skip trufflehog js by dns policy url:{} reason:{} resolver_ips:{} system_ips:{}".format(
                        js_url,
                        policy_detail.get("reason", ""),
                        policy_detail.get("resolver_ips", []),
                        policy_detail.get("system_ips", []),
                    )
                )
                continue

            try:
                conn = utils.http_req(
                    js_url,
                    "get",
                    timeout=(5, 12),
                    waf_guard=self.waf_guard,
                    waf_module="trufflehog_js",
                )
            except Exception as e:
                logger.debug("download js failed {} {}".format(js_url, e))
                continue

            status_code = int(getattr(conn, "status_code", 0) or 0)
            if status_code >= 400:
                continue

            body = bytes(getattr(conn, "content", b"") or b"")
            if not body:
                continue

            body = body[: self.max_file_bytes]
            file_name = "js_{:04d}.js".format(index)
            file_path = os.path.abspath(os.path.join(self.scan_dir, file_name))

            try:
                with open(file_path, "wb") as file_obj:
                    file_obj.write(body)
            except Exception as e:
                logger.debug("write js tmp file failed {} {}".format(file_path, e))
                continue

            self.file_source_map[file_path] = js_url
            saved_count += 1

        return saved_count

    @staticmethod
    def _collect_strings(data, output: List[str]):
        if isinstance(data, dict):
            for _, value in data.items():
                TrufflehogJSScanner._collect_strings(value, output)
        elif isinstance(data, list):
            for item in data:
                TrufflehogJSScanner._collect_strings(item, output)
        elif isinstance(data, str):
            text = data.strip()
            if text:
                output.append(text)

    @staticmethod
    def _pick_first_by_keys(data, key_set: Set[str]):
        if isinstance(data, dict):
            for key, value in data.items():
                if str(key).strip().lower() in key_set and value not in ("", None, [], {}):
                    return value

            for _, value in data.items():
                hit = TrufflehogJSScanner._pick_first_by_keys(value, key_set)
                if hit not in ("", None, [], {}):
                    return hit
        elif isinstance(data, list):
            for item in data:
                hit = TrufflehogJSScanner._pick_first_by_keys(item, key_set)
                if hit not in ("", None, [], {}):
                    return hit

        return None

    def _resolve_source_url(self, payload: dict) -> str:
        all_strings: List[str] = []
        self._collect_strings(payload, all_strings)

        for text in all_strings:
            full_path = os.path.abspath(text)
            if full_path in self.file_source_map:
                return self.file_source_map[full_path]

        for text in all_strings:
            file_name = os.path.basename(text)
            if not file_name:
                continue
            for path_key, source_url in self.file_source_map.items():
                if os.path.basename(path_key) == file_name:
                    return source_url

        return ""

    @staticmethod
    def _pick_secret_value(payload: dict) -> str:
        """
        优先提取原始值，若不存在再回退到 redacted 字段
        """
        key_order = [
            "raw",
            "rawresult",
            "raw_v2",
            "rawv2",
            "secret",
            "redacted",
        ]
        for key_name in key_order:
            value = TrufflehogJSScanner._pick_first_by_keys(payload, {key_name})
            text = str(value or "").strip()
            if text:
                return text
        return ""

    @staticmethod
    def _sanitize_detector(detector: str) -> str:
        text = str(detector or "").strip().lower()
        if not text:
            return "secret"
        text = re.sub(r"[^a-z0-9_]+", "_", text)
        text = re.sub(r"_+", "_", text).strip("_")
        if not text:
            return "secret"
        return text[:60]

    @staticmethod
    def _stable_hash(text: str) -> int:
        # WihRecord.__hash__ 需要整数；将 md5 十六进制稳定映射为 64bit 整数。
        digest = utils.gen_md5(str(text or ""))
        return int(digest[:16], 16)

    def _build_record(self, payload: dict) -> WihRecord:
        detector = self._pick_first_by_keys(payload, {"detectorname", "detectortype", "detector"})
        detector = str(detector or "").strip()
        detector_name = self._sanitize_detector(detector)
        record_type = "trufflehog_{}".format(detector_name)

        result_type = self._pick_first_by_keys(payload, {"resulttype", "result_type"})
        result_type = str(result_type or "").strip().lower()
        if not result_type:
            verified = self._pick_first_by_keys(payload, {"verified", "isverified"})
            if isinstance(verified, bool):
                result_type = "verified" if verified else "unverified"

        secret_value = self._pick_secret_value(payload)
        if not secret_value:
            secret_value = "[empty]"

        content = secret_value
        if detector:
            content = "[{}] {}".format(detector, secret_value)
        if result_type:
            content = "{} ({})".format(content, result_type)

        source_url = self._resolve_source_url(payload)
        source = source_url or "system"
        site = self._safe_site_from_url(source_url)
        if not site and self.sites:
            site = str(self.sites[0])

        hash_text = "{}|{}|{}|{}".format(record_type, content, source, site)
        fnv_hash = self._stable_hash(hash_text)
        return WihRecord(
            record_type=record_type,
            content=content,
            source=source,
            site=site,
            fnv_hash=fnv_hash,
        )

    def _run_trufflehog(self) -> List[dict]:
        command = [
            self.trufflehog_bin,
            "filesystem",
            self.scan_dir,
            "--json",
            "--no-update",
        ]

        if self.result_types:
            command.append("--results={}".format(self.result_types))

        if self.no_verification:
            command.append("--no-verification")

        logger.info("run trufflehog js command: {}".format(" ".join(command)))
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.scan_timeout,
            check=False,
        )

        stdout_text = completed.stdout.decode("utf-8", errors="ignore")
        stderr_text = completed.stderr.decode("utf-8", errors="ignore").strip()
        if stderr_text:
            logger.info("trufflehog js stderr: {}".format(stderr_text))

        payload_list = []
        for line in stdout_text.splitlines():
            text = line.strip()
            if not text:
                continue
            if not text.startswith("{"):
                continue
            try:
                payload = json.loads(text)
            except Exception:
                continue
            if isinstance(payload, dict):
                payload_list.append(payload)

        return payload_list

    def run(self) -> List[WihRecord]:
        if not self.check_have_trufflehog():
            return []

        js_urls = self._collect_js_urls()
        if not js_urls:
            return []

        try:
            saved_count = self._download_js_files(js_urls)
            if saved_count <= 0:
                return []

            payload_list = self._run_trufflehog()
            records = []
            for payload in payload_list:
                try:
                    record = self._build_record(payload)
                except Exception as e:
                    logger.debug("build trufflehog record failed {}".format(e))
                    continue
                records.append(record)

            logger.info(
                "trufflehog js scan done, js_urls:{} saved_files:{} findings:{}".format(
                    len(js_urls),
                    saved_count,
                    len(records),
                )
            )
            return records
        except Exception as e:
            logger.warning("run trufflehog js scan failed {}".format(e))
            return []
        finally:
            self._cleanup()


def run_trufflehog_js(sites: List[str], wih_records: List[WihRecord], waf_guard=None) -> List[WihRecord]:
    """
    对 WIH 收集到的 JS 源执行 TruffleHog 泄漏扫描
    """
    scanner = TrufflehogJSScanner(sites=sites, wih_records=wih_records, waf_guard=waf_guard)
    return scanner.run()
