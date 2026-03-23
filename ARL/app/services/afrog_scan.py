"""
afrog 漏洞扫描
"""
import json
import os
import shlex
import subprocess
import time
import zipfile

from app import utils
from app.config import Config


logger = utils.get_logger()


class AfrogScan(object):
    """
    afrog 扫描执行器

    说明：
    - 以批量目标文件方式执行（-T）
    - 优先加载本地 PoC 目录（-P）
    - 通过 -json 输出结果并解析
    """

    def __init__(self, targets, search_keywords=None, severity=None):
        self.targets = self._normalize_targets(targets)
        self.afrog_bin_path = str(getattr(Config, "AFROG_BIN", "") or "").strip()
        self.afrog_pocs_dir = str(getattr(Config, "AFROG_POCS_DIR", "") or "").strip()
        self.afrog_search_keywords = str(getattr(Config, "AFROG_SEARCH_KEYWORDS", "") or "").strip()
        self.afrog_severity = str(getattr(Config, "AFROG_SEVERITY", "") or "").strip().lower()
        if search_keywords is not None:
            self.afrog_search_keywords = str(search_keywords or "").strip()
        if severity is not None:
            self.afrog_severity = str(severity or "").strip().lower()
        self.afrog_concurrency = int(getattr(Config, "AFROG_CONCURRENCY", 5) or 5)
        self.afrog_rate_limit = int(getattr(Config, "AFROG_RATE_LIMIT", 5) or 5)
        self.exec_timeout_sec = int(getattr(Config, "AFROG_EXEC_TIMEOUT_SEC", 7200) or 7200)
        self.stage_timeout_sec = int(getattr(Config, "AFROG_STAGE_TIMEOUT_SEC", 0) or 0)
        self.stage_max_targets = int(getattr(Config, "AFROG_STAGE_MAX_TARGETS", 0) or 0)
        self.targets_per_batch = int(getattr(Config, "AFROG_TARGETS_PER_BATCH", 50) or 50)
        if self.afrog_concurrency < 1:
            self.afrog_concurrency = 1
        if self.afrog_rate_limit < 1:
            self.afrog_rate_limit = 1
        if self.exec_timeout_sec < 60:
            self.exec_timeout_sec = 60
        if self.stage_timeout_sec < 0:
            self.stage_timeout_sec = 0
        if self.stage_max_targets < 0:
            self.stage_max_targets = 0
        if self.targets_per_batch < 1:
            self.targets_per_batch = 1

        self.tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()
        self.target_file = os.path.join(self.tmp_path, "afrog_target_{}.txt".format(rand_str))
        self.result_file = os.path.join(self.tmp_path, "afrog_result_{}.json".format(rand_str))

    def _get_afrog_base_dir(self):
        """
        获取 afrog 相关目录：
        - 优先使用 AFROG_BIN 所在目录
        - 为空时回退到项目 tools/afrog
        """
        configured = str(getattr(Config, "AFROG_BIN", "") or "").strip()
        if configured:
            return os.path.dirname(configured) or configured
        return os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "tools", "afrog"))

    @staticmethod
    def _runtime_arch_tokens():
        arch = str(utils.get_runtime_arch() or "").strip().lower()
        if arch in ["x86_64", "amd64"]:
            return ["amd64", "x86_64"]
        if arch in ["aarch64", "arm64"]:
            return ["arm64", "aarch64"]
        if arch:
            return [arch]
        return []

    def _find_linux_afrog_zip(self):
        base_dir = self._get_afrog_base_dir()
        if not os.path.isdir(base_dir):
            logger.warning("afrog base dir not found:{}".format(base_dir))
            return ""

        zip_files = []
        try:
            for file_name in os.listdir(base_dir):
                file_name = str(file_name or "").strip()
                if file_name.lower().endswith(".zip") and file_name.lower().startswith("afrog"):
                    zip_files.append(os.path.join(base_dir, file_name))
        except Exception as e:
            logger.warning("list afrog zip failed dir:{} err:{}".format(base_dir, e))
            return ""

        if not zip_files:
            return ""

        linux_zips = []
        windows_zips = []
        for zip_path in zip_files:
            zip_name = os.path.basename(zip_path).lower()
            if "linux" in zip_name:
                linux_zips.append(zip_path)
            if "windows" in zip_name:
                windows_zips.append(zip_path)

        if not linux_zips:
            if windows_zips:
                logger.warning("afrog only windows zip found:{} please provide linux package".format(
                    ",".join([os.path.basename(x) for x in windows_zips])[:300]
                ))
            return ""

        arch_tokens = self._runtime_arch_tokens()
        for zip_path in sorted(linux_zips, reverse=True):
            zip_name = os.path.basename(zip_path).lower()
            if arch_tokens and any(token in zip_name for token in arch_tokens):
                return zip_path

        return sorted(linux_zips, reverse=True)[0]

    def _extract_binary_from_zip(self, zip_path):
        if not zip_path or not os.path.isfile(zip_path):
            return ""

        zip_tag = "{}_{}_{}".format(
            os.path.basename(zip_path),
            int(os.path.getmtime(zip_path)),
            int(os.path.getsize(zip_path)),
        )
        extract_root = os.path.join(self.tmp_path, "afrog_extract", str(utils.stable_hash(zip_tag)))
        os.makedirs(extract_root, 0o755, True)

        cached_bin = os.path.join(extract_root, "afrog")
        if os.path.isfile(cached_bin) and os.access(cached_bin, os.X_OK):
            return cached_bin

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_file:
                file_infos = [info for info in zip_file.infolist() if not info.is_dir()]
                if not file_infos:
                    logger.warning("afrog zip has no file:{}".format(zip_path))
                    return ""

                binary_info = None
                for info in file_infos:
                    base_name = os.path.basename(str(info.filename or ""))
                    base_name_lc = base_name.lower()
                    if base_name_lc == "afrog":
                        binary_info = info
                        break
                if binary_info is None:
                    for info in file_infos:
                        base_name = os.path.basename(str(info.filename or ""))
                        base_name_lc = base_name.lower()
                        if base_name_lc.endswith(".exe"):
                            continue
                        if base_name_lc.startswith("afrog"):
                            binary_info = info
                            break

                if binary_info is None:
                    logger.warning("afrog zip binary not found zip:{}".format(zip_path))
                    return ""

                extracted_path = zip_file.extract(binary_info, path=extract_root)
                if not extracted_path:
                    return ""

                try:
                    os.chmod(extracted_path, 0o755)
                except Exception:
                    pass

                if extracted_path != cached_bin:
                    try:
                        with open(extracted_path, "rb") as src, open(cached_bin, "wb") as dst:
                            dst.write(src.read())
                        os.chmod(cached_bin, 0o755)
                    except Exception:
                        cached_bin = extracted_path

                resolved_bin = utils.resolve_executable(cached_bin)
                if resolved_bin:
                    logger.info("afrog binary extracted from zip:{} -> {}".format(zip_path, resolved_bin))
                    return resolved_bin
        except zipfile.BadZipFile:
            logger.warning("afrog zip invalid:{}".format(zip_path))
        except Exception as e:
            logger.warning("extract afrog binary failed zip:{} err:{}".format(zip_path, e))

        return ""

    def _resolve_afrog_binary(self):
        configured_bin = str(self.afrog_bin_path or "").strip()
        resolved_bin = utils.resolve_executable(configured_bin)
        if resolved_bin:
            return resolved_bin

        zip_path = self._find_linux_afrog_zip()
        if not zip_path:
            return ""

        return self._extract_binary_from_zip(zip_path)

    @staticmethod
    def _normalize_targets(targets):
        target_set = set()
        for item in targets or []:
            target = str(item or "").strip()
            if not target:
                continue
            target_set.add(target)

        return sorted(target_set)

    def _delete_file(self):
        for file_path in [self.target_file, self.result_file]:
            try:
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning("delete afrog temp file failed {} {}".format(file_path, e))

    def _resolve_pocs_dir(self):
        pocs_dir = str(self.afrog_pocs_dir or "").strip()
        if pocs_dir and os.path.isdir(pocs_dir):
            return pocs_dir

        compat_candidates = []
        if pocs_dir:
            compat_candidates.append(os.path.join(pocs_dir, "afrog-pocs"))
        compat_candidates.append(os.path.join(os.path.dirname(self.afrog_bin_path or ""), "afrog-pocs"))

        for candidate in compat_candidates:
            candidate = str(candidate or "").strip()
            if not candidate:
                continue
            if os.path.isdir(candidate):
                return candidate

        return ""

    def check_have_afrog(self):
        self.afrog_bin_path = self._resolve_afrog_binary()
        if not self.afrog_bin_path:
            logger.warning("not found afrog binary, configured:{} base_dir:{}".format(
                str(getattr(Config, "AFROG_BIN", "") or "").strip() or "-",
                self._get_afrog_base_dir(),
            ))
            return False

        try:
            completed = utils.exec_system(
                [shlex.quote(self.afrog_bin_path), "-h"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
            # afrog 帮助命令在不同版本可能返回 0/1，二者都视为“可执行文件可用”。
            if completed.returncode in [0, 1]:
                logger.info("afrog binary ready path:{}".format(self.afrog_bin_path))
                return True
            stderr_text = completed.stderr.decode("utf-8", errors="ignore").strip() if completed.stderr else ""
            stdout_text = completed.stdout.decode("utf-8", errors="ignore").strip() if completed.stdout else ""
            logger.warning(
                "afrog binary check failed rc:{} path:{} stderr:{} stdout:{}".format(
                    completed.returncode, self.afrog_bin_path, stderr_text[:300], stdout_text[:300]
                )
            )
        except Exception as e:
            logger.warning("afrog check failed {} error:{}".format(self.afrog_bin_path, e))

        return False

    def _gen_target_file(self, targets):
        with open(self.target_file, "w", encoding="utf-8") as f:
            for target in targets:
                f.write(target + "\n")
        logger.info("afrog targets prepared count:{} file:{}".format(len(targets), self.target_file))

    @staticmethod
    def _normalize_severity(value):
        severity = str(value or "").strip().lower()
        if severity in {"critical", "high", "medium", "low", "info"}:
            return severity
        return "info"

    @staticmethod
    def _safe_json_loads(text):
        raw = str(text or "").strip()
        if not raw:
            return []

        try:
            return json.loads(raw)
        except Exception:
            pass

        # afrog 写入中断时可能缺失右中括号，补齐后再尝试解析。
        if raw.startswith("[") and not raw.endswith("]"):
            try:
                return json.loads(raw + "]")
            except Exception:
                pass

        # 兜底兼容按行 JSON 的格式。
        items = []
        for line in raw.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in {"[", "]"}:
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue
            if isinstance(data, dict):
                items.append(data)
        return items

    def _load_results(self):
        if not os.path.exists(self.result_file):
            return []

        try:
            with open(self.result_file, "r", encoding="utf-8", errors="ignore") as f:
                payload = self._safe_json_loads(f.read())
        except Exception as e:
            logger.warning("read afrog result failed {}".format(e))
            return []

        if isinstance(payload, dict):
            if isinstance(payload.get("results"), list):
                payload = payload.get("results") or []
            else:
                payload = [payload]

        if not isinstance(payload, list):
            return []

        results = []
        for item in payload:
            if not isinstance(item, dict):
                continue

            info = item.get("info", {})
            if not isinstance(info, dict):
                info = {}

            poc_id = str(item.get("id", "") or "").strip()
            target = str(item.get("fulltarget", "") or "").strip()
            if not target:
                target = str(item.get("target", "") or "").strip()

            vuln_name = str(info.get("name", "") or "").strip()
            if not vuln_name:
                vuln_name = poc_id or "afrog 漏洞"

            severity = self._normalize_severity(info.get("severity", item.get("severity", "")))
            description = str(info.get("description", "") or "").strip()
            reference = info.get("reference", [])
            if isinstance(reference, str):
                reference = [reference]
            if not isinstance(reference, list):
                reference = []

            # 限制长度，避免单条结果过大影响风险模块展示。
            verify_payload = {
                "id": poc_id,
                "target": target,
                "reference": reference[:10],
            }
            request_text = str(item.get("request", "") or "").strip()
            response_text = str(item.get("response", "") or "").strip()
            if request_text:
                verify_payload["request"] = request_text[:1500]
            if response_text:
                verify_payload["response"] = response_text[:1500]

            verify_data = json.dumps(verify_payload, ensure_ascii=False)
            if len(verify_data) > 4096:
                verify_data = "{}...[truncated]".format(verify_data[:4096])

            results.append(
                {
                    "poc_id": poc_id,
                    "target": target,
                    "vuln_name": vuln_name,
                    "severity": severity,
                    "description": description,
                    "verify_data": verify_data,
                }
            )

        return results

    def _build_command(self):
        command = [
            shlex.quote(self.afrog_bin_path),
            "-T {}".format(shlex.quote(self.target_file)),
            "-json {}".format(shlex.quote(self.result_file)),
            "-c {}".format(int(self.afrog_concurrency)),
            "-rl {}".format(int(self.afrog_rate_limit)),
        ]

        pocs_dir = self._resolve_pocs_dir()
        if pocs_dir:
            command.append("-P {}".format(shlex.quote(pocs_dir)))
            logger.info("afrog pocs dir resolved:{}".format(pocs_dir))
        else:
            logger.warning(
                "afrog pocs dir unavailable config:{} bin_dir:{}".format(
                    self.afrog_pocs_dir,
                    os.path.dirname(self.afrog_bin_path or ""),
                )
            )

        if self.afrog_search_keywords:
            command.append("-s {}".format(shlex.quote(self.afrog_search_keywords)))

        if self.afrog_severity:
            command.append("-S {}".format(shlex.quote(self.afrog_severity)))

        return command

    def _apply_stage_target_limit(self):
        limit = int(self.stage_max_targets or 0)
        if limit <= 0:
            return

        total = len(self.targets)
        if total <= limit:
            return

        self.targets = self.targets[:limit]
        logger.warning(
            "afrog stage target cap reached total:{} limit:{} skipped:{}".format(
                total, limit, total - limit
            )
        )

    @staticmethod
    def _split_target_batches(targets, batch_size):
        if batch_size < 1:
            batch_size = 1
        for idx in range(0, len(targets), batch_size):
            yield targets[idx: idx + batch_size]

    def _calc_batch_timeout(self, stage_start_time):
        timeout_sec = int(self.exec_timeout_sec)
        if self.stage_timeout_sec > 0:
            remaining = int(self.stage_timeout_sec - (time.time() - stage_start_time))
            if remaining <= 0:
                return 0
            timeout_sec = min(timeout_sec, max(1, remaining))
        return timeout_sec

    def run(self):
        if not self.targets:
            return []

        if not self.check_have_afrog():
            logger.warning("skip afrog scan, binary unavailable")
            return []

        self._apply_stage_target_limit()
        if not self.targets:
            logger.info("afrog targets all skipped by stage target cap")
            return []

        logger.info(
            "afrog scan options exec_timeout:{}s stage_timeout:{}s batch_size:{} stage_target_cap:{} concurrency:{} rate_limit:{} keywords:{} severity:{}".format(
                self.exec_timeout_sec,
                self.stage_timeout_sec,
                self.targets_per_batch,
                self.stage_max_targets,
                self.afrog_concurrency,
                self.afrog_rate_limit,
                self.afrog_search_keywords or "-",
                self.afrog_severity or "-",
            )
        )

        stage_start_time = time.time()
        all_results = []
        seen_keys = set()
        timeout_reached = False
        target_batches = list(self._split_target_batches(self.targets, self.targets_per_batch))
        total_batches = len(target_batches)

        try:
            for batch_idx, batch_targets in enumerate(target_batches, start=1):
                batch_timeout = self._calc_batch_timeout(stage_start_time)
                elapsed = time.time() - stage_start_time
                if batch_timeout <= 0:
                    timeout_reached = True
                    logger.warning(
                        "afrog stage timeout reached elapsed:{:.2f}s timeout:{}s finished_batch:{}/{}".format(
                            elapsed, self.stage_timeout_sec, batch_idx - 1, total_batches
                        )
                    )
                    break

                self._gen_target_file(batch_targets)
                try:
                    if os.path.exists(self.result_file):
                        os.unlink(self.result_file)
                except Exception:
                    pass
                command = self._build_command()
                logger.info(
                    "afrog batch {}/{} targets:{} timeout:{}s cmd:{}".format(
                        batch_idx, total_batches, len(batch_targets), batch_timeout, " ".join(command)
                    )
                )

                stdout_text = ""
                stderr_text = ""
                return_code = -1
                try:
                    completed = utils.exec_system(
                        command,
                        timeout=batch_timeout,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    return_code = int(completed.returncode)
                    stdout_text = completed.stdout.decode("utf-8", errors="ignore").strip() if completed.stdout else ""
                    stderr_text = completed.stderr.decode("utf-8", errors="ignore").strip() if completed.stderr else ""
                except subprocess.TimeoutExpired as e:
                    stdout_text = e.stdout.decode("utf-8", errors="ignore").strip() if getattr(e, "stdout", None) else ""
                    stderr_text = e.stderr.decode("utf-8", errors="ignore").strip() if getattr(e, "stderr", None) else ""
                    logger.warning(
                        "afrog batch timeout {}/{} timeout={}s stderr={} stdout={}".format(
                            batch_idx, total_batches, batch_timeout, stderr_text[:500], stdout_text[:500]
                        )
                    )
                except Exception as e:
                    logger.warning("afrog batch run failed {}/{} error:{}".format(batch_idx, total_batches, e))

                batch_results = self._load_results()
                if return_code not in [0] and len(batch_results) == 0:
                    logger.warning(
                        "afrog batch exit non-zero and no result {}/{} rc:{} stderr={} stdout={}".format(
                            batch_idx, total_batches, return_code, stderr_text[:500], stdout_text[:500]
                        )
                    )

                merged_count = 0
                for item in batch_results:
                    key = (
                        str(item.get("target", "")).strip(),
                        str(item.get("poc_id", "")).strip(),
                        str(item.get("vuln_name", "")).strip(),
                    )
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    all_results.append(item)
                    merged_count += 1

                logger.info(
                    "afrog batch done {}/{} rc:{} raw_result:{} merged_new:{} merged_total:{} stderr={} stdout={}".format(
                        batch_idx,
                        total_batches,
                        return_code,
                        len(batch_results),
                        merged_count,
                        len(all_results),
                        stderr_text[:300],
                        stdout_text[:300],
                    )
                )
        finally:
            self._delete_file()

        if timeout_reached:
            logger.warning(
                "afrog stage timeout reached timeout:{}s elapsed:{:.2f}s partial_result:{}".format(
                    self.stage_timeout_sec, time.time() - stage_start_time, len(all_results)
                )
            )
        logger.info("afrog run done result:{}".format(len(all_results)))
        return all_results


def run_afrog_scan(targets, search_keywords=None, severity=None):
    if not targets:
        return []

    scanner = AfrogScan(targets=targets, search_keywords=search_keywords, severity=severity)
    return scanner.run()
