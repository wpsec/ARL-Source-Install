"""
afrog 漏洞扫描
"""
import json
import os
import shlex
import subprocess

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

    def __init__(self, targets):
        self.targets = self._normalize_targets(targets)
        self.afrog_bin_path = str(getattr(Config, "AFROG_BIN", "") or "").strip()
        self.afrog_pocs_dir = str(getattr(Config, "AFROG_POCS_DIR", "") or "").strip()
        self.afrog_search_keywords = str(getattr(Config, "AFROG_SEARCH_KEYWORDS", "") or "").strip()
        self.afrog_severity = str(getattr(Config, "AFROG_SEVERITY", "") or "").strip().lower()
        self.exec_timeout_sec = int(getattr(Config, "AFROG_EXEC_TIMEOUT_SEC", 7200) or 7200)
        if self.exec_timeout_sec < 60:
            self.exec_timeout_sec = 60

        self.tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()
        self.target_file = os.path.join(self.tmp_path, "afrog_target_{}.txt".format(rand_str))
        self.result_file = os.path.join(self.tmp_path, "afrog_result_{}.json".format(rand_str))

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
        self.afrog_bin_path = utils.resolve_executable(self.afrog_bin_path)
        if not self.afrog_bin_path:
            logger.warning("not found afrog binary, set ARL.AFROG_BIN or ARL_AFROG_BIN")
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
        except Exception as e:
            logger.warning("afrog check failed {} error:{}".format(self.afrog_bin_path, e))

        return False

    def _gen_target_file(self):
        with open(self.target_file, "w", encoding="utf-8") as f:
            for target in self.targets:
                f.write(target + "\n")

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
        ]

        pocs_dir = self._resolve_pocs_dir()
        if pocs_dir:
            command.append("-P {}".format(shlex.quote(pocs_dir)))
        else:
            logger.warning(
                "afrog pocs dir unavailable config:{} bin_dir:{}",
                self.afrog_pocs_dir,
                os.path.dirname(self.afrog_bin_path or ""),
            )

        if self.afrog_search_keywords:
            command.append("-s {}".format(shlex.quote(self.afrog_search_keywords)))

        if self.afrog_severity:
            command.append("-S {}".format(shlex.quote(self.afrog_severity)))

        return command

    def run(self):
        if not self.targets:
            return []

        if not self.check_have_afrog():
            logger.warning("skip afrog scan, binary unavailable")
            return []

        self._gen_target_file()
        command = self._build_command()
        logger.info(
            "afrog scan options timeout:{}s keywords:{} severity:{}",
            self.exec_timeout_sec,
            self.afrog_search_keywords or "-",
            self.afrog_severity or "-",
        )
        logger.info("afrog command targets:{} cmd:{}".format(len(self.targets), " ".join(command)))
        stdout_text = ""
        stderr_text = ""
        return_code = -1
        try:
            completed = utils.exec_system(
                command,
                timeout=self.exec_timeout_sec,
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
                "afrog run timeout timeout={}s stderr={} stdout={}".format(
                    self.exec_timeout_sec, stderr_text[:500], stdout_text[:500]
                )
            )
        except Exception as e:
            logger.warning("afrog run failed {}".format(e))

        results = self._load_results()
        if return_code not in [0] and len(results) == 0:
            logger.warning(
                "afrog run exit non-zero and no result rc:{} stderr={} stdout={}".format(
                    return_code, stderr_text[:500], stdout_text[:500]
                )
            )
        logger.info(
            "afrog run done rc:{} result:{} stderr={} stdout={}".format(
                return_code, len(results), stderr_text[:300], stdout_text[:300]
            )
        )
        self._delete_file()

        return results


def run_afrog_scan(targets):
    if not targets:
        return []

    scanner = AfrogScan(targets=targets)
    return scanner.run()
