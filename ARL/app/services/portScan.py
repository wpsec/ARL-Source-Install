"""
端口扫描执行
"""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import math
import threading
import time
from app import utils
from app.utils import nmap
from app.config import Config
from app.utils.log_safety import safe_error_text

logger = utils.get_logger()


class PortScanResult(list):
    """保持 list 兼容，同时携带本次扫描的独立批次指标。"""

    def __init__(self, values=None, metrics=None, scan_coverage=None):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})
        self.scan_coverage = dict(scan_coverage or {})


class PortScanBatchResult(list):
    """保持批次结果的 list 兼容，同时携带本批次执行指标。"""

    def __init__(self, values=None, metrics=None):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})


class PortScan:
    def __init__(self, targets, ports=None, service_detect=False, os_detect=False,
                 port_parallelism=None, port_min_rate=None, custom_host_timeout=None):
        self.target_list = [str(item or "").strip() for item in (targets or []) if str(item or "").strip()]
        self.ports = str(ports or "").strip() or Config.TOP_10
        self.requested_port_count = self._estimate_port_count(self.ports)
        self.service_detect = bool(service_detect)
        self.os_detect = bool(os_detect)
        self.custom_host_timeout = self._safe_positive_int(custom_host_timeout, 0, min_value=1)

        self.max_host_group = 32
        self.alive_port = "22,80,443,843,3389,8007-8011,8443,9090,8080-8091,8093,8099,5000-5004,2222,3306,1433,21,25"
        self.max_retries = 3
        self.base_host_timeout = 60 * 5
        self.parallelism = self._safe_positive_int(port_parallelism, Config.PORT_PARALLELISM)
        self.min_rate = self._safe_positive_int(port_min_rate, Config.PORT_MIN_RATE)
        self.syn_scan_enabled = bool(getattr(Config, "PORT_SCAN_SYN_ENABLE", True))
        self.syn_scan_fallback_enabled = bool(
            getattr(Config, "PORT_SCAN_SYN_FALLBACK_ENABLE", True)
        )
        self._syn_scan_unavailable = False
        self._syn_scan_state_lock = threading.Lock()
        self.base_nmap_arguments = "{} -n --open".format(
            "-sS" if self.syn_scan_enabled else "-sT"
        )

        # 扫描分片大小：避免一次性 nmap 扫描过多目标导致任务长时间无输出。
        self.port_scan_target_batch_size = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_TARGET_BATCH_SIZE", 24), 24
        )
        self.port_scan_heavy_target_batch_size = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_HEAVY_TARGET_BATCH_SIZE", 8), 8
        )
        self.port_scan_all_target_batch_size = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_ALL_TARGET_BATCH_SIZE", 1), 1
        )
        # 只并行独立 nmap 批次；上限由配置约束，避免把全端口扫描变成进程洪峰。
        self.batch_concurrency = min(
            max(1, self._safe_positive_int(
                getattr(Config, "PORT_SCAN_BATCH_CONCURRENCY", 3), 3
            )),
            4,
        )
        self.batch_timeout_sec = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_BATCH_TIMEOUT_SEC", 600),
            600,
            min_value=0,
        )
        self.last_scan_metrics = {}
        self._last_completed_scan_methods = {}

        # 二阶段精扫端口分段大小：
        # 说明：这里不做“裁剪”，仅做“分段”，确保结果完整不缩水。
        self.stage2_port_chunk_size = self._safe_positive_int(
            getattr(
                Config,
                "PORT_SCAN_STAGE2_PORT_CHUNK_SIZE",
                getattr(Config, "PORT_SCAN_STAGE2_MAX_PORTS_PER_HOST", 300)
            ),
            300
        )
        # 端口扫描阶段超时预算（秒）：基础值 + 按目标数追加 + 按端口规模追加（带上限）。
        self.stage_timeout_base_sec = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_STAGE_TIMEOUT_SEC", 900),
            900,
            min_value=0,
        )
        self.stage_timeout_per_target_sec = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_STAGE_TIMEOUT_PER_TARGET_SEC", 90),
            90,
            min_value=0,
        )
        self.stage_timeout_per_1000_ports_sec = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_STAGE_TIMEOUT_PER_1000_PORTS_SEC", 120),
            120,
            min_value=0,
        )
        self.stage_timeout_max_sec = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_STAGE_TIMEOUT_MAX_SEC", 3600),
            3600,
            min_value=0,
        )

        self._apply_scan_profile()

    @staticmethod
    def _safe_positive_int(value, default, min_value=1):
        try:
            num = int(value)
        except Exception:
            return default

        if num < min_value:
            return default

        return num

    def _apply_scan_profile(self):
        port_token_count = len([x for x in self.ports.split(",") if str(x).strip()])

        if port_token_count > 60:
            self.base_nmap_arguments += " -PE -PS{}".format(self.alive_port)
            self.max_retries = 2
        elif self.ports != "0-65535":
            self.base_nmap_arguments += " -Pn"

        if self.ports == "0-65535":
            self.max_host_group = 2
            self.min_rate = max(self.min_rate, 800)
            self.parallelism = max(self.parallelism, 128)
            self.base_nmap_arguments += " -PE -PS{}".format(self.alive_port)
            self.base_host_timeout += 60 * 5
            self.max_retries = 2

    def _build_nmap_arguments(self, enable_service=False, enable_os=False):
        host_timeout = self.base_host_timeout
        args = self.base_nmap_arguments

        if enable_service:
            host_timeout += 60 * 5
            args += " -sV"

        if enable_os:
            host_timeout += 60 * 4
            args += " -O"

        if self.custom_host_timeout > 0:
            host_timeout = self.custom_host_timeout

        args += " --max-rtt-timeout 800ms"
        args += " --min-rate {}".format(self.min_rate)
        args += " --script-timeout 6s"
        args += " --max-hostgroup {}".format(self.max_host_group)
        args += " --host-timeout {}s".format(host_timeout)
        args += " --min-parallelism {}".format(self.parallelism)
        args += " --max-retries {}".format(self.max_retries)
        return args

    @staticmethod
    def _is_syn_permission_error(error):
        """只把 raw socket 权限错误降级为 connect scan，避免掩盖真实故障。"""
        message = str(error or "").strip().lower()
        if not message:
            return False
        return any(
            marker in message
            for marker in (
                "requires root",
                "raw socket",
                "cap_net_raw",
                "operation not permitted",
                "permission denied",
                "not permitted",
            )
        )

    def _mark_syn_scan_unavailable(self):
        with self._syn_scan_state_lock:
            self._syn_scan_unavailable = True

    def _effective_scan_arguments(self, arguments):
        if not self._syn_scan_unavailable:
            return arguments, "syn" if "-sS" in arguments.split() else "connect"
        if "-sS" not in arguments.split():
            return arguments, "connect"
        return arguments.replace("-sS", "-sT", 1), "connect_fallback"

    @staticmethod
    def _estimate_port_count(ports):
        ports = str(ports or "").strip()
        if not ports:
            return 0
        if ports == "0-65535":
            return 65535

        total = 0
        for token in ports.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                start, end = token.split("-", 1)
                try:
                    start_i = int(start)
                    end_i = int(end)
                    if end_i >= start_i:
                        total += (end_i - start_i + 1)
                except Exception:
                    continue
            else:
                try:
                    int(token)
                    total += 1
                except Exception:
                    continue

        return total

    def _is_suspected_all_open(self, open_port_count, port_info_list=None):
        """识别需要独立 TCP connect 复核的异常开放结果。"""
        if open_port_count <= 0:
            return False

        if open_port_count >= 800:
            return True

        if self.requested_port_count <= 0:
            return self._has_suspicious_port_run(port_info_list)

        open_ratio = float(open_port_count) / float(self.requested_port_count)
        if self.requested_port_count <= 64 and open_port_count >= 4 and open_ratio >= 0.75:
            return True

        if self.requested_port_count > 64 and open_port_count >= max(
            25, int(math.ceil(self.requested_port_count * 0.80))
        ):
            return True

        return self._has_suspicious_port_run(port_info_list)

    @staticmethod
    def _has_suspicious_port_run(port_info_list, minimum_run=8):
        ports_by_protocol = {}
        for item in port_info_list or []:
            try:
                port_id = int(item.get("port_id"))
            except (TypeError, ValueError):
                continue
            protocol = str(item.get("protocol", "tcp") or "tcp").lower()
            ports_by_protocol.setdefault(protocol, set()).add(port_id)

        for ports in ports_by_protocol.values():
            ordered_ports = sorted(ports)
            run_length = 0
            previous_port = None
            for port_id in ordered_ports:
                run_length = run_length + 1 if previous_port is not None and port_id == previous_port + 1 else 1
                if run_length >= minimum_run:
                    return True
                previous_port = port_id
        return False

    @staticmethod
    def _build_targets_preview(targets, sample_size=6):
        target_list = list(targets or [])
        if not target_list:
            return "-"

        sample = target_list[:sample_size]
        sample_text = " ".join(sample)
        if len(target_list) > sample_size:
            sample_text = "{} ...(+{})".format(sample_text, len(target_list) - sample_size)
        return sample_text

    @staticmethod
    def _normalize_port_info_item(item):
        return {
            "port_id": int(item.get("port_id", 0) or 0),
            "service_name": str(item.get("service_name", "") or ""),
            "version": str(item.get("version", "") or ""),
            "product": str(item.get("product", "") or ""),
            "protocol": str(item.get("protocol", "tcp") or "tcp"),
            "state": str(item.get("state", "") or ""),
            "reason": str(item.get("reason", "") or ""),
            "scan_method": str(item.get("scan_method", "") or ""),
            "verified": bool(item.get("verified", False)),
            "nmap_service_method": str(item.get("nmap_service_method", "") or ""),
            "nmap_service_confidence": str(item.get("nmap_service_confidence", "") or ""),
            "nmap_service_table_name": str(item.get("nmap_service_table_name", "") or ""),
            "service_confidence": item.get("service_confidence", 0),
            "service_sources": list(item.get("service_sources", []) or []),
            "service_conflict": item.get("service_conflict"),
        }

    @staticmethod
    def _sort_ip_info_list(ip_info_map):
        ip_info_list = list(ip_info_map.values())
        ip_info_list.sort(key=lambda x: str(x.get("ip", "")))
        for item in ip_info_list:
            item["port_info"].sort(key=lambda x: (int(x.get("port_id", 0) or 0), str(x.get("protocol", ""))))
        return ip_info_list

    @staticmethod
    def _chunk_list(data, chunk_size):
        if chunk_size <= 0:
            chunk_size = 1

        chunk = []
        for item in data:
            chunk.append(item)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []

        if chunk:
            yield chunk

    @staticmethod
    def _format_timeout(timeout_sec):
        if int(timeout_sec or 0) <= 0:
            return "unlimited"
        return "{}s".format(int(timeout_sec))

    def _calc_stage_timeout(self, target_count, port_count):
        """
        计算阶段超时预算（秒）：
        - base
        - + 每目标追加
        - + 每 1000 端口追加（向下取整）
        - 最后受 max 约束（max=0 表示不限制）
        """
        base = int(self.stage_timeout_base_sec or 0)
        per_target = int(self.stage_timeout_per_target_sec or 0)
        per_1000_ports = int(self.stage_timeout_per_1000_ports_sec or 0)
        max_budget = int(self.stage_timeout_max_sec or 0)

        if base <= 0 and per_target <= 0 and per_1000_ports <= 0:
            return 0

        budget = max(base, 0)
        if target_count > 0 and per_target > 0:
            budget += int(target_count) * per_target
        if port_count >= 1000 and per_1000_ports > 0:
            budget += (int(port_count) // 1000) * per_1000_ports

        if max_budget > 0:
            budget = min(budget, max_budget)

        if budget <= 0:
            return 0
        return budget

    def _resolve_target_batch_size(self):
        if self.ports == "0-65535":
            return self.port_scan_all_target_batch_size

        if self.requested_port_count >= 1000:
            return self.port_scan_heavy_target_batch_size

        return self.port_scan_target_batch_size

    @staticmethod
    def _port_key(port_info):
        return "{}:{}".format(
            str(port_info.get("protocol", "tcp") or "tcp").lower(),
            int(port_info.get("port_id", 0) or 0),
        )

    @staticmethod
    def _nmap_scan_errors(scan_result):
        if not isinstance(scan_result, dict):
            return []
        nmap_result = scan_result.get("nmap") or {}
        if not isinstance(nmap_result, dict):
            return []
        scaninfo = nmap_result.get("scaninfo") or {}
        if not isinstance(scaninfo, dict):
            scaninfo = {}
        errors = scaninfo.get("error") or []
        if isinstance(errors, str):
            errors = [errors]
        elif not isinstance(errors, (list, tuple, set)):
            errors = [errors]
        normalized_errors = [
            str(error).strip() for error in errors if str(error or "").strip()
        ]

        scanstats = nmap_result.get("scanstats") or {}
        if isinstance(scanstats, dict):
            scan_exit = str(scanstats.get("exit", "") or "").strip().lower()
            if scan_exit and scan_exit != "success":
                normalized_errors.append("Nmap scan exited with status {}".format(scan_exit))
            error_message = str(scanstats.get("errormsg", "") or "").strip()
            if error_message:
                normalized_errors.append("Nmap scan reported an error message")
        return normalized_errors

    @staticmethod
    def _extract_host_open_ports(nm, host, scan_method):
        if host not in nm.all_hosts():
            return []

        port_info_list = []
        host_data = nm[host]
        for proto in host_data.all_protocols():
            for port, port_info in host_data[proto].items():
                state = str(port_info.get("state", "") or "").lower()
                if state != "open":
                    continue
                service_method = str(port_info.get("method", "") or "").lower()
                service_name = str(port_info.get("name", "") or "")
                port_info_list.append({
                    "port_id": int(port),
                    # Nmap 的 table 名称来自端口号映射，不代表已探测到服务。
                    "service_name": "" if service_method == "table" else service_name,
                    "version": str(port_info.get("version", "") or ""),
                    "product": str(port_info.get("product", "") or ""),
                    "protocol": str(proto or "tcp"),
                    "state": state,
                    "reason": str(port_info.get("reason", "") or ""),
                    "scan_method": str(scan_method or ""),
                    "verified": str(scan_method or "") != "syn",
                    "nmap_service_method": service_method,
                    "nmap_service_confidence": str(port_info.get("conf", "") or ""),
                    "nmap_service_table_name": service_name if service_method == "table" else "",
                    "service_confidence": 90 if service_method == "probed" and service_name else 0,
                    "service_sources": ["nmap_service_name"] if service_method == "probed" and service_name else [],
                })
        return port_info_list

    def _extract_scan_result(self, nm, scan_method="syn"):
        ip_info_list = []
        for host in nm.all_hosts():
            port_info_list = self._extract_host_open_ports(nm, host, scan_method)

            total_open_count = len(port_info_list)
            tcp_port_info = [
                port for port in port_info_list
                if str(port.get("protocol", "tcp")).lower() == "tcp"
            ]
            suspected_all_open = self._is_suspected_all_open(
                len(tcp_port_info),
                tcp_port_info,
            )
            if suspected_all_open:
                logger.warning(
                    "suspected fake all-open host:{} open_ports:{} requested_ports:{}".format(
                        host,
                        total_open_count,
                        self.requested_port_count,
                    )
                )

            osmatch_list = nm[host].get("osmatch", [])
            os_info = self.os_match_by_accuracy(osmatch_list)
            ip_info_list.append({
                "ip": host,
                "port_info": port_info_list,
                "os_info": os_info,
                # 仅作为当前扫描链路的内部标记。
                "_suspected_all_open": suspected_all_open,
            })

        return ip_info_list

    @staticmethod
    def _merge_ip_info(ip_info_map, ip_info_list):
        for item in ip_info_list:
            host = str(item.get("ip", "")).strip()
            if not host:
                continue

            old = ip_info_map.get(host)
            if not old:
                ip_info_map[host] = {
                    "ip": host,
                    "port_info": [PortScan._normalize_port_info_item(x) for x in item.get("port_info", [])],
                    "os_info": item.get("os_info", {}) or {},
                    "_suspected_all_open": bool(item.get("_suspected_all_open")),
                    "_scan_coverage": dict(item.get("_scan_coverage", {}) or {}),
                }
                continue

            # 端口按 protocol + port_id 合并，保留精扫阶段更完整的字段。
            port_map = {}
            for port_item in old.get("port_info", []):
                norm = PortScan._normalize_port_info_item(port_item)
                key = "{}:{}".format(norm["protocol"], norm["port_id"])
                port_map[key] = norm

            for port_item in item.get("port_info", []):
                norm = PortScan._normalize_port_info_item(port_item)
                key = "{}:{}".format(norm["protocol"], norm["port_id"])
                if key not in port_map:
                    port_map[key] = norm
                    continue

                origin = port_map[key]
                for field in [
                    "service_name",
                    "version",
                    "product",
                    "nmap_service_method",
                    "nmap_service_confidence",
                    "nmap_service_table_name",
                    "service_confidence",
                    "service_sources",
                    "service_conflict",
                ]:
                    if norm.get(field):
                        origin[field] = norm[field]
                if norm.get("nmap_service_method"):
                    origin["nmap_service_table_name"] = norm.get("nmap_service_table_name", "")
                if norm.get("verified") or not origin.get("verified"):
                    for field in ("state", "reason", "scan_method", "verified"):
                        if norm.get(field) not in (None, ""):
                            origin[field] = norm[field]

            old["port_info"] = list(port_map.values())
            if item.get("os_info"):
                old["os_info"] = item["os_info"]
            old["_suspected_all_open"] = bool(
                old.get("_suspected_all_open") or item.get("_suspected_all_open")
            )
            if not old.get("_scan_coverage") and item.get("_scan_coverage"):
                old["_scan_coverage"] = dict(item["_scan_coverage"])

    @staticmethod
    def _build_connect_validation_arguments(arguments):
        scan_flags = {"-sS", "-sT", "-sV", "-O"}
        tokens = [token for token in str(arguments or "").split() if token not in scan_flags]
        return " ".join(["-sT"] + tokens)

    def _validate_suspected_hosts(self, ip_info_map, arguments):
        metrics = {
            "connect_validation_host_count": 0,
            "connect_validation_candidate_count": 0,
            "connect_validation_verified_count": 0,
            "connect_validation_not_open_count": 0,
            "connect_validation_unverified_count": 0,
            "connect_validation_error_count": 0,
            "connect_validation_pending_count": 0,
            "connect_validation_elapsed_sec": 0.0,
        }
        suspects = [
            item for item in (ip_info_map or {}).values()
            if item.get("_suspected_all_open")
            and any(
                port.get("scan_method") == "syn"
                and str(port.get("protocol", "tcp")).lower() == "tcp"
                for port in item.get("port_info", [])
            )
        ]
        if not suspects:
            return metrics

        candidate_total = sum(
            sum(
                1 for port in item.get("port_info", [])
                if port.get("scan_method") == "syn"
                and str(port.get("protocol", "tcp")).lower() == "tcp"
            )
            for item in suspects
        )
        timeout_budget = self._calc_stage_timeout(
            target_count=len(suspects),
            port_count=candidate_total,
        )
        validation_started_at = time.time()
        deadline_ts = validation_started_at + timeout_budget if timeout_budget > 0 else None
        connect_arguments = self._build_connect_validation_arguments(arguments)

        for host_item in suspects:
            host = str(host_item.get("ip", "")).strip()
            original_ports = list(host_item.get("port_info", []) or [])
            candidates = [
                port for port in original_ports
                if port.get("scan_method") == "syn" and str(port.get("protocol", "tcp")).lower() == "tcp"
            ]
            candidate_keys = {self._port_key(port) for port in candidates}
            candidate_ids = sorted({int(port.get("port_id", 0) or 0) for port in candidates})
            verified_by_key = {}
            checked_keys = set()
            metrics["connect_validation_host_count"] += 1
            metrics["connect_validation_candidate_count"] += len(candidate_keys)

            chunks = list(self._chunk_list(candidate_ids, self.stage2_port_chunk_size))
            host_pending_count = 0
            for chunk_index, chunk in enumerate(chunks):
                if deadline_ts is not None and time.time() >= deadline_ts:
                    host_pending_count += sum(len(item) for item in chunks[chunk_index:])
                    break

                scan_kwargs = {
                    "hosts": host,
                    "ports": ",".join(str(port_id) for port_id in chunk),
                    "arguments": connect_arguments,
                }
                if self.batch_timeout_sec > 0:
                    batch_timeout = self.batch_timeout_sec
                    if deadline_ts is not None:
                        remaining = int(deadline_ts - time.time())
                        if remaining <= 0:
                            host_pending_count += sum(len(item) for item in chunks[chunk_index:])
                            break
                        batch_timeout = min(batch_timeout, max(1, remaining))
                    scan_kwargs["timeout"] = batch_timeout

                try:
                    scanner = nmap.PortScanner()
                    scan_result = scanner.scan(**scan_kwargs)
                    scan_errors = self._nmap_scan_errors(scan_result)
                    if scan_errors:
                        metrics["connect_validation_error_count"] += 1
                        logger.warning(
                            "port_scan connect_validation_reported_error host:{} ports:{} error_count:{}".format(
                                host,
                                scan_kwargs["ports"],
                                len(scan_errors),
                            )
                        )
                        continue
                    open_ports = self._extract_host_open_ports(
                        scanner,
                        host,
                        "connect_validation",
                    )
                    chunk_ports = {int(port_id) for port_id in chunk}
                    checked_keys.update(
                        self._port_key(port)
                        for port in candidates
                        if int(port.get("port_id", 0) or 0) in chunk_ports
                    )
                    for port in open_ports:
                        key = self._port_key(port)
                        if key in candidate_keys:
                            verified_by_key[key] = port
                except Exception as error:
                    metrics["connect_validation_error_count"] += 1
                    logger.warning(
                        "port_scan connect_validation_failed host:{} ports:{} err:{}".format(
                            host,
                            scan_kwargs["ports"],
                            safe_error_text(error),
                        )
                    )
            metrics["connect_validation_pending_count"] += host_pending_count

            validated_ports = []
            for candidate in candidates:
                verified = verified_by_key.get(self._port_key(candidate))
                if not verified:
                    continue
                confirmed = dict(candidate)
                confirmed.update({
                    "state": verified.get("state", "open"),
                    "reason": verified.get("reason", ""),
                    "scan_method": "connect_validation",
                    "verified": True,
                })
                validated_ports.append(confirmed)

            metrics["connect_validation_verified_count"] += len(validated_ports)
            verified_keys = set(verified_by_key).intersection(checked_keys)
            not_open_keys = checked_keys - verified_keys
            metrics["connect_validation_not_open_count"] += len(not_open_keys)
            metrics["connect_validation_unverified_count"] += len(candidate_keys - checked_keys)
            host_item["_connect_validation"] = {
                "not_open_ports": [
                    {
                        "port_id": int(candidate.get("port_id", 0) or 0),
                        "protocol": str(candidate.get("protocol", "tcp") or "tcp").lower(),
                    }
                    for candidate in candidates
                    if self._port_key(candidate) in not_open_keys
                ],
            }
            host_item["port_info"] = validated_ports + [
                port for port in original_ports if self._port_key(port) not in candidate_keys
            ]
            logger.warning(
                "port_scan connect_validation host:{} candidate:{} verified:{} not_open:{} unverified:{}".format(
                    host,
                    len(candidate_keys),
                    len(validated_ports),
                    len(checked_keys - verified_keys),
                    len(candidate_keys - checked_keys),
                )
            )

        metrics["connect_validation_elapsed_sec"] = round(
            max(0.0, time.time() - validation_started_at),
            3,
        )
        stage_metrics = dict(self.last_scan_metrics or {})
        stage_metrics.update(metrics)
        validation_degraded = (
            metrics["connect_validation_error_count"]
            + metrics["connect_validation_pending_count"]
        )
        if validation_degraded:
            stage_metrics["degraded_count"] = int(stage_metrics.get("degraded_count", 0) or 0) + validation_degraded
            stage_metrics["failed_count"] = int(stage_metrics.get("failed_count", 0) or 0) + metrics[
                "connect_validation_error_count"
            ]
            stage_metrics["pending_count"] = int(stage_metrics.get("pending_count", 0) or 0) + metrics[
                "connect_validation_pending_count"
            ]
            stage_metrics["status"] = "partial"
            stage_metrics["end_reason"] = "connect_validation_incomplete"
        self.last_scan_metrics = stage_metrics
        return metrics

    def _run_batch_scan(
        self,
        target_batch,
        ports,
        arguments,
        stage_name,
        batch_index,
        batch_total,
        stage_deadline_ts=None,
    ):
        ports_text = str(ports or "")
        if len(ports_text) > 64:
            ports_text = "{}...".format(ports_text[:64])

        logger.info(
            "nmap stage:{} batch:{}/{} targets:{} preview:{} ports:{} arguments {}".format(
                stage_name,
                batch_index,
                batch_total,
                len(target_batch),
                self._build_targets_preview(target_batch),
                ports_text,
                arguments
            )
        )

        if stage_deadline_ts and time.time() >= stage_deadline_ts:
            logger.warning(
                "nmap stage:{} batch:{}/{} pending before start reason:stage_budget".format(
                    stage_name, batch_index, batch_total
                )
            )
            return None

        scan_arguments, scan_type = self._effective_scan_arguments(arguments)
        scan_kwargs = {
            "hosts": " ".join(target_batch),
            "ports": ports,
            "arguments": scan_arguments,
        }
        if self.batch_timeout_sec > 0:
            batch_timeout = self.batch_timeout_sec
            if stage_deadline_ts:
                batch_timeout = min(
                    batch_timeout,
                    max(1, int(stage_deadline_ts - time.time())),
                )
            scan_kwargs["timeout"] = batch_timeout

        fallback_count = 0
        fallback_reason = ""
        scan_result = None
        nm = nmap.PortScanner()
        try:
            scan_result = nm.scan(**scan_kwargs)
        except Exception as error:
            if not (
                scan_type == "syn"
                and self.syn_scan_fallback_enabled
                and self._is_syn_permission_error(error)
            ):
                logger.error(
                    "nmap stage:{} batch:{}/{} failed targets:{} scan_type:{} err:{}".format(
                        stage_name,
                        batch_index,
                        batch_total,
                        len(target_batch),
                        scan_type,
                        safe_error_text(error),
                    )
                )
                return PortScanBatchResult(
                    [],
                    metrics={
                        "status": "failed",
                        "scan_type": scan_type,
                        "fallback_count": 0,
                        "error_type": type(error).__name__,
                    },
                )

            fallback_count = 1
            fallback_reason = type(error).__name__
            self._mark_syn_scan_unavailable()
            scan_kwargs["arguments"] = scan_arguments.replace("-sS", "-sT", 1)
            logger.warning(
                "nmap stage:{} batch:{}/{} syn_scan_fallback targets:{} reason:{}".format(
                    stage_name,
                    batch_index,
                    batch_total,
                    len(target_batch),
                    fallback_reason,
                )
            )
            try:
                nm = nmap.PortScanner()
                scan_result = nm.scan(**scan_kwargs)
                scan_type = "connect_fallback"
            except Exception as fallback_error:
                logger.error(
                    "nmap stage:{} batch:{}/{} fallback_failed targets:{} err:{}".format(
                        stage_name,
                        batch_index,
                        batch_total,
                        len(target_batch),
                        safe_error_text(fallback_error),
                    )
                )
                return PortScanBatchResult(
                    [],
                    metrics={
                        "status": "failed",
                        "scan_type": "connect_fallback",
                        "fallback_count": fallback_count,
                        "fallback_reason": fallback_reason,
                        "error_type": type(fallback_error).__name__,
                    },
                )

        scan_errors = self._nmap_scan_errors(scan_result)
        if scan_errors:
            logger.error(
                "nmap stage:{} batch:{}/{} reported_error targets:{} scan_type:{} error_count:{}".format(
                    stage_name,
                    batch_index,
                    batch_total,
                    len(target_batch),
                    scan_type,
                    len(scan_errors),
                )
            )
            return PortScanBatchResult(
                [],
                metrics={
                    "status": "failed",
                    "scan_type": scan_type,
                    "fallback_count": fallback_count,
                    "fallback_reason": fallback_reason,
                    "error_type": "NmapScanError",
                    "scan_error_count": len(scan_errors),
                },
            )

        try:
            result = self._extract_scan_result(nm, scan_method=scan_type)
        except Exception as e:
            logger.error(
                "nmap stage:{} batch:{}/{} result_parse_failed targets:{} err:{}".format(
                    stage_name, batch_index, batch_total, len(target_batch), safe_error_text(e)
                )
            )
            return PortScanBatchResult(
                [],
                metrics={
                    "status": "failed",
                    "scan_type": scan_type,
                    "fallback_count": fallback_count,
                    "fallback_reason": fallback_reason,
                    "error_type": type(e).__name__,
                },
            )
        if stage_name in ("single", "fast") and str(ports or "") == self.ports:
            coverage = {
                "complete": True,
                "ports": self.ports,
                "scan_method": scan_type,
            }
            for item in result:
                item["_scan_coverage"] = coverage
        logger.info(
            "nmap stage:{} batch:{}/{} host_result:{}".format(
                stage_name, batch_index, batch_total, len(result)
            )
        )
        suspected_all_open_count = sum(
            1 for item in result if item.get("_suspected_all_open")
        )
        return PortScanBatchResult(
            result,
            metrics={
                "scan_type": scan_type,
                "fallback_count": fallback_count,
                "fallback_reason": fallback_reason,
                "suspected_all_open_count": suspected_all_open_count,
            },
        )

    def _scan_with_batches(self, targets, ports, arguments, stage_name, force_batch_size=None, stage_timeout_sec=0):
        target_list = [str(x or "").strip() for x in (targets or []) if str(x or "").strip()]
        if not target_list:
            self._last_completed_scan_methods = {}
            return {}, False

        batch_size = force_batch_size if force_batch_size else self._resolve_target_batch_size()
        batches = list(self._chunk_list(target_list, batch_size))
        total = len(batches)
        result_map = {}
        stage_start_ts = time.time()
        timeout_hit = False
        failed_batches = 0
        failed_target_count = 0
        processed_batches = 0
        successful_batches = 0
        executor = ThreadPoolExecutor(max_workers=min(self.batch_concurrency, total))
        future_map = {}
        pending = set()
        next_batch_index = 0
        fallback_count = 0
        fallback_reasons = {}
        failed_reasons = {}
        suspected_all_open_count = 0
        completed_scan_methods = {}

        def submit_next_batch():
            nonlocal next_batch_index
            if next_batch_index >= total:
                return False
            next_batch_index += 1
            batch_index = next_batch_index
            future = executor.submit(
                self._run_batch_scan,
                target_batch=batches[batch_index - 1],
                ports=ports,
                arguments=arguments,
                stage_name=stage_name,
                batch_index=batch_index,
                batch_total=total,
                stage_deadline_ts=(
                    stage_start_ts + stage_timeout_sec
                    if stage_timeout_sec > 0
                    else None
                ),
            )
            future_map[future] = batch_index
            pending.add(future)
            return True

        for _ in range(min(self.batch_concurrency, total)):
            submit_next_batch()

        try:
            while pending:
                remaining = None
                if stage_timeout_sec > 0:
                    remaining = stage_timeout_sec - (time.time() - stage_start_ts)
                    if remaining <= 0:
                        timeout_hit = True
                        break
                completed_set, _ = wait(
                    pending,
                    timeout=remaining,
                    return_when=FIRST_COMPLETED,
                )
                if not completed_set:
                    timeout_hit = True
                    break
                for completed in completed_set:
                    pending.remove(completed)
                    processed_batches += 1
                    batch_index = future_map[completed]
                    try:
                        batch_result = completed.result()
                    except Exception as error:
                        failed_batches += 1
                        failed_target_count += len(batches[batch_index - 1])
                        error_type = type(error).__name__
                        failed_reasons[error_type] = failed_reasons.get(error_type, 0) + 1
                        logger.error(
                            "nmap stage:{} batch:{} worker_failed err:{}".format(
                                stage_name, batch_index, safe_error_text(error)
                            )
                        )
                        if not timeout_hit:
                            submit_next_batch()
                        continue
                    batch_metrics = dict(getattr(batch_result, "metrics", {}) or {})
                    batch_fallback_count = int(batch_metrics.get("fallback_count", 0) or 0)
                    fallback_count += batch_fallback_count
                    suspected_all_open_count += int(
                        batch_metrics.get("suspected_all_open_count", 0) or 0
                    )
                    fallback_reason = str(batch_metrics.get("fallback_reason", "") or "").strip()
                    if fallback_reason:
                        fallback_reasons[fallback_reason] = fallback_reasons.get(fallback_reason, 0) + 1
                    if batch_result is None or batch_metrics.get("status") == "failed":
                        failed_batches += 1
                        failed_target_count += len(batches[batch_index - 1])
                        error_type = str(batch_metrics.get("error_type", "unknown") or "unknown")
                        failed_reasons[error_type] = failed_reasons.get(error_type, 0) + 1
                        if not timeout_hit:
                            submit_next_batch()
                        continue
                    if stage_name in ("single", "fast") and str(ports or "") == self.ports:
                        scan_method = str(
                            batch_metrics.get("scan_type")
                            or ("syn" if self.syn_scan_enabled else "connect")
                        )
                        for target in batches[batch_index - 1]:
                            completed_scan_methods[target] = scan_method
                    successful_batches += 1
                    self._merge_ip_info(result_map, batch_result)

                    if not timeout_hit:
                        submit_next_batch()
        finally:
            for future in pending:
                future.cancel()
            # 阶段超时后不能继续等待未完成的 nmap 批次，否则上层看到的超时只是日志。
            executor.shutdown(wait=not timeout_hit, cancel_futures=timeout_hit)

        queued_pending_batches = max(0, total - next_batch_index)
        pending_batches = len(pending) + queued_pending_batches
        pending_target_count = sum(
            len(batches[future_map[future] - 1])
            for future in pending
        ) + sum(len(batch) for batch in batches[next_batch_index:])
        if timeout_hit:
            logger.warning(
                "port_scan stage:{} timeout elapsed:{:.2f}s timeout:{}s processed_batch:{}/{} pending_batch:{} partial_host:{}".format(
                    stage_name,
                    time.time() - stage_start_ts,
                    stage_timeout_sec,
                    processed_batches,
                    total,
                    pending_batches,
                    len(result_map),
                )
            )

        self.last_scan_metrics = {
            "stage": stage_name,
            "target_count": len(target_list),
            "requested_port_count": self.requested_port_count,
            "batch_count": total,
            "processed_batch_count": processed_batches,
            "successful_batch_count": successful_batches,
            "failed_batch_count": failed_batches,
            "pending_batch_count": pending_batches,
            "failed_target_count": failed_target_count,
            "pending_target_count": pending_target_count,
            "result_host_count": len(result_map),
            "timeout_hit": bool(timeout_hit),
            "degraded_count": int(failed_batches + pending_batches),
            "fallback_count": fallback_count,
            "fallback_reasons": fallback_reasons,
            "failed_reasons": failed_reasons,
            "suspected_all_open_count": suspected_all_open_count,
            "scan_type": "connect_fallback" if fallback_count else (
                "syn" if self.syn_scan_enabled and not self._syn_scan_unavailable else "connect"
            ),
            "elapsed_sec": round(max(0.0, time.time() - stage_start_ts), 3),
        }
        self._last_completed_scan_methods = completed_scan_methods

        logger.info(
            "nmap stage:{} done targets:{} batches:{} processed:{} failed:{} pending:{} host_result:{} timeout_hit:{} timeout_budget:{}".format(
                stage_name,
                len(target_list),
                total,
                processed_batches,
                failed_batches,
                pending_batches,
                len(result_map),
                timeout_hit,
                self._format_timeout(stage_timeout_sec),
            )
        )
        return result_map, timeout_hit

    def _build_precise_plan(self, fast_map):
        """
        基于快扫结果构建精扫计划：
        - 覆盖所有发现开放端口的主机
        - 覆盖该主机全部开放端口
        - 通过端口分段控制单次命令长度
        """
        plan = []
        for host, item in fast_map.items():
            if item.get("_suspected_all_open") and len(item.get("port_info", [])) > self.stage2_port_chunk_size:
                # 大量端口经 TCP connect 复核后仍开放时，限制昂贵的版本探测规模。
                logger.warning(
                    "skip precise service scan for verified high-port-count host:{} ports:{}".format(
                        host, len(item.get("port_info", []))
                    )
                )
                continue
            port_ids = sorted(
                list({int(x.get("port_id", 0) or 0) for x in item.get("port_info", []) if int(x.get("port_id", 0) or 0) > 0})
            )
            if not port_ids:
                continue

            plan.append({
                "host": host,
                "port_ids": port_ids,
            })

        plan.sort(key=lambda x: str(x["host"]))
        return plan

    def _build_two_stage_metrics(self, fast_metrics, precise_metrics=None,
                                 output_count=0, timeout_hit=False):
        """把快扫和精扫的批次状态提升到阶段顶层，供任务状态和告警查询。"""
        fast = dict(fast_metrics or {})
        precise = dict(precise_metrics or {})
        metrics = {
            "stage": "two_stage",
            "target_count": len(self.target_list),
            "requested_port_count": self.requested_port_count,
            "fast": fast,
            "precise": precise,
            "output_count": max(int(output_count or 0), 0),
            "timeout_hit": bool(timeout_hit),
        }
        for key in (
            "batch_count",
            "processed_batch_count",
            "successful_batch_count",
            "failed_batch_count",
            "pending_batch_count",
            "failed_target_count",
            "pending_target_count",
        ):
            metrics[key] = int(fast.get(key, 0) or 0) + int(precise.get(key, 0) or 0)
        metrics["timeout_count"] = int(bool(timeout_hit))
        metrics["failed_count"] = metrics["failed_batch_count"]
        metrics["pending_count"] = metrics["pending_batch_count"]
        metrics["degraded_count"] = metrics["failed_batch_count"] + metrics["pending_batch_count"]
        metrics["fallback_count"] = int(fast.get("fallback_count", 0) or 0) + int(
            precise.get("fallback_count", 0) or 0
        )
        metrics["suspected_all_open_count"] = int(
            fast.get("suspected_all_open_count", 0) or 0
        ) + int(precise.get("suspected_all_open_count", 0) or 0)
        for key in (
            "connect_validation_host_count",
            "connect_validation_candidate_count",
            "connect_validation_verified_count",
            "connect_validation_not_open_count",
            "connect_validation_unverified_count",
            "connect_validation_error_count",
            "connect_validation_pending_count",
        ):
            metrics[key] = int(fast.get(key, 0) or 0) + int(precise.get(key, 0) or 0)
        metrics["connect_validation_elapsed_sec"] = round(
            float(fast.get("connect_validation_elapsed_sec", 0) or 0)
            + float(precise.get("connect_validation_elapsed_sec", 0) or 0),
            3,
        )
        metrics["degraded_count"] += (
            metrics["connect_validation_error_count"]
            + metrics["connect_validation_pending_count"]
        )
        metrics["failed_count"] += metrics["connect_validation_error_count"]
        metrics["pending_count"] += metrics["connect_validation_pending_count"]
        fallback_reasons = {}
        for source in (fast, precise):
            for reason, count in (source.get("fallback_reasons", {}) or {}).items():
                fallback_reasons[str(reason)] = fallback_reasons.get(str(reason), 0) + int(count or 0)
        metrics["fallback_reasons"] = fallback_reasons
        failed_reasons = {}
        for source in (fast, precise):
            for reason, count in (source.get("failed_reasons", {}) or {}).items():
                failed_reasons[str(reason)] = failed_reasons.get(str(reason), 0) + int(count or 0)
        metrics["failed_reasons"] = failed_reasons
        metrics["scan_type"] = (
            "connect_fallback"
            if metrics["fallback_count"] > 0
            else str(fast.get("scan_type") or precise.get("scan_type") or "syn")
        )
        if timeout_hit:
            metrics["status"] = "partial"
            metrics["end_reason"] = "budget_exhausted"
        elif metrics["degraded_count"] > 0:
            metrics["status"] = "partial"
            metrics["end_reason"] = (
                "connect_validation_incomplete"
                if metrics["connect_validation_error_count"] or metrics["connect_validation_pending_count"]
                else "batch_failed"
            )
        else:
            metrics["status"] = "success"
            metrics["end_reason"] = "completed"
        return metrics

    def _run_two_stage_scan(self):
        logger.info(
            "port_scan mode:two-stage targets:{} ports:{} service_detect:{} os_detect:{}".format(
                len(self.target_list), self.ports, self.service_detect, self.os_detect
            )
        )

        fast_args = self._build_nmap_arguments(enable_service=False, enable_os=False)
        fast_stage_timeout_sec = self._calc_stage_timeout(
            target_count=len(self.target_list),
            port_count=self.requested_port_count,
        )
        logger.info(
            "port_scan stage:fast timeout_budget:{} targets:{} requested_ports:{}".format(
                self._format_timeout(fast_stage_timeout_sec),
                len(self.target_list),
                self.requested_port_count,
            )
        )
        fast_map, fast_timeout_hit = self._scan_with_batches(
            targets=self.target_list,
            ports=self.ports,
            arguments=fast_args,
            stage_name="fast",
            stage_timeout_sec=fast_stage_timeout_sec,
        )
        fast_completed_scan_methods = dict(self._last_completed_scan_methods)
        scan_coverage = {
            "ports": self.ports,
            "completed_targets": fast_completed_scan_methods,
        }
        fast_metrics = dict(self.last_scan_metrics)
        if not fast_map:
            metrics = self._build_two_stage_metrics(
                fast_metrics,
                output_count=0,
                timeout_hit=fast_timeout_hit,
            )
            self.last_scan_metrics = metrics
            return PortScanResult([], metrics=metrics, scan_coverage=scan_coverage)
        fast_metrics.update(self._validate_suspected_hosts(fast_map, fast_args))
        if fast_timeout_hit:
            logger.warning(
                "port_scan skip precise stage because fast stage timeout host_result:{}".format(
                    len(fast_map)
                )
            )
            result = self._sort_ip_info_list(fast_map)
            metrics = self._build_two_stage_metrics(
                fast_metrics,
                output_count=len(result),
                timeout_hit=True,
            )
            self.last_scan_metrics = metrics
            return PortScanResult(result, metrics=metrics, scan_coverage=scan_coverage)

        precise_plan = self._build_precise_plan(fast_map)
        if not precise_plan:
            result = self._sort_ip_info_list(fast_map)
            metrics = self._build_two_stage_metrics(
                fast_metrics,
                output_count=len(result),
                timeout_hit=False,
            )
            self.last_scan_metrics = metrics
            return PortScanResult(result, metrics=metrics, scan_coverage=scan_coverage)

        precise_args = self._build_nmap_arguments(
            enable_service=self.service_detect,
            enable_os=self.os_detect,
        )
        precise_total_ports = sum(len(x.get("port_ids", [])) for x in precise_plan)
        precise_stage_timeout_sec = self._calc_stage_timeout(
            target_count=len(precise_plan),
            port_count=precise_total_ports,
        )
        logger.info(
            "port_scan stage:precise timeout_budget:{} hosts:{} total_open_ports:{}".format(
                self._format_timeout(precise_stage_timeout_sec),
                len(precise_plan),
                precise_total_ports,
            )
        )

        precise_stage_start_ts = time.time()
        precise_timeout_hit = False
        precise_metrics = {
            "stage": "precise",
            "batch_count": 0,
            "processed_batch_count": 0,
            "failed_batch_count": 0,
            "pending_batch_count": 0,
            "result_host_count": 0,
            "fallback_count": 0,
            "fallback_reasons": {},
            "failed_reasons": {},
            "suspected_all_open_count": 0,
        }
        for host_index, item in enumerate(precise_plan, 1):
            if precise_stage_timeout_sec > 0 and (time.time() - precise_stage_start_ts) >= precise_stage_timeout_sec:
                precise_timeout_hit = True
                logger.warning(
                    "port_scan precise stage timeout before host:{}/{} partial_host:{} timeout_budget:{}s".format(
                        host_index, len(precise_plan), len(fast_map), precise_stage_timeout_sec
                    )
                )
                break
            host = item["host"]
            port_ids = item["port_ids"]
            port_chunks = list(self._chunk_list(port_ids, self.stage2_port_chunk_size))
            for chunk_index, chunk_port_ids in enumerate(port_chunks, 1):
                if precise_stage_timeout_sec > 0 and (time.time() - precise_stage_start_ts) >= precise_stage_timeout_sec:
                    precise_timeout_hit = True
                    logger.warning(
                        "port_scan precise stage timeout host:{}/{} chunk:{}/{} current_host:{} partial_host:{} timeout_budget:{}s".format(
                            host_index, len(precise_plan), chunk_index - 1, len(port_chunks), host, len(fast_map), precise_stage_timeout_sec
                        )
                    )
                    break
                ports_text = ",".join([str(x) for x in chunk_port_ids])
                precise_remaining_sec = 0
                if precise_stage_timeout_sec > 0:
                    precise_remaining_sec = max(
                        1,
                        int(precise_stage_timeout_sec - (time.time() - precise_stage_start_ts)),
                    )
                precise_map, _ = self._scan_with_batches(
                    targets=[host],
                    ports=ports_text,
                    arguments=precise_args,
                    stage_name="precise",
                    force_batch_size=1,
                    # 将全阶段剩余预算传入批次层，避免单个 nmap chunk 在外层
                    # 超时检查前继续运行，导致阶段总耗时突破配置上限。
                    stage_timeout_sec=precise_remaining_sec,
                )
                current_metrics = dict(self.last_scan_metrics)
                for key in (
                    "batch_count",
                    "processed_batch_count",
                    "failed_batch_count",
                    "pending_batch_count",
                ):
                    precise_metrics[key] += int(current_metrics.get(key, 0) or 0)
                precise_metrics["fallback_count"] += int(current_metrics.get("fallback_count", 0) or 0)
                precise_metrics["suspected_all_open_count"] += int(
                    current_metrics.get("suspected_all_open_count", 0) or 0
                )
                for reason, count in (current_metrics.get("failed_reasons", {}) or {}).items():
                    precise_metrics["failed_reasons"][str(reason)] = (
                        precise_metrics["failed_reasons"].get(str(reason), 0) + int(count or 0)
                    )
                for reason, count in (current_metrics.get("fallback_reasons", {}) or {}).items():
                    precise_metrics["fallback_reasons"][str(reason)] = (
                        precise_metrics["fallback_reasons"].get(str(reason), 0) + int(count or 0)
                    )
                if current_metrics.get("scan_type"):
                    precise_metrics["scan_type"] = current_metrics["scan_type"]
                precise_metrics["result_host_count"] = len(precise_map)
                self._merge_ip_info(fast_map, list(precise_map.values()))
                logger.info(
                    "port_scan stage2 progress host:{}/{} chunk:{}/{} current_host:{} chunk_ports:{}".format(
                        host_index,
                        len(precise_plan),
                        chunk_index,
                        len(port_chunks),
                        host,
                        len(chunk_port_ids),
                    )
                )
            if precise_timeout_hit:
                break

        if precise_timeout_hit:
            logger.warning("port_scan precise stage timeout return partial result host:{}".format(len(fast_map)))

        result = self._sort_ip_info_list(fast_map)
        precise_metrics["timeout_hit"] = bool(precise_timeout_hit)
        precise_metrics["elapsed_sec"] = round(max(0.0, time.time() - precise_stage_start_ts), 3)
        self.last_scan_metrics = self._build_two_stage_metrics(
            fast_metrics,
            precise_metrics,
            output_count=len(result),
            timeout_hit=bool(fast_timeout_hit or precise_timeout_hit),
        )
        return PortScanResult(result, metrics=self.last_scan_metrics, scan_coverage=scan_coverage)

    def run(self):
        if not self.target_list:
            logger.info("skip port_scan, empty target list")
            self.last_scan_metrics = {
                "stage": "empty",
                "target_count": 0,
                "output_count": 0,
            }
            return PortScanResult([], metrics=self.last_scan_metrics, scan_coverage={
                "ports": self.ports,
                "completed_targets": {},
            })

        if self.service_detect or self.os_detect:
            return self._run_two_stage_scan()

        logger.info(
            "port_scan mode:single targets:{} ports:{} service_detect:{} os_detect:{}".format(
                len(self.target_list), self.ports, self.service_detect, self.os_detect
            )
        )
        single_args = self._build_nmap_arguments(
            enable_service=self.service_detect,
            enable_os=self.os_detect,
        )
        single_stage_timeout_sec = self._calc_stage_timeout(
            target_count=len(self.target_list),
            port_count=self.requested_port_count,
        )
        logger.info(
            "port_scan stage:single timeout_budget:{} targets:{} requested_ports:{}".format(
                self._format_timeout(single_stage_timeout_sec),
                len(self.target_list),
                self.requested_port_count,
            )
        )
        single_map, _ = self._scan_with_batches(
            targets=self.target_list,
            ports=self.ports,
            arguments=single_args,
            stage_name="single",
            stage_timeout_sec=single_stage_timeout_sec,
        )
        scan_coverage = {
            "ports": self.ports,
            "completed_targets": dict(self._last_completed_scan_methods),
        }
        validation_metrics = self._validate_suspected_hosts(single_map, single_args)
        result = self._sort_ip_info_list(single_map)
        metrics = dict(self.last_scan_metrics)
        metrics.update(validation_metrics)
        metrics["output_count"] = len(result)
        return PortScanResult(result, metrics=metrics, scan_coverage=scan_coverage)

    def os_match_by_accuracy(self, os_match_list):
        for os_match in os_match_list:
            accuracy = os_match.get('accuracy', '0')
            if int(accuracy) > 90:
                return os_match

        return {}


def port_scan(targets, ports=Config.TOP_10, service_detect=False, os_detect=False,
              port_parallelism=Config.PORT_PARALLELISM,
              port_min_rate=Config.PORT_MIN_RATE,
              custom_host_timeout=None):
    valid_targets = []
    invalid_targets = set()
    for raw_target in targets or []:
        target = str(raw_target or "").strip()
        if not target:
            continue

        if not utils.is_vaild_ip_target(target):
            invalid_targets.add(target)
            continue

        if not utils.not_in_black_ips(target):
            continue

        valid_targets.append(target)

    if invalid_targets:
        invalid_sample = sorted(list(invalid_targets))[:6]
        logger.warning(
            "skip invalid port_scan targets count:{} sample:{}".format(
                len(invalid_targets), " ".join(invalid_sample)
            )
        )

    targets = sorted(list(set(valid_targets)))
    if not targets:
        logger.info("skip port_scan, no valid targets")
        return PortScanResult([], metrics={
            "stage": "empty",
            "target_count": 0,
            "output_count": 0,
        }, scan_coverage={"ports": str(ports or ""), "completed_targets": {}})

    ps = PortScan(targets=targets, ports=ports, service_detect=service_detect, os_detect=os_detect,
                  port_parallelism=port_parallelism, port_min_rate=port_min_rate,
                  custom_host_timeout=custom_host_timeout)
    return ps.run()
