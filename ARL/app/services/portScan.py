"""
端口扫描执行
"""
import time
from app import utils
from app.utils import nmap
from app.config import Config

logger = utils.get_logger()


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
        self.base_nmap_arguments = "-sT -n --open"

        # 扫描分片大小：避免一次性 nmap 扫描过多目标导致任务长时间无输出。
        self.port_scan_target_batch_size = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_TARGET_BATCH_SIZE", 24), 24
        )
        self.port_scan_heavy_target_batch_size = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_HEAVY_TARGET_BATCH_SIZE", 8), 8
        )
        self.port_scan_all_target_batch_size = self._safe_positive_int(
            getattr(Config, "PORT_SCAN_ALL_TARGET_BATCH_SIZE", 2), 2
        )

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

    def _is_suspected_all_open(self, open_port_count):
        """
        识别疑似“伪全开端口”主机：
        - 全端口扫描时，开放端口数量非常大
        - 或在大范围端口扫描中开放率异常高
        """
        if open_port_count <= 0:
            return False

        if open_port_count >= 800:
            return True

        if self.requested_port_count <= 0:
            return False

        open_ratio = float(open_port_count) / float(self.requested_port_count)
        if self.requested_port_count >= 1000 and open_port_count >= 500 and open_ratio >= 0.80:
            return True

        if self.requested_port_count >= 100 and open_port_count >= 90 and open_ratio >= 0.95:
            return True

        return False

    @staticmethod
    def _filter_suspected_ports(port_info_list):
        """
        疑似伪全开端口时，保留少量高价值端口继续后续流程。
        """
        keep_ports = {80, 443, 8080, 8443, 22, 3389}
        filtered = []
        for item in port_info_list:
            port_id = item.get("port_id")
            if port_id in keep_ports:
                filtered.append(item)
        return filtered

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

    def _extract_scan_result(self, nm):
        ip_info_list = []
        for host in nm.all_hosts():
            port_info_list = []
            for proto in nm[host].all_protocols():
                proto_ports = nm[host][proto]
                port_len = len(proto_ports)
                for port in proto_ports:
                    # 对于开了很多端口的直接丢弃
                    if port_len > 600 and (port not in [80, 443]):
                        continue

                    port_info = proto_ports[port]
                    item = {
                        "port_id": port,
                        "service_name": str(port_info.get("name", "") or ""),
                        "version": str(port_info.get("version", "") or ""),
                        "product": str(port_info.get("product", "") or ""),
                        "protocol": proto
                    }
                    port_info_list.append(item)

            total_open_count = len(port_info_list)
            if self._is_suspected_all_open(total_open_count):
                old_count = total_open_count
                port_info_list = self._filter_suspected_ports(port_info_list)
                logger.warning(
                    "suspected fake all-open host:{} open_ports:{} requested_ports:{} kept_ports:{}".format(
                        host, old_count, self.requested_port_count, len(port_info_list)
                    )
                )

            osmatch_list = nm[host].get("osmatch", [])
            os_info = self.os_match_by_accuracy(osmatch_list)
            ip_info_list.append({
                "ip": host,
                "port_info": port_info_list,
                "os_info": os_info
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
                    "os_info": item.get("os_info", {}) or {}
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
                for field in ["service_name", "version", "product"]:
                    if norm.get(field):
                        origin[field] = norm[field]

            old["port_info"] = list(port_map.values())
            if item.get("os_info"):
                old["os_info"] = item["os_info"]

    def _run_batch_scan(self, target_batch, ports, arguments, stage_name, batch_index, batch_total):
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

        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=" ".join(target_batch), ports=ports, arguments=arguments)
        except Exception as e:
            logger.exception(
                "nmap stage:{} batch:{}/{} failed targets:{} err:{}".format(
                    stage_name, batch_index, batch_total, len(target_batch), e
                )
            )
            return []

        result = self._extract_scan_result(nm)
        logger.info(
            "nmap stage:{} batch:{}/{} host_result:{}".format(
                stage_name, batch_index, batch_total, len(result)
            )
        )
        return result

    def _scan_with_batches(self, targets, ports, arguments, stage_name, force_batch_size=None, stage_timeout_sec=0):
        target_list = [str(x or "").strip() for x in (targets or []) if str(x or "").strip()]
        if not target_list:
            return {}, False

        batch_size = force_batch_size if force_batch_size else self._resolve_target_batch_size()
        batches = list(self._chunk_list(target_list, batch_size))
        total = len(batches)
        result_map = {}
        stage_start_ts = time.time()
        timeout_hit = False
        for index, batch in enumerate(batches, 1):
            elapsed = time.time() - stage_start_ts
            if stage_timeout_sec > 0 and elapsed >= stage_timeout_sec:
                logger.warning(
                    "port_scan stage:{} timeout elapsed:{:.2f}s timeout:{}s processed_batch:{}/{} partial_host:{}".format(
                        stage_name, elapsed, stage_timeout_sec, index - 1, total, len(result_map)
                    )
                )
                timeout_hit = True
                break
            batch_result = self._run_batch_scan(
                target_batch=batch,
                ports=ports,
                arguments=arguments,
                stage_name=stage_name,
                batch_index=index,
                batch_total=total,
            )
            self._merge_ip_info(result_map, batch_result)

        logger.info(
            "nmap stage:{} done targets:{} batches:{} host_result:{} timeout_hit:{} timeout_budget:{}".format(
                stage_name, len(target_list), total, len(result_map), timeout_hit, self._format_timeout(stage_timeout_sec)
            )
        )
        return result_map, timeout_hit

    def _build_precise_plan(self, fast_map):
        """
        基于快扫结果构建精扫计划：
        - 覆盖所有发现开放端口的主机
        - 覆盖该主机全部开放端口
        - 通过端口分段控制单次命令长度，不裁剪结果
        """
        plan = []
        for host, item in fast_map.items():
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
        if not fast_map:
            return []
        if fast_timeout_hit:
            logger.warning(
                "port_scan skip precise stage because fast stage timeout host_result:{}".format(
                    len(fast_map)
                )
            )
            return self._sort_ip_info_list(fast_map)

        precise_plan = self._build_precise_plan(fast_map)
        if not precise_plan:
            return self._sort_ip_info_list(fast_map)

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
                precise_map, _ = self._scan_with_batches(
                    targets=[host],
                    ports=ports_text,
                    arguments=precise_args,
                    stage_name="precise",
                    force_batch_size=1,
                    stage_timeout_sec=0,
                )
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

        return self._sort_ip_info_list(fast_map)

    def run(self):
        if not self.target_list:
            logger.info("skip port_scan, empty target list")
            return []

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
        return self._sort_ip_info_list(single_map)

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
        return []

    ps = PortScan(targets=targets, ports=ports, service_detect=service_detect, os_detect=os_detect,
                  port_parallelism=port_parallelism, port_min_rate=port_min_rate,
                  custom_host_timeout=custom_host_timeout)
    return ps.run()
