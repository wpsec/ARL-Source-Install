"""IP 网络阶段的具体业务服务。

这些服务承接 IPTask 的端口扫描和站点发现逻辑，保留 Python 的网络、数据库和
任务上下文能力；IPTask 仅保留兼容入口，避免外部任务调用方发生变化。
"""

import ipaddress

from app import services, utils
from app.config import Config
from app.modules import ScanPortType
from app.services.task_result_write_service import TaskResultWriteService
from app.services.probe_policy import normalize_port_id, select_probe_port_infos


logger = utils.get_logger()


class IPPortScanStageService(object):
    """执行 IP 端口扫描、IP 结果补充和结果写回。"""

    def __init__(self, task, services_module=None, utils_module=None, config=None):
        self.task = task
        self.services = services_module or services
        self.utils = utils_module or utils
        self.config = config or Config

    def _build_scan_options(self):
        task = self.task
        options = task.options if isinstance(task.options, dict) else {}
        scan_port_map = {
            "test": ScanPortType.TEST,
            "top100": ScanPortType.TOP100,
            "top1000": ScanPortType.TOP1000,
            "all": ScanPortType.ALL,
            "custom": options.get("port_custom", "80,443"),
        }
        option_scan_port_type = options.get("port_scan_type", "test")
        scan_port_option = {
            "ports": scan_port_map.get(option_scan_port_type, ScanPortType.TEST),
            "service_detect": bool(options.get("service_detection")),
            "os_detect": options.get("os_detection", False),
            "port_parallelism": options.get(
                "port_parallelism", self.config.PORT_PARALLELISM
            ),
            "port_min_rate": options.get(
                "port_min_rate", self.config.PORT_MIN_RATE
            ),
            "custom_host_timeout": None,
        }

        host_timeout_type = str(
            options.get("host_timeout_type", self.config.HOST_TIMEOUT_TYPE)
        ).strip().lower()
        if host_timeout_type == "custom":
            scan_port_option["custom_host_timeout"] = options.get(
                "host_timeout", self.config.HOST_TIMEOUT
            )
        return scan_port_option

    @staticmethod
    def _port_key(port_info):
        if not isinstance(port_info, dict):
            return None
        try:
            port_id = int(port_info.get("port_id"))
        except (TypeError, ValueError):
            return None
        protocol = str(port_info.get("protocol", "tcp") or "tcp").strip().lower()
        return (protocol or "tcp", port_id)

    @staticmethod
    def _port_in_scan_scope(port_id, protocol, ports):
        protocol = str(protocol or "tcp").strip().lower()
        for raw_token in str(ports or "").split(","):
            token = raw_token.strip()
            if not token:
                continue
            token_protocol = "tcp"
            if ":" in token:
                prefix, token = token.split(":", 1)
                prefix = prefix.strip().lower()
                if prefix in ("t", "tcp"):
                    token_protocol = "tcp"
                elif prefix in ("u", "udp"):
                    token_protocol = "udp"
                else:
                    continue
            if token_protocol != protocol:
                continue
            try:
                if "-" in token:
                    start, end = token.split("-", 1)
                    start_port, end_port = int(start), int(end)
                else:
                    start_port = end_port = int(token)
            except (TypeError, ValueError):
                continue
            if start_port <= int(port_id) <= end_port:
                return True
        return False

    @classmethod
    def _attach_complete_connect_scan_evidence(cls, ip_port_result, ports, asset_ip_info_map):
        scan_coverage = getattr(ip_port_result, "scan_coverage", {}) or {}
        if not isinstance(scan_coverage, dict):
            scan_coverage = {}
        completed_targets = scan_coverage.get("completed_targets", {}) or {}
        if not isinstance(completed_targets, dict):
            completed_targets = {}
        scan_ports = scan_coverage.get("ports") or ports

        result_by_ip = {
            str(ip_info.get("ip", "")).strip(): ip_info
            for ip_info in (ip_port_result or [])
            if isinstance(ip_info, dict) and str(ip_info.get("ip", "")).strip()
        }
        for ip, asset_info in (asset_ip_info_map or {}).items():
            if ip in result_by_ip or not isinstance(asset_info, dict):
                continue
            scan_method = cls._scan_method_for_ip(ip, completed_targets)
            if scan_method not in ("connect", "connect_fallback"):
                continue
            ip_info = {
                "ip": ip,
                "port_info": [],
                "os_info": {},
                "_scan_coverage": {
                    "complete": True,
                    "ports": scan_ports,
                    "scan_method": scan_method,
                },
            }
            ip_port_result.append(ip_info)
            result_by_ip[ip] = ip_info

        for ip_info in ip_port_result or []:
            coverage = ip_info.get("_scan_coverage")
            if not isinstance(coverage, dict) or not coverage.get("complete"):
                scan_method = cls._scan_method_for_ip(ip_info.get("ip", ""), completed_targets)
                if scan_method in ("connect", "connect_fallback"):
                    coverage = {
                        "complete": True,
                        "ports": scan_ports,
                        "scan_method": scan_method,
                    }
                    ip_info["_scan_coverage"] = coverage
            if not isinstance(coverage, dict) or not coverage.get("complete"):
                continue
            if str(coverage.get("scan_method", "")).lower() not in ("connect", "connect_fallback"):
                continue

            asset_info = (asset_ip_info_map or {}).get(ip_info.get("ip"))
            if not isinstance(asset_info, dict):
                continue
            open_keys = {
                key for key in (
                    cls._port_key(port_info)
                    for port_info in (ip_info.get("port_info", []) or [])
                )
                if key
            }
            validation = ip_info.get("_connect_validation")
            if not isinstance(validation, dict):
                validation = {}
                ip_info["_connect_validation"] = validation

            not_open = {
                key for key in (
                    cls._port_key(port_info)
                    for port_info in (validation.get("not_open_ports", []) or [])
                )
                if key
            }
            for port_info in asset_info.get("port_info", []) or []:
                key = cls._port_key(port_info)
                if (
                    key
                    and key[0] == "tcp"
                    and key not in open_keys
                    and cls._port_in_scan_scope(key[1], key[0], coverage.get("ports") or ports)
                ):
                    not_open.add(key)

            validation["not_open_ports"] = [
                {"protocol": protocol, "port_id": port_id}
                for protocol, port_id in sorted(not_open)
            ]

    @staticmethod
    def _scan_method_for_ip(ip, completed_targets):
        try:
            ip_address = ipaddress.ip_address(str(ip or "").strip())
        except ValueError:
            return ""
        matching_methods = []
        for target, scan_method in (completed_targets or {}).items():
            matched = False
            range_parts = str(target).strip().rsplit("-", 1)
            if len(range_parts) == 2 and "." in range_parts[0] and range_parts[1].isdigit():
                try:
                    start_address = ipaddress.IPv4Address(range_parts[0])
                    end_octet = int(range_parts[1])
                except ipaddress.AddressValueError:
                    start_address = None
                    end_octet = -1
                if (
                    start_address is not None
                    and isinstance(ip_address, ipaddress.IPv4Address)
                    and start_address.packed[:3] == ip_address.packed[:3]
                    and start_address.packed[3] <= ip_address.packed[3] <= end_octet <= 255
                ):
                    matched = True
            if not matched:
                try:
                    network = ipaddress.ip_network(str(target).strip(), strict=False)
                except ValueError:
                    continue
                matched = ip_address in network
            if matched:
                matching_methods.append(str(scan_method or "").strip().lower())

        # 重叠目标可能由不同扫描方式完成；完整 connect 覆盖可以校正资产。
        for preferred_method in ("connect_fallback", "connect"):
            if preferred_method in matching_methods:
                return preferred_method
        return matching_methods[0] if matching_methods else ""

    def run(self):
        task = self.task
        scan_port_option = self._build_scan_options()
        targets = str(task.ip_target or "").split()
        ip_port_result = self.services.port_scan(targets, **scan_port_option)

        if task.task_tag == "monitor":
            task.set_asset_ip()
            self._attach_complete_connect_scan_evidence(
                ip_port_result,
                scan_port_option.get("ports"),
                getattr(task, "asset_ip_info_map", {}),
            )

        task.ip_info_list.extend(ip_port_result)

        for ip_info in ip_port_result:
            curr_ip = ip_info["ip"]
            task.ip_set.add(curr_ip)
            if not self.utils.not_in_black_ips(curr_ip):
                continue

            ip_info["task_id"] = task.task_id
            ip_info["ip_type"] = self.utils.get_ip_type(curr_ip)
            ip_info["geo_asn"] = {}
            ip_info["geo_city"] = {}
            if ip_info["ip_type"] == "PUBLIC":
                ip_info["geo_asn"] = self.utils.get_ip_asn(curr_ip)
                ip_info["geo_city"] = self.utils.get_ip_city(curr_ip)

            if task.task_tag == "task":
                writer = getattr(task, "_result_writer", None) or TaskResultWriteService(
                    task.task_id,
                    utils_module=self.utils,
                )
                persisted_ip_info = dict(ip_info)
                persisted_ip_info.pop("_suspected_all_open", None)
                persisted_ip_info.pop("_connect_validation", None)
                persisted_ip_info.pop("_scan_coverage", None)
                writer.insert_one("ip", persisted_ip_info)

        if task.task_tag == "monitor":
            task.async_ip_info()
        return ip_port_result


class IPSiteDiscoveryStageService(object):
    """根据开放端口批量探测 HTTP/HTTPS 站点。"""

    def __init__(self, task, services_module=None):
        self.task = task
        self.services = services_module or services

    def _build_candidates(self):
        url_temp_list = []
        selected_port_count = 0
        dropped_port_count = 0
        suspected_all_open_count = 0
        for ip_info in self.task.ip_info_list:
            port_info_list = list(ip_info.get("port_info", []) or [])
            suspected_all_open = bool(ip_info.get("_suspected_all_open"))
            if suspected_all_open:
                suspected_all_open_count += 1
            selected_ports = select_probe_port_infos(
                port_info_list,
                getattr(Config, "SITE_DISCOVERY_MAX_PORTS_PER_HOST", 32),
                suspected_all_open=suspected_all_open,
                probe_kind="http",
            )
            selected_port_count += len(selected_ports)
            dropped_port_count += max(0, len(port_info_list) - len(selected_ports))
            for port_info in selected_ports:
                curr_ip = ip_info["ip"]
                port_id = normalize_port_id(port_info)
                if port_id == 80:
                    url_temp_list.append("http://{}".format(curr_ip))
                elif port_id == 443:
                    url_temp_list.append("https://{}".format(curr_ip))
                else:
                    url_temp_list.extend(
                        [
                            "http://{}:{}".format(curr_ip, port_id),
                            "https://{}:{}".format(curr_ip, port_id),
                        ]
                    )
        logger.info(
            "ip site candidate ports selected:{} dropped:{} suspected_all_open:{}".format(
                selected_port_count,
                dropped_port_count,
                suspected_all_open_count,
            )
        )
        return url_temp_list

    def run(self):
        task = self.task
        url_temp_list = self._build_candidates()
        check_map = self.services.check_http(url_temp_list)
        alive_site = []
        for url in check_map:
            if url.startswith("https://"):
                alive_site.append(url)
            elif url.startswith("http://"):
                https_url = "https://" + url[7:]
                if https_url not in check_map:
                    alive_site.append(url)

        task.site_list.extend(alive_site)
        return alive_site
