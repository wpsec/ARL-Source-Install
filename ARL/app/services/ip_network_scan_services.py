"""IP 网络阶段的具体业务服务。

这些服务承接 IPTask 的端口扫描和站点发现逻辑，保留 Python 的网络、数据库和
任务上下文能力；IPTask 仅保留兼容入口，避免外部任务调用方发生变化。
"""

from app import services, utils
from app.config import Config
from app.modules import ScanPortType


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

    def run(self):
        task = self.task
        scan_port_option = self._build_scan_options()
        targets = str(task.ip_target or "").split()
        ip_port_result = self.services.port_scan(targets, **scan_port_option)
        task.ip_info_list.extend(ip_port_result)

        if task.task_tag == "monitor":
            task.set_asset_ip()

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
                self.utils.conn_db("ip").insert_one(ip_info)

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
        for ip_info in self.task.ip_info_list:
            for port_info in ip_info["port_info"]:
                curr_ip = ip_info["ip"]
                port_id = port_info["port_id"]
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
