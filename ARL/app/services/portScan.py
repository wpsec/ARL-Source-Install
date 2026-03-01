"""
端口扫描执行
"""
from app import utils
from app.utils import nmap
from app.config import Config

logger = utils.get_logger()


class PortScan:
    def __init__(self, targets, ports=None, service_detect=False, os_detect=False,
                 port_parallelism=None, port_min_rate=None, custom_host_timeout=None):
        self.targets = " ".join(targets)
        self.ports = ports
        self.requested_port_count = self._estimate_port_count(ports)
        self.max_host_group = 32
        self.alive_port = "22,80,443,843,3389,8007-8011,8443,9090,8080-8091,8093,8099,5000-5004,2222,3306,1433,21,25"
        self.nmap_arguments = "-sT -n --open"
        self.max_retries = 3
        self.host_timeout = 60*5
        self.parallelism = port_parallelism  # 默认 32
        self.min_rate = port_min_rate  # 默认64
        # 全端口扫描遇到“伪全开”设备时，限制最大开放端口返回数量，避免扫描时间失控
        self.max_open_guard = None

        if service_detect:
            self.host_timeout += 60 * 5
            self.nmap_arguments += " -sV"

        if os_detect:
            self.host_timeout += 60 * 4
            self.nmap_arguments += " -O"

        if len(self.ports.split(",")) > 60:
            self.nmap_arguments += " -PE -PS{}".format(self.alive_port)
            self.max_retries = 2
        else:
            if self.ports != "0-65535":
                self.nmap_arguments += " -Pn"

        if self.ports == "0-65535":
            self.max_host_group = 2
            self.min_rate = max(self.min_rate, 800)
            self.parallelism = max(self.parallelism, 128)
            self.max_open_guard = 1200

            self.nmap_arguments += " -PE -PS{}".format(self.alive_port)
            self.host_timeout += 60 * 5
            self.max_retries = 2
            self.nmap_arguments += " --max-open {}".format(self.max_open_guard)

        self.nmap_arguments += " --max-rtt-timeout 800ms"
        self.nmap_arguments += " --min-rate {}".format(self.min_rate)
        self.nmap_arguments += " --script-timeout 6s"
        self.nmap_arguments += " --max-hostgroup {}".format(self.max_host_group)

        # 依据传过来的超时为准
        if custom_host_timeout is not None:
            if int(custom_host_timeout) > 0:
                self.host_timeout = custom_host_timeout
        self.nmap_arguments += " --host-timeout {}s".format(self.host_timeout)
        self.nmap_arguments += " --min-parallelism {}".format(self.parallelism)
        self.nmap_arguments += " --max-retries {}".format(self.max_retries)

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

    def run(self):
        logger.info("nmap target {}  ports {}  arguments {}".format(
            self.targets[:20], self.ports[:20], self.nmap_arguments))
        nm = nmap.PortScanner()
        nm.scan(hosts=self.targets, ports=self.ports, arguments=self.nmap_arguments)
        ip_info_list = []
        for host in nm.all_hosts():
            port_info_list = []
            for proto in nm[host].all_protocols():
                port_len = len(nm[host][proto])

                for port in nm[host][proto]:
                    # 对于开了很多端口的直接丢弃
                    if port_len > 600 and (port not in [80, 443]):
                        continue

                    port_info = nm[host][proto][port]
                    item = {
                        "port_id": port,
                        "service_name": port_info["name"],
                        "version": port_info["version"],
                        "product": port_info["product"],
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

            ip_info = {
                "ip": host,
                "port_info": port_info_list,
                "os_info": os_info
            }
            ip_info_list.append(ip_info)

        return ip_info_list

    def os_match_by_accuracy(self, os_match_list):
        for os_match in os_match_list:
            accuracy = os_match.get('accuracy', '0')
            if int(accuracy) > 90:
                return os_match

        return {}


def port_scan(targets, ports=Config.TOP_10, service_detect=False, os_detect=False,
              port_parallelism=32, port_min_rate=64, custom_host_timeout=None):
    targets = list(set(targets))
    targets = list(filter(utils.not_in_black_ips, targets))
    ps = PortScan(targets=targets, ports=ports, service_detect=service_detect, os_detect=os_detect,
                  port_parallelism=port_parallelism, port_min_rate=port_min_rate,
                  custom_host_timeout=custom_host_timeout)
    return ps.run()
