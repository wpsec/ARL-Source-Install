"""
SSL证书获取和解析
"""
import time
from app import utils, modules, services
from .baseThread import BaseThread

logger = utils.get_logger()


def split_host_port(target):
    """
    解析 host:port，失败时返回("", 0)。
    """
    text = str(target or "").strip()
    if not text or ":" not in text:
        return "", 0

    host, port_text = text.rsplit(":", 1)
    host = host.strip()
    port_text = port_text.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    try:
        port = int(port_text)
    except Exception:
        return "", 0

    return host, port


def _normalize_domains(domains):
    """
    归一化域名列表，去重并过滤非法项。
    """
    if isinstance(domains, str):
        domains = [domains]
    if not isinstance(domains, list):
        return []

    result = []
    seen = set()
    for raw_domain in domains:
        domain = str(raw_domain or "").strip().lower().strip(".")
        if not domain:
            continue
        if domain.startswith("*."):
            domain = domain[2:]
        if not utils.is_valid_domain(domain):
            continue
        if domain in seen:
            continue
        seen.add(domain)
        result.append(domain)

    return sorted(result)


def _pick_server_name(domains, base_domain=""):
    """
    选择 SNI 域名：
    1) 优先 base_domain 本身
    2) 再选 base_domain 子域
    3) 最后取首个候选
    """
    domains = _normalize_domains(domains)
    if not domains:
        return ""

    base = str(base_domain or "").strip().lower().strip(".")
    if base.startswith("*."):
        base = base[2:]

    if base:
        for domain in domains:
            if domain == base:
                return domain
        suffix = ".{}".format(base)
        for domain in domains:
            if domain.endswith(suffix):
                return domain

    return domains[0]


def _merge_target_domains(target_info, domains, base_domain=""):
    """
    合并并刷新 target 的域名候选与 SNI 域名。
    """
    old_domains = target_info.get("domains", [])
    merged = _normalize_domains(list(old_domains) + list(domains or []))
    target_info["domains"] = merged
    target_info["server_name"] = _pick_server_name(merged, base_domain=base_domain)
    return target_info


def _build_target_info(endpoint, connect_host, port, domains=None, base_domain=""):
    domains = _normalize_domains(domains or [])
    target_info = {
        "endpoint": str(endpoint or "").strip(),
        "connect_host": str(connect_host or "").strip(),
        "port": int(port),
        "domains": domains,
        "server_name": _pick_server_name(domains, base_domain=base_domain),
    }

    connect_host_text = target_info["connect_host"]
    if not target_info["server_name"] and utils.is_valid_domain(connect_host_text):
        target_info["server_name"] = connect_host_text.lower()
        if connect_host_text.lower() not in target_info["domains"]:
            target_info["domains"].append(connect_host_text.lower())

    return target_info




class FetchCert(BaseThread):
    def __init__(self, targets, concurrency=6):
        super().__init__(targets, concurrency=concurrency)
        self.fetch_map = {}

    def work(self, target):
        target_info = {}
        if isinstance(target, dict):
            target_info = dict(target)
        elif isinstance(target, str):
            host, port = split_host_port(target)
            if host and port > 0:
                target_info = _build_target_info(
                    endpoint="{}:{}".format(host, port),
                    connect_host=host,
                    port=port,
                )

        endpoint = str(target_info.get("endpoint", "")).strip()
        connect_host = str(target_info.get("connect_host", "")).strip()
        server_name = str(target_info.get("server_name", "")).strip()
        domains = _normalize_domains(target_info.get("domains", []))

        port = target_info.get("port", 0)
        try:
            port = int(port)
        except Exception:
            port = 0

        if not endpoint or not connect_host or port <= 0:
            return

        cert = utils.get_cert(connect_host, port, server_hostname=server_name)
        if cert:
            if isinstance(cert, dict):
                cert["_scan_meta"] = {
                    "endpoint": endpoint,
                    "connect_host": connect_host,
                    "server_name": server_name,
                    "domains": domains,
                }
            self.fetch_map[endpoint] = cert

    def run(self):
        t1 = time.time()
        logger.info("start FetchCert {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        logger.info("end FetchCert elapse {}".format(elapse))
        return self.fetch_map



def fetch_cert(targets, concurrency = 15):
    f = FetchCert(targets, concurrency = concurrency)
    return f.run()



class SSLCert():
    def __init__(self, ip_info_list, base_doamin = None):
        self.ip_info_list = ip_info_list
        self.base_domain = base_doamin

    def _append_target_info(self, target_map, endpoint, connect_host, port, domains=None):
        endpoint = str(endpoint or "").strip()
        connect_host = str(connect_host or "").strip()
        if not endpoint or not connect_host:
            return

        try:
            port = int(port)
        except Exception:
            return

        if port <= 0:
            return

        if endpoint not in target_map:
            target_map[endpoint] = _build_target_info(
                endpoint=endpoint,
                connect_host=connect_host,
                port=port,
                domains=domains or [],
                base_domain=self.base_domain,
            )
            return

        target_info = target_map[endpoint]
        target_map[endpoint] = _merge_target_domains(
            target_info=target_info,
            domains=domains or [],
            base_domain=self.base_domain,
        )

    def run(self):
        target_map = {}
        for info in self.ip_info_list:
            if isinstance(info, modules.IPInfo):
                domains = _normalize_domains(getattr(info, "domain", []))
                for port_info in info.port_info_list:
                    port_id = port_info.port_id
                    if port_id == 80:
                        continue

                    endpoint = "{}:{}".format(info.ip, port_id)
                    self._append_target_info(
                        target_map=target_map,
                        endpoint=endpoint,
                        connect_host=info.ip,
                        port=port_id,
                        domains=domains,
                    )

            elif isinstance(info, dict):
                ip = str(info.get("ip", "")).strip()
                if not ip:
                    continue

                domains = _normalize_domains(info.get("domain", []))
                for port_info in info.get("port_info", []):
                    port_id = ""
                    if isinstance(port_info, dict):
                        port_id = port_info.get("port_id", "")
                    elif isinstance(port_info, modules.PortInfo):
                        port_id = port_info.port_id

                    try:
                        port_id = int(port_id)
                    except Exception:
                        continue

                    if port_id == 80:
                        continue

                    endpoint = "{}:{}".format(ip, port_id)
                    self._append_target_info(
                        target_map=target_map,
                        endpoint=endpoint,
                        connect_host=ip,
                        port=port_id,
                        domains=domains,
                    )

            elif isinstance(info, str) and utils.is_vaild_ip_target(info):
                endpoint = "{}:443".format(info)
                self._append_target_info(
                    target_map=target_map,
                    endpoint=endpoint,
                    connect_host=info,
                    port=443,
                    domains=[],
                )

            elif isinstance(info, str) and ":" in info:
                host, port = split_host_port(info)
                if not host or port <= 0 or port == 80:
                    continue

                endpoint = "{}:{}".format(host, port)
                domains = [host] if utils.is_valid_domain(host) else []
                self._append_target_info(
                    target_map=target_map,
                    endpoint=endpoint,
                    connect_host=host,
                    port=port,
                    domains=domains,
                )

        target_temp_list = [target_map[key] for key in sorted(target_map.keys())]

        cert_map = services.fetch_cert(target_temp_list)

        return cert_map
