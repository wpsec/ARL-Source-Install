"""
SSL证书获取和解析
"""
import time
from app import utils, modules, services
from app.config import Config
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
        domain = utils.normalize_domain(raw_domain)
        if not domain or not utils.is_valid_domain(domain):
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

    base = utils.normalize_domain(base_domain)

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
    target_info["base_domain"] = utils.normalize_domain(base_domain)
    target_info["server_name"] = _pick_server_name(merged, base_domain=base_domain)
    return target_info


def _build_target_info(endpoint, connect_host, port, domains=None, base_domain=""):
    connect_host = utils.normalize_domain(connect_host) or str(connect_host or "").strip()
    try:
        port = int(port)
    except Exception:
        port = 0

    domains = _normalize_domains(domains or [])
    target_info = {
        "endpoint": "{}:{}".format(connect_host, port),
        "connect_host": connect_host,
        "port": port,
        "domains": domains,
        "base_domain": utils.normalize_domain(base_domain),
        "server_name": _pick_server_name(domains, base_domain=base_domain),
    }

    connect_host_text = target_info["connect_host"]
    if not target_info["server_name"] and utils.is_valid_domain(connect_host_text):
        target_info["server_name"] = connect_host_text
        if connect_host_text not in target_info["domains"]:
            target_info["domains"].append(connect_host_text)

    return target_info


def _sort_sni_domains(domains, base_domain=""):
    """
    对 SNI 域名候选排序：
    1) base_domain 本身
    2) base_domain 子域
    3) 其他域名
    """
    domain_list = _normalize_domains(domains or [])
    if not domain_list:
        return []

    base = utils.normalize_domain(base_domain)

    def _score(domain):
        if base and domain == base:
            return (0, len(domain), domain)
        if base and domain.endswith(".{}".format(base)):
            return (1, len(domain), domain)
        return (2, len(domain), domain)

    return sorted(domain_list, key=_score)


def _normalize_cert_domain_pattern(value):
    """
    归一化证书域名模式（支持 *.example.com 通配符）。
    """
    text = str(value or "").strip().lower().rstrip(".")
    if not text:
        return ""

    if text.startswith("*."):
        base = utils.normalize_domain(text[2:])
        if not base or not utils.is_valid_domain(base):
            return ""
        return "*.{}".format(base)

    text = utils.normalize_domain(text)
    if not text or not utils.is_valid_domain(text):
        return ""

    return text


def _extract_cert_dns_patterns(cert_obj):
    """
    从证书对象中提取可匹配的 DNS 模式（subject CN + SAN DNS）。
    """
    if not isinstance(cert_obj, dict):
        return []

    patterns = []
    seen = set()

    def _append_pattern(value):
        pattern = _normalize_cert_domain_pattern(value)
        if not pattern or pattern in seen:
            return
        seen.add(pattern)
        patterns.append(pattern)

    subject = cert_obj.get("subject", {}) if isinstance(cert_obj.get("subject"), dict) else {}
    _append_pattern(subject.get("common_name", ""))

    extensions = cert_obj.get("extensions", {}) if isinstance(cert_obj.get("extensions"), dict) else {}
    san_text = str(extensions.get("subjectAltName", "") or "").strip()
    if san_text:
        for raw_item in san_text.split(","):
            item = str(raw_item or "").strip()
            if not item:
                continue

            if ":" in item:
                prefix, value = item.split(":", 1)
                if prefix.strip().lower() != "dns":
                    continue
                _append_pattern(value)
            else:
                _append_pattern(item)

    return patterns


def _match_cert_pattern(pattern, domain):
    """
    判断证书模式是否匹配目标域名。
    """
    pattern = _normalize_cert_domain_pattern(pattern)
    domain = utils.normalize_domain(domain)
    if not pattern or not domain:
        return False

    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not suffix:
            return False
        if domain == suffix:
            return False
        if not domain.endswith(".{}".format(suffix)):
            return False
        left = domain[: -(len(suffix) + 1)]
        return bool(left) and "." not in left

    return domain == pattern


def normalize_domains(domains):
    """
    对外暴露的域名归一化工具。
    """
    return _normalize_domains(domains)


def match_cert_domains(cert_obj, domains):
    """
    返回证书与给定域名列表的命中结果（去重后按字典序）。
    """
    domain_list = _normalize_domains(domains)
    if not domain_list:
        return []

    patterns = _extract_cert_dns_patterns(cert_obj)
    if not patterns:
        return []

    matched = []
    for domain in domain_list:
        for pattern in patterns:
            if _match_cert_pattern(pattern, domain):
                matched.append(domain)
                break

    return sorted(list(set(matched)))


def cert_matches_domain(cert_obj, domain):
    """
    判断证书是否命中指定域名。
    """
    domain_text = utils.normalize_domain(domain)
    if not domain_text:
        return False
    return domain_text in match_cert_domains(cert_obj, [domain_text])


def _build_cert_scan_targets(target_info, max_sni_per_endpoint=3):
    """
    将端点目标展开为证书扫描目标：
    - default：无SNI握手（获取默认证书）
    - sni：按候选域名逐个SNI握手（获取业务域名证书）
    """
    endpoint = str(target_info.get("endpoint", "")).strip()
    connect_host = str(target_info.get("connect_host", "")).strip()
    connect_host = utils.normalize_domain(connect_host) or connect_host
    domains = _normalize_domains(target_info.get("domains", []))
    base_domain = utils.normalize_domain(target_info.get("base_domain", ""))
    port = target_info.get("port", 0)
    try:
        port = int(port)
    except Exception:
        port = 0

    if not endpoint or not connect_host or port <= 0:
        return []

    try:
        max_sni = int(max_sni_per_endpoint)
    except Exception:
        max_sni = 3
    max_sni = max(min(max_sni, 8), 0)

    scan_targets = []
    # 先扫描默认握手，获取未携带SNI时服务返回的默认证书。
    scan_targets.append(
        {
            "endpoint": endpoint,
            "connect_host": connect_host,
            "port": port,
            "domains": domains,
            "scan_mode": "default",
            "sni_domain": "",
            "observe_id": "{}|default".format(endpoint),
        }
    )

    if max_sni <= 0:
        return scan_targets

    sni_domains = _sort_sni_domains(domains, base_domain=base_domain)
    for domain in sni_domains[:max_sni]:
        scan_targets.append(
            {
                "endpoint": endpoint,
                "connect_host": connect_host,
                "port": port,
                "domains": domains,
                "scan_mode": "sni",
                "sni_domain": domain,
                "observe_id": "{}|sni:{}".format(endpoint, domain),
            }
        )

    return scan_targets




class FetchCert(BaseThread):
    def __init__(self, targets, concurrency=6):
        super().__init__(targets, concurrency=concurrency)
        self.fetch_map = {}
        self.dns_policy_cache = {}

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
        connect_host = utils.normalize_domain(connect_host) or connect_host
        scan_mode = str(target_info.get("scan_mode", "") or "").strip().lower() or "default"
        sni_domain = utils.normalize_domain(target_info.get("sni_domain", ""))
        if not sni_domain and scan_mode == "sni":
            # 兼容旧结构：未显式传入 sni_domain 时回退到 server_name 字段。
            sni_domain = utils.normalize_domain(target_info.get("server_name", ""))
        domains = _normalize_domains(target_info.get("domains", []))
        observe_id = str(target_info.get("observe_id", "")).strip() or endpoint

        port = target_info.get("port", 0)
        try:
            port = int(port)
        except Exception:
            port = 0

        if not endpoint or not connect_host or port <= 0:
            return

        if utils.is_valid_domain(connect_host):
            if connect_host in self.dns_policy_cache:
                allow_scan, policy_detail = self.dns_policy_cache[connect_host]
            else:
                allow_scan, policy_detail = utils.check_dns_policy_for_host(connect_host)
                self.dns_policy_cache[connect_host] = (allow_scan, policy_detail)

            if not allow_scan:
                logger.info(
                    "skip fetch_cert by dns policy host:{} reason:{} resolver_ips:{} system_ips:{} socket_ips:{}".format(
                        connect_host,
                        policy_detail.get("reason", ""),
                        policy_detail.get("resolver_ips", []),
                        policy_detail.get("system_ips", []),
                        policy_detail.get("socket_ips", []),
                    )
                )
                return

        cert = utils.get_cert(connect_host, port, server_hostname=sni_domain)
        if cert:
            if scan_mode == "sni" and sni_domain and isinstance(cert, dict):
                # SNI 指定域名时，仅保留证书域名命中该 SNI 的结果，避免将默认证书误标为业务证书。
                if not cert_matches_domain(cert, sni_domain):
                    logger.debug(
                        "skip cert observe mismatch observe_id:{} sni:{} endpoint:{}".format(
                            observe_id, sni_domain, endpoint
                        )
                    )
                    return

            if isinstance(cert, dict):
                cert["_scan_meta"] = {
                    "observe_id": observe_id,
                    "endpoint": endpoint,
                    "connect_host": connect_host,
                    "scan_mode": scan_mode,
                    "sni_domain": sni_domain,
                    "domains": domains,
                }
            self.fetch_map[observe_id] = cert

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
        # 同一端点执行 default + 多SNI 握手，避免多域名复用IP场景下证书被误判。
        expanded_targets = []
        for target_info in target_temp_list:
            expanded_targets.extend(
                _build_cert_scan_targets(
                    target_info=target_info,
                    max_sni_per_endpoint=getattr(Config, "CERT_MULTI_SNI_MAX_PER_ENDPOINT", 3),
                )
            )

        cert_map = services.fetch_cert(expanded_targets)

        return cert_map
