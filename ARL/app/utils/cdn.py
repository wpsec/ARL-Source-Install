"""
CDN识别
"""
import json
import ipaddress
from .IPy import IP
from app.config import Config


cdn_ip_cidr_list = []
cdn_cname_list = []
cdn_info = []

CNAME_HEURISTIC_KEYWORDS = (
    "cdn", "cache", "edge", "waf", "gslb", "cloudfront", "fastly", "akamai",
)


def _normalize_cname(cname):
    cname = str(cname or "").strip().lower().rstrip(".")
    return cname


def _split_cname_chain(cname):
    """
    例: a.b.c.com -> [com, c.com, b.c.com, a.b.c.com]
    """
    cname = _normalize_cname(cname)
    if not cname:
        return []

    parts = cname.split(".")
    size = len(parts)
    if size == 0:
        return []

    items = []
    curr = parts[-1]
    items.append(curr)
    for i in range(size - 2, -1, -1):
        curr = "{}.{}".format(parts[i], curr)
        items.append(curr)

    return items


def _is_public_ipv4(ip):
    try:
        obj = ipaddress.ip_address(str(ip or "").strip())
        return obj.version == 4 and obj.is_global
    except Exception:
        return False


def _same_ipv4_c_segment(ip_list):
    segments = set()
    for ip in ip_list:
        ip = str(ip or "").strip()
        if not _is_public_ipv4(ip):
            continue
        parts = ip.split(".")
        if len(parts) != 4:
            continue
        segments.add("{}.{}.{}".format(parts[0], parts[1], parts[2]))
    if len(segments) <= 1:
        return True
    return False


def _looks_like_cdn_cname(cname):
    cname = _normalize_cname(cname)
    if not cname:
        return False
    for keyword in CNAME_HEURISTIC_KEYWORDS:
        if keyword in cname:
            return True
    return False


def _init_cdn_info():
    from . import load_file
    global cdn_ip_cidr_list, cdn_cname_list, cdn_info
    if not cdn_info:
        cdn_ip_cidr_list = []
        cdn_cname_list = []
        data = "\n".join(load_file(Config.CDN_JSON_PATH))
        cdn_info = json.loads(data)

        for item in cdn_info:
            cdn_cname_list.extend(item["cname_domain"])
            if item.get("ip_cidr"):
                cdn_ip_cidr_list.extend(item["ip_cidr"])


def _ip_in_cidr_list(ip):
    for item in cdn_ip_cidr_list:
        if IP(ip) in IP(item):
            return True


def _cname_in_cname_list(cname):
    cname = _normalize_cname(cname)
    for item in cdn_cname_list:
        item = _normalize_cname(item)
        if not item:
            continue
        if cname == item or cname.endswith("." + item):
            return True


def get_cdn_name_by_ip(ip):
    from . import get_logger
    logger = get_logger()
    try:
        _init_cdn_info()

        if not _ip_in_cidr_list(ip):
            return ""

        for item in cdn_info:
            if item.get("ip_cidr"):
                for ip_cidr in item["ip_cidr"]:
                    if IP(ip) in IP(ip_cidr):
                        return item["name"]

    except Exception as e:
        logger.warning("{} {}".format(e, ip))
        return ""


def _get_cdn_name_by_cname(cname):
    from . import get_logger
    logger = get_logger()
    try:
        cname = _normalize_cname(cname)
        _init_cdn_info()
        if not _cname_in_cname_list(cname):
            return ""

        cname_variants = _split_cname_chain(cname)
        for item in cdn_info:
            for target in item["cname_domain"]:
                target = _normalize_cname(target)
                if not target:
                    continue
                if target in cname_variants:
                    return item["name"]

    except Exception as e:
        logger.warning("{} {}".format(e, cname))
        return ""


def get_cdn_name_by_cname(cname):
    cname = _normalize_cname(cname)
    cdn_name = _get_cdn_name_by_cname(cname)

    check_list = ["gslb", "dns", "cache"]

    if not cdn_name:
        for check in check_list:
            if check in cname:
                return "CDN"

    return cdn_name


def infer_cdn_by_dns(cname="", ip_list=None):
    """
    结合 CNAME 与解析IP的启发式判定 CDN。
    返回:
        - 厂商名（命中静态规则）
        - "CDN"（命中启发式）
        - ""（未命中）
    """
    if ip_list is None:
        ip_list = []

    cname = _normalize_cname(cname)
    if cname:
        cdn_name = _get_cdn_name_by_cname(cname)
        if cdn_name:
            return cdn_name
        if _looks_like_cdn_cname(cname):
            return "CDN"

    normalized_public_ips = []
    for ip in ip_list:
        ip = str(ip or "").strip()
        if not ip:
            continue
        if _is_public_ipv4(ip):
            normalized_public_ips.append(ip)

    normalized_public_ips = list(set(normalized_public_ips))
    # kscan 启发式：多IP且不在同一C段，可能使用CDN
    if len(normalized_public_ips) >= 2 and not _same_ipv4_c_segment(normalized_public_ips):
        return "CDN"

    return ""
