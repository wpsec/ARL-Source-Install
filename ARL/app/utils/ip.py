"""
IP地址处理和转换工具
"""
import re
import geoip2.database
from app.config import Config
from .IPy import IP

_ASN_READER = None
_CITY_READER = None


def _get_asn_reader():
    global _ASN_READER
    if _ASN_READER is None:
        _ASN_READER = geoip2.database.Reader(Config.GEOIP_ASN)
    return _ASN_READER


def _get_city_reader():
    global _CITY_READER
    if _CITY_READER is None:
        _CITY_READER = geoip2.database.Reader(Config.GEOIP_CITY)
    return _CITY_READER


def is_vaild_ip_target(ip):
    if re.match(
            r"^\d+\.\d+\.\d+\.\d+$|^\d+\.\d+\.\d+\.\d+/\d+$|^\d+\.\d+\.\d+.\d+-\d+$", ip):
        return True
    else:
        return False


def _parse_ipv4_range(text):
    """解析 a.b.c.d-e.f.g.h 形态；非法或反向返回 None。"""
    parts = str(text or "").split("-")
    if len(parts) != 2:
        return None
    start_text = parts[0].strip()
    end_text = parts[1].strip()
    if not start_text or not end_text:
        return None
    start = IP(start_text)
    end = IP(end_text)
    if start.version() != 4 or end.version() != 4:
        raise ValueError("first-last notation only allowed for IPv4")
    if end.int() < start.int():
        raise ValueError("last address should be larger than first")
    return start, end


def transfer_ip_scope(target):
    """
    将目标IP,IP段转换为合法的CIDR表示方法。

    无法折叠为单一 CIDR 的非对齐区间(如 192.0.2.10-192.0.2.20)保留规范 start-end
    文本,由 ip_in_scope 按区间直比匹配;不再误判为非法输入。
    """
    from . import get_logger
    logger = get_logger()

    try:
        return IP(target, make_net=True).strNormal(1)
    except Exception:
        pass

    try:
        parsed = _parse_ipv4_range(target)
        if parsed is None:
            raise ValueError("not a valid ip scope")
        start, end = parsed
        return "{}-{}".format(str(start), str(end))
    except Exception as e:
        logger.warn("error on ip_scope {} {}".format(target, e))


#判断是否在黑名单IP内，有点不严谨
def not_in_black_ips(target):
    from . import get_logger
    logger = get_logger()
    try:
        for ip in Config.BLACK_IPS:
            if "-" in target:
                target = target.split("-")[0]

            if "/" in target:
                target = target.split("/")[0]

            if IP(target) in IP(ip):
                return False
    except Exception as e:
        logger.warn("error on check black ip {} {}".format(target, e))

    return True


def get_ip_asn(ip):
    from . import get_logger
    logger = get_logger()
    item = {}
    try:
        reader = _get_asn_reader()
        response = reader.asn(ip)
        item["number"] = response.autonomous_system_number
        item["organization"] = response.autonomous_system_organization
    except Exception as e:
        logger.warning("{} {}".format(e, ip))

    return item


def get_ip_city(ip):
    from . import get_logger
    logger = get_logger()
    try:
        reader = _get_city_reader()
        response = reader.city(ip)
        item = {
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "country_name": response.country.name,
            "country_code": response.country.iso_code,
            "region_name": response.subdivisions.most_specific.name,
            "region_code": response.subdivisions.most_specific.iso_code,
        }
        return item

    except Exception as e:
        logger.warning("{} {}".format(e,ip))
        return {}


def get_ip_type(ip):
    from . import get_logger
    logger = get_logger()
    try:
        # 国内好多企业把这两个段当成内网域名
        if ip.startswith("9.") or ip.startswith("11."):
            return "PRIVATE"

        ip_type = IP(ip).iptype()

        # 为了方便全部设置为 PRIVATE
        if ip_type in ["CARRIER_GRADE_NAT", "LOOPBACK", "RESERVED"]:
            return "PRIVATE"

        return ip_type

    except Exception as e:
        logger.warning("{} {}".format(e, ip))
        return "ERROR"


def ip_in_scope(ip, scope_list):
    from . import get_logger
    logger = get_logger()

    try:
        ip_obj = IP(ip)
        ip_int = ip_obj.int()
    except Exception as e:
        logger.warning("{} {}".format(e, ip))
        return False

    for item in scope_list:
        try:
            item_text = str(item or "").strip()
            if "-" in item_text and ip_obj.version() == 4:
                # 非对齐区间不能经 IPy 构造,这里按整数区间直比。
                range_parts = _parse_ipv4_range(item_text)
                if range_parts is None:
                    continue
                start, end = range_parts
                if start.int() <= ip_int <= end.int():
                    return True
                continue
            if ip_obj in IP(item):
                return True
        except Exception as e:
            logger.warning("{} {} {}".format(e, ip, item))

    return False
