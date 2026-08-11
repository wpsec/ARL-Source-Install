"""
域名泛解析判定辅助工具
"""
from app import utils


DEFAULT_WILDCARD_PROBE_COUNT = 3


def _normalize_dns_record(value):
    text = str(value or "").strip().strip(".").lower()
    return text


def _get_probe_root(domain):
    normalized = utils.normalize_domain(domain)
    if not normalized:
        return ""

    # 对已有子域使用同层探测，避免把更高层级的泛解析误当成当前结果。
    cut_name = utils.domain.cut_first_name(normalized)
    return cut_name or normalized


def build_wildcard_probe_domains(domains, probe_count=DEFAULT_WILDCARD_PROBE_COUNT):
    probe_domains = set()
    roots = set()

    for domain in domains or []:
        root = _get_probe_root(domain)
        if root:
            roots.add(root)

    try:
        probe_count = int(probe_count or DEFAULT_WILDCARD_PROBE_COUNT)
    except (TypeError, ValueError):
        probe_count = DEFAULT_WILDCARD_PROBE_COUNT

    if probe_count <= 0:
        probe_count = DEFAULT_WILDCARD_PROBE_COUNT

    for root in roots:
        for _ in range(probe_count):
            probe_domains.add("{}.{}".format(utils.random_choices(8), root))

    return probe_domains


def resolve_domain_records(domain):
    records = set()

    for item in utils.get_ip(domain, log_flag=False):
        normalized = _normalize_dns_record(item)
        if normalized:
            records.add(normalized)

    for item in utils.get_cname(domain, log_flag=False):
        normalized = _normalize_dns_record(item)
        if normalized:
            records.add(normalized)

    return records


def collect_wildcard_records_from_domains(domains, probe_count=DEFAULT_WILDCARD_PROBE_COUNT):
    wildcard_records = set()
    probe_domains = build_wildcard_probe_domains(domains, probe_count=probe_count)

    for probe_domain in probe_domains:
        wildcard_records |= resolve_domain_records(probe_domain)

    return wildcard_records


def extract_domain_info_records(domain_info):
    records = set()
    if not domain_info:
        return records

    for attr_name in ("record_list", "ip_list"):
        for item in getattr(domain_info, attr_name, []) or []:
            normalized = _normalize_dns_record(item)
            if normalized:
                records.add(normalized)

    return records


def domain_info_hits_wildcard_records(domain_info, wildcard_records):
    if not domain_info or not wildcard_records:
        return False

    return bool(extract_domain_info_records(domain_info) & set(wildcard_records))
