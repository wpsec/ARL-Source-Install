"""
域名泛解析判定辅助工具
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from app import utils
from app.config import Config


DEFAULT_WILDCARD_PROBE_COUNT = 3
DEFAULT_WILDCARD_VERIFY_ROUNDS = 2
DEFAULT_WILDCARD_MAX_LEVELS = 2


def _safe_positive_int(value, default_value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default_value

    if number <= 0:
        return default_value

    return number


def get_wildcard_probe_count():
    return _safe_positive_int(
        getattr(Config, "WILDCARD_PROBE_COUNT", DEFAULT_WILDCARD_PROBE_COUNT),
        DEFAULT_WILDCARD_PROBE_COUNT,
    )


def get_wildcard_verify_rounds():
    return _safe_positive_int(
        getattr(Config, "WILDCARD_VERIFY_ROUNDS", DEFAULT_WILDCARD_VERIFY_ROUNDS),
        DEFAULT_WILDCARD_VERIFY_ROUNDS,
    )


def get_wildcard_max_levels():
    return _safe_positive_int(
        getattr(Config, "WILDCARD_MAX_LEVELS", DEFAULT_WILDCARD_MAX_LEVELS),
        DEFAULT_WILDCARD_MAX_LEVELS,
    )


def get_wildcard_profile_concurrency():
    return _safe_positive_int(
        getattr(Config, "WILDCARD_PROFILE_CONCURRENCY", 8),
        8,
    )


def get_wildcard_probe_concurrency():
    return _safe_positive_int(
        getattr(Config, "WILDCARD_PROBE_CONCURRENCY", 2),
        2,
    )


def _normalize_dns_record(value):
    return str(value or "").strip().strip(".").lower()


def _normalize_signature(records):
    normalized = []
    seen = set()
    for item in records or []:
        record = _normalize_dns_record(item)
        if not record or record in seen:
            continue
        seen.add(record)
        normalized.append(record)
    normalized.sort()
    return tuple(normalized)


def _empty_record_detail():
    return {
        "records": set(),
        "a_records": set(),
        "cname_records": set(),
    }


def _empty_profile(root):
    return {
        "root": root,
        "records": set(),
        "a_records": set(),
        "cname_records": set(),
        "signatures": set(),
        "record_counter": Counter(),
        "signature_counter": Counter(),
        "probe_domains": set(),
        "sample_count": 0,
    }


def _get_probe_root(domain):
    normalized = utils.normalize_domain(domain)
    if not normalized:
        return ""

    # 对已有子域使用同层探测，避免把更高层级的泛解析误当成当前结果。
    cut_name = utils.domain.cut_first_name(normalized)
    return cut_name or normalized


def build_wildcard_probe_roots(domains, max_levels=None):
    roots = []
    seen = set()
    max_levels = _safe_positive_int(max_levels or get_wildcard_max_levels(), get_wildcard_max_levels())

    for domain in domains or []:
        normalized = utils.normalize_domain(domain)
        if not normalized:
            continue

        current = normalized
        level_count = 0
        while current and level_count < max_levels:
            root = _get_probe_root(current)
            if not root:
                break
            if root in seen:
                if root == current:
                    break
                current = root
                level_count += 1
                continue

            seen.add(root)
            roots.append(root)
            level_count += 1

            if root == current:
                break
            current = root

    return roots


def build_wildcard_probe_domains(domains, probe_count=None, max_levels=None):
    probe_domains = set()
    roots = build_wildcard_probe_roots(domains, max_levels=max_levels)
    probe_count = _safe_positive_int(probe_count or get_wildcard_probe_count(), get_wildcard_probe_count())

    for root in roots:
        for _ in range(probe_count):
            probe_domains.add("{}.{}".format(utils.random_choices(8), root))

    return probe_domains


def resolve_domain_record_detail(domain):
    detail = _empty_record_detail()

    for item in utils.get_ip(domain, log_flag=False):
        normalized = _normalize_dns_record(item)
        if not normalized:
            continue
        detail["records"].add(normalized)
        detail["a_records"].add(normalized)

    for item in utils.get_cname(domain, log_flag=False):
        normalized = _normalize_dns_record(item)
        if not normalized:
            continue
        detail["records"].add(normalized)
        detail["cname_records"].add(normalized)

    return detail


def resolve_domain_records(domain):
    return resolve_domain_record_detail(domain)["records"]


def _collect_wildcard_profile_for_root(root, probe_count, verify_rounds):
    profile = _empty_profile(root)
    probe_domains = set()
    for _ in range(probe_count):
        probe_domains.add("{}.{}".format(utils.random_choices(8), root))
    profile["probe_domains"] = probe_domains

    probe_jobs = [
        (probe_domain, round_index)
        for probe_domain in sorted(probe_domains)
        for round_index in range(verify_rounds)
    ]
    probe_results = {}
    worker_count = min(get_wildcard_probe_concurrency(), len(probe_jobs))
    if worker_count <= 1:
        for index, (probe_domain, _round_index) in enumerate(probe_jobs):
            probe_results[index] = resolve_domain_record_detail(probe_domain)
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {
                executor.submit(resolve_domain_record_detail, probe_domain): index
                for index, (probe_domain, _round_index) in enumerate(probe_jobs)
            }
            for future in as_completed(future_map):
                probe_results[future_map[future]] = future.result()

    for index in range(len(probe_jobs)):
        detail = probe_results[index]
        signature = _normalize_signature(detail["records"])
        profile["sample_count"] += 1
        if not signature:
            continue

        profile["records"].update(detail["records"])
        profile["a_records"].update(detail["a_records"])
        profile["cname_records"].update(detail["cname_records"])
        profile["signatures"].add(signature)
        profile["record_counter"].update(signature)
        profile["signature_counter"][signature] += 1

    return profile


def _collect_wildcard_profiles_for_roots(roots, probe_count=None, verify_rounds=None):
    profile_map = {}
    probe_count = _safe_positive_int(probe_count or get_wildcard_probe_count(), get_wildcard_probe_count())
    verify_rounds = _safe_positive_int(verify_rounds or get_wildcard_verify_rounds(), get_wildcard_verify_rounds())

    normalized_roots = []
    seen_roots = set()
    for root in roots or []:
        normalized_root = utils.normalize_domain(root)
        if not normalized_root or normalized_root in seen_roots:
            continue
        seen_roots.add(normalized_root)
        normalized_roots.append(normalized_root)

    if not normalized_roots:
        return profile_map

    logger = None
    get_logger = getattr(utils, "get_logger", None)
    if callable(get_logger):
        logger = get_logger()

    def collect_one(root):
        try:
            return root, _collect_wildcard_profile_for_root(
                root,
                probe_count=probe_count,
                verify_rounds=verify_rounds,
            )
        except Exception as exc:
            # 画像探测失败时不执行过滤，避免把网络故障误报成泛解析结果。
            if logger:
                logger.warning(
                    "wildcard profile degraded root:{} error_type:{}".format(
                        root,
                        type(exc).__name__,
                    )
                )
            return root, _empty_profile(root)

    worker_count = min(get_wildcard_profile_concurrency(), len(normalized_roots))
    if worker_count <= 1:
        for root in normalized_roots:
            key, profile = collect_one(root)
            profile_map[key] = profile
        return profile_map

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(collect_one, root): root
            for root in normalized_roots
        }
        for future in as_completed(future_map):
            root = future_map[future]
            try:
                key, profile = future.result()
            except Exception as exc:
                # collect_one 已覆盖普通异常；保留最后一道防线，避免整批失败。
                if logger:
                    logger.warning(
                        "wildcard profile batch degraded root:{} error_type:{}".format(
                            root,
                            type(exc).__name__,
                        )
                    )
                key, profile = root, _empty_profile(root)
            profile_map[key] = profile

    return profile_map


def collect_wildcard_profiles_from_roots(roots, probe_count=None, verify_rounds=None):
    return _collect_wildcard_profiles_for_roots(
        roots,
        probe_count=probe_count,
        verify_rounds=verify_rounds,
    )


def collect_wildcard_profiles_from_domains(domains, probe_count=None, max_levels=None, verify_rounds=None):
    return _collect_wildcard_profiles_for_roots(
        build_wildcard_probe_roots(domains, max_levels=max_levels),
        probe_count=probe_count,
        verify_rounds=verify_rounds,
    )


def collect_wildcard_records_from_domains(domains, probe_count=None, max_levels=None, verify_rounds=None):
    wildcard_records = set()
    profile_map = collect_wildcard_profiles_from_domains(
        domains,
        probe_count=probe_count,
        max_levels=max_levels,
        verify_rounds=verify_rounds,
    )

    for profile in profile_map.values():
        wildcard_records |= set(profile.get("records", set()))

    return wildcard_records


def extract_domain_info_record_detail(domain_info):
    detail = _empty_record_detail()
    if not domain_info:
        return detail

    domain_type = str(getattr(domain_info, "type", "") or "").strip().upper()

    for item in getattr(domain_info, "record_list", []) or []:
        normalized = _normalize_dns_record(item)
        if not normalized:
            continue
        detail["records"].add(normalized)
        if domain_type == "CNAME":
            detail["cname_records"].add(normalized)
        else:
            detail["a_records"].add(normalized)

    for item in getattr(domain_info, "ip_list", []) or []:
        normalized = _normalize_dns_record(item)
        if not normalized:
            continue
        detail["records"].add(normalized)
        detail["a_records"].add(normalized)

    return detail


def extract_domain_info_records(domain_info):
    return extract_domain_info_record_detail(domain_info)["records"]


def _verify_candidate_details(domain, base_detail=None, verify_rounds=None):
    details = []
    verify_rounds = _safe_positive_int(verify_rounds or get_wildcard_verify_rounds(), get_wildcard_verify_rounds())

    if isinstance(base_detail, dict) and base_detail.get("records"):
        details.append(base_detail)

    while len(details) < verify_rounds:
        details.append(resolve_domain_record_detail(domain))

    return details


def build_wildcard_candidate_details(domain_info, verify_rounds=None):
    """构建单个候选的泛解析复验详情，供批次调度复用。"""
    domain = utils.normalize_domain(getattr(domain_info, "domain", ""))
    if not domain:
        return []

    return _verify_candidate_details(
        domain,
        base_detail=extract_domain_info_record_detail(domain_info),
        verify_rounds=verify_rounds,
    )


def _candidate_hits_profile(candidate_details, profile):
    if not candidate_details or not profile:
        return False

    profile_records = set(profile.get("records", set()))
    if not profile_records:
        return False

    profile_signatures = set(profile.get("signatures", set()))
    profile_cname_records = set(profile.get("cname_records", set()))
    record_counter = profile.get("record_counter", Counter())

    exact_match_count = 0
    subset_match_count = 0
    single_record_repeat_match = 0
    non_empty_count = 0

    for detail in candidate_details:
        signature = _normalize_signature(detail.get("records", set()))
        if not signature:
            continue

        non_empty_count += 1
        signature_set = set(signature)

        if detail.get("cname_records", set()) & profile_cname_records:
            return True

        if signature in profile_signatures:
            exact_match_count += 1

        if signature_set.issubset(profile_records):
            subset_match_count += 1
            if len(signature_set) == 1:
                only_record = next(iter(signature_set))
                if record_counter.get(only_record, 0) >= 2:
                    single_record_repeat_match += 1

    if non_empty_count <= 0:
        return False

    required_match_count = 2 if non_empty_count >= 2 else 1
    if exact_match_count >= required_match_count:
        return True
    if subset_match_count >= required_match_count and single_record_repeat_match >= required_match_count:
        return True

    return False


def _domain_info_hits_wildcard_profile(
    domain_info,
    wildcard_profile_map,
    verify_rounds=None,
    max_levels=None,
    candidate_details=None,
):
    if not domain_info or not wildcard_profile_map:
        return False

    domain = utils.normalize_domain(getattr(domain_info, "domain", ""))
    if not domain:
        return False

    roots = build_wildcard_probe_roots([domain], max_levels=max_levels)
    if not roots:
        return False

    if candidate_details is None:
        candidate_details = build_wildcard_candidate_details(
            domain_info,
            verify_rounds=verify_rounds,
        )

    for root in roots:
        profile = wildcard_profile_map.get(root)
        if not profile:
            continue

        if _candidate_hits_profile(candidate_details, profile):
            return True

    return False


def domain_info_hits_wildcard_profile(domain_info, wildcard_profile_map, verify_rounds=None, max_levels=None):
    return _domain_info_hits_wildcard_profile(
        domain_info,
        wildcard_profile_map,
        verify_rounds=verify_rounds,
        max_levels=max_levels,
    )


def domain_info_hits_wildcard_profile_with_details(
    domain_info,
    wildcard_profile_map,
    candidate_details,
    verify_rounds=None,
    max_levels=None,
):
    """使用已批量复验详情判断泛解析，避免在过滤循环中重复发起 DNS 请求。"""
    return _domain_info_hits_wildcard_profile(
        domain_info,
        wildcard_profile_map,
        verify_rounds=verify_rounds,
        max_levels=max_levels,
        candidate_details=candidate_details,
    )


def domain_info_hits_wildcard_records(domain_info, wildcard_records):
    if not domain_info or not wildcard_records:
        return False

    return bool(extract_domain_info_records(domain_info) & set(wildcard_records))
