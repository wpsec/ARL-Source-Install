"""服务识别阶段的共享适配逻辑。

域名任务和 IP 任务的端口模型不同，但 NPoC 目标选择与结果回填规则一致；
把这部分放在服务层，避免任务类继续持有阶段业务实现。
"""


LOW_CONF_SERVICE_NAMES = {
    "",
    "unknown",
    "tcpwrapped",
    "wrapped",
    "ssl/unknown",
    "unrecognized",
}


def _get_field(value, name, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _set_field(value, name, field_value):
    if isinstance(value, dict):
        value[name] = field_value
    else:
        setattr(value, name, field_value)


def is_low_conf_service(port_info):
    """判断端口服务是否需要协议识别补充。"""
    service_name = str(_get_field(port_info, "service_name", "") or "").strip().lower()
    return not service_name or service_name in LOW_CONF_SERVICE_NAMES


def normalize_scheme(value, use_registry=True):
    value = str(value or "").strip().lower()
    if not value:
        return ""

    if use_registry:
        from app.services.service_fingerprint_registry import get_service_registry

        registry = get_service_registry()
        if registry.ok:
            return registry.canonical(value) or value

    alias_map = {
        "ssl/http": "https",
        "http/ssl": "https",
        "www": "http",
    }
    return alias_map.get(value, value)


def extract_detected_service(service_name, product=""):
    """仅从已有识别结果提取服务名，不根据端口号猜测。"""
    name = str(service_name or "").strip().lower()
    if name:
        return name

    product_name = str(product or "").strip().lower()
    if product_name in {"https-alt", "ssl/http", "http/ssl", "www"}:
        return product_name

    return ""


def resolve_service_result(
    service_name="",
    product="",
    npoc_scheme="",
    port=None,
    proto="tcp",
    use_registry=True,
):
    """把 Nmap/NPoC 观测统一为服务识别结果。

    端口仅能产生弱候选；Registry 不可用时保留旧的服务名提取逻辑，避免服务
    规范文件故障把整个端口结果吞掉。
    """

    if use_registry:
        try:
            from app.services.service_fingerprint_registry import get_service_registry

            result = get_service_registry().normalize_result(
                nmap_service=service_name,
                nmap_product=product,
                npoc_scheme=npoc_scheme,
                port=port,
                proto=proto,
            )
            if result.get("service"):
                return result
        except (AttributeError, ImportError, TypeError, ValueError) as exc:
            # Registry 属增强面，失败时继续使用兼容归一化；调用方仍可保留端口结果。
            fallback_reason = type(exc).__name__
        else:
            fallback_reason = "empty_registry_result"
    else:
        fallback_reason = "registry_disabled"

    raw_name = extract_detected_service(service_name=service_name, product=product)
    service = normalize_scheme(raw_name, use_registry=False)
    if service in LOW_CONF_SERVICE_NAMES:
        service = ""
    source = "nmap_service_name" if str(service_name or "").strip() else "legacy_passthrough"
    return {
        "service": service,
        "confirmed": bool(service),
        "confidence": 90 if service else 0,
        "sources": [source] if service else [],
        "fallback_reason": fallback_reason,
        "conflict": None,
    }


def build_sniffer_targets(task, full_port=False):
    """从两种任务端口模型构建去重后的协议识别目标。"""
    all_targets = []
    low_conf_targets = []
    target_set = set()

    for ip_info in getattr(task, "ip_info_list", []) or []:
        ip = str(_get_field(ip_info, "ip", "") or "").strip()
        if not ip:
            continue

        port_info_list = _get_field(ip_info, "port_info_list", None)
        if port_info_list is None:
            port_info_list = _get_field(ip_info, "port_info", [])

        for port_info in port_info_list or []:
            port_id = _get_field(port_info, "port_id")
            if port_id is None:
                continue

            target = "{}:{}".format(ip, port_id)
            if target in target_set:
                continue
            target_set.add(target)
            all_targets.append(target)

            if is_low_conf_service(port_info):
                low_conf_targets.append(target)

    if full_port:
        return all_targets, len(all_targets), len(low_conf_targets), "full"

    selected = list(low_conf_targets)
    if not selected and all_targets:
        for target in all_targets:
            port = target.rsplit(":", 1)[-1]
            if port in {"80", "443"}:
                continue
            selected.append(target)
            if len(selected) >= 300:
                break

    if not selected and all_targets:
        selected = all_targets[:100]

    return selected, len(all_targets), len(low_conf_targets), "smart"


def apply_npoc_service_result(task, sniffer_items, use_registry=True):
    """把协议识别结果回填到属性型或字典型端口模型。"""
    if not sniffer_items:
        return 0

    scheme_map = {}
    for item in sniffer_items:
        host = str(item.get("host", "") or "").strip()
        port = str(item.get("port", "") or "").strip()
        scheme = normalize_scheme(item.get("scheme"), use_registry=use_registry)
        if not host or not port or not scheme or scheme in LOW_CONF_SERVICE_NAMES:
            continue
        scheme_map["{}:{}".format(host, port)] = scheme

    if not scheme_map:
        return 0

    updated = 0
    for ip_info in getattr(task, "ip_info_list", []) or []:
        ip = str(_get_field(ip_info, "ip", "") or "").strip()
        if not ip:
            continue

        port_info_list = _get_field(ip_info, "port_info_list", None)
        if port_info_list is None:
            port_info_list = _get_field(ip_info, "port_info", [])

        for port_info in port_info_list or []:
            port_id = _get_field(port_info, "port_id")
            if port_id is None:
                continue

            key = "{}:{}".format(ip, port_id)
            if key not in scheme_map:
                continue

            scheme = scheme_map[key]
            curr_service = str(_get_field(port_info, "service_name", "") or "").strip().lower()
            if isinstance(port_info, dict) and use_registry:
                from app.services.service_fingerprint_registry import get_service_registry

                result = get_service_registry().normalize_result(
                    nmap_service=curr_service,
                    npoc_scheme=scheme,
                )
                new_service = result["service"] or scheme
                if curr_service != new_service:
                    updated += 1
                _set_field(port_info, "service_name", new_service)
                _set_field(port_info, "service_confidence", result["confidence"])
                _set_field(port_info, "service_sources", result["sources"])
                if result["conflict"]:
                    _set_field(port_info, "service_conflict", result["conflict"])
            else:
                if curr_service != scheme:
                    updated += 1
                _set_field(port_info, "service_name", scheme)

            if not str(_get_field(port_info, "product", "") or "").strip() or is_low_conf_service(port_info):
                _set_field(port_info, "product", scheme)

    return updated
