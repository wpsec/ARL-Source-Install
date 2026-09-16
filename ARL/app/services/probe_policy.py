"""站点与证书探测的候选收敛策略。

端口扫描结果必须完整保留，但后续 HTTP/SSL 探测不能把疑似全开端口或错误开放
端口原样展开。这个模块只做确定性的候选排序与上限控制，不改变资产结果。
"""
from urllib.parse import urlparse


HTTP_PRIORITY_PORTS = (
    80,
    443,
    8080,
    8443,
    8000,
    8008,
    8081,
    8082,
    8083,
    8880,
    8888,
    9080,
    9443,
    8181,
    3000,
    5000,
    5001,
    7001,
    7002,
    8001,
    8002,
    9000,
    10000,
)
_HTTP_PRIORITY_MAP = {port: index for index, port in enumerate(HTTP_PRIORITY_PORTS)}
TLS_PRIORITY_PORTS = (
    443,
    8443,
    9443,
    993,
    995,
    465,
    636,
    990,
)

_HTTP_SERVICE_HINTS = (
    "http",
    "https",
    "web",
    "www",
    "proxy",
    "nginx",
    "apache",
    "tomcat",
    "jetty",
    "weblogic",
    "gunicorn",
    "uwsgi",
    "iis",
)
_TLS_SERVICE_HINTS = (
    "ssl",
    "https",
    "tls",
    "imap",
    "pop3",
    "smtps",
    "ldaps",
    "ftps",
)


def port_info_value(port_info, field, default=""):
    """同时读取 PortInfo 和持久化字典，避免候选策略依赖具体模型。"""
    if isinstance(port_info, dict):
        return port_info.get(field, default)
    return getattr(port_info, field, default)


def normalize_port_id(port_info):
    try:
        port_id = int(port_info_value(port_info, "port_id", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return port_id if 1 <= port_id <= 65535 else 0


def _service_hint_match(port_info, probe_kind):
    fields = (
        port_info_value(port_info, "service_name", ""),
        port_info_value(port_info, "service", ""),
        port_info_value(port_info, "product", ""),
    )
    text = " ".join(str(value or "").strip().lower() for value in fields)
    hints = _TLS_SERVICE_HINTS if probe_kind == "tls" else _HTTP_SERVICE_HINTS
    return any(token in text for token in hints)


def select_probe_port_infos(
    port_infos,
    max_ports_per_host,
    suspected_all_open=False,
    probe_kind="http",
):
    """按 Web/TLS 价值选择每个主机的探测端口。

    疑似全开主机只保留常见 Web/TLS 端口和服务识别明确的端口，防止错误开放端口
    让连接超时成倍放大；普通主机仍保留排序后的其他端口，直到达到配置上限。
    """
    try:
        limit = int(max_ports_per_host)
    except (TypeError, ValueError):
        limit = 0
    if limit <= 0:
        return []

    priority_ports = TLS_PRIORITY_PORTS if str(probe_kind).lower() == "tls" else HTTP_PRIORITY_PORTS
    priority_map = {port: index for index, port in enumerate(priority_ports)}
    selected = {}
    for port_info in list(port_infos or []):
        port_id = normalize_port_id(port_info)
        if not port_id or port_id in selected:
            continue
        selected[port_id] = port_info

    ranked = []
    for port_id, port_info in selected.items():
        is_priority = port_id in priority_map
        has_service_hint = _service_hint_match(port_info, str(probe_kind).lower())
        if suspected_all_open and not is_priority and not has_service_hint:
            continue
        ranked.append(
            (
                0 if is_priority else 1 if has_service_hint else 2,
                priority_map.get(port_id, len(priority_ports)),
                port_id,
                port_info,
            )
        )

    ranked.sort(key=lambda item: item[:3])
    return [item[3] for item in ranked[:limit]]


def cap_http_probe_urls(urls, max_candidates):
    """对所有调用方做最后一道 URL 数量上限，返回（保留项、丢弃数）。"""
    try:
        limit = int(max_candidates)
    except (TypeError, ValueError):
        limit = 0

    unique = sorted({str(url or "").strip() for url in list(urls or []) if str(url or "").strip()})
    if limit <= 0 or len(unique) <= limit:
        return unique, 0

    def sort_key(url):
        parsed = urlparse(url)
        try:
            port = int(parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
        except ValueError:
            port = 0
        return (
            _HTTP_PRIORITY_MAP.get(port, len(HTTP_PRIORITY_PORTS)),
            (parsed.hostname or "").lower(),
            0 if parsed.scheme.lower() == "https" else 1,
            url,
        )

    selected = sorted(unique, key=sort_key)[:limit]
    return selected, max(0, len(unique) - len(selected))


__all__ = [
    "cap_http_probe_urls",
    "normalize_port_id",
    "port_info_value",
    "select_probe_port_infos",
]
