"""
通用测绘任务下发服务。

职责：
- 统一读取 FOFA / Hunter / Shodan / Quake / Zoomeye 配置
- 按 provider 执行原生语法测试
- 提取命中的 IP 列表，用于后续复用现有 IP 扫描执行链
"""
import base64
import re
from ipaddress import ip_address
from urllib.parse import urlparse

from app import utils
from app.config import Config, refresh_runtime_config_best_effort
from app.services.fofaClient import FofaClient


SUPPORTED_MEASURE_PROVIDERS = ("fofa", "hunter_qax", "shodan", "zoomeye", "quake_360")
PROVIDER_ALIAS = {
    "fofa": "fofa",
    "hunter": "hunter_qax",
    "hunter_qax": "hunter_qax",
    "shodan": "shodan",
    "zoomeye": "zoomeye",
    "quake": "quake_360",
    "quake_360": "quake_360",
}
SHODAN_HOST_SEARCH_PAGE_SIZE = 100
FOFA_PAGE_SIZE_MAX = 10000
ZOOMEYE_HOST_SEARCH_URL = "https://api.zoomeye.org/host/search"
ZOOMEYE_WEB_SEARCH_URL = "https://api.zoomeye.org/web/search"
API_JSON_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "ARL/measure-task",
}
PROVIDER_LABEL = {
    "fofa": "FOFA",
    "hunter_qax": "Hunter",
    "shodan": "Shodan",
    "zoomeye": "Zoomeye",
    "quake_360": "Quake360",
}


def normalize_measure_provider(provider):
    normalized = str(provider or "").strip().lower()
    normalized = PROVIDER_ALIAS.get(normalized, normalized)
    if normalized not in SUPPORTED_MEASURE_PROVIDERS:
        raise ValueError("unsupported provider")
    return normalized


def normalize_measure_queries(query_text):
    if not isinstance(query_text, str):
        query_text = str(query_text or "")

    query_lines = query_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    query_list = []
    query_seen = set()
    for query_item in query_lines:
        query_item = query_item.strip()
        if not query_item or query_item in query_seen:
            continue
        query_list.append(query_item)
        query_seen.add(query_item)
    return query_list


def normalize_measure_query_for_provider(provider, query):
    provider = normalize_measure_provider(provider)
    query_text = str(query or "").strip()
    match = re.match(r"^ip\s*={1,2}\s*['\"]?([^'\"\s]+)['\"]?$", query_text, re.IGNORECASE)
    if match:
        ip_text = _normalize_ip_candidate(match.group(1))
        if ip_text:
            if provider == "shodan":
                return "ip:{}".format(ip_text)
            if provider == "quake_360":
                return 'ip:"{}"'.format(ip_text)

    domain_match = re.match(r"^domain\s*={1,2}\s*['\"]?([^'\"\s]+)['\"]?$", query_text, re.IGNORECASE)
    if domain_match:
        domain_text = domain_match.group(1).strip()
        if domain_text:
            if provider == "shodan":
                return 'hostname:"{}"'.format(domain_text)

    if provider == "shodan":
        return re.sub(r"(?i)(^|\s)host\s*:", r"\1hostname:", query_text)
    return query_text


def get_measure_provider_label(provider):
    normalized = normalize_measure_provider(provider)
    return PROVIDER_LABEL.get(normalized, normalized)


def get_measure_provider_label_safe(provider):
    try:
        return get_measure_provider_label(provider)
    except Exception:
        normalized = str(provider or "").strip()
        return normalized or "Unknown"


def _mask_secret(secret_text):
    secret_text = str(secret_text or "")
    if not secret_text:
        return secret_text
    if len(secret_text) <= 8:
        return "***"
    return "{}***".format(secret_text[:8])


def _mask_secret_values(text, secret_values):
    text = str(text or "")
    for secret in secret_values or []:
        secret = str(secret or "")
        if secret:
            text = text.replace(secret, _mask_secret(secret))
    return text


def _response_text_snippet(conn, limit=200):
    try:
        text = getattr(conn, "text", "") or ""
    except Exception:
        text = ""
    text = " ".join(str(text).split())
    if len(text) > limit:
        return "{}...".format(text[:limit])
    return text


def _format_request_exception(exc):
    message = str(exc)
    if "Name or service not known" in message or "nodename nor servname provided" in message:
        return "网络连接失败或域名无法解析：{}".format(message)
    if "Max retries exceeded" in message:
        return "网络连接失败或远端不可达：{}".format(message)
    return message


def _request_provider_json(provider, url, method, secret_values=None, **kwargs):
    label = get_measure_provider_label_safe(provider)
    try:
        conn = utils.http_req(url, method, **kwargs)
    except Exception as exc:
        message = _format_request_exception(exc)
        message = _mask_secret_values(message, secret_values)
        raise RuntimeError("{} 请求失败：{}".format(label, message))

    status_code = _safe_int(getattr(conn, "status_code", 0), 0)
    try:
        data = conn.json() if conn is not None else {}
    except Exception:
        message = "{} 返回非 JSON 响应".format(label)
        if status_code:
            message = "{}，HTTP {}".format(message, status_code)
        snippet = _response_text_snippet(conn)
        if provider == "shodan" and re.search(r"(?i)(just a moment|cloudflare|cf-browser)", snippet):
            message = "{}：API 请求被防护页拦截，请检查服务器出口网络、代理或 api.shodan.io 访问策略".format(message)
            raise RuntimeError(_mask_secret_values(message, secret_values))
        if snippet:
            message = "{}：{}".format(message, snippet)
        raise RuntimeError(_mask_secret_values(message, secret_values))

    if not isinstance(data, dict):
        raise RuntimeError("{} 返回数据格式异常：{}".format(label, type(data).__name__))
    return data


def _safe_int(value, default_value=0):
    try:
        return int(value)
    except Exception:
        return int(default_value)


def _safe_float(value, default_value=0.0):
    try:
        return float(value)
    except Exception:
        return float(default_value)


def _list_size(value):
    if isinstance(value, list):
        return len(value)
    return 0


def _normalize_ip_candidate(value):
    text = str(value or "").strip()
    if not text:
        return ""

    if "://" in text:
        try:
            text = str(urlparse(text).hostname or "").strip()
        except Exception:
            text = ""
    else:
        text = text.split("/")[0].strip()
        if text.startswith("[") and "]" in text:
            text = text[1:text.index("]")]
        elif text.count(":") == 1:
            text = text.split(":", 1)[0].strip()

    if not text:
        return ""

    try:
        return str(ip_address(text))
    except Exception:
        return ""


def _resolve_zoomeye_sub_type(query):
    query_text = str(query or "")
    if re.search(r"(?i)(^|[\s(])(?:domain|hostname|site|web\.|http\.|title)\s*(?:=|:)", query_text):
        return "web"
    return "v4"


def _extract_ip_from_url_fields(item, field_names):
    for field_name in field_names:
        raw_url = str(item.get(field_name) or "").strip()
        if not raw_url:
            continue
        if "://" not in raw_url:
            raw_url = "//{}".format(raw_url)
        try:
            ip_text = str(urlparse(raw_url).hostname or "").strip()
        except Exception:
            ip_text = ""
        normalized = _normalize_ip_candidate(ip_text)
        if normalized:
            return normalized
    return ""


def _extract_fofa_ips(data):
    ip_set = set()
    for item in data.get("results", []):
        if not isinstance(item, (list, tuple)):
            continue
        if len(item) > 1:
            ip_text = _normalize_ip_candidate(item[1])
            if ip_text:
                ip_set.add(ip_text)
                continue
        if len(item) > 0:
            ip_text = _normalize_ip_candidate(item[0])
            if ip_text:
                ip_set.add(ip_text)
    return sorted(ip_set)


def _extract_hunter_ips(data):
    ip_set = set()
    payload = data.get("data") if isinstance(data, dict) else {}
    items = payload.get("arr") if isinstance(payload, dict) else []
    if not isinstance(items, list):
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        for field_name in ("ip", "ip_address", "host"):
            ip_text = _normalize_ip_candidate(item.get(field_name))
            if ip_text:
                ip_set.add(ip_text)
                break
        else:
            ip_text = _extract_ip_from_url_fields(item, ("url", "web", "web_url", "link"))
            if ip_text:
                ip_set.add(ip_text)
    return sorted(ip_set)


def _extract_shodan_ips(data):
    ip_set = set()
    matches = data.get("matches", []) if isinstance(data, dict) else []
    if not isinstance(matches, list):
        matches = []

    for item in matches:
        if not isinstance(item, dict):
            continue
        for field_name in ("ip_str", "ip"):
            ip_text = _normalize_ip_candidate(item.get(field_name))
            if ip_text:
                ip_set.add(ip_text)
                break
        else:
            ip_text = _extract_ip_from_url_fields(item, ("hostnames",))
            if ip_text:
                ip_set.add(ip_text)
    return sorted(ip_set)


def _extract_zoomeye_ips(data):
    ip_set = set()
    items = data.get("matches", []) if isinstance(data, dict) else []
    if not isinstance(items, list):
        items = data.get("list", []) if isinstance(data, dict) else []
    if not isinstance(items, list):
        items = data.get("data", []) if isinstance(data, dict) else []
    if not isinstance(items, list):
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        candidate_values = [
            item.get("ip"),
            item.get("ip_address"),
            item.get("ip_str"),
            item.get("host"),
        ]
        port_info = item.get("portinfo")
        if isinstance(port_info, dict):
            candidate_values.extend([
                port_info.get("ip"),
                port_info.get("host"),
            ])
        site = item.get("site")
        if isinstance(site, dict):
            candidate_values.extend([
                site.get("ip"),
                site.get("ip_address"),
            ])
        for value in candidate_values:
            ip_text = _normalize_ip_candidate(value)
            if ip_text:
                ip_set.add(ip_text)
                break
    return sorted(ip_set)


def _extract_quake_ips(data):
    ip_set = set()
    items = data.get("data", []) if isinstance(data, dict) else []
    if not isinstance(items, list):
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        candidate_values = [
            item.get("ip"),
            item.get("ip_addr"),
            item.get("ip_str"),
            item.get("host"),
            item.get("hostname"),
        ]
        components = item.get("components")
        if isinstance(components, list):
            for component in components:
                if isinstance(component, dict):
                    candidate_values.extend([
                        component.get("ip"),
                        component.get("ip_addr"),
                        component.get("ip_str"),
                    ])
        service = item.get("service")
        if isinstance(service, dict):
            candidate_values.extend([
                service.get("ip"),
                service.get("ip_str"),
                service.get("ip_addr"),
                service.get("host"),
            ])
            http_service = service.get("http")
            if isinstance(http_service, dict):
                candidate_values.extend([
                    http_service.get("host"),
                    http_service.get("hostname"),
                ])
        for value in candidate_values:
            ip_text = _normalize_ip_candidate(value)
            if ip_text:
                ip_set.add(ip_text)
                break
    return sorted(ip_set)


def _fofa_service_config():
    refresh_runtime_config_best_effort()
    return {
        "url": str(Config.FOFA_URL or "https://fofa.info").strip() or "https://fofa.info",
        "email": str(Config.FOFA_EMAIL or "").strip(),
        "key": str(Config.FOFA_KEY or "").strip(),
    }


def _query_plugin_service_config(provider):
    refresh_runtime_config_best_effort()
    query_conf = Config.QUERY_PLUGIN_CONFIG if isinstance(Config.QUERY_PLUGIN_CONFIG, dict) else {}
    provider_conf = query_conf.get(provider, {}) if isinstance(query_conf.get(provider, {}), dict) else {}
    return provider_conf.copy()


def _ensure_fofa_credentials(conf):
    if not conf.get("email") or not conf.get("key"):
        raise ValueError("请先在配置中心填写 FOFA 邮箱和 KEY")


def _ensure_query_plugin_credentials(provider, conf):
    required_fields = {
        "hunter_qax": ("api_key",),
        "shodan": ("api_key",),
        "zoomeye": ("api_key",),
        "quake_360": ("quake_token",),
    }
    miss_keys = [key for key in required_fields.get(provider, ()) if not str(conf.get(key) or "").strip()]
    if miss_keys:
        raise ValueError("{} 缺少配置 {}".format(get_measure_provider_label(provider), ",".join(miss_keys)))


def _request_fofa_info(conf):
    _ensure_fofa_credentials(conf)
    client = FofaClient(conf["email"], conf["key"], page_size=1)
    client.base_url = conf["url"]
    return client.info_my() or {}


def _run_fofa_query(query, page_size=1, page=1):
    conf = _fofa_service_config()
    try:
        profile = _request_fofa_info(conf)
        if bool(profile.get("error")):
            raise ValueError(str(profile.get("errmsg") or "未知错误"))

        vip_level = _safe_int(profile.get("vip_level"), 0)
        if vip_level == 0:
            raise ValueError("不支持注册用户")

        client = FofaClient(conf["email"], conf["key"], page_size=page_size)
        client.base_url = conf["url"]
        if vip_level == 1:
            client.page_size = min(page_size, 100)
        data = client.fofa_search_all(query, page=page) or {}
        return data
    except Exception as exc:
        error_msg = str(exc)
        secret = conf.get("key") or ""
        if secret:
            error_msg = error_msg.replace(secret, _mask_secret(secret))
        raise RuntimeError(error_msg)


def _request_query(provider, query, page_size=1, page=1, start=0):
    provider = normalize_measure_provider(provider)
    query = str(query or "").strip()
    if not query:
        raise ValueError("query is empty")

    if provider == "fofa":
        return _run_fofa_query(query, page_size=page_size, page=page)

    if provider == "hunter_qax":
        conf = _query_plugin_service_config(provider)
        _ensure_query_plugin_credentials(provider, conf)
        resolved_page_size = min(max(_safe_int(conf.get("page_size"), 20), 1), max(page_size, 1))
        params = {
            "search": base64.urlsafe_b64encode(query.encode("utf-8")),
            "page": page,
            "page_size": resolved_page_size,
            "is_web": "1",
            "api-key": conf.get("api_key"),
        }
        return _request_provider_json(
            provider,
            "https://hunter.qianxin.com/openApi/search",
            "get",
            secret_values=[conf.get("api_key")],
            params=params,
            timeout=(30.1, 50.1),
        )

    if provider == "shodan":
        conf = _query_plugin_service_config(provider)
        _ensure_query_plugin_credentials(provider, conf)
        params = {
            "key": conf.get("api_key"),
            "query": query,
            "page": page,
        }
        return _request_provider_json(
            provider,
            "https://api.shodan.io/shodan/host/search",
            "get",
            secret_values=[conf.get("api_key")],
            params=params,
            headers=API_JSON_HEADERS.copy(),
            timeout=(30.1, 50.1),
        )

    if provider == "zoomeye":
        conf = _query_plugin_service_config(provider)
        _ensure_query_plugin_credentials(provider, conf)
        sub_type = _resolve_zoomeye_sub_type(query)
        search_url = ZOOMEYE_WEB_SEARCH_URL if sub_type == "web" else ZOOMEYE_HOST_SEARCH_URL
        params = {
            "query": query,
            "page": page,
        }
        if page_size and page_size > 1:
            params["pagesize"] = page_size
        headers = {
            "API-KEY": conf.get("api_key"),
        }
        return _request_provider_json(
            provider,
            search_url,
            "get",
            secret_values=[conf.get("api_key")],
            params=params,
            headers=headers,
            timeout=(30.1, 50.1),
        )

    if provider == "quake_360":
        conf = _query_plugin_service_config(provider)
        _ensure_query_plugin_credentials(provider, conf)
        resolved_page_size = min(max(_safe_int(conf.get("max_size"), 20), 1), max(page_size, 1))
        json_data = {
            "query": query,
            "start": max(_safe_int(start, 0), 0),
            "size": resolved_page_size,
            "latest": True,
        }
        headers = {
            "X-QuakeToken": conf.get("quake_token"),
        }
        return _request_provider_json(
            provider,
            "https://quake.360.net/api/v3/search/quake_service",
            "post",
            secret_values=[conf.get("quake_token")],
            json=json_data,
            headers=headers,
            timeout=(30.1, 100.1),
        )

    raise ValueError("unsupported provider")


def _extract_total_size(provider, data):
    provider = normalize_measure_provider(provider)
    if not isinstance(data, dict):
        return 0

    if provider == "fofa":
        return _safe_int(data.get("size"), 0)

    if provider == "hunter_qax":
        payload = data.get("data", {})
        if isinstance(payload, dict):
            total = _safe_int(payload.get("total"), 0)
            if total > 0:
                return total
            return _list_size(payload.get("arr"))
        return 0

    if provider == "shodan":
        total = _safe_int(data.get("total"), 0)
        if total > 0:
            return total
        return _list_size(data.get("matches"))

    if provider == "zoomeye":
        total = _safe_int(data.get("total"), 0)
        if total > 0:
            return total
        return _list_size(data.get("matches")) or _list_size(data.get("list")) or _list_size(data.get("data"))

    if provider == "quake_360":
        meta = data.get("meta", {})
        if isinstance(meta, dict):
            for key in ("total", "pagination_total", "count", "size"):
                total = _safe_int(meta.get(key), 0)
                if total > 0:
                    return total
            pagination = meta.get("pagination")
            if isinstance(pagination, dict):
                for key in ("total", "count", "total_count"):
                    total = _safe_int(pagination.get(key), 0)
                    if total > 0:
                        return total
        total = _safe_int(data.get("total"), 0)
        if total > 0:
            return total
        return _list_size(data.get("data"))

    return 0


def _extract_error_message(provider, data):
    if not isinstance(data, dict):
        return "返回数据格式异常"

    if provider == "fofa":
        if data.get("error"):
            return str(data.get("errmsg") or "未知错误")
        return ""

    if provider == "hunter_qax":
        code = _safe_int(data.get("code"), 0)
        if code not in (0, 200, 40205):
            return str(data.get("message") or data.get("error") or "未知错误")
        return ""

    if provider == "shodan":
        error_text = str(data.get("error") or "").strip().lower()
        if not error_text:
            return ""
        if "insufficient query credits" in error_text:
            return "Shodan API 查询配额不足，请升级 API 计划或等待月度配额重置"
        if "invalid api key" in error_text or "unauthorized" in error_text:
            return "Shodan API Key 无效，请检查配置"
        if "rate limit" in error_text:
            return "Shodan API 请求频率超限，请稍后重试"
        return str(data.get("error") or "未知错误")

    if provider == "zoomeye":
        code = str(data.get("code") or "").strip().lower()
        if code == "credits_insufficent":
            return "Zoomeye API 查询配额不足，请充值或等待月度配额重置"
        result_items = data.get("matches") or data.get("list") or data.get("data")
        if str(data.get("message") or "").strip() and not isinstance(result_items, list):
            return str(data.get("message") or "")
        return ""

    if provider == "quake_360":
        code = _safe_int(data.get("code"), 0)
        if code != 0:
            return str(data.get("message") or data.get("errmsg") or "未知错误")
        return ""

    return ""


def _extract_ips(provider, data):
    provider = normalize_measure_provider(provider)
    if provider == "fofa":
        return _extract_fofa_ips(data)
    if provider == "hunter_qax":
        return _extract_hunter_ips(data)
    if provider == "shodan":
        return _extract_shodan_ips(data)
    if provider == "zoomeye":
        return _extract_zoomeye_ips(data)
    if provider == "quake_360":
        return _extract_quake_ips(data)
    return []


def _fetch_fofa_query_ips(query):
    page = 1
    page_size = FOFA_PAGE_SIZE_MAX
    total_size = 0
    ip_set = set()

    while True:
        data = _request_query("fofa", query, page_size=page_size, page=page)
        error_message = _extract_error_message("fofa", data)
        if error_message:
            raise RuntimeError(error_message)

        page_total = _extract_total_size("fofa", data)
        if page == 1:
            total_size = page_total

        page_ips = _extract_ips("fofa", data)
        ip_set.update(page_ips)

        results = data.get("results", []) if isinstance(data, dict) else []
        if not isinstance(results, list) or not results:
            break

        if len(results) < page_size:
            break

        if total_size > 0 and page * page_size >= total_size:
            break

        page += 1

    return total_size, sorted(ip_set)


def _fetch_hunter_query_ips(query):
    conf = _query_plugin_service_config("hunter_qax")
    _ensure_query_plugin_credentials("hunter_qax", conf)

    page = 1
    page_size = max(_safe_int(conf.get("page_size"), 100), 1)
    max_page = max(_safe_int(conf.get("max_page"), 5), 1)
    total_size = 0
    ip_set = set()

    while page <= max_page:
        data = _request_query("hunter_qax", query, page_size=page_size, page=page)
        error_message = _extract_error_message("hunter_qax", data)
        if error_message:
            raise RuntimeError(error_message)

        payload = data.get("data", {}) if isinstance(data, dict) else {}
        items = payload.get("arr", []) if isinstance(payload, dict) else []
        if not isinstance(items, list):
            items = []

        if page == 1:
            total_size = _extract_total_size("hunter_qax", data)

        ip_set.update(_extract_ips("hunter_qax", data))

        if not items or len(items) < page_size:
            break

        page += 1

    return total_size, sorted(ip_set)


def _fetch_shodan_query_ips(query):
    conf = _query_plugin_service_config("shodan")
    _ensure_query_plugin_credentials("shodan", conf)

    page = 1
    max_page = max(_safe_int(conf.get("max_page"), 20), 1)
    total_size = 0
    ip_set = set()

    while page <= max_page:
        data = _request_query("shodan", query, page=page)
        error_message = _extract_error_message("shodan", data)
        if error_message:
            raise RuntimeError(error_message)

        matches = data.get("matches", []) if isinstance(data, dict) else []
        if not isinstance(matches, list):
            matches = []

        if page == 1:
            total_size = _extract_total_size("shodan", data)

        ip_set.update(_extract_ips("shodan", data))

        if not matches:
            break

        if len(matches) < SHODAN_HOST_SEARCH_PAGE_SIZE:
            break

        if total_size > 0 and page * SHODAN_HOST_SEARCH_PAGE_SIZE >= total_size:
            break

        page += 1

    return total_size, sorted(ip_set)


def _fetch_zoomeye_query_ips(query):
    conf = _query_plugin_service_config("zoomeye")
    _ensure_query_plugin_credentials("zoomeye", conf)

    page = 1
    page_size = max(_safe_int(conf.get("page_size"), 20), 1)
    max_page = max(_safe_int(conf.get("max_page"), 20), 1)
    total_size = 0
    ip_set = set()

    while page <= max_page:
        data = _request_query("zoomeye", query, page_size=page_size, page=page)
        error_message = _extract_error_message("zoomeye", data)
        if error_message:
            raise RuntimeError(error_message)

        items = data.get("matches", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            items = data.get("list", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            items = data.get("data", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            items = []

        if page == 1:
            total_size = _extract_total_size("zoomeye", data)

        ip_set.update(_extract_ips("zoomeye", data))

        if not items:
            break

        if len(items) < page_size:
            break

        if total_size > 0 and len(ip_set) >= total_size:
            break

        page += 1

    return total_size, sorted(ip_set)


def _fetch_quake_query_ips(query):
    conf = _query_plugin_service_config("quake_360")
    _ensure_query_plugin_credentials("quake_360", conf)

    max_size = max(_safe_int(conf.get("max_size"), 500), 1)
    batch_size = min(max_size, 500)
    start = 0
    total_size = 0
    ip_set = set()

    while start < max_size:
        current_size = min(batch_size, max_size - start)
        data = _request_query("quake_360", query, page_size=current_size, start=start)
        error_message = _extract_error_message("quake_360", data)
        if error_message:
            raise RuntimeError(error_message)

        items = data.get("data", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            items = []

        if start == 0:
            total_size = _extract_total_size("quake_360", data)

        ip_set.update(_extract_ips("quake_360", data))

        if not items or len(items) < current_size:
            break

        if total_size > 0 and start + current_size >= total_size:
            break

        start += current_size

    return total_size, sorted(ip_set)


def _fetch_provider_query_ips(provider, query):
    provider = normalize_measure_provider(provider)
    if provider == "fofa":
        return _fetch_fofa_query_ips(query)
    if provider == "hunter_qax":
        return _fetch_hunter_query_ips(query)
    if provider == "shodan":
        return _fetch_shodan_query_ips(query)
    if provider == "zoomeye":
        return _fetch_zoomeye_query_ips(query)
    if provider == "quake_360":
        return _fetch_quake_query_ips(query)
    raise ValueError("unsupported provider")


def run_measure_query_test(provider, query):
    provider = normalize_measure_provider(provider)
    query_list = normalize_measure_queries(query)
    if not query_list:
        raise ValueError("query is empty")

    total_size = 0
    query_items = []
    for query_item in query_list:
        normalized_query_item = normalize_measure_query_for_provider(provider, query_item)
        data = _request_query(provider, normalized_query_item, page_size=1)
        error_message = _extract_error_message(provider, data)
        if error_message:
            raise RuntimeError(error_message)

        size = _extract_total_size(provider, data)
        total_size += size
        query_items.append({
            "query": normalized_query_item,
            "size": size,
        })

    return {
        "provider": provider,
        "provider_label": get_measure_provider_label(provider),
        "size": total_size,
        "query": "\n".join(query_list),
        "query_count": len(query_list),
        "items": query_items,
    }


def fetch_measure_query_ips(provider, query):
    provider = normalize_measure_provider(provider)
    query_list = normalize_measure_queries(query)
    if not query_list:
        raise ValueError("query is empty")

    total_size = 0
    ip_set = set()
    query_items = []
    for query_item in query_list:
        normalized_query_item = normalize_measure_query_for_provider(provider, query_item)
        size, ips = _fetch_provider_query_ips(provider, normalized_query_item)
        total_size += size
        ip_set.update(ips)
        query_items.append({
            "query": normalized_query_item,
            "size": size,
            "ip_count": len(ips),
        })

    return {
        "provider": provider,
        "provider_label": get_measure_provider_label(provider),
        "size": total_size,
        "query_count": len(query_list),
        "items": query_items,
        "ips": sorted(ip_set),
    }
