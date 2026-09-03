"""
通用工具模块初始化
"""
import subprocess
import shlex
import shutil
import platform
import random
import string
import psutil
import os
import re
import sys
import hashlib
import socket
from concurrent.futures import ThreadPoolExecutor
from bson import ObjectId
from urllib.parse import urlparse
from celery.utils.log import get_task_logger
from celery import current_task
import colorlog
import logging
import dns.resolver
from tld import get_tld
from .conn import http_req, conn_db
from .log_safety import safe_error_text
from .http import get_title, get_headers
from .domain import (
    check_domain_black,
    is_valid_domain,
    is_in_scope,
    is_in_scopes,
    is_valid_fuzz_domain,
    normalize_domain,
    normalize_fuzz_domain,
)
from .ip import is_vaild_ip_target, not_in_black_ips, get_ip_asn, get_ip_city, get_ip_type
from .arl import arl_domain, get_asset_domain_by_id
from .time import curr_date, time2date, curr_date_obj
from .url import rm_similar_url, get_hostname, normal_url, same_netloc, verify_cert, url_ext
from .cert import get_cert
from .arlupdate import arl_update
from .cdn import get_cdn_name_by_cname, get_cdn_name_by_ip, infer_cdn_by_dns
from .device import device_info
from .cron import check_cron, check_cron_interval
from .query_loader import load_query_plugins

_dns_resolver_cache = None
_dns_resolver_cache_key = None
_runtime_arch_cache = None


def load_file(path):
    with open(path, "r+", encoding="utf-8") as f:
        return f.readlines()


def exec_system(cmd, **kwargs):
    cmd = " ".join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs['timeout']
        kwargs.pop('timeout')

    completed = subprocess.run(shlex.split(cmd), timeout=timeout, check=False, close_fds=True, **kwargs)

    return completed


def check_output(cmd, **kwargs):
    cmd = " ".join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs.pop('timeout')

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')

    output = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, timeout=timeout, check=False,
               **kwargs).stdout
    return output


def resolve_executable(command):
    """
    解析可执行文件路径
    """
    if command is None:
        return ""

    command = str(command).strip()
    if not command:
        return ""

    has_path_sep = os.path.sep in command
    if os.path.altsep:
        has_path_sep = has_path_sep or os.path.altsep in command

    if has_path_sep:
        if os.path.isfile(command) and os.access(command, os.X_OK):
            return command
        return ""

    return shutil.which(command) or ""


def stable_hash(text):
    """
    将文本稳定映射为 64bit 整数，便于生成可复用的缓存/临时目录标识。
    """
    digest = gen_md5(str(text or ""))
    return int(digest[:16], 16)


def get_runtime_arch():
    """
    获取当前运行时架构，并做常见别名归一化
    """
    global _runtime_arch_cache
    if _runtime_arch_cache:
        return _runtime_arch_cache

    arch = ""
    try:
        arch = str(platform.machine() or "").strip().lower()
    except Exception:
        arch = ""

    alias_map = {
        "amd64": "x86_64",
        "arm64": "aarch64",
    }
    arch = alias_map.get(arch, arch)
    if not arch:
        arch = "unknown"

    _runtime_arch_cache = arch
    return arch


def is_x86_64_arch():
    return get_runtime_arch() == "x86_64"


def get_phantomjs_bin(logger=None):
    """
    获取并校验 phantomjs 可执行文件
    """
    from app.config import Config

    command = resolve_executable(Config.PHANTOMJS_BIN)
    if not command:
        if logger:
            logger.error(
                "phantomjs not found, set ARL.PHANTOMJS_BIN in config.yaml or ARL_PHANTOMJS_BIN env."
            )
        return ""

    try:
        completed = exec_system([command, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
    except subprocess.TimeoutExpired as e:
        if logger:
            logger.error(
                "phantomjs check timeout {} timeout={}s arch={}".format(
                    command,
                    getattr(e, "timeout", 8),
                    get_runtime_arch(),
                )
            )
        return ""
    except OSError as e:
        if logger:
            logger.error("phantomjs exec failed {} error: {}".format(command, e))
        return ""
    except Exception as e:
        if logger:
            logger.error("phantomjs check unexpected error {} error: {}".format(command, e))
        return ""

    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="ignore").strip() if completed.stderr else ""
        if logger:
            logger.error("phantomjs check failed {} rc={} {}".format(command, completed.returncode, stderr))
        return ""

    return command


def random_choices(k=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))


def append_task_error(task_id: str, error: Exception = None, stage: str = "", traceback_text: str = "", max_logs: int = 20):
    """
    记录任务异常详情，便于前端展示“异常原因/日志”。
    """
    task_id = str(task_id or "").strip()
    if len(task_id) != 24:
        return

    stage = str(stage or "").strip()
    message = safe_error_text(error).strip()
    if not message:
        message = error.__class__.__name__ if error else "unknown error"

    query = {"_id": ObjectId(task_id)}
    task_item = conn_db('task').find_one(query, {"status": 1})
    current_stage = str((task_item or {}).get("status", "") or "").strip()
    if current_stage and current_stage not in {"error", "done", "stop"}:
        stage = "{} / {}".format(stage, current_stage) if stage else current_stage

    detail = {
        "time": curr_date(),
        "stage": stage,
        "message": message,
    }
    traceback_text = safe_error_text(traceback_text, max_length=12000).strip()
    if traceback_text:
        detail["traceback"] = traceback_text

    update = {
        "$set": {
            "status": "error",
            "end_time": curr_date(),
            "last_error": detail,
        },
        "$push": {
            "error_logs": {
                "$each": [detail],
                "$slice": -max(1, int(max_logs)),
            }
        }
    }
    conn_db('task').update_one(query, update)


def gen_md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def init_logger():
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(
        fmt = '%(log_color)s[%(asctime)s] [%(levelname)s] '
              '[%(threadName)s] [%(filename)s:%(lineno)d] %(message)s', datefmt = "%Y-%m-%d %H:%M:%S"))

    logger = colorlog.getLogger('arlv2')

    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False


def get_logger():
    if 'celery' in sys.argv[0]:
        task_logger = get_task_logger(__name__)
        return task_logger

    logger = logging.getLogger('arlv2')
    if not logger.handlers:
        init_logger()

    return logging.getLogger('arlv2')


def split_dns_resolver_item(resolver_item):
    """
    解析 DNS 解析器配置项，支持 ip 或 ip:port
    """
    value = str(resolver_item).strip()
    if not value:
        return "", 53

    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        host = host.strip()
        if host and port.isdigit():
            return host, int(port)

    return value, 53


def get_dns_resolver():
    """
    获取 DNS 解析器
    - 默认使用系统解析器
    - 配置 ARL.DNS_RESOLVERS 后，优先使用指定解析器
    """
    global _dns_resolver_cache
    global _dns_resolver_cache_key

    from app.config import Config
    dns_resolvers = tuple([x.strip() for x in Config.DNS_RESOLVERS if isinstance(x, str) and x.strip()])

    if _dns_resolver_cache is not None and _dns_resolver_cache_key == dns_resolvers:
        return _dns_resolver_cache

    try:
        if dns_resolvers:
            nameservers = []
            nameserver_ports = {}
            for item in dns_resolvers:
                host, port = split_dns_resolver_item(item)
                if not host:
                    continue
                nameservers.append(host)
                if port != 53:
                    nameserver_ports[host] = port

            if nameservers:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = nameservers
                if nameserver_ports:
                    resolver.nameserver_ports = nameserver_ports
                # 限制单次解析总超时时间，避免任务长时间阻塞
                resolver.lifetime = 6
                resolver.timeout = 3
                logger = get_logger()
                logger.info("dns resolver use custom {}".format(",".join(dns_resolvers)))
            else:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = []
                resolver.timeout = 3
                resolver.lifetime = 6
                logger = get_logger()
                logger.error("dns resolver config is empty after parse and custom resolver required")
        else:
            resolver = dns.resolver.Resolver()
            # 系统 resolver 也必须有明确上限，否则大量候选域名的单次异常解析
            # 会在线程池中累积，最终表现为阶段长时间无进度。
            resolver.timeout = 3
            resolver.lifetime = 6
            logger = get_logger()
            logger.info("dns resolver use system default")
    except Exception as e:
        logger = get_logger()
        if dns_resolvers:
            # 配置了自定义解析器时，不回退系统DNS，避免解析漂移到集群/宿主默认DNS
            logger.error("init dns resolver error {} and custom resolver required".format(e))
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = []
            resolver.timeout = 3
            resolver.lifetime = 6
        else:
            logger.warning("init dns resolver error {} fallback system resolver".format(e))
            resolver = dns.resolver.Resolver()

    _dns_resolver_cache = resolver
    _dns_resolver_cache_key = dns_resolvers
    return resolver


def _normalize_ip_list(ip_list):
    """
    归一化 IP 列表并按优先级排序：
    1) PUBLIC
    2) 其他类型（UNKNOWN/ERROR）
    3) PRIVATE
    """
    seen = set()
    public_ips = []
    other_ips = []
    private_ips = []

    for raw_ip in ip_list:
        ip = str(raw_ip or "").strip()
        if not ip or ip in seen or ip == "0.0.0.1":
            continue
        seen.add(ip)

        ip_type = get_ip_type(ip)
        if ip_type == "PUBLIC":
            public_ips.append(ip)
        elif ip_type == "PRIVATE":
            private_ips.append(ip)
        else:
            other_ips.append(ip)

    return public_ips + other_ips + private_ips


def _dns_resolution_lifetime(default=6):
    """将单次 DNS 解析限制在当前阶段仍可使用的时间内。"""
    try:
        from .provider_http import current_stage_remaining_sec

        remaining = current_stage_remaining_sec()
    except Exception:
        remaining = None

    try:
        default_value = max(float(default), 0.1)
    except (TypeError, ValueError):
        default_value = 6.0
    if remaining is None:
        return default_value
    return max(0.1, min(default_value, float(remaining)))


def get_ip(domain, log_flag=True):
    domain = normalize_domain(domain) or str(domain or "").strip().lower().rstrip(".")
    if not domain:
        return []

    logger = get_logger()
    ips = []
    try:
        resolver = get_dns_resolver()
        answers = resolver.resolve(
            domain,
            'A',
            lifetime=_dns_resolution_lifetime(getattr(resolver, "lifetime", 6)),
        )
        for rdata in answers:
            if rdata.address == '0.0.0.1':
                continue
            ips.append(rdata.address)
    except dns.resolver.NXDOMAIN as e:
        if log_flag:
            logger.info("{} {}".format(domain, e))

    except Exception as e:
        if log_flag:
            logger.warning("{} {}".format(domain, e))

    return _normalize_ip_list(ips)


def get_ip_system(domain, log_flag=True):
    """
    使用系统默认 DNS 解析器获取 A 记录
    """
    domain = normalize_domain(domain) or str(domain or "").strip().lower().rstrip(".")
    if not domain:
        return []

    logger = get_logger()
    ips = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6
        resolver.timeout = 3
        answers = resolver.resolve(
            domain,
            'A',
            lifetime=_dns_resolution_lifetime(getattr(resolver, "lifetime", 6)),
        )
        for rdata in answers:
            if rdata.address == '0.0.0.1':
                continue
            ips.append(rdata.address)
    except dns.resolver.NXDOMAIN as e:
        if log_flag:
            logger.info("{} {}".format(domain, e))
    except Exception as e:
        if log_flag:
            logger.warning("{} {}".format(domain, e))

    return _normalize_ip_list(ips)


def get_ip_socket(domain, log_flag=True):
    """
    使用运行时 socket/getaddrinfo 解析 IPv4。
    该链路会受 /etc/hosts 与系统 NameService 配置影响，可用于识别
    “DNS 查询结果与实际连接目标不一致”的解析漂移。
    """
    domain = normalize_domain(domain) or str(domain or "").strip().lower().rstrip(".")
    if not domain:
        return []

    logger = get_logger()
    ips = []
    try:
        answers = socket.getaddrinfo(
            domain,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
        for item in answers:
            sockaddr = item[4] if len(item) >= 5 else ()
            if not isinstance(sockaddr, tuple) or not sockaddr:
                continue
            ips.append(sockaddr[0])
    except socket.gaierror as e:
        if log_flag:
            logger.info("{} {}".format(domain, e))
    except Exception as e:
        if log_flag:
            logger.warning("{} {}".format(domain, e))

    return _normalize_ip_list(ips)


def _select_preferred_resolver_ips(ip_list):
    normalized_ips = _normalize_ip_list(ip_list or [])
    public_ips = [ip for ip in normalized_ips if get_ip_type(ip) == "PUBLIC"]
    if public_ips:
        return public_ips
    return normalized_ips


def _resolve_dns_policy_views(host, has_custom_resolver):
    """并行获取 DNS policy 所需的解析视角，避免单域名串行等待多个超时。"""
    lookup_items = [
        ("resolver", get_ip if has_custom_resolver else get_ip_system),
        ("system", get_ip_system),
        ("socket", get_ip_socket),
    ]
    if not has_custom_resolver:
        lookup_items = [lookup_items[0], lookup_items[2]]

    values = {}
    with ThreadPoolExecutor(max_workers=len(lookup_items)) as executor:
        future_map = {
            executor.submit(lookup, host, log_flag=False): name
            for name, lookup in lookup_items
        }
        for future, name in future_map.items():
            try:
                values[name] = future.result()
            except Exception as exc:
                logger = get_logger()
                logger.warning(
                    "dns policy lookup failed view:{} error:{}".format(
                        name,
                        safe_error_text(exc),
                    )
                )
                values[name] = []

    return values


def build_http_connect_kwargs_for_url(url, policy_detail=None, cache_map=None):
    """
    为 HTTP 请求生成“连接 IP + Host/SNI 域名”参数。
    """
    try:
        parsed = urlparse(str(url or "").strip())
    except Exception:
        return {}

    hostname = normalize_domain(parsed.hostname) or str(parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname or is_vaild_ip_target(hostname):
        return {}

    preferred_ips = []
    if isinstance(policy_detail, dict):
        preferred_ips = _select_preferred_resolver_ips(policy_detail.get("preferred_ips", []))
        if not preferred_ips:
            preferred_ips = _select_preferred_resolver_ips(policy_detail.get("resolver_ips", []))

    if not preferred_ips:
        if isinstance(cache_map, dict) and hostname in cache_map:
            preferred_ips = _select_preferred_resolver_ips(cache_map[hostname])
        else:
            preferred_ips = _select_preferred_resolver_ips(get_ip(hostname, log_flag=False))
            if isinstance(cache_map, dict):
                cache_map[hostname] = list(preferred_ips)

    if not preferred_ips:
        return {}

    host_header = hostname
    if parsed.port:
        default_port = 443 if parsed.scheme == "https" else 80
        if parsed.port != default_port:
            host_header = "{}:{}".format(hostname, parsed.port)

    return {
        "connect_ip": preferred_ips[0],
        "server_hostname": hostname,
        "host_header": host_header,
    }


def check_dns_policy_for_host(hostname):
    """
    校验扫描目标域名在“自定义解析器”和“系统解析器”之间是否发生解析漂移。

    返回:
        (allow: bool, detail: dict)
    """
    # 函数内导入，避免在模块初始化早期引入配置导致的循环依赖问题。
    from app.config import Config

    host = str(hostname or "").strip().lower().rstrip(".")
    normalized_host = normalize_domain(host)
    if normalized_host:
        host = normalized_host

    detail = {
        "host": host,
        "reason": "",
        "resolver_ips": [],
        "preferred_ips": [],
        "resolver_public_ips": [],
        "system_ips": [],
        "system_private_ips": [],
        "socket_ips": [],
        "socket_private_ips": [],
        "matched_ips": [],
        "matched_socket_ips": [],
    }

    if not host:
        detail["reason"] = "empty_host"
        return True, detail

    if is_vaild_ip_target(host):
        detail["reason"] = "ip_target"
        return True, detail

    # 未配置自定义解析器时尽量保持历史行为，但补充 socket 漂移兜底
    dns_resolvers = [x.strip() for x in Config.DNS_RESOLVERS if isinstance(x, str) and x.strip()]
    if not dns_resolvers:
        policy_views = _resolve_dns_policy_views(host, has_custom_resolver=False)
        resolver_ips = _normalize_ip_list(policy_views.get("resolver", []))
        socket_ips = _normalize_ip_list(policy_views.get("socket", []))
        detail["resolver_ips"] = resolver_ips
        detail["preferred_ips"] = _select_preferred_resolver_ips(resolver_ips)
        detail["resolver_public_ips"] = [ip for ip in resolver_ips if get_ip_type(ip) == "PUBLIC"]
        detail["system_ips"] = resolver_ips
        detail["socket_ips"] = socket_ips
        detail["system_private_ips"] = [ip for ip in resolver_ips if get_ip_type(ip) == "PRIVATE"]
        detail["socket_private_ips"] = [ip for ip in socket_ips if get_ip_type(ip) == "PRIVATE"]

        if resolver_ips and socket_ips:
            resolver_set = set(resolver_ips)
            socket_set = set(socket_ips)
            matched_socket_ips = sorted(list(resolver_set & socket_set))
            detail["matched_socket_ips"] = matched_socket_ips

            if not matched_socket_ips:
                private_socket_ips = [ip for ip in socket_ips if get_ip_type(ip) == "PRIVATE"]
                if private_socket_ips:
                    detail["reason"] = "dns_drift_socket_no_overlap"
                    detail["private_socket_ips"] = private_socket_ips
                    return False, detail

            extra_socket_ips = sorted(list(socket_set - resolver_set))
            for ip in extra_socket_ips:
                if get_ip_type(ip) == "PRIVATE":
                    detail["reason"] = "dns_drift_socket_private_extra"
                    detail["extra_socket_ips"] = extra_socket_ips
                    return False, detail

        if (not resolver_ips) and socket_ips:
            private_socket_ips = [ip for ip in socket_ips if get_ip_type(ip) == "PRIVATE"]
            if private_socket_ips:
                detail["reason"] = "dns_socket_private_only"
                detail["private_socket_ips"] = private_socket_ips
                return False, detail

        detail["reason"] = "no_custom_resolver"
        return True, detail

    policy_views = _resolve_dns_policy_views(host, has_custom_resolver=True)
    resolver_ips = _normalize_ip_list(policy_views.get("resolver", []))
    system_ips = _normalize_ip_list(policy_views.get("system", []))
    socket_ips = _normalize_ip_list(policy_views.get("socket", []))
    detail["resolver_ips"] = resolver_ips
    detail["preferred_ips"] = _select_preferred_resolver_ips(resolver_ips)
    detail["resolver_public_ips"] = [ip for ip in resolver_ips if get_ip_type(ip) == "PUBLIC"]
    detail["system_ips"] = system_ips
    detail["socket_ips"] = socket_ips
    detail["system_private_ips"] = [ip for ip in system_ips if get_ip_type(ip) == "PRIVATE"]
    detail["socket_private_ips"] = [ip for ip in socket_ips if get_ip_type(ip) == "PRIVATE"]

    if not resolver_ips:
        detail["reason"] = "resolver_no_a_record"
        return False, detail

    if not system_ips:
        detail["reason"] = "system_no_a_record"
        return False, detail

    resolver_set = set(resolver_ips)
    system_set = set(system_ips)
    matched_ips = sorted(list(resolver_set & system_set))
    detail["matched_ips"] = matched_ips
    resolver_public_ips = detail["resolver_public_ips"]
    system_private_ips = detail["system_private_ips"]
    socket_private_ips = detail["socket_private_ips"]

    if not matched_ips:
        # 公网解析器给出公网 IP，而系统解析仅落到内网时，允许按公网视角继续扫描。
        if resolver_public_ips and system_private_ips and len(system_private_ips) == len(system_ips):
            detail["reason"] = "split_horizon_system_private_only"
        else:
            detail["reason"] = "dns_drift_no_overlap"
            return False, detail

    # 系统解析出了自定义解析器未返回的内网/保留IP：
    # 若公网解析器已有公网结果，则视为 split-horizon 阴影内网，不阻断公网扫描。
    extra_system_ips = _normalize_ip_list(list(system_set - resolver_set))
    extra_system_private_ips = [ip for ip in extra_system_ips if get_ip_type(ip) == "PRIVATE"]
    if extra_system_private_ips:
        detail["extra_system_ips"] = extra_system_ips
        if resolver_public_ips:
            if not detail["reason"]:
                detail["reason"] = "split_horizon_private_extra"
        else:
            detail["reason"] = "dns_drift_private_extra"
            return False, detail

    if socket_ips:
        socket_set = set(socket_ips)
        matched_socket_ips = sorted(list(resolver_set & socket_set))
        detail["matched_socket_ips"] = matched_socket_ips

        if not matched_socket_ips:
            if resolver_public_ips and socket_private_ips and len(socket_private_ips) == len(socket_ips):
                if not detail["reason"]:
                    detail["reason"] = "split_horizon_socket_private_only"
            else:
                detail["reason"] = "dns_drift_socket_no_overlap"
                return False, detail

        extra_socket_ips = _normalize_ip_list(list(socket_set - resolver_set))
        extra_socket_private_ips = [ip for ip in extra_socket_ips if get_ip_type(ip) == "PRIVATE"]
        if extra_socket_private_ips:
            detail["extra_socket_ips"] = extra_socket_ips
            if resolver_public_ips:
                if not detail["reason"]:
                    detail["reason"] = "split_horizon_socket_private_extra"
            else:
                detail["reason"] = "dns_drift_socket_private_extra"
                return False, detail

    if not detail["reason"]:
        detail["reason"] = "pass"

    return True, detail


def check_dns_policy_for_url(url, cache_map=None):
    """
    基于 URL 进行 DNS 漂移校验，支持可选缓存。

    参数:
        url: 待校验 URL
        cache_map: 可选缓存字典，键为 hostname
    """
    try:
        host = urlparse(str(url)).hostname or ""
    except Exception:
        host = ""

    cache_key = normalize_domain(host) or str(host).strip().lower().rstrip(".")
    if isinstance(cache_map, dict) and cache_key:
        if cache_key in cache_map:
            return cache_map[cache_key]

    result = check_dns_policy_for_host(cache_key)
    if isinstance(cache_map, dict) and cache_key:
        cache_map[cache_key] = result

    return result


def get_cname(domain, log_flag=True):
    domain = normalize_domain(domain) or str(domain or "").strip().lower().rstrip(".")
    if not domain:
        return []

    logger = get_logger()
    cnames = []
    try:
        resolver = get_dns_resolver()
        answers = resolver.resolve(
            domain,
            'CNAME',
            lifetime=_dns_resolution_lifetime(getattr(resolver, "lifetime", 6)),
        )
        for rdata in answers:
            cnames.append(str(rdata.target).strip(".").lower())
    except dns.resolver.NoAnswer as e:
        if log_flag:
            logger.debug(e)
    except Exception as e:
        if log_flag:
            logger.warning("{} {}".format(domain, safe_error_text(e)))

    return cnames


def domain_parsed(domain, fail_silently=True):
    domain = normalize_domain(domain)
    if not domain:
        return

    try:
        res = get_tld(domain, fix_protocol=True,  as_object=True)
        item = {
            "subdomain": res.subdomain,
            "domain":res.domain,
            "fld": res.fld
        }
        return item
    except Exception as e:
        if not fail_silently:
            raise e


def get_fld(d):
    """获取域名的主域"""
    res = domain_parsed(d)
    if res:
        return res["fld"]


def gen_filename(site):
    filename = site.replace('://', '_')

    return re.sub(r'[^\w\-_\\. ]', '_', filename)


def build_ret(error, data):
    if isinstance(error, str):
        error = {
            "message": error,
            "code": 999,
        }

    ret = {}
    ret.update(error)
    ret["data"] = data
    msg = error["message"]

    if error["code"] != 200:
        for k in data:
            if k.endswith("id"):
                continue
            if not data[k]:
                continue
            if isinstance(data[k], str):
                msg += " {}:{}".format(k, data[k])

    ret["message"] = msg
    return ret


def kill_child_process(pid):
    logger = get_logger()
    parent = psutil.Process(pid)
    for child in parent.children(recursive=True):
        logger.info("kill child_process {}".format(child))
        child.kill()


def exit_gracefully(signum, frame):
    logger = get_logger()
    logger.info('Receive signal {} frame {}'.format(signum, frame))
    mark_task_interrupted(signum=signum)
    pid = os.getpid()
    kill_child_process(pid)
    parent = psutil.Process(pid)
    logger.info("kill self {}".format(parent))
    parent.kill()


def mark_task_interrupted(signum):
    """
    在 worker 收到终止信号时，尽量把运行中的任务标记为 error，并写入 stop_reason。
    说明：
    - 手动 stop 已提前写入 stop 状态，这里不会覆盖终态。
    - 优先按当前 celery_id 反查任务，避免依赖进程内变量。
    """
    logger = get_logger()
    reason = "worker interrupted by signal {}".format(signum)

    try:
        request = getattr(current_task, "request", None)
        celery_id = getattr(request, "id", None)
        if not celery_id:
            return

        update = {
            "$set": {
                "status": "error",
                "end_time": curr_date(),
                "stop_reason": reason,
                "interrupted": True,
            }
        }

        query = {"celery_id": celery_id, "status": {"$nin": ["done", "stop", "error"]}}
        task_result = conn_db("task").update_one(query, update)
        github_result = conn_db("github_task").update_one(query, update)

        if task_result.modified_count or github_result.modified_count:
            logger.warning(
                "mark interrupted task by celery_id:{} reason:{}".format(celery_id, reason)
            )
    except Exception as e:
        logger.warning("mark_task_interrupted error {}".format(e))


def recover_interrupted_tasks_on_worker_start(
    reason="worker restarted before task finished",
    max_logs=20,
    live_task_id_set=None,
):
    """
    Worker 启动时恢复中断任务，避免任务长期卡在中间状态。

    恢复规则：
    - 仅处理已开始但未进入终态的任务
    - waiting/done/stop/error 状态不会被覆盖
    - 恢复为 error，避免 ACK 已丢失但任务再次显示为 waiting 的假象
    """
    logger = get_logger()
    now = curr_date()
    safe_max_logs = max(1, int(max_logs))
    live_ids = {
        str(item or "").strip()
        for item in list(live_task_id_set or [])
        if str(item or "").strip()
    }

    detail = {
        "time": now,
        "stage": "worker_bootstrap",
        "message": reason,
    }
    update = {
        "$set": {
            "status": "error",
            "end_time": now,
            "stop_reason": reason,
            "interrupted": True,
            "last_error": detail,
        },
        "$push": {
            "error_logs": {
                "$each": [detail],
                "$slice": -safe_max_logs,
            }
        }
    }
    query = {
        "status": {"$nin": ["waiting", "done", "stop", "error"]},
        "start_time": {"$nin": ["", "-"]},
    }
    if live_ids:
        query["$or"] = [
            {"celery_id": {"$in": ["", None]}},
            {"celery_id": {"$nin": list(live_ids)}},
        ]

    result = {
        "task": 0,
        "github_task": 0,
    }
    if live_ids:
        result["live_skip"] = len(live_ids)
    for collection in ["task", "github_task"]:
        try:
            db_result = conn_db(collection).update_many(query, update)
            result[collection] = int(db_result.modified_count or 0)
        except Exception as e:
            logger.warning(
                "recover_interrupted_tasks_on_worker_start failed collection:{} error:{}".format(
                    collection, e
                )
            )

    if result["task"] or result["github_task"]:
        logger.warning(
            "recover interrupted tasks on worker start task:{} github_task:{} live_skip:{} reason:{}".format(
                result["task"], result["github_task"], int(result.get("live_skip", 0) or 0), reason
            )
        )
    else:
        logger.info("recover interrupted tasks on worker start no stale task found")

    return result


def truncate_string(s):
    if len(s) > 30:
        truncated_string = s[:30]
        return truncated_string + "..."
    else:
        return s


from .user import user_login, user_login_header, auth, user_logout, change_pass
from .push import message_push
from .fingerprint import parse_human_rule, transform_rule_map
