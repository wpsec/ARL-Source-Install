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
from bson import ObjectId
from urllib.parse import urlparse
from celery.utils.log import get_task_logger
from celery import current_task
import colorlog
import logging
import dns.resolver
from tld import get_tld
from .conn import http_req, conn_db
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
    message = str(error or "").strip()
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
    traceback_text = str(traceback_text or "").strip()
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


def get_ip(domain, log_flag=True):
    domain = normalize_domain(domain) or str(domain or "").strip().lower().rstrip(".")
    if not domain:
        return []

    logger = get_logger()
    ips = []
    try:
        resolver = get_dns_resolver()
        answers = resolver.resolve(domain, 'A')
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
        answers = resolver.resolve(domain, 'A')
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
        "system_ips": [],
        "socket_ips": [],
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
        resolver_ips = sorted(set(get_ip_system(host, log_flag=False)))
        socket_ips = sorted(set(get_ip_socket(host, log_flag=False)))
        detail["resolver_ips"] = resolver_ips
        detail["system_ips"] = resolver_ips
        detail["socket_ips"] = socket_ips

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

    resolver_ips = sorted(set(get_ip(host, log_flag=False)))
    system_ips = sorted(set(get_ip_system(host, log_flag=False)))
    socket_ips = sorted(set(get_ip_socket(host, log_flag=False)))
    detail["resolver_ips"] = resolver_ips
    detail["system_ips"] = system_ips
    detail["socket_ips"] = socket_ips

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

    # 完全无交集：高风险漂移，拒绝扫描
    if not matched_ips:
        detail["reason"] = "dns_drift_no_overlap"
        return False, detail

    # 系统解析出了自定义解析器未返回的内网/保留IP，也视为漂移风险
    extra_system_ips = sorted(list(system_set - resolver_set))
    for ip in extra_system_ips:
        if get_ip_type(ip) == "PRIVATE":
            detail["reason"] = "dns_drift_private_extra"
            detail["extra_system_ips"] = extra_system_ips
            return False, detail

    # 追加 socket 解析链路校验（覆盖 /etc/hosts / NSS 覆盖场景）
    if socket_ips:
        socket_set = set(socket_ips)
        matched_socket_ips = sorted(list(resolver_set & socket_set))
        detail["matched_socket_ips"] = matched_socket_ips

        if not matched_socket_ips:
            detail["reason"] = "dns_drift_socket_no_overlap"
            return False, detail

        extra_socket_ips = sorted(list(socket_set - resolver_set))
        for ip in extra_socket_ips:
            if get_ip_type(ip) == "PRIVATE":
                detail["reason"] = "dns_drift_socket_private_extra"
                detail["extra_socket_ips"] = extra_socket_ips
                return False, detail

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
        answers = resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cnames.append(str(rdata.target).strip(".").lower())
    except dns.resolver.NoAnswer as e:
        if log_flag:
            logger.debug(e)
    except Exception as e:
        logger.warning("{} {}".format(domain, e))

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
):
    """
    Worker 启动时恢复中断任务，避免任务长期卡在中间状态。

    恢复规则：
    - 仅处理已开始但未进入终态的任务
    - waiting/done/stop/error 状态不会被覆盖
    """
    logger = get_logger()
    now = curr_date()
    safe_max_logs = max(1, int(max_logs))

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

    result = {
        "task": 0,
        "github_task": 0,
    }
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
            "recover interrupted tasks on worker start task:{} github_task:{} reason:{}".format(
                result["task"], result["github_task"], reason
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
