"""
通用工具模块初始化
"""
import subprocess
import shlex
import shutil
import random
import string
import psutil
import os
import re
import sys
import hashlib
from celery.utils.log import get_task_logger
from celery import current_task
import colorlog
import logging
import dns.resolver
from tld import get_tld
from .conn import http_req, conn_db
from .http import get_title, get_headers
from .domain import check_domain_black, is_valid_domain, is_in_scope, is_in_scopes, is_valid_fuzz_domain
from .ip import is_vaild_ip_target, not_in_black_ips, get_ip_asn, get_ip_city, get_ip_type
from .arl import arl_domain, get_asset_domain_by_id
from .time import curr_date, time2date, curr_date_obj
from .url import rm_similar_url, get_hostname, normal_url, same_netloc, verify_cert, url_ext
from .cert import get_cert
from .arlupdate import arl_update
from .cdn import get_cdn_name_by_cname, get_cdn_name_by_ip
from .device import device_info
from .cron import check_cron, check_cron_interval
from .query_loader import load_query_plugins

_dns_resolver_cache = None
_dns_resolver_cache_key = None


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
    except OSError as e:
        if logger:
            logger.error("phantomjs exec failed {} error: {}".format(command, e))
        return ""

    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="ignore").strip() if completed.stderr else ""
        if logger:
            logger.error("phantomjs check failed {} rc={} {}".format(command, completed.returncode, stderr))
        return ""

    return command


def random_choices(k=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))


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


def get_ip(domain, log_flag=True):
    domain = domain.strip()
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

    return ips


def get_cname(domain, log_flag=True):
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
    domain = domain.strip()
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


def truncate_string(s):
    if len(s) > 30:
        truncated_string = s[:30]
        return truncated_string + "..."
    else:
        return s


from .user import user_login, user_login_header, auth, user_logout, change_pass
from .push import message_push
from .fingerprint import parse_human_rule, transform_rule_map
