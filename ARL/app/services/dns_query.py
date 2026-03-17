"""
DNS查询和解析
"""
import time

from app import utils
from app.config import Config


class DNSQueryBase(object):
    def __init__(self):
        self.source_name = None
        self.logger = utils.get_logger()
        # 插件是否支持按IP反查子域名，默认关闭
        self.support_ip_query = False
        # 插件是否支持按证书反查子域名，默认关闭
        self.support_cert_query = False
        # 请求频率受限常见关键词（中英文）
        self._rate_limit_keywords = (
            "rate limit", "too many", "429", "q3005", "频繁", "请求太多", "过于频繁", "稍后再试",
        )

    def init_key(self, **kwargs):
        """
        用来初始化各种key
        :param kwargs:
        :return:
        """
        raise NotImplementedError()

    def sub_domains(self, target):
        """
        根据子域名查询
        :param target:
        :return:
        """
        raise NotImplementedError()

    def sub_domains_by_ip(self, ip):
        """
        根据IP查询子域名（默认插件不实现）
        :param ip:
        :return:
        """
        return []

    def sub_domains_by_cert(self, cert):
        """
        根据证书查询子域名（默认插件不实现）
        :param cert:
        :return:
        """
        return []

    def _normalize_domains(self, domains, target="", scope_domain=""):
        """
        标准化并过滤插件返回的域名列表
        """
        subdomains = []
        # 旧链路使用 target，新链路使用 scope_domain（两者二选一）
        target_domain = utils.normalize_domain(target) if target else ""
        scope_domain = utils.normalize_domain(scope_domain) if scope_domain else ""
        base_domain = target_domain or scope_domain
        for domain in domains:
            if not isinstance(domain, str):
                continue

            domain = str(domain or "").strip(" \t\r\n")
            domain = utils.normalize_domain(domain)
            if not domain:
                continue

            if target_domain:
                if not domain.endswith(".{}".format(target_domain)):
                    continue

            if scope_domain:
                if not utils.is_in_scope(domain, scope_domain):
                    continue

            # 删除掉过长的域名
            if base_domain and domain != base_domain:
                if len(domain) - len(base_domain) >= Config.DOMAIN_MAX_LEN:
                    continue

            if not utils.is_valid_domain(domain):
                continue

            # 屏蔽和谐域名和黑名单域名
            if utils.check_domain_black(domain):
                continue

            if utils.domain_parsed(domain):
                subdomains.append(domain)

        return list(set(subdomains))

    def query(self, target):
        t1 = time.time()
        self.logger.info("start query {} on {}".format(target, self.source_name))
        try:
            domains = self.sub_domains(target)
        except Exception as e:
            self.logger.error("{} error: {}".format(self.source_name, e))
            return []

        if not isinstance(domains, list):
            self.logger.warning("{} is not list".format(domains))
            return []

        subdomains = self._normalize_domains(domains, target=target)

        t2 = time.time()
        self.logger.info("end query {} on {}, source result:{}, real result:{} ({:.2f}s)".format(
            target, self.source_name, len(domains), len(subdomains), t2 - t1))

        return subdomains

    def query_by_ip(self, ip, target_domain=""):
        """
        按IP反查域名，target_domain用于范围约束
        """
        t1 = time.time()
        self.logger.info("start query ip {} on {}".format(ip, self.source_name))
        try:
            domains = self.sub_domains_by_ip(ip)
        except Exception as e:
            self.logger.error("{} ip {} error: {}".format(self.source_name, ip, e))
            return []

        if not isinstance(domains, list):
            self.logger.warning("{} is not list".format(domains))
            return []

        subdomains = self._normalize_domains(domains, scope_domain=target_domain)
        t2 = time.time()
        self.logger.info(
            "end query ip {} on {}, source result:{}, real result:{} ({:.2f}s)".format(
                ip, self.source_name, len(domains), len(subdomains), t2 - t1
            )
        )
        return subdomains

    def query_by_cert(self, cert, target_domain="", cert_id=""):
        """
        按证书反查域名，target_domain用于范围约束
        """
        show_cert_id = cert_id or "-"
        t1 = time.time()
        self.logger.info("start query cert {} on {}".format(show_cert_id, self.source_name))
        try:
            domains = self.sub_domains_by_cert(cert)
        except Exception as e:
            self.logger.error("{} cert {} error: {}".format(self.source_name, show_cert_id, e))
            return []

        if not isinstance(domains, list):
            self.logger.warning("{} is not list".format(domains))
            return []

        subdomains = self._normalize_domains(domains, scope_domain=target_domain)
        t2 = time.time()
        self.logger.info(
            "end query cert {} on {}, source result:{}, real result:{} ({:.2f}s)".format(
                show_cert_id, self.source_name, len(domains), len(subdomains), t2 - t1
            )
        )
        return subdomains

    @staticmethod
    def _safe_to_int(value, default=0):
        try:
            return int(str(value).strip())
        except Exception:
            return default

    @staticmethod
    def _safe_to_float(value, default=0.0):
        try:
            return float(str(value).strip())
        except Exception:
            return default

    def _is_rate_limited(self, status_code=0, data=None, message=""):
        """
        判断当前响应是否属于“请求频率受限”。
        """
        if self._safe_to_int(status_code, 0) == 429:
            return True

        data_code = ""
        data_message = ""
        if isinstance(data, dict):
            data_code = str(data.get("code", "")).strip().lower()
            data_message = str(data.get("message", "")).strip().lower()

        merged = "{} {} {}".format(str(message).lower(), data_code, data_message)
        for keyword in self._rate_limit_keywords:
            if keyword in merged:
                return True

        return False

    def _calc_retry_sleep(self, attempt=1, conn=None, data=None, base=2, cap=120):
        """
        计算重试等待时长，优先使用服务端 Retry-After。
        """
        base = max(self._safe_to_int(base, 2), 1)
        cap = max(self._safe_to_int(cap, 120), base)
        attempt = max(self._safe_to_int(attempt, 1), 1)

        retry_after = 0
        if conn is not None:
            try:
                retry_after = self._safe_to_int(conn.headers.get("Retry-After", 0), 0)
            except Exception:
                retry_after = 0

        if retry_after <= 0 and isinstance(data, dict):
            retry_after = self._safe_to_int(data.get("retry_after", 0), 0)
            if retry_after <= 0 and isinstance(data.get("data"), dict):
                retry_after = self._safe_to_int(data["data"].get("retry_after", 0), 0)

        if retry_after > 0:
            return min(max(retry_after + 1, base), cap)

        sleep_time = max(base, base * (2 ** max(attempt - 1, 0)))
        return min(sleep_time, cap)


def _prepare_query_plugin(p, source_filter_set, query_key, logger):
    """
    统一处理插件筛选、启停和密钥初始化

    返回:
        (should_run: bool, skip_reason: str)
    """
    source_name = p.source_name
    if source_filter_set and source_name not in source_filter_set:
        return False, "source_filter"

    if query_key.get(source_name):
        source_conf = query_key[source_name]
        if not isinstance(source_conf, dict):
            logger.warning("{} config {} is not dict".format(source_name, source_conf))
            return False, "invalid_config"

        source_kwargs = source_conf.copy()
        plugin_enable_flag = source_kwargs.pop("enable", None)
        if plugin_enable_flag is not None and not plugin_enable_flag:
            return False, "enable=false"

        if source_kwargs:
            if all(source_kwargs.values()):
                p.init_key(**source_kwargs)
            else:
                miss_keys = [k for k, v in source_kwargs.items() if not v]
                logger.warning(
                    "skip query plugin {} because required config missing: {}".format(
                        source_name, ",".join(miss_keys)
                    )
                )
                return False, "required_config_missing"

    return True, ""


def _get_auto_enabled_sources(query_key):
    """
    从 QUERY_PLUGIN 配置中提取 enable=true 的来源
    """
    enabled = set()
    if not isinstance(query_key, dict):
        return enabled

    for source_name, source_conf in query_key.items():
        if not isinstance(source_conf, dict):
            continue

        if source_conf.get("enable", None) is False:
            continue

        enabled.add(source_name)

    return enabled


# *****  执行域名查询插件
"""
返回: [{
    "domain": "www.baidu.com",
    "source": "crtsh"
}]
"""


# *********


def run_query_plugin(target, sources=None):
    """
    批量运行子域名查询插件
    :param sources:
    :param target:
    :return:
    """
    if sources is None:
        sources = []
    source_filter_set = set([x.strip() for x in sources if isinstance(x, str) and x.strip()])

    plugins = utils.load_query_plugins(Config.dns_query_plugin_path)
    query_key = Config.QUERY_PLUGIN_CONFIG
    logger = utils.get_logger()
    ret = []
    # 全局去重：同一域名只保留一条记录（来源保留首次命中插件）
    subdomains = set()
    t1 = time.time()
    run_count = 0
    skip_count = 0
    error_count = 0
    for p in plugins:
        try:
            source_name = p.source_name
            should_run, reason = _prepare_query_plugin(p, source_filter_set, query_key, logger)
            if not should_run:
                skip_count += 1
                if reason == "source_filter":
                    logger.info("skip query plugin {} by source filter".format(source_name))
                elif reason == "enable=false":
                    logger.info("skip query plugin {} because enable=false".format(source_name))
                continue

            run_count += 1
            logger.info("start query plugin {} target:{}".format(source_name, target))
            results = p.query(target)
            source_new_cnt = 0
            for result in results:
                if result in subdomains:
                    continue
                item = {
                    "domain": result,
                    "source": source_name
                }
                ret.append(item)
                subdomains.add(result)
                source_new_cnt += 1

            logger.info(
                "end query plugin {} source_result:{} new_result:{}".format(
                    source_name, len(results), source_new_cnt
                )
            )

        except Exception as e:
            error_str = str(e)
            if "please set fofa key" in error_str:
                logger.debug(error_str)
            else:
                logger.error("{} error {} {}".format(p.source_name, type(e), str(e)))
            error_count += 1

    t2 = time.time()
    logger.info(
        "{} subdomains result {} run:{} skip:{} error:{} ({:.2f}s)".format(
            target, len(subdomains), run_count, skip_count, error_count, t2 - t1
        )
    )
    return ret


def run_query_plugin_by_ip(ip_list, target_domain="", sources=None, max_domains=0):
    """
    对公网IP进行三方反查，获取同域名范围内的新增域名

    参数:
        ip_list: 待反查IP列表
        target_domain: 域名范围约束（为空时不过滤范围）
        sources: 指定数据源（为空时按配置自动）
        max_domains: 最大返回域名数（<=0 表示不限制）
    """
    if sources is None:
        sources = []

    normalized_ip_list = []
    for ip in ip_list:
        ip = str(ip or "").strip()
        if not ip:
            continue
        if not utils.is_vaild_ip_target(ip):
            continue
        normalized_ip_list.append(ip)
    normalized_ip_list = list(dict.fromkeys(normalized_ip_list))
    if not normalized_ip_list:
        return []

    plugins = utils.load_query_plugins(Config.dns_query_plugin_path)
    query_key = Config.QUERY_PLUGIN_CONFIG
    logger = utils.get_logger()
    source_filter_set = set([x.strip() for x in sources if isinstance(x, str) and x.strip()])
    if not source_filter_set:
        source_filter_set = _get_auto_enabled_sources(query_key)
        logger.info(
            "ip query auto source mode enabled sources:{}".format(
                ",".join(sorted(source_filter_set)) if source_filter_set else "-"
            )
        )
        if not source_filter_set:
            logger.warning("ip query auto source mode no enabled source found in QUERY_PLUGIN")
            return []

    ret = []
    subdomains = set()
    t1 = time.time()
    run_count = 0
    skip_count = 0
    error_count = 0
    limit_hit = False

    for p in plugins:
        source_name = p.source_name
        try:
            should_run, reason = _prepare_query_plugin(p, source_filter_set, query_key, logger)
            if not should_run:
                skip_count += 1
                if reason == "source_filter":
                    logger.info("skip ip query plugin {} by source filter".format(source_name))
                elif reason == "enable=false":
                    logger.info("skip ip query plugin {} because enable=false".format(source_name))
                continue

            if not getattr(p, "support_ip_query", False):
                skip_count += 1
                logger.info("skip ip query plugin {} because support_ip_query=false".format(source_name))
                continue

            run_count += 1
            source_result_cnt = 0
            source_new_cnt = 0
            for ip in normalized_ip_list:
                logger.info("start ip query plugin {} target:{}".format(source_name, ip))
                results = p.query_by_ip(ip, target_domain=target_domain)
                source_result_cnt += len(results)
                for result in results:
                    if result in subdomains:
                        continue

                    item = {
                        "domain": result,
                        "source": source_name,
                        "pivot_ip": ip
                    }
                    ret.append(item)
                    subdomains.add(result)
                    source_new_cnt += 1

                    if max_domains > 0 and len(subdomains) >= max_domains:
                        limit_hit = True
                        break

                if limit_hit:
                    break

            logger.info(
                "end ip query plugin {} source_result:{} new_result:{}".format(
                    source_name, source_result_cnt, source_new_cnt
                )
            )

            if limit_hit:
                logger.info("ip query plugin reach max_domains {} stop".format(max_domains))
                break

        except Exception as e:
            error_str = str(e)
            if "please set fofa key" in error_str:
                logger.debug(error_str)
            else:
                logger.error("{} ip query error {} {}".format(source_name, type(e), str(e)))
            error_count += 1

    t2 = time.time()
    logger.info(
        "ip_query target_domain:{} ip:{} result:{} run:{} skip:{} error:{} ({:.2f}s)".format(
            target_domain or "-", len(normalized_ip_list), len(subdomains), run_count, skip_count, error_count, t2 - t1
        )
    )
    return ret


def _build_cert_query_key(cert):
    """
    构建证书唯一标识，优先 serial + sha1
    """
    if not isinstance(cert, dict):
        return ""

    serial_number = str(cert.get("serial_number") or "").strip()
    fingerprint = cert.get("fingerprint") or {}
    cert_sha1 = ""
    if isinstance(fingerprint, dict):
        cert_sha1 = str(fingerprint.get("sha1") or "").strip().lower()

    if serial_number and cert_sha1:
        return "{}|{}".format(serial_number, cert_sha1)
    if serial_number:
        return "sn:{}".format(serial_number)
    if cert_sha1:
        return "sha1:{}".format(cert_sha1)

    return ""


def run_query_plugin_by_cert(cert_list, target_domain="", sources=None, max_domains=0):
    """
    对证书进行三方反查，获取同域名范围内的新增域名

    参数:
        cert_list: 证书列表，支持两种格式
            - 证书对象(dict)
            - {"cert": 证书对象, "cert_key": "证书唯一标识"}
        target_domain: 域名范围约束（为空时不过滤范围）
        sources: 指定数据源（为空时按配置自动）
        max_domains: 最大返回域名数（<=0 表示不限制）
    """
    if sources is None:
        sources = []

    normalized_cert_list = []
    seen_cert_key = set()
    for item in cert_list:
        cert_obj = item
        cert_key = ""

        if isinstance(item, dict) and isinstance(item.get("cert"), dict):
            cert_obj = item["cert"]
            cert_key = str(item.get("cert_key") or "").strip()

        if not isinstance(cert_obj, dict):
            continue

        if not cert_key:
            cert_key = _build_cert_query_key(cert_obj)

        if not cert_key:
            continue

        if cert_key in seen_cert_key:
            continue

        seen_cert_key.add(cert_key)
        normalized_cert_list.append({
            "cert": cert_obj,
            "cert_key": cert_key
        })

    if not normalized_cert_list:
        return []

    plugins = utils.load_query_plugins(Config.dns_query_plugin_path)
    query_key = Config.QUERY_PLUGIN_CONFIG
    logger = utils.get_logger()
    source_filter_set = set([x.strip() for x in sources if isinstance(x, str) and x.strip()])
    if not source_filter_set:
        source_filter_set = _get_auto_enabled_sources(query_key)
        logger.info(
            "cert query auto source mode enabled sources:{}".format(
                ",".join(sorted(source_filter_set)) if source_filter_set else "-"
            )
        )
        if not source_filter_set:
            logger.warning("cert query auto source mode no enabled source found in QUERY_PLUGIN")
            return []

    ret = []
    subdomains = set()
    t1 = time.time()
    run_count = 0
    skip_count = 0
    error_count = 0
    limit_hit = False

    for p in plugins:
        source_name = p.source_name
        try:
            should_run, reason = _prepare_query_plugin(p, source_filter_set, query_key, logger)
            if not should_run:
                skip_count += 1
                if reason == "source_filter":
                    logger.info("skip cert query plugin {} by source filter".format(source_name))
                elif reason == "enable=false":
                    logger.info("skip cert query plugin {} because enable=false".format(source_name))
                continue

            if not getattr(p, "support_cert_query", False):
                skip_count += 1
                logger.info("skip cert query plugin {} because support_cert_query=false".format(source_name))
                continue

            run_count += 1
            source_result_cnt = 0
            source_new_cnt = 0
            for cert_item in normalized_cert_list:
                cert_obj = cert_item["cert"]
                cert_key = cert_item["cert_key"]
                logger.info("start cert query plugin {} target:{}".format(source_name, cert_key))
                results = p.query_by_cert(cert_obj, target_domain=target_domain, cert_id=cert_key)
                source_result_cnt += len(results)
                for result in results:
                    if result in subdomains:
                        continue

                    item = {
                        "domain": result,
                        "source": source_name,
                        "pivot_cert": cert_key
                    }
                    ret.append(item)
                    subdomains.add(result)
                    source_new_cnt += 1

                    if max_domains > 0 and len(subdomains) >= max_domains:
                        limit_hit = True
                        break

                if limit_hit:
                    break

            logger.info(
                "end cert query plugin {} source_result:{} new_result:{}".format(
                    source_name, source_result_cnt, source_new_cnt
                )
            )

            if limit_hit:
                logger.info("cert query plugin reach max_domains {} stop".format(max_domains))
                break

        except Exception as e:
            error_str = str(e)
            if "please set fofa key" in error_str:
                logger.debug(error_str)
            else:
                logger.error("{} cert query error {} {}".format(source_name, type(e), str(e)))
            error_count += 1

    t2 = time.time()
    logger.info(
        "cert_query target_domain:{} cert:{} result:{} run:{} skip:{} error:{} ({:.2f}s)".format(
            target_domain or "-", len(normalized_cert_list), len(subdomains), run_count, skip_count, error_count, t2 - t1
        )
    )
    return ret
