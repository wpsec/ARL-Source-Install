"""
域名信息构建与保存
"""
import time
import threading
from app import  modules
from app import  utils
from app.config import Config
from .baseThread import BaseThread
logger = utils.get_logger()


class BuildDomainInfo(BaseThread):
    def __init__(self, domains, concurrency=6, dns_policy_cache=None):
        super().__init__(domains, concurrency=concurrency)
        self.domain_info_list = []
        # 同一任务内不同来源共享策略结果，避免重复 DNS 视角检查。
        self.dns_policy_cache = dns_policy_cache if isinstance(dns_policy_cache, dict) else {}
        self._dns_policy_cache_lock = threading.Lock()

    def _get_dns_policy(self, domain):
        with self._dns_policy_cache_lock:
            cached = self.dns_policy_cache.get(domain)
        if cached is not None:
            return cached

        policy = utils.check_dns_policy_for_host(domain)
        with self._dns_policy_cache_lock:
            # 并发调用方只保留首次结果，避免同一域名跨来源重复写入。
            return self.dns_policy_cache.setdefault(domain, policy)

    def work(self, target):
        domain = target
        if hasattr(target, "domain"):
            domain = target.domain

        domain = utils.normalize_domain(domain)
        if not domain:
            return

        allow_scan, policy_detail = self._get_dns_policy(domain)

        if not allow_scan:
            logger.info(
                "skip build_domain_info by dns policy domain:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    domain,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return

        preferred_ips = list(policy_detail.get("preferred_ips", []) or [])
        # 优先使用 DNS policy 选出的公网视角 IP，避免双视角域名回落到内网。
        if preferred_ips:
            ips = preferred_ips
        else:
            ips = utils.get_ip(domain, log_flag=False)
        if not ips:
            return

        cnames = utils.get_cname(domain, False)

        info = {
            "domain": domain,
            "type": "A",
            "record": ips,
            "ips": ips
        }

        if cnames:
            info["type"] = 'CNAME'
            info["record"] = cnames

        self.domain_info_list.append(modules.DomainInfo(**info))

    def run(self):
        t1 = time.time()
        logger.info("start build Domain info {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        logger.info("end build Domain info {} elapse {}".format(len(self.domain_info_list), elapse))

        return self.domain_info_list


def build_domain_info(domains, concurrency=None, dns_policy_cache=None):
    if concurrency is None:
        concurrency = Config.DOMAIN_INFO_CONCURRENCY
    p = BuildDomainInfo(
        domains,
        concurrency=concurrency,
        dns_policy_cache=dns_policy_cache,
    )
    return p.run()
