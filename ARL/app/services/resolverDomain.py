"""
域名解析和转换
"""
from app import utils
import threading
import collections
from app.config import Config
from app.modules import  DomainInfo
from .baseThread import BaseThread
logger = utils.get_logger()


class ResolverDomain(BaseThread):
    def __init__(self, domains, concurrency=6):
        super().__init__(domains, concurrency=concurrency)
        self.resolver_map = {}
        self.dns_policy_cache = {}

    '''
    {
        "api.baike.baidu.com":[
            "180.97.93.62",
            "180.97.93.61"
        ],
        "apollo.baidu.com":[
            "123.125.115.15"
        ],
        "www.baidu.com":[
            "180.101.49.12",
            "180.101.49.11"
        ]
    }
    '''
    def work(self, domain):
        curr_domain = domain
        if isinstance(domain, dict):
            curr_domain = domain.get("domain")

        elif isinstance(domain, DomainInfo):
            curr_domain = domain.domain

        if not curr_domain:
            return

        curr_domain = str(curr_domain or "").strip().lower().rstrip(".")
        if not curr_domain:
            return

        if curr_domain in self.resolver_map:
            return

        if curr_domain in self.dns_policy_cache:
            allow_scan, policy_detail = self.dns_policy_cache[curr_domain]
        else:
            allow_scan, policy_detail = utils.check_dns_policy_for_host(curr_domain)
            self.dns_policy_cache[curr_domain] = (allow_scan, policy_detail)

        if not allow_scan:
            logger.info(
                "skip resolver_domain by dns policy domain:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    curr_domain,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return

        self.resolver_map[curr_domain] = utils.get_ip(curr_domain)

    def run(self):
        self._run()
        return self.resolver_map


def resolver_domain(domains, concurrency=None):
    if concurrency is None:
        concurrency = Config.DOMAIN_RESOLVE_CONCURRENCY
    r = ResolverDomain(domains, concurrency)
    return r.run()
