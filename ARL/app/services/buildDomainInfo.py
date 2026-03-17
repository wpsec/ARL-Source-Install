"""
域名信息构建与保存
"""
import time
from app import  modules
from app import  utils
from app.config import Config
from .baseThread import BaseThread
logger = utils.get_logger()


class BuildDomainInfo(BaseThread):
    def __init__(self, domains, concurrency=6):
        super().__init__(domains, concurrency=concurrency)
        self.domain_info_list = []
        self.dns_policy_cache = {}

    def work(self, target):
        domain = target
        if hasattr(target, "domain"):
            domain = target.domain

        domain = utils.normalize_domain(domain)
        if not domain:
            return

        if domain in self.dns_policy_cache:
            allow_scan, policy_detail = self.dns_policy_cache[domain]
        else:
            allow_scan, policy_detail = utils.check_dns_policy_for_host(domain)
            self.dns_policy_cache[domain] = (allow_scan, policy_detail)

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

        # 不记录日志
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


def build_domain_info(domains, concurrency=None):
    if concurrency is None:
        concurrency = Config.DOMAIN_INFO_CONCURRENCY
    p = BuildDomainInfo(domains, concurrency=concurrency)
    return p.run()
