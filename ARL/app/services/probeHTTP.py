"""
HTTP协议探测
"""
import time
from app import utils
from app.config import Config
from .baseThread import BaseThread
logger = utils.get_logger()


class ProbeHTTP(BaseThread):
    def __init__(self, domains, concurrency=6):
        super().__init__(self._build_targets(domains), concurrency = concurrency)

        self.sites = []
        self.domains = domains
        self.dns_policy_cache = {}
        self.http_connect_cache = {}

    def _build_targets(self, domains):
        _targets = []
        for item in domains:
            domain = item
            if hasattr(item, 'domain'):
                domain = item.domain

            _targets.append("https://{}".format(domain))
            _targets.append("http://{}".format(domain))

        return _targets

    def work(self, target):
        allow_scan, policy_detail = utils.check_dns_policy_for_url(target, cache_map=self.dns_policy_cache)
        if not allow_scan:
            logger.info(
                "skip probe_http by dns policy target:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    target,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return

        connect_kwargs = utils.build_http_connect_kwargs_for_url(
            target,
            policy_detail=policy_detail,
            cache_map=self.http_connect_cache,
        )
        conn = utils.http_req(target, 'get', timeout=(3, 2), stream=True, **connect_kwargs)
        conn.close()

        if conn.status_code in [502, 504, 501, 422, 410]:
            logger.debug(f"{target} 状态码为 {conn.status_code} 跳过")
            return

        self.sites.append(target)

    def run(self):
        t1 = time.time()
        logger.info("start ProbeHTTP {}".format(len(self.targets)))
        self._run()
        # 去除https和http相同的
        alive_site = []
        for x in self.sites:
            if x.startswith("https://"):
                alive_site.append(x)

            elif x.startswith("http://"):
                x_temp = "https://" + x[7:]
                if x_temp not in self.sites:
                    alive_site.append(x)

        elapse = time.time() - t1
        logger.info("end ProbeHTTP {} elapse {}".format(len(alive_site), elapse))

        return alive_site


def probe_http(domain, concurrency=None):
    if concurrency is None:
        concurrency = Config.PROBE_HTTP_CONCURRENCY
    p = ProbeHTTP(domain, concurrency=concurrency)
    return p.run()
