"""
DNS查询和解析
"""
import logging
import time

from app import utils
from app.config import Config


class DNSQueryBase(object):
    def __init__(self):
        self.source_name = None
        self.logger = utils.get_logger()

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

        """下面是过滤掉不合法的数据"""
        subdomains = []

        for domain in domains:
            domain = domain.strip("*.")
            domain = domain.lower()
            if not domain:
                continue

            if not domain.endswith(".{}".format(target)):
                continue

            # 删除掉过长的域名
            if len(domain) - len(target) >= Config.DOMAIN_MAX_LEN:
                continue

            if not utils.is_valid_domain(domain):
                continue

            # 屏蔽和谐域名和黑名单域名
            if utils.check_domain_black(domain):
                continue

            if utils.domain_parsed(domain):
                subdomains.append(domain)

        subdomains = list(set(subdomains))

        t2 = time.time()
        self.logger.info("end query {} on {}, source result:{}, real result:{} ({:.2f}s)".format(
            target, self.source_name, len(domains), len(subdomains), t2 - t1))

        return subdomains


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
            if sources and source_name not in sources:
                skip_count += 1
                logger.info("skip query plugin {} by source filter".format(source_name))
                continue

            # ***　查看是否有配置
            if query_key.get(source_name):
                source_conf = query_key[source_name]
                if not isinstance(source_conf, dict):
                    logger.warning("{} config {} is not dict".format(source_name, source_conf))
                    skip_count += 1
                    continue
                source_kwargs = source_conf.copy()

                # 插件是否启用， 没有配置 enable 这个字段默认启用
                plugin_enable_flag = source_kwargs.pop("enable", None)
                if plugin_enable_flag is not None:
                    if not plugin_enable_flag:
                        skip_count += 1
                        logger.info("skip query plugin {} because enable=false".format(source_name))
                        continue

                # 判断是否为空，为空就跳过 init_key 调用
                if source_kwargs:
                    if all(source_kwargs.values()):
                        p.init_key(**source_kwargs)
                    else:
                        skip_count += 1
                        miss_keys = [k for k, v in source_kwargs.items() if not v]
                        logger.warning(
                            "skip query plugin {} because required config missing: {}".format(
                                source_name, ",".join(miss_keys)
                            )
                        )
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
