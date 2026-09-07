"""
域名扫描任务执行模块

功能说明：
- 域名扫描任务的核心执行逻辑
- 负责域名资产的发现、识别和探测

主要功能：
1. 域名爆破：使用字典进行子域名爆破
2. 域名解析：解析域名对应的IP地址
3. 站点探测：探测域名对应的Web服务
4. 证书获取：获取SSL证书信息
5. DNS查询：查询DNS记录（A、CNAME等）
6. 搜索引擎：通过搜索引擎发现子域名
7. 虚拟主机：发现同IP下的其他域名
8. 风险巡航：针对站点进行安全检测

主要类：
- DomainBrute: 域名爆破类
- DomainTask: 域名扫描任务主类
- DomainExecutor: 域名任务执行器

执行流程：
1. 域名爆破 -> 2. DNS解析 -> 3. IP端口扫描 -> 4. 站点探测 -> 5. 数据保存
"""
import time
import random
import os
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from app import utils
from app.config import Config, normalize_dict_path_compat
from app import services
from app import modules
from app.modules import ScanPortType, CollectSource
from app.services import fetchCert, run_risk_cruising, run_sniffer, BaseUpdateTask
from app.services.commonTask import CommonTask, WebSiteFetch
from app.services.wildcardDomain import (
    collect_wildcard_records_from_domains,
    collect_wildcard_profiles_from_roots,
    build_wildcard_candidate_details,
    domain_info_hits_wildcard_records,
    domain_info_hits_wildcard_profile,
    domain_info_hits_wildcard_profile_with_details,
    build_wildcard_probe_roots,
)
from app.helpers.domain import find_private_domain_by_task_id, find_public_ip_by_task_id
from app.services.findVhost import find_vhost
from app.services.dns_query import run_query_plugin, run_query_plugin_by_ip, run_query_plugin_by_cert
from app.utils.log_safety import safe_error_text
from app.services.domainSiteUpdate import domain_site_update
from app.repositories import DomainRepository
from app.services.task_orchestrator import DomainTaskOrchestrator
from app.services.task_pipeline import TaskPipeline
from app.services.waf_guard import WAFSmartSkipGuard
from app.services.domain_stage_services import (
    AltDNS,
    DomainBrute as _DomainBruteService,
    DomainDiscoveryStageService,
    DomainNetworkStageService,
    DomainPostProcessStageService,
    DomainSiteStageService,
    _normalize_domain_target,
    alt_dns,
    domain_brute,
)

logger = utils.get_logger()


class _LegacyDomainBrute(object):
    pass
    """
    域名爆破类
    
    功能说明：
    - 使用字典对目标域名进行子域名爆破
    - 支持泛解析检测和过滤
    - 支持CNAME记录追踪
    
    主要方法：
    - _brute_domain(): 使用massdns进行爆破
    - _resolver(): 解析爆破结果的IP地址
    - run(): 执行完整的爆破流程
    
    属性：
    - base_domain: 目标主域名
    - dicts: 爆破字典
    - brute_out: 爆破原始结果
    - resolver_map: 解析后的域名IP映射
    - wildcard_domain_ip: 泛解析IP列表
    """
DomainBrute = _DomainBruteService


class DomainScanResult(list):
    """保持历史 IPInfo 列表接口，同时传递端口批次指标。"""

    def __init__(self, values=None, metrics=None):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})


# 端口扫描
class ScanPort(object):
    def __init__(self, domain_info_list, option):
        self.domain_info_list = domain_info_list
        self.ipv4_map = {}
        self.ip_cdn_map = {}
        self.have_cdn_ip_list = []
        self.skip_scan_cdn_ip = Config.PORT_SCAN_SKIP_CDN_IP_DEFAULT

        if option is None:
            default_custom_host_timeout = None
            if str(Config.HOST_TIMEOUT_TYPE).strip().lower() == "custom":
                default_custom_host_timeout = Config.HOST_TIMEOUT
            option = {
                "ports": ScanPortType.TEST,
                "service_detect": False,
                "os_detect": False,
                "port_parallelism": Config.PORT_PARALLELISM,
                "port_min_rate": Config.PORT_MIN_RATE,
                "custom_host_timeout": default_custom_host_timeout
            }
        else:
            # 避免修改调用方复用的配置对象（例如 DomainTask.scan_port_option）
            option = dict(option)

        self.skip_scan_cdn_ip = option.pop(
            "skip_scan_cdn_ip", Config.PORT_SCAN_SKIP_CDN_IP_DEFAULT
        )

        self.option = option

    def get_cdn_name(self, ip, domain_info):
        cdn_name = utils.get_cdn_name_by_ip(ip)
        if cdn_name:
            return cdn_name

        cname = ""
        if domain_info.type == "CNAME" and domain_info.record_list:
            cname = domain_info.record_list[0]

        # 厂商专属 CNAME 属于高特异性证据，优先于通用 CDN 关键词，
        # 让端口调度可以直接跳过已确认的 CDN/WAF 边缘 IP。
        dns_vendor, _, _ = WAFSmartSkipGuard.identify_vendor_from_dns(cname=cname)
        if dns_vendor:
            return dns_vendor

        # 吸收 kscan 启发式能力：CNAME 关键词 + 多IP跨网段
        cdn_name = utils.infer_cdn_by_dns(cname=cname, ip_list=domain_info.ip_list)
        if cdn_name:
            return cdn_name

        return ""

    def run(self):
        for info in self.domain_info_list:
            for ip in info.ip_list:
                old_domain = self.ipv4_map.get(ip, set())
                old_domain.add(info.domain)
                self.ipv4_map[ip] = old_domain

                if ip not in self.ip_cdn_map:
                    cdn_name = self.get_cdn_name(ip, info)
                    self.ip_cdn_map[ip] = cdn_name
                    if cdn_name:
                        self.have_cdn_ip_list.append(ip)

        all_ipv4_list = list(self.ipv4_map.keys())
        skipped_cdn_ip_count = 0
        if self.skip_scan_cdn_ip:
            cdn_ip_set = set(self.have_cdn_ip_list)
            skipped_cdn_ip_count = len(cdn_ip_set)
            all_ipv4_list = [ip for ip in all_ipv4_list if ip not in cdn_ip_set]

        logger.info(
            "port_scan target_summary total:{} selected:{} skipped_cdn:{} skip_cdn_enabled:{}".format(
                len(self.ipv4_map),
                len(all_ipv4_list),
                skipped_cdn_ip_count,
                bool(self.skip_scan_cdn_ip),
            )
        )

        start_time = time.time()
        logger.info("start port_scan {}".format(len(all_ipv4_list)))
        ip_port_result = []
        if all_ipv4_list:
            ip_port_result = services.port_scan(all_ipv4_list, **self.option)
            elapse = time.time() - start_time
            logger.info("end port_scan result {}, elapse {}".format(len(ip_port_result), elapse))

        ip_info_obj = []
        for result in ip_port_result:
            curr_ip = result["ip"]
            result["domain"] = list(self.ipv4_map[curr_ip])
            result["cdn_name"] = self.ip_cdn_map.get(curr_ip, "")

            port_info_obj_list = []
            for port_info in result["port_info"]:
                if isinstance(port_info, modules.PortInfo):
                    port_info_obj_list.append(port_info)
                else:
                    port_info_obj_list.append(modules.PortInfo(**port_info))

            result["port_info"] = port_info_obj_list

            # 该标记只服务于端口扫描内部的两阶段调度，不能进入既有 IPInfo 模型。
            ip_info_data = dict(result)
            ip_info_data.pop("_suspected_all_open", None)
            ip_info_obj.append(modules.IPInfo(**ip_info_data))

        if self.skip_scan_cdn_ip:
            skipped_cdn_ip_info = self.build_fake_cdn_ip_info()
            ip_info_obj.extend(skipped_cdn_ip_info)

        scan_metrics = dict(getattr(ip_port_result, "metrics", {}) or {})
        scan_metrics.update({
            "cdn_skip_enabled": bool(self.skip_scan_cdn_ip),
            "cdn_target_count": len(self.have_cdn_ip_list),
            "cdn_skipped_target_count": skipped_cdn_ip_count,
        })
        if not all_ipv4_list and skipped_cdn_ip_count:
            scan_metrics.update({
                "stage": "cdn_filter",
                "status": "skipped",
                "end_reason": "all_targets_cdn",
                "target_count": len(self.ipv4_map),
                "output_count": len(ip_info_obj),
            })

        return DomainScanResult(
            ip_info_obj,
            metrics=scan_metrics,
        )

    def build_fake_cdn_ip_info(self):
        """保留 CDN IP 资产记录，但不伪造未经探测的开放端口。"""
        ret = []

        for ip in self.ip_cdn_map:
            cdn_name = self.ip_cdn_map[ip]
            if not cdn_name:
                continue

            item = {
                "ip": ip,
                "domain": list(self.ipv4_map[ip]),
                "port_info": [],
                "cdn_name": cdn_name,
                "os_info": {}

            }
            ret.append(modules.IPInfo(**item))

        return ret


'''
站点发现
'''


class FindSite(object):
    def __init__(self, ip_info_list):
        self.ip_info_list = ip_info_list

    def _build_prevalidated_dns_domains(self):
        """为站点探测传递端口阶段已经确认过的公网域名关系。"""
        domains = set()
        for info in self.ip_info_list:
            if utils.get_ip_type(str(getattr(info, "ip", ""))) != "PUBLIC":
                continue
            for domain in getattr(info, "domain", []) or []:
                normalized_domain = utils.normalize_domain(domain)
                if normalized_domain:
                    domains.add(normalized_domain)
        return domains

    def _build(self):
        url_temp_list = []
        for info in self.ip_info_list:
            for domain in info.domain:
                port_info_list = list(info.port_info_list or [])
                if not port_info_list and info.cdn_name:
                    # CDN IP 跳过端口扫描时，仍以业务域名探测 80/443，避免把
                    # CDN 边缘 IP 的未验证端口写成资产结果。
                    port_info_list = [
                        modules.PortInfo(port_id=80, service_name="http"),
                        modules.PortInfo(port_id=443, service_name="https"),
                    ]
                for port_info in port_info_list:
                    port_id = port_info.port_id
                    if port_id == 80:
                        url_temp = "http://{}".format(domain)
                        url_temp_list.append(url_temp)
                        continue

                    if port_id == 443:
                        url_temp = "https://{}".format(domain)
                        url_temp_list.append(url_temp)
                        continue

                    url_temp1 = "http://{}:{}".format(domain, port_id)
                    url_temp2 = "https://{}:{}".format(domain, port_id)
                    url_temp_list.append(url_temp1)
                    url_temp_list.append(url_temp2)

        return url_temp_list

    def run(self):
        url_temp_list = set(self._build())
        prevalidated_dns_domains = self._build_prevalidated_dns_domains()
        start_time = time.time()
        logger.info(
            "start site check candidates:{} prevalidated_public_domains:{}".format(
                len(url_temp_list),
                len(prevalidated_dns_domains),
            )
        )
        check_map = services.check_http(
            url_temp_list,
            prevalidated_dns_domains=prevalidated_dns_domains,
        )

        # 去除https和http相同的
        alive_site = []
        for x in check_map:
            if x.startswith("https://"):
                alive_site.append(x)

            elif x.startswith("http://"):
                x_temp = "https://" + x[7:]
                if x_temp not in check_map:
                    alive_site.append(x)

        elapse = time.time() - start_time
        logger.info("end check_http result {}, elapse {}".format(len(alive_site), elapse))

        return alive_site


'''
域名智能组合
'''


def scan_port(domain_info_list, option=None):
    s = ScanPort(domain_info_list, option)
    return s.run()


def find_site(ip_info_list):
    f = FindSite(ip_info_list)
    return f.run()


def ssl_cert(ip_info_list, base_domain):
    try:
        f = fetchCert.SSLCert(ip_info_list, base_domain)
        return f.run()
    except Exception as e:
        logger.error("ssl certificate stage failed error:{}".format(safe_error_text(e)))

    return {}


'''
domain_brute
domain_brute_type  test big bigbig
port_scan_type
port_scan
service_detection
service_brute
os_detection
link_fetch
site_identify
site_capture
file_leak
alt_dns
ssl_cert
skip_scan_cdn_ip
dns_query_plugin
'''

MAX_MAP_COUNT = 35


class DomainTask(CommonTask):
    def __init__(self, base_domain=None, task_id=None, options=None):
        super().__init__(task_id=task_id)

        self.base_domain = _normalize_domain_target(base_domain)
        self.task_id = task_id
        self.options = options

        self.domain_info_list = []  # 在 start_site_fetch 运行后会清空，用来释放内存
        self.ip_info_list = []
        self.ip_set = set()
        self.site_list = []
        self.record_map = {}
        self.ipv4_map = {}
        self.cert_map = {}
        self.service_info_list = []
        # 用来区分是正常任务还是监控任务
        self.task_tag = "task"
        # 记录域名来源，避免监控任务重建数据时丢失真实来源
        self.domain_source_map = {}
        self._dns_policy_cache = {}

        # 历史命名保留为 not_found_domain_ips，但这里实际缓存的是泛解析返回记录集合。
        self._wildcard_domain_records = None
        self._wildcard_profile_cache = {}
        self._wildcard_candidate_detail_cache = {}
        self._wildcard_domain_hit_cache = {}
        self._domain_dict_size = None
        self._domain_word_file = None

        self.npoc_service_target_set = set()
        self._last_port_scan_metrics = {}
        self._last_dns_query_metrics = {}
        self._last_ip_query_metrics = {}

        self.web_site_fetch = None

        self.wih_domain_set = set()  # 通过调用 WebInfoHunter 获取的域名集合

        scan_port_map = {
            "test": ScanPortType.TEST,
            "top100": ScanPortType.TOP100,
            "top1000": ScanPortType.TOP1000,
            "all": ScanPortType.ALL,
            "custom": self.options.get("port_custom", "80,443")
        }
        option_scan_port_type = self.options.get("port_scan_type", "test")
        scan_port_option = {
            "ports": scan_port_map.get(option_scan_port_type, ScanPortType.TEST),
            # 开启 service_detection 时启用 nmap -sV，用于补充产品/版本信息。
            # 协议识别仍由 npoc(sniffer) 做二次增强。
            "service_detect": bool(self.options.get("service_detection")),
            "os_detect": self.options.get("os_detection", False),
            "skip_scan_cdn_ip": self.options.get(
                "skip_scan_cdn_ip", Config.PORT_SCAN_SKIP_CDN_IP_DEFAULT
            ),  # 跳过扫描CDN IP
            # 任务未显式配置时，回退到配置管理中的全局默认参数。
            "port_parallelism": self.options.get("port_parallelism", Config.PORT_PARALLELISM),  # 探测报文并行度
            "port_min_rate": self.options.get("port_min_rate", Config.PORT_MIN_RATE),  # 最少发包速率
            "custom_host_timeout": None  # 主机超时时间(s)
        }

        # 只有当超时策略为 custom 时才会设置主机超时。
        host_timeout_type = str(
            self.options.get("host_timeout_type", Config.HOST_TIMEOUT_TYPE)
        ).strip().lower()
        if host_timeout_type == "custom":
            scan_port_option["custom_host_timeout"] = self.options.get("host_timeout", Config.HOST_TIMEOUT)

        self.scan_port_option = scan_port_option

        self.base_update_task = BaseUpdateTask(self.task_id)

    @staticmethod
    def _is_low_conf_service(port_info):
        """
        判断端口服务识别是否低置信度。
        低置信度端口优先走协议识别（sniffer）。
        """
        service_name = str(getattr(port_info, "service_name", "")).strip().lower()
        if not service_name:
            return True

        low_conf_names = {
            "unknown",
            "tcpwrapped",
            "wrapped",
            "ssl/unknown",
            "unrecognized",
        }
        return service_name in low_conf_names

    @staticmethod
    def _normalize_scheme(value):
        value = str(value or "").strip().lower()
        if not value:
            return ""
        alias_map = {
            "ssl/http": "https",
            "http/ssl": "https",
            "www": "http",
        }
        return alias_map.get(value, value)

    @staticmethod
    def _extract_detected_service(service_name, product=""):
        """
        仅从已有识别结果提取服务名，不做端口号猜测。
        """
        name = str(service_name or "").strip().lower()
        if name:
            return name

        product_name = str(product or "").strip().lower()
        # 仅处理明确协议别名，避免把产品名/端口映射当成服务名
        if product_name in {"https-alt", "ssl/http", "http/ssl", "www"}:
            return product_name

        return ""

    def _enable_protocol_detection(self):
        """
        兼容历史选项：
        - service_detection：启用服务识别增强（nmap -sV + sniffer）
        - npoc_service_detection：历史开关，继续兼容
        """
        return bool(self.options.get("service_detection") or self.options.get("npoc_service_detection"))

    def _build_sniffer_targets(self, full_port=False):
        """
        构建协议识别目标。
        - full_port=True: 全端口识别（更慢、更全面）
        - full_port=False: 智能模式，仅识别低置信度端口（更快）
        """
        all_targets = []
        low_conf_targets = []
        target_set = set()

        for ip_info in self.ip_info_list:
            ip = str(getattr(ip_info, "ip", "")).strip()
            if not ip:
                continue

            for port_info in getattr(ip_info, "port_info_list", []):
                port_id = getattr(port_info, "port_id", None)
                if port_id is None:
                    continue

                target = "{}:{}".format(ip, port_id)
                if target in target_set:
                    continue
                target_set.add(target)
                all_targets.append(target)

                if self._is_low_conf_service(port_info):
                    low_conf_targets.append(target)

        if full_port:
            return all_targets, len(all_targets), len(low_conf_targets), "full"

        # 智能模式：优先低置信度端口
        selected = list(low_conf_targets)

        # 若低置信度目标为空，补充少量非80/443端口，避免完全不执行识别
        if not selected and all_targets:
            for target in all_targets:
                port = target.rsplit(":", 1)[-1]
                if port in {"80", "443"}:
                    continue
                selected.append(target)
                if len(selected) >= 300:
                    break

        if not selected and all_targets:
            selected = all_targets[:100]

        return selected, len(all_targets), len(low_conf_targets), "smart"

    def _apply_npoc_service_result(self, sniffer_items):
        """
        将 NPoC 协议识别结果回填到端口信息，提升 service 结果质量。
        """
        if not sniffer_items:
            return 0

        scheme_map = {}
        for item in sniffer_items:
            host = str(item.get("host", "")).strip()
            port = str(item.get("port", "")).strip()
            scheme = self._normalize_scheme(item.get("scheme"))
            if not host or not port or not scheme:
                continue
            scheme_map["{}:{}".format(host, port)] = scheme

        if not scheme_map:
            return 0

        updated = 0
        for ip_info in self.ip_info_list:
            ip = str(ip_info.ip).strip()
            if not ip:
                continue

            for port_info in ip_info.port_info_list:
                key = "{}:{}".format(ip, port_info.port_id)
                if key not in scheme_map:
                    continue

                scheme = scheme_map[key]
                curr_service = str(port_info.service_name or "").strip().lower()
                # 服务识别以 sniffer 为准，nmap 结果作为回退
                if curr_service != scheme:
                    updated += 1
                port_info.service_name = scheme
                if not str(port_info.product or "").strip() or self._is_low_conf_service(port_info):
                    port_info.product = scheme

        return updated

    @property
    def domain_word_file(self) -> str:
        if self._domain_word_file is None:
            # 任务级字典优先；未设置时再按 test/big 选择系统默认字典。
            custom_domain_dict = normalize_dict_path_compat(self.options.get("domain_dict", ""))
            custom_domain_dict = str(custom_domain_dict or "").strip()
            if custom_domain_dict and os.path.isfile(custom_domain_dict):
                self._domain_word_file = custom_domain_dict
                logger.info("task_id:{} use custom domain_dict {}".format(self.task_id, custom_domain_dict))
                return self._domain_word_file

            brute_dict_map = {
                "test": Config.DOMAIN_DICT_TEST,
                "big": Config.DOMAIN_DICT_2W,
            }
            domain_brute_type = self.options.get("domain_brute_type", "test")
            domain_word_file = brute_dict_map.get(domain_brute_type, Config.DOMAIN_DICT_TEST)
            self._domain_word_file = domain_word_file

        return self._domain_word_file

    @property
    def domain_dict_size(self):
        if self._domain_dict_size is None:
            self._domain_dict_size = len(utils.load_file(self.domain_word_file))

        return self._domain_dict_size

    @property
    def wildcard_domain_records(self):
        if self._wildcard_domain_records is None:
            self._wildcard_domain_records = sorted(self._get_wildcard_records_for_domains([self.base_domain]))
            if self._wildcard_domain_records:
                logger.info(
                    "wildcard_domain_records {} {}".format(
                        self.base_domain, self._wildcard_domain_records
                    )
                )

        return self._wildcard_domain_records

    @property
    def not_found_domain_ips(self):
        # 兼容历史调用方，返回值已扩展为 A/CNAME 泛解析记录集合。
        return self.wildcard_domain_records

    def _get_wildcard_profile(self, root):
        root = utils.normalize_domain(root)
        if not root:
            return None

        if root not in self._wildcard_profile_cache:
            profile_map = collect_wildcard_profiles_from_roots([root])
            self._wildcard_profile_cache[root] = profile_map.get(root)

        return self._wildcard_profile_cache.get(root)

    def _get_wildcard_profile_map_for_domain(self, domain):
        profile_map = {}
        for root in build_wildcard_probe_roots([domain]):
            # 目标根的画像已在初始泛解析校准中处理，继续使用原有记录集合兜底。
            if root == self.base_domain and self._wildcard_domain_records is not None:
                continue
            profile = self._get_wildcard_profile(root)
            if profile and profile.get("records"):
                profile_map[root] = profile
        return profile_map

    def _prewarm_wildcard_profiles(self, domain_info_list):
        """按当前批次并发收集泛解析画像，避免逐候选串行探测。"""
        roots = []
        seen = set()
        for info in domain_info_list or []:
            if not getattr(info, "record_list", None):
                continue
            domain = utils.normalize_domain(getattr(info, "domain", ""))
            if not domain:
                continue
            for root in build_wildcard_probe_roots([domain]):
                if root == self.base_domain and self._wildcard_domain_records is not None:
                    continue
                if root in seen or root in self._wildcard_profile_cache:
                    continue
                seen.add(root)
                roots.append(root)

        if not roots:
            return

        started_at = time.time()
        logger.info(
            "wildcard profile prewarm start task_id:{} domains:{} roots:{}".format(
                self.task_id,
                len(domain_info_list or []),
                len(roots),
            )
        )
        profile_map = collect_wildcard_profiles_from_roots(roots)
        for root in roots:
            # 缺失/异常画像写入 None，当前批次后续不再重复发起同一探测。
            self._wildcard_profile_cache[root] = profile_map.get(root)
        logger.info(
            "wildcard profile prewarm end task_id:{} roots:{} profiles:{} elapsed:{:.2f}s".format(
                self.task_id,
                len(roots),
                len([root for root in roots if self._wildcard_profile_cache.get(root)]),
                time.time() - started_at,
            )
        )

    def _prewarm_wildcard_candidate_details(self, domain_info_list):
        """按当前批次并发完成候选复验，避免过滤循环逐条等待 DNS。"""
        candidates = []
        seen = set()
        for info in domain_info_list or []:
            if not getattr(info, "record_list", None):
                continue
            domain = utils.normalize_domain(getattr(info, "domain", ""))
            if not domain or domain in seen or domain in self._wildcard_candidate_detail_cache:
                continue
            if not self._get_wildcard_profile_map_for_domain(domain):
                continue
            seen.add(domain)
            candidates.append(info)

        if not candidates:
            return

        started_at = time.time()
        concurrency = max(
            1,
            int(getattr(Config, "WILDCARD_PROFILE_CONCURRENCY", 8) or 8),
        )
        logger.info(
            "wildcard candidate verify prewarm start task_id:{} candidates:{} concurrency:{}".format(
                self.task_id,
                len(candidates),
                concurrency,
            )
        )

        def verify_one(info):
            domain = utils.normalize_domain(getattr(info, "domain", ""))
            try:
                return domain, build_wildcard_candidate_details(info)
            except Exception as exc:
                # 复验失败时保留基础记录，避免网络故障导致候选被误过滤。
                logger.warning(
                    "wildcard candidate verify degraded task_id:{} domain:{} error_type:{}".format(
                        self.task_id,
                        domain,
                        type(exc).__name__,
                    )
                )
                return domain, []

        worker_count = min(concurrency, len(candidates))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {
                executor.submit(verify_one, info): info
                for info in candidates
            }
            for future in as_completed(future_map):
                info = future_map[future]
                domain = utils.normalize_domain(getattr(info, "domain", ""))
                try:
                    key, details = future.result()
                except Exception as exc:
                    logger.warning(
                        "wildcard candidate verify batch degraded task_id:{} domain:{} error_type:{}".format(
                            self.task_id,
                            domain,
                            type(exc).__name__,
                        )
                    )
                    key, details = domain, []
                if key:
                    self._wildcard_candidate_detail_cache[key] = details

        logger.info(
            "wildcard candidate verify prewarm end task_id:{} candidates:{} cached:{} elapsed:{:.2f}s".format(
                self.task_id,
                len(candidates),
                len([item for item in candidates if utils.normalize_domain(getattr(item, "domain", "")) in self._wildcard_candidate_detail_cache]),
                time.time() - started_at,
            )
        )

    def _get_wildcard_records_for_domains(self, domains):
        wildcard_records = set()
        for root in build_wildcard_probe_roots(domains):
            profile = self._get_wildcard_profile(root)
            if not profile:
                continue
            wildcard_records.update(profile.get("records", set()))
        return wildcard_records

    def save_domain_info_list(self, domain_info_list, source=CollectSource.DOMAIN_BRUTE):
        for domain_info_obj in domain_info_list:
            domain_info = domain_info_obj.dump_json(flag=False)
            domain_parsed = utils.domain_parsed(domain_info["domain"])
            if domain_parsed:
                domain_info["fld"] = domain_parsed["fld"]
            domain = utils.normalize_domain(domain_info.get("domain"))
            source_list = self._get_domain_sources(domain, source)
            DomainRepository.upsert_discovered_domain(
                task_id=self.task_id,
                domain_info=domain_info,
                primary_source=source,
                sources=source_list,
            )

    def save_domain_info_list_by_source_map(self, domain_info_list, default_source=CollectSource.DOMAIN_BRUTE):
        """
        按域名来源映射进行保存（一个域名可对应多个来源）
        """
        for domain_info_obj in domain_info_list:
            domain = utils.normalize_domain(getattr(domain_info_obj, "domain", ""))
            source_list = self._get_domain_sources(domain, default_source)
            self.save_domain_info_list([domain_info_obj], source=default_source)
            logger.debug(
                "save domain source aggregation task_id:{} domain:{} sources:{}".format(
                    self.task_id, domain, ",".join(source_list)
                )
            )

    def _get_domain_sources(self, domain, default_source):
        domain = utils.normalize_domain(domain)
        source_set = set(self.domain_source_map.get(domain, set()))
        if default_source:
            source_set.add(str(default_source).strip())
        return sorted(source for source in source_set if source)

    def add_domain_source_names(self, domains, source):
        """在去重前记录原始发现来源，避免后到的数据源被首次命中覆盖。"""
        source = str(source or "").strip()
        if not source:
            return

        normalized_domains = []
        for item in domains or []:
            domain = item
            if isinstance(item, dict):
                domain = item.get("domain", "")
            else:
                domain = getattr(item, "domain", domain)

            domain = utils.normalize_domain(domain)
            if not domain:
                continue

            source_set = self.domain_source_map.get(domain, set())
            source_set.add(source)
            self.domain_source_map[domain] = source_set
            normalized_domains.append(domain)

        if self.task_id and normalized_domains:
            DomainRepository.add_sources_by_domains(
                task_id=self.task_id,
                domains=normalized_domains,
                sources=[source],
            )

    def add_domain_source_map(self, domain_info_list, source):
        """
        记录域名与来源的关系，便于监控任务重建时保留来源
        """
        if not source:
            return

        self.add_domain_source_names(domain_info_list, source)

    def domain_brute(self):
        return DomainDiscoveryStageService(self).run_domain_brute()

    def clear_domain_info_by_record(self, domain_info_list):
        self._prewarm_wildcard_profiles(domain_info_list)
        self._prewarm_wildcard_candidate_details(domain_info_list)
        new_list = []
        for info in domain_info_list:
            if not info.record_list:
                continue

            domain = utils.normalize_domain(getattr(info, "domain", ""))
            if not domain:
                continue

            if domain in self._dns_policy_cache:
                allow_scan, policy_detail = self._dns_policy_cache[domain]
            else:
                allow_scan, policy_detail = utils.check_dns_policy_for_host(domain)
                self._dns_policy_cache[domain] = (allow_scan, policy_detail)

            if not allow_scan:
                logger.info(
                    "skip domain by dns policy domain:{} reason:{} resolver_ips:{} system_ips:{}".format(
                        domain,
                        policy_detail.get("reason", ""),
                        policy_detail.get("resolver_ips", []),
                        policy_detail.get("system_ips", []),
                    )
                )
                continue

            if domain in self._wildcard_domain_hit_cache:
                if self._wildcard_domain_hit_cache[domain]:
                    continue
            else:
                wildcard_profile_map = self._get_wildcard_profile_map_for_domain(domain)
                wildcard_hit = False
                if wildcard_profile_map:
                    candidate_details = self._wildcard_candidate_detail_cache.get(domain)
                    if candidate_details is None:
                        wildcard_hit = domain_info_hits_wildcard_profile(info, wildcard_profile_map)
                    else:
                        wildcard_hit = domain_info_hits_wildcard_profile_with_details(
                            info,
                            wildcard_profile_map,
                            candidate_details,
                        )
                elif domain_info_hits_wildcard_records(info, self.wildcard_domain_records):
                    wildcard_hit = True

                self._wildcard_domain_hit_cache[domain] = wildcard_hit
                if wildcard_hit:
                    continue

            record = info.record_list[0]
            cnt = self.record_map.get(record, 0)
            cnt += 1
            self.record_map[record] = cnt
            if cnt > MAX_MAP_COUNT:
                continue

            new_list.append(info)

        return new_list

    def arl_search(self):
        return DomainDiscoveryStageService(self).run_arl_search()

    def build_domain_info(self, domains):
        """
        构建domain_info_list 带去重功能
        """
        fake_list = []
        domains_set = set()
        for item in domains:
            domain = item
            if isinstance(item, dict):
                domain = item["domain"]

            domain = utils.normalize_domain(domain)
            if not domain:
                continue

            if domain in domains_set:
                continue
            domains_set.add(domain)

            if utils.check_domain_black(domain):
                continue

            fake = {
                "domain": domain,
                "type": "CNAME",
                "record": [],
                "ips": []
            }
            fake_info = modules.DomainInfo(**fake)
            if fake_info not in self.domain_info_list:
                fake_list.append(fake_info)

        if self.task_tag == "monitor":
            return fake_list
        domain_info_list = services.build_domain_info(
            fake_list,
            dns_policy_cache=self._dns_policy_cache,
        )

        return domain_info_list

    def alt_dns_current(self):
        return DomainDiscoveryStageService(self).run_alt_dns_current()

    def alt_dns(self):
        return DomainDiscoveryStageService(self).run_alt_dns()

    def port_scan(self):
        ip_info_list = scan_port(self.domain_info_list, self.scan_port_option)
        self._last_port_scan_metrics = dict(getattr(ip_info_list, "metrics", {}) or {})

        for ip_info_obj in ip_info_list:
            ip_info = ip_info_obj.dump_json(flag=False)
            ip_info["task_id"] = self.task_id

            utils.conn_db("ip").update_one(
                {"task_id": self.task_id, "ip": ip_info_obj.ip},
                {"$set": ip_info},
                upsert=True,
            )

        self.ip_info_list.extend(ip_info_list)
        return ip_info_list

    def find_site(self):
        if self.options.get("port_scan"):
            '''***站点寻找***'''
            sites = find_site(self.ip_info_list)
        else:
            sites = services.probe_http(self.domain_info_list)

        existing_sites = set(self.site_list)
        for site in sites:
            if site in existing_sites:
                continue
            existing_sites.add(site)
            self.site_list.append(site)

    def update_services(self, service_name, elapsed, metrics=None):
        self.base_update_task.update_services(
            service_name=service_name,
            elapsed=elapsed,
            metrics=metrics,
        )

    def update_task_field(self, field=None, value=None):
        self.base_update_task.update_task_field(field=field, value=value)

    def gen_ipv4_map(self):
        ipv4_map = {}
        for domain_info in self.domain_info_list:
            for ip in domain_info.ip_list:
                old_domain = ipv4_map.get(ip, set())
                old_domain.add(domain_info.domain)
                ipv4_map[ip] = old_domain
                self.ip_set.add(ip)

        self.ipv4_map = ipv4_map

    # 只是保存没有开放端口的
    def save_ip_info(self):
        fake_ip_info_list = []
        for ip in self.ipv4_map:
            data = {
                "ip": ip,
                "domain": list(self.ipv4_map[ip]),
                "port_info": [],
                "os_info": {},
                "cdn_name": utils.get_cdn_name_by_ip(ip)
            }
            info_obj = modules.IPInfo(**data)
            if info_obj not in self.ip_info_list:
                fake_ip_info_list.append(info_obj)

        for ip_info_obj in fake_ip_info_list:
            ip_info = ip_info_obj.dump_json(flag=False)
            ip_info["task_id"] = self.task_id
            utils.conn_db("ip").update_one(
                {"task_id": self.task_id, "ip": ip_info_obj.ip},
                {"$set": ip_info},
                upsert=True,
            )

    def save_service_info(self):
        self.service_info_list = []
        service_map = {}
        service_seen = set()
        port_total = 0
        merged_total = 0
        nmap_merged = 0
        npoc_merged = 0

        def _append_item(service_name, ip, port_id, product="", version="", source=""):
            nonlocal merged_total, nmap_merged, npoc_merged
            raw_name = self._extract_detected_service(
                service_name=service_name,
                product=product,
            )
            service = self._normalize_scheme(raw_name)
            if not service:
                return

            ip = str(ip or "").strip()
            if not ip:
                return

            try:
                port_id = int(port_id)
            except Exception:
                return

            uniq_key = (service, ip, port_id)
            if uniq_key in service_seen:
                return
            service_seen.add(uniq_key)

            service_map.setdefault(service, [])
            normalized_product = str(product or "").strip()
            if not normalized_product:
                # -sV 未开启或未命中时，回退协议名，避免 Product 长期空白。
                normalized_product = service
            service_map[service].append({
                "ip": ip,
                "port_id": port_id,
                "product": normalized_product,
                "version": str(version or "").strip(),
            })
            merged_total += 1
            if source == "nmap":
                nmap_merged += 1
            elif source == "npoc":
                npoc_merged += 1

        # 1) nmap 结果（已被 npoc 回填增强）
        for ip_item in self.ip_info_list:
            port_info_list = getattr(ip_item, "port_info_list", [])
            for port_item in port_info_list:
                port_total += 1
                _append_item(
                    service_name=getattr(port_item, "service_name", ""),
                    ip=getattr(ip_item, "ip", ""),
                    port_id=getattr(port_item, "port_id", None),
                    product=getattr(port_item, "product", ""),
                    version=getattr(port_item, "version", ""),
                    source="nmap",
                )

        # 2) npoc 明细补充（用于兜底合并来源）
        for item in utils.conn_db('npoc_service').find({"task_id": self.task_id}):
            _append_item(
                service_name=item.get("scheme", ""),
                ip=item.get("host", ""),
                port_id=item.get("port", None),
                product=item.get("scheme", ""),
                version=item.get("version", ""),
                source="npoc",
            )

        for service_name, info_list in service_map.items():
            self.service_info_list.append({
                "service_name": service_name,
                "service_info": info_list,
                "task_id": self.task_id
            })

        # 同任务重跑时先清理旧数据，避免重复堆积
        utils.conn_db('service').delete_many({"task_id": self.task_id})
        if self.service_info_list:
            utils.conn_db('service').insert_many(self.service_info_list)

        logger.info(
            "save_service_info task_id:{} ports:{} merged:{} nmap:{} npoc:{} service_group:{}".format(
                self.task_id, port_total, merged_total, nmap_merged, npoc_merged, len(self.service_info_list)
            )
        )

    def ssl_cert(self):
        if self.options.get("port_scan"):
            self.cert_map = ssl_cert(self.ip_info_list, self.base_domain)
        else:
            # 未启用端口扫描时，仍构建 443 目标并携带域名上下文，保证 CDN 场景优先拿到业务域名证书
            fake_targets = []
            for ip in sorted(self.ip_set):
                domains = list(self.ipv4_map.get(ip, set()))
                fake_targets.append(
                    modules.IPInfo(
                        ip=ip,
                        domain=domains,
                        port_info=[modules.PortInfo(port_id=443, service_name="https")],
                        os_info={},
                        cdn_name="",
                    )
                )
            self.cert_map = ssl_cert(fake_targets, self.base_domain)

        # 同一 endpoint 若已经命中 SNI 证书，则 default 结果仅作兜底不再入库，
        # 避免 CDN 场景下“默认证书”覆盖业务观感。
        sni_success_endpoints = set()
        for target in self.cert_map:
            cert_obj = self.cert_map.get(target, {})
            if not isinstance(cert_obj, dict):
                continue

            cert_data = dict(cert_obj)
            scan_meta = cert_data.pop("_scan_meta", {})
            if not isinstance(scan_meta, dict):
                scan_meta = {}

            endpoint = str(scan_meta.get("endpoint", "")).strip() or str(target).strip()
            ip, port = fetchCert.split_host_port(endpoint)
            if not ip or port <= 0:
                continue

            scan_mode = str(scan_meta.get("scan_mode", "default") or "default").strip().lower()
            if scan_mode != "sni":
                continue

            sni_domain = utils.normalize_domain(scan_meta.get("sni_domain", ""))
            legacy_server_name = utils.normalize_domain(scan_meta.get("server_name", ""))
            if not sni_domain:
                sni_domain = legacy_server_name
            if not sni_domain:
                continue

            domains = fetchCert.normalize_domains(scan_meta.get("domains", []))
            if sni_domain not in domains:
                domains = fetchCert.normalize_domains(domains + [sni_domain])

            matched_domains = fetchCert.match_cert_domains(cert_data, domains)
            if domains and not matched_domains:
                continue
            if matched_domains and sni_domain not in matched_domains:
                continue

            sni_success_endpoints.add(endpoint)

        for target in self.cert_map:
            cert_obj = self.cert_map.get(target, {})
            if not isinstance(cert_obj, dict):
                continue

            cert_data = dict(cert_obj)
            scan_meta = cert_data.pop("_scan_meta", {})
            if not isinstance(scan_meta, dict):
                scan_meta = {}

            endpoint = str(scan_meta.get("endpoint", "")).strip() or str(target).strip()
            ip, port = fetchCert.split_host_port(endpoint)
            if not ip or port <= 0:
                continue

            scan_mode = str(scan_meta.get("scan_mode", "default") or "default").strip().lower()
            if scan_mode not in ["default", "sni"]:
                scan_mode = "default"

            if scan_mode == "default" and endpoint in sni_success_endpoints:
                continue

            sni_domain = utils.normalize_domain(scan_meta.get("sni_domain", ""))
            # 兼容旧结构：历史扫描元数据只有 server_name 字段。
            legacy_server_name = utils.normalize_domain(scan_meta.get("server_name", ""))
            if not sni_domain and scan_mode == "sni":
                sni_domain = legacy_server_name

            domains = fetchCert.normalize_domains(scan_meta.get("domains", []))
            if sni_domain and sni_domain not in domains:
                domains = fetchCert.normalize_domains(domains + [sni_domain])

            matched_domains = fetchCert.match_cert_domains(cert_data, domains)
            # domain 任务仅保留与目标域上下文命中的证书，避免将 CDN 默认证书映射到业务域名。
            if domains and not matched_domains:
                continue

            if scan_mode == "sni" and sni_domain and matched_domains and sni_domain not in matched_domains:
                continue

            domains = matched_domains if matched_domains else domains

            if scan_mode == "sni" and sni_domain and sni_domain in domains:
                domain = sni_domain
            elif domains:
                domain = domains[0]
            else:
                domain = ""

            fingerprint = cert_data.get("fingerprint", {}) if isinstance(cert_data.get("fingerprint"), dict) else {}
            cert_sha256 = str(fingerprint.get("sha256", "")).strip().lower().replace(":", "")
            cert_sha1 = str(fingerprint.get("sha1", "")).strip().lower().replace(":", "")
            serial_number = str(cert_data.get("serial_number", "")).strip().lower().replace(" ", "")
            cert_identity_key = cert_sha256 or cert_sha1 or serial_number or ""

            validity = cert_data.get("validity", {}) if isinstance(cert_data.get("validity"), dict) else {}
            cert_end_time = str(validity.get("end", "")).strip()
            observe_id = str(scan_meta.get("observe_id", "")).strip()

            item = {
                "ip": ip,
                "port": port,
                "host": endpoint,
                "domain": domain,
                "domains": domains,
                "sni_domain": sni_domain,
                "scan_mode": scan_mode,
                "observe_id": observe_id,
                "cert_identity_key": cert_identity_key,
                "cert_end_time": cert_end_time,
                "cert": cert_data,
                "task_id": self.task_id,
            }

            # 多SNI扫描后按任务维度做轻量去重，避免重复落库同一观测。
            query = {
                "task_id": self.task_id,
                "ip": ip,
                "port": port,
                "scan_mode": scan_mode,
                "sni_domain": sni_domain,
            }
            if cert_identity_key:
                query["cert_identity_key"] = cert_identity_key
            if cert_end_time:
                query["cert_end_time"] = cert_end_time
            if not cert_identity_key and not cert_end_time:
                query["observe_id"] = observe_id or endpoint

            utils.conn_db('cert').update_one(query, {"$setOnInsert": item}, upsert=True)

    def build_single_domain_info(self, domain):
        domain = utils.normalize_domain(domain)
        if not domain:
            return

        if domain in self._dns_policy_cache:
            allow_scan, policy_detail = self._dns_policy_cache[domain]
        else:
            allow_scan, policy_detail = utils.check_dns_policy_for_host(domain)
            self._dns_policy_cache[domain] = (allow_scan, policy_detail)

        if not allow_scan:
            logger.info(
                "skip build_single_domain_info by dns policy domain:{} reason:{} resolver_ips:{} system_ips:{}".format(
                    domain,
                    policy_detail.get("reason", ""),
                    policy_detail.get("resolver_ips", []),
                    policy_detail.get("system_ips", []),
                )
            )
            return

        _type = "A"
        cname = utils.get_cname(domain)
        if cname:
            _type = 'CNAME'
        preferred_ips = list(policy_detail.get("preferred_ips", []) or [])
        if preferred_ips:
            ips = preferred_ips
        else:
            ips = utils.get_ip(domain)
        if _type == "A":
            record = ips
        else:
            record = cname

        if not ips:
            return

        item = {
            "domain": domain,
            "type": _type,
            "record": record,
            "ips": ips
        }

        return modules.DomainInfo(**item)

    @staticmethod
    def _chunk_list(items, chunk_size):
        return DomainDiscoveryStageService._chunk_list(items, chunk_size)

    @staticmethod
    def _format_timeout(timeout_sec):
        return DomainDiscoveryStageService._format_timeout(timeout_sec)

    @staticmethod
    def _calc_dns_query_plugin_stage_timeout(source_count):
        return DomainDiscoveryStageService._calc_dns_query_plugin_stage_timeout(source_count)

    def _resolve_dns_query_sources(self):
        return DomainDiscoveryStageService(self)._resolve_dns_query_sources()

    def _run_query_plugin(self, target, source_batch):
        return run_query_plugin(target, source_batch)

    # *** 保留历史入口，实际 DNS 阶段由 DomainDiscoveryStageService 持有。
    def dns_query_plugin(self):
        return DomainDiscoveryStageService(self).run_dns_query_plugin()

    def get_ip_pivot_candidates(self):
        """
        从已发现域名中提取公网A记录IP，作为三方IP反查候选
        """
        ip_map = {}
        skip_non_a = 0
        skip_non_public = 0
        skip_black = 0
        skip_cdn = 0
        for domain_info in self.domain_info_list:
            if domain_info.type != "A":
                skip_non_a += 1
                continue

            for ip in domain_info.ip_list:
                ip = str(ip or "").strip()
                if not ip or not utils.is_vaild_ip_target(ip):
                    continue

                if utils.get_ip_type(ip) != "PUBLIC":
                    skip_non_public += 1
                    continue

                if not utils.not_in_black_ips(ip):
                    skip_black += 1
                    continue

                if Config.IP_PIVOT_QUERY_SKIP_CDN and utils.get_cdn_name_by_ip(ip):
                    skip_cdn += 1
                    continue

                old_set = ip_map.get(ip, set())
                old_set.add(domain_info.domain)
                ip_map[ip] = old_set

        all_ips = sorted(ip_map.keys())
        max_ips = max(int(Config.IP_PIVOT_QUERY_MAX_IPS or 0), 0)
        if max_ips > 0 and len(all_ips) > max_ips:
            all_ips = all_ips[:max_ips]

        logger.info(
            "ip pivot candidate total:{} selected:{} skip_non_a:{} skip_non_public:{} skip_black:{} skip_cdn:{}".format(
                len(ip_map), len(all_ips), skip_non_a, skip_non_public, skip_black, skip_cdn
            )
        )
        return all_ips

    def ip_query_plugin_enhance(self):
        """
        公网A记录IP反查增强：通过三方API补充同域资产
        """
        if not Config.IP_PIVOT_QUERY_ENABLE:
            return

        # 与域名插件开关保持一致，避免用户关闭插件后仍触发三方调用
        if not self.options.get("dns_query_plugin"):
            logger.info("skip ip_query_plugin_enhance because dns_query_plugin=false")
            return

        if "{fuzz}" in self.base_domain:
            return

        candidate_ips = self.get_ip_pivot_candidates()
        if not candidate_ips:
            logger.info("skip ip_query_plugin_enhance because no candidate ip")
            return

        target_domain = self.base_domain if Config.IP_PIVOT_QUERY_REQUIRE_SCOPE else ""
        max_domains = int(Config.IP_PIVOT_QUERY_MAX_DOMAINS or 0)
        logger.info(
            "start run ip_query_plugin_enhance base_domain:{} ip:{} source_mode:auto-enabled require_scope:{} max_domains:{}".format(
                self.base_domain, len(candidate_ips),
                bool(Config.IP_PIVOT_QUERY_REQUIRE_SCOPE), max_domains
            )
        )

        results = run_query_plugin_by_ip(
            ip_list=candidate_ips,
            target_domain=target_domain,
            max_domains=max_domains,
        )
        self._last_ip_query_metrics = dict(getattr(results, "metrics", {}) or {})
        if not results:
            logger.info("end run ip_query_plugin_enhance {} result 0".format(self.base_domain))
            return

        sources_map = dict()
        for result in results:
            domain = result["domain"]
            source = result["source"]
            source_domains = sources_map.get(source, set())
            source_domains.add(domain)
            sources_map[source] = source_domains

        cnt = 0
        for source in sources_map:
            source_domains = list(sources_map[source])
            if not source_domains:
                continue

            # 与常规来源区分，便于排查“域名来源”
            source_name = "{}_ip_pivot".format(source)
            self.add_domain_source_names(source_domains, source_name)
            logger.info("start build domain info, source:{}".format(source_name))
            domain_info_list = self.build_domain_info(source_domains)
            if self.task_tag == "task":
                domain_info_list = self.clear_domain_info_by_record(domain_info_list)
                if domain_info_list:
                    self.save_domain_info_list(domain_info_list, source=source_name)

            self.add_domain_source_map(domain_info_list, source_name)
            cnt += len(domain_info_list)
            self.domain_info_list.extend(domain_info_list)

        logger.info(
            "end run ip_query_plugin_enhance {}, source_result:{}, real_result:{}".format(
                self.base_domain, len(results), cnt
            )
        )

    def get_scope_domain_list(self):
        """
        获取当前任务的域名范围：目标域名 + 目标主域名（去重）
        """
        scope_domains = [self.base_domain]
        primary_domain = utils.get_fld(self.base_domain)
        if primary_domain and primary_domain not in scope_domains:
            scope_domains.append(primary_domain)

        return scope_domains

    def normalize_cert_domain(self, value):
        """
        标准化证书中提取到的域名（支持去掉通配符、协议和端口）
        """
        domain = utils.normalize_domain(value)
        if not domain:
            return ""

        if not utils.is_valid_domain(domain):
            return ""

        return domain

    def extract_cert_domain_candidates(self, cert_obj):
        """
        提取证书中的域名候选（subject CN / issuer CN / SAN）
        """
        domains = set()
        if not isinstance(cert_obj, dict):
            return []

        subject = cert_obj.get("subject") or {}
        issuer = cert_obj.get("issuer") or {}

        subject_cn = self.normalize_cert_domain(subject.get("common_name"))
        if subject_cn:
            domains.add(subject_cn)

        issuer_cn = self.normalize_cert_domain(issuer.get("common_name"))
        if issuer_cn:
            domains.add(issuer_cn)

        extensions = cert_obj.get("extensions") or {}
        san_text = str(extensions.get("subjectAltName") or "").strip()
        if san_text:
            for raw_item in san_text.split(","):
                raw_item = raw_item.strip()
                if not raw_item:
                    continue

                if ":" in raw_item:
                    prefix, value = raw_item.split(":", 1)
                    if prefix.strip().lower() != "dns":
                        continue
                    domain = self.normalize_cert_domain(value)
                else:
                    domain = self.normalize_cert_domain(raw_item)

                if domain:
                    domains.add(domain)

        return sorted(list(domains))

    def match_cert_scope_domains(self, cert_obj):
        """
        仅保留命中目标域或目标主域范围的证书域名候选
        """
        cert_domains = self.extract_cert_domain_candidates(cert_obj)
        if not cert_domains:
            return []

        scope_domains = self.get_scope_domain_list()
        matched = []
        for cert_domain in cert_domains:
            for scope_domain in scope_domains:
                if utils.is_in_scope(cert_domain, scope_domain):
                    matched.append(cert_domain)
                    break

        return sorted(list(set(matched)))

    def build_cert_pivot_key(self, cert_obj):
        """
        构建证书反查唯一标识，优先 serial + sha1
        """
        if not isinstance(cert_obj, dict):
            return ""

        serial_number = str(cert_obj.get("serial_number") or "").strip()
        fingerprint = cert_obj.get("fingerprint") or {}
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

    def get_cert_pivot_candidates(self):
        """
        生成证书反查候选：必须命中目标范围，且满足去重/配额/CDN过滤
        """
        cert_map = self.cert_map if isinstance(self.cert_map, dict) else {}
        if not cert_map:
            return []

        ip_cdn_map = {}
        for ip_info_obj in self.ip_info_list:
            if ip_info_obj.cdn_name:
                ip_cdn_map[ip_info_obj.ip] = ip_info_obj.cdn_name

        skip_cdn = 0
        skip_scope = 0
        skip_no_key = 0
        skip_dup = 0

        seen_cert_key = set()
        candidates = []
        for observe_id in sorted(cert_map.keys()):
            cert_obj = cert_map.get(observe_id)
            if not isinstance(cert_obj, dict):
                continue

            scan_meta = cert_obj.get("_scan_meta", {}) if isinstance(cert_obj.get("_scan_meta"), dict) else {}
            endpoint = str(scan_meta.get("endpoint", "")).strip() or str(observe_id)
            curr_ip, _ = fetchCert.split_host_port(endpoint)
            if not curr_ip:
                curr_ip = endpoint.split(":")[0] if ":" in endpoint else endpoint

            if Config.CERT_PIVOT_QUERY_SKIP_CDN:
                cdn_name = ip_cdn_map.get(curr_ip) or utils.get_cdn_name_by_ip(curr_ip)
                if cdn_name:
                    skip_cdn += 1
                    continue

            matched_domains = self.match_cert_scope_domains(cert_obj)
            if not matched_domains:
                skip_scope += 1
                continue

            cert_key = self.build_cert_pivot_key(cert_obj)
            if not cert_key:
                skip_no_key += 1
                continue

            if cert_key in seen_cert_key:
                skip_dup += 1
                continue

            seen_cert_key.add(cert_key)
            candidates.append({
                "cert": cert_obj,
                "cert_key": cert_key,
                "endpoint": endpoint,
                "observe_id": str(observe_id),
                "match_domains": matched_domains
            })

        max_certs = max(int(Config.CERT_PIVOT_QUERY_MAX_CERTS or 0), 0)
        if max_certs > 0 and len(candidates) > max_certs:
            candidates = candidates[:max_certs]

        logger.info(
            "cert pivot candidate total:{} selected:{} skip_cdn:{} skip_scope:{} skip_no_key:{} skip_dup:{}".format(
                len(seen_cert_key), len(candidates), skip_cdn, skip_scope, skip_no_key, skip_dup
            )
        )
        return candidates

    def incremental_port_scan_for_new_ips(self):
        """
        对证书反查新增域名产生的新增IP执行增量端口扫描
        """
        scanned_ip_set = set()
        for ip_info_obj in self.ip_info_list:
            scanned_ip_set.add(ip_info_obj.ip)

        new_ips = []
        for ip in sorted(self.ipv4_map.keys()):
            if ip not in scanned_ip_set:
                new_ips.append(ip)

        if not new_ips:
            return 0

        domain_ip_map = {}
        for ip in new_ips:
            domains = self.ipv4_map.get(ip, set())
            for domain in domains:
                ip_set = domain_ip_map.get(domain, set())
                ip_set.add(ip)
                domain_ip_map[domain] = ip_set

        new_domain_info_list = []
        for domain, ip_set in domain_ip_map.items():
            ips = sorted(list(ip_set))
            if not ips:
                continue
            item = {
                "domain": domain,
                "type": "A",
                "record": ips,
                "ips": ips
            }
            new_domain_info_list.append(modules.DomainInfo(**item))

        if not new_domain_info_list:
            return 0

        ip_info_list = scan_port(new_domain_info_list, self.scan_port_option)
        for ip_info_obj in ip_info_list:
            ip_info = ip_info_obj.dump_json(flag=False)
            ip_info["task_id"] = self.task_id
            utils.conn_db("ip").update_one(
                {"task_id": self.task_id, "ip": ip_info_obj.ip},
                {"$set": ip_info},
                upsert=True,
            )

        self.ip_info_list.extend(ip_info_list)
        logger.info(
            "cert pivot incremental port_scan new_ip:{} result:{}".format(len(new_ips), len(ip_info_list))
        )
        return len(ip_info_list)

    def sync_ip_domain_from_ipv4_map(self):
        """
        将最新域名映射同步到已扫描IP对象和数据库记录
        """
        for ip_info_obj in self.ip_info_list:
            domain_set = self.ipv4_map.get(ip_info_obj.ip, set())
            if not domain_set:
                continue

            merged_domain = sorted(list(set(ip_info_obj.domain) | set(domain_set)))
            if merged_domain == ip_info_obj.domain:
                continue

            ip_info_obj.domain = merged_domain
            query = {
                "task_id": self.task_id,
                "ip": ip_info_obj.ip
            }
            utils.conn_db('ip').update_one(query, {"$set": {"domain": merged_domain}})

    def cert_query_plugin_enhance(self):
        """
        证书反查增强：证书命中目标范围后，调用三方API补充同域资产
        """
        if not Config.CERT_PIVOT_QUERY_ENABLE:
            return 0

        if not self.options.get("ssl_cert"):
            logger.info("skip cert_query_plugin_enhance because ssl_cert=false")
            return 0

        # 与域名插件开关保持一致，避免用户关闭插件后仍触发三方调用
        if not self.options.get("dns_query_plugin"):
            logger.info("skip cert_query_plugin_enhance because dns_query_plugin=false")
            return 0

        if "{fuzz}" in self.base_domain:
            return 0

        cert_candidates = self.get_cert_pivot_candidates()
        if not cert_candidates:
            logger.info("skip cert_query_plugin_enhance because no candidate cert")
            return 0

        target_domain = self.base_domain if Config.CERT_PIVOT_QUERY_REQUIRE_SCOPE else ""
        max_domains = int(Config.CERT_PIVOT_QUERY_MAX_DOMAINS or 0)
        logger.info(
            "start run cert_query_plugin_enhance base_domain:{} cert:{} source_mode:auto-enabled require_scope:{} max_domains:{}".format(
                self.base_domain, len(cert_candidates), bool(Config.CERT_PIVOT_QUERY_REQUIRE_SCOPE), max_domains
            )
        )

        results = run_query_plugin_by_cert(
            cert_list=cert_candidates,
            target_domain=target_domain,
            max_domains=max_domains
        )
        if not results:
            logger.info("end run cert_query_plugin_enhance {} result 0".format(self.base_domain))
            return 0

        sources_map = dict()
        for result in results:
            domain = result["domain"]
            source = result["source"]
            source_domains = sources_map.get(source, set())
            source_domains.add(domain)
            sources_map[source] = source_domains

        cnt = 0
        for source in sources_map:
            source_domains = list(sources_map[source])
            if not source_domains:
                continue

            source_name = "{}_cert_pivot".format(source)
            self.add_domain_source_names(source_domains, source_name)
            logger.info("start build domain info, source:{}".format(source_name))
            domain_info_list = self.build_domain_info(source_domains)
            if self.task_tag == "task":
                domain_info_list = self.clear_domain_info_by_record(domain_info_list)
                if domain_info_list:
                    self.save_domain_info_list(domain_info_list, source=source_name)

            self.add_domain_source_map(domain_info_list, source_name)
            cnt += len(domain_info_list)
            self.domain_info_list.extend(domain_info_list)

        logger.info(
            "end run cert_query_plugin_enhance {}, source_result:{}, real_result:{}".format(
                self.base_domain, len(results), cnt
            )
        )
        return cnt

    def domain_fetch(self):
        return DomainDiscoveryStageService(self).run()

    def start_ip_fetch(self):
        return DomainNetworkStageService(self).run()

    def start_site_fetch(self):
        return DomainSiteStageService(self).run()

    def npoc_service_detection(self, full_port=False):
        targets, total_targets, low_conf_targets, mode = self._build_sniffer_targets(
            full_port=full_port
        )
        skip_common_http_ports = not full_port

        logger.info(
            "npoc_service_detection mode:{} selected:{} total:{} low_conf:{} skip_common_http_ports:{}".format(
                mode, len(targets), total_targets, low_conf_targets, skip_common_http_ports
            )
        )

        if not targets:
            return

        result = run_sniffer(targets, skip_common_http_ports=skip_common_http_ports)
        enriched_count = self._apply_npoc_service_result(result)
        logger.info(
            "npoc_service_detection result:{} enriched_port:{}".format(
                len(result), enriched_count
            )
        )
        for item in result:
            self.npoc_service_target_set.add(item["target"])
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            item["source"] = "npoc_sniffer"
            utils.conn_db('npoc_service').insert_one(item)

    def start_poc_run(self):
        return DomainPostProcessStageService(self).run_poc()

    def brute_config(self):
        plugins = []
        brute_config = self.options.get("brute_config")
        for x in brute_config:
            if not x.get("enable"):
                continue
            plugins.append(x["plugin_name"])

        if not plugins:
            return
        targets = self.site_list.copy()
        targets += list(self.npoc_service_target_set)
        result = run_risk_cruising(targets=targets, plugins=plugins)
        for item in result:
            target = str(item.get("target", "") or item.get("url", "") or "").strip()
            if target and not self._url_in_task_scope(target, seed_sites=self.site_list, scope_domains=[self.base_domain]):
                continue
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('vuln').insert_one(item)

    def find_vhost_vuln(self):
        domains = find_private_domain_by_task_id(self.task_id)
        if not domains:
            return

        ips = find_public_ip_by_task_id(self.task_id)
        results = find_vhost(ips=ips, domains=domains)
        for result in results:
            if not self._url_in_task_scope(result.get("url", ""), seed_sites=self.site_list, scope_domains=[self.base_domain]):
                continue
            save_item = dict()
            save_item["plg_name"] = "FindVhost"
            save_item["plg_type"] = "scan"
            save_item["vul_name"] = "发现Host碰撞漏洞"
            save_item["app_name"] = "web"
            save_item["target"] = result["url"]
            save_item["verify_data"] = "{}-{}-{}-{}".format(result["domain"],
                                                            result["title"],
                                                            result["status_code"],
                                                            result["body_length"])
            save_item["verify_obj"] = result
            save_item["task_id"] = self.task_id
            save_item["save_date"] = utils.curr_date()
            utils.conn_db('vuln').insert_one(save_item)

    def start_find_vhost(self):
        return DomainPostProcessStageService(self).run_find_vhost()

    # 搜索引擎调用
    def search_engines(self):
        return DomainDiscoveryStageService(self).run_search_engines()

    def _register_search_page_candidates(self, urls, page_map):
        return DomainDiscoveryStageService(self).register_search_page_candidates(urls, page_map)

    def start_wih_domain_update(self):
        if self.wih_domain_set:
            domains = list(self.wih_domain_set)
            self._run_internal_stage(
                "wih_domain_update",
                lambda: domain_site_update(self.task_id, domains, "wih"),
                detail="domains={}".format(len(domains)),
            )

    def _load_saved_domain_info(self):
        """从当前任务已落库的域名记录恢复深度阶段输入，避免重跑发现阶段。"""
        if self.domain_info_list:
            return len(self.domain_info_list)

        restored = []
        source_map = {}
        cursor = DomainRepository.find_by_task_id(
            self.task_id,
            projection={"domain": 1, "record": 1, "type": 1, "ips": 1, "source": 1, "sources": 1},
            batch_size=500,
        )
        for item in cursor:
            domain = utils.normalize_domain(item.get("domain"))
            if not domain:
                continue
            restored.append(modules.DomainInfo(
                domain=domain,
                record=item.get("record") or [],
                type=item.get("type") or "CNAME",
                ips=item.get("ips") or [],
            ))
            sources = item.get("sources")
            if not isinstance(sources, list):
                sources = [item.get("source", "")]
            source_map[domain] = {
                str(source or "").strip()
                for source in sources
                if str(source or "").strip()
            }

        self.domain_info_list = restored
        self.domain_source_map.update(source_map)
        logger.info(
            "restore domain info for deep scan task_id:{} count:{}".format(
                self.task_id, len(restored)
            )
        )
        return len(restored)

    def _seed_base_domain(self):
        """先落库用户目标，避免字典爆破或 provider 阻塞首批结果。"""
        base_domain_info = self.build_single_domain_info(self.base_domain)
        if not base_domain_info:
            return 0
        if base_domain_info not in self.domain_info_list:
            self.domain_info_list.append(base_domain_info)
        self.add_domain_source_map([base_domain_info], CollectSource.DOMAIN_BRUTE)
        if self.task_tag == "task":
            self.save_domain_info_list([base_domain_info], source=CollectSource.DOMAIN_BRUTE)
        return 1

    def _run_discovery_preview(self):
        """为渐进式任务快速落库基础 IP/站点，不改变深度扫描范围。"""
        started_at = time.time()
        preview_ip_count = 0
        preview_site_count = 0
        try:
            self.gen_ipv4_map()
            preview_ip_count = len(self.ipv4_map)
            self.save_ip_info()

            preview_sites = services.probe_http(self.domain_info_list)
            preview_sites = list(
                dict.fromkeys(
                    str(site).strip()
                    for site in preview_sites
                    if str(site).strip()
                )
            )
            if preview_sites:
                preview_fetch = WebSiteFetch(
                    task_id=self.task_id,
                    sites=preview_sites,
                    options=self.options,
                    scope_domain=[self.base_domain],
                )
                preview_fetch.fetch_site()
                preview_fetch.save_site_info()
                preview_site_count = len(preview_fetch.site_info_list)
            self.update_services("discovery_preview", time.time() - started_at)
            logger.info(
                "discovery preview task_id:{} ips:{} sites:{} elapsed:{:.2f}s".format(
                    self.task_id,
                    preview_ip_count,
                    preview_site_count,
                    time.time() - started_at,
                )
            )
        except Exception as exc:
            # 预览失败不阻断后续完整深度链路，但必须留下 degraded 证据。
            logger.warning(
                "discovery preview degraded task_id:{} ips:{} sites:{} error:{}".format(
                    self.task_id, preview_ip_count, preview_site_count, exc
                )
            )
            self.update_services("discovery_preview_degraded", time.time() - started_at)

    def run_discovery(self, include_preview=False):
        """先完成可快速落库的基础发现，深度枚举由后续队列继续。"""
        return DomainTaskOrchestrator(self).run_discovery(include_preview=include_preview)

    def run_deep(self):
        """执行可恢复的深度阶段；可由新的 Celery 消息独立运行。"""
        return DomainTaskOrchestrator(self).run_deep()

    def run(self):
        return DomainTaskOrchestrator(self).run()


def domain_task(base_domain, task_id, options):
    d = DomainTask(base_domain=base_domain, task_id=task_id, options=options)
    try:
        d.run()
    except Exception as e:
        logger.error("domain task failed task_id:{} error:{}".format(task_id, safe_error_text(e)))
        utils.append_task_error(
            task_id=task_id,
            error=e,
            stage="domain_task",
            traceback_text=traceback.format_exc(),
        )


def domain_discovery_task(base_domain, task_id, options):
    """渐进式任务的发现阶段；成功后由 Celery 继续投递深度阶段。"""
    d = DomainTask(base_domain=base_domain, task_id=task_id, options=options)
    try:
        d.run_discovery(include_preview=True)
        d.update_task_field("status", "deep_scan_pending")
        return True
    except Exception as e:
        logger.error("domain discovery task failed task_id:{} error:{}".format(task_id, safe_error_text(e)))
        utils.append_task_error(
            task_id=task_id,
            error=e,
            stage="domain_discovery",
            traceback_text=traceback.format_exc(),
        )
        return False


def domain_deep_task(base_domain, task_id, options):
    """渐进式任务的深度阶段；只恢复已落库发现结果，不重复发现。"""
    d = DomainTask(base_domain=base_domain, task_id=task_id, options=options)
    try:
        d.run_deep()
        return True
    except Exception as e:
        logger.error("domain deep task failed task_id:{} error:{}".format(task_id, safe_error_text(e)))
        utils.append_task_error(
            task_id=task_id,
            error=e,
            stage="domain_deep",
            traceback_text=traceback.format_exc(),
        )
        return False
