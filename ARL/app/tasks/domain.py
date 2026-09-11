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
from app.services import fetchCert, BaseUpdateTask
from app.services.service_detection import (
    apply_npoc_service_result,
    build_sniffer_targets,
    extract_detected_service,
    is_low_conf_service,
    normalize_scheme,
)
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
from app.services.dns_query import run_query_plugin, run_query_plugin_by_ip, run_query_plugin_by_cert
from app.utils.log_safety import safe_error_text
from app.services.domainSiteUpdate import domain_site_update
from app.repositories import DomainRepository
from app.services.task_orchestrator import DomainTaskOrchestrator
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
        return is_low_conf_service(port_info)

    @staticmethod
    def _normalize_scheme(value):
        return normalize_scheme(value, use_registry=True)

    @staticmethod
    def _extract_detected_service(service_name, product=""):
        return extract_detected_service(service_name, product)

    def _enable_protocol_detection(self):
        """
        兼容历史选项：
        - service_detection：启用服务识别增强（nmap -sV + sniffer）
        - npoc_service_detection：历史开关，继续兼容
        """
        return bool(self.options.get("service_detection") or self.options.get("npoc_service_detection"))

    def _build_sniffer_targets(self, full_port=False):
        return build_sniffer_targets(self, full_port=full_port)

    def _apply_npoc_service_result(self, sniffer_items):
        return apply_npoc_service_result(self, sniffer_items, use_registry=True)

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
        return DomainDiscoveryStageService(self).clear_domain_info_by_record(domain_info_list)

    def arl_search(self):
        return DomainDiscoveryStageService(self).run_arl_search()

    def build_domain_info(self, domains):
        return DomainDiscoveryStageService(self).build_domain_info(domains)

    def alt_dns_current(self):
        return DomainDiscoveryStageService(self).run_alt_dns_current()

    def alt_dns(self):
        return DomainDiscoveryStageService(self).run_alt_dns()

    def port_scan(self):
        return DomainNetworkStageService(self).run_port_scan()

    def find_site(self):
        return DomainSiteStageService(self).run_find_site()

    def update_services(self, service_name, elapsed, metrics=None):
        self.base_update_task.update_services(
            service_name=service_name,
            elapsed=elapsed,
            metrics=metrics,
        )

    def update_task_field(self, field=None, value=None):
        self.base_update_task.update_task_field(field=field, value=value)

    def gen_ipv4_map(self):
        return DomainNetworkStageService(self).run_gen_ipv4_map()

    def save_ip_info(self):
        return DomainNetworkStageService(self).run_save_ip_info()

    def save_service_info(self):
        return DomainNetworkStageService(self).run_save_service_info()

    def ssl_cert(self):
        return DomainNetworkStageService(self).run_ssl_cert()

    def _legacy_ssl_cert(self):
        """历史私有入口保留兼容性，证书阶段由 DomainNetworkStageService 持有。"""
        return self.ssl_cert()
    def build_single_domain_info(self, domain):
        return DomainDiscoveryStageService(self).build_single_domain_info(domain)

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
        return DomainNetworkStageService(self).get_ip_pivot_candidates()

    def ip_query_plugin_enhance(self):
        return DomainNetworkStageService(self).run_ip_query_plugin_enhance()

    def get_scope_domain_list(self):
        return DomainNetworkStageService(self).get_scope_domain_list()

    def normalize_cert_domain(self, value):
        return DomainNetworkStageService.normalize_cert_domain(value)

    def extract_cert_domain_candidates(self, cert_obj):
        return DomainNetworkStageService(self).extract_cert_domain_candidates(cert_obj)

    def match_cert_scope_domains(self, cert_obj):
        return DomainNetworkStageService(self).match_cert_scope_domains(cert_obj)

    def build_cert_pivot_key(self, cert_obj):
        return DomainNetworkStageService.build_cert_pivot_key(cert_obj)

    def get_cert_pivot_candidates(self):
        return DomainNetworkStageService(self).get_cert_pivot_candidates()

    def incremental_port_scan_for_new_ips(self):
        return DomainNetworkStageService(self).run_incremental_port_scan_for_new_ips()

    def sync_ip_domain_from_ipv4_map(self):
        return DomainNetworkStageService(self).run_sync_ip_domain_from_ipv4_map()

    def cert_query_plugin_enhance(self):
        return DomainNetworkStageService(self).run_cert_query_plugin_enhance()

    def asset_pivot_round(self):
        return DomainNetworkStageService(self).run_asset_pivot_round()

    def domain_fetch(self):
        return DomainDiscoveryStageService(self).run()

    def start_ip_fetch(self):
        return DomainNetworkStageService(self).run()

    def start_site_fetch(self):
        return DomainSiteStageService(self).run()

    def npoc_service_detection(self, full_port=False):
        return DomainPostProcessStageService(self).run_npoc_service_detection(
            full_port=full_port
        )

    def start_poc_run(self):
        return DomainPostProcessStageService(self).run_poc()

    def brute_config(self):
        return DomainPostProcessStageService(self).run_brute_config()

    def find_vhost_vuln(self):
        return DomainPostProcessStageService(self).run_find_vhost_vuln()

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
        return DomainDiscoveryStageService(self).run_load_saved_domain_info()

    def _seed_base_domain(self):
        return DomainDiscoveryStageService(self).run_seed_base_domain()

    def _run_discovery_preview(self):
        return DomainDiscoveryStageService(self).run_discovery_preview()

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
