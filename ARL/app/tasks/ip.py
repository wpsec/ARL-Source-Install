"""
IP扫描任务执行模块

功能说明：
- IP扫描任务的核心执行逻辑
- 负责IP资产的发现、端口探测和服务识别

主要功能：
1. 端口扫描：支持多种扫描模式（测试、Top100、Top1000、全端口、自定义）
2. 服务识别：识别开放端口上运行的服务及版本
3. 操作系统识别：识别目标主机的操作系统类型
4. 站点探测：探测HTTP/HTTPS服务
5. SSL证书获取：获取HTTPS服务的SSL证书信息
6. 风险巡航：针对发现的服务进行安全检测
7. PoC扫描：使用漏洞验证插件进行检测

主要类：
- IPTask: IP扫描任务主类
- IPExecutor: IP任务执行器

执行流程：
1. 端口扫描 -> 2. 服务识别 -> 3. 站点探测 -> 4. SSL证书 -> 5. PoC扫描 -> 6. 数据保存
"""
from bson.objectid import  ObjectId
import time
import traceback
from app import services
from app.modules import ScanPortType, TaskStatus
from app.services import fetchCert, run_risk_cruising, run_sniffer
from app import utils
from app.services.commonTask import CommonTask, BaseUpdateTask, WebSiteFetch
from app.config import Config
from app.helpers.message_notify import push_task_finish_notify


logger = utils.get_logger()


def ssl_cert(ip_info_list):
    """
    批量获取SSL证书信息
    
    参数：
        ip_info_list: IP信息列表
    
    返回：
        dict: IP:Port -> 证书信息的映射
    
    说明：
    - 遍历所有IP的开放端口
    - 跳过80端口（HTTP不使用SSL）
    - 批量获取HTTPS服务的SSL证书
    - 用于发现证书关联的域名和组织信息
    """
    try:
        f = fetchCert.SSLCert(ip_info_list)
        return f.run()
    except Exception as e:
        logger.exception(e)

    return {}


class IPTask(CommonTask):
    """
    IP扫描任务类
    
    功能说明：
    - 执行完整的IP扫描流程
    - 支持任务模式和监控模式
    
    主要属性：
    - ip_target: 扫描目标（IP或IP段，空格分隔）
    - task_id: 任务ID
    - options: 扫描选项配置
    - ip_info_list: IP信息列表
    - site_list: 站点列表
    - cert_map: 证书信息映射
    - task_tag: 任务标签（task/monitor）
    
    主要方法：
    - port_scan(): 端口扫描
    - find_site(): 站点探测
    - ssl_cert(): SSL证书获取
    - run_risk_cruising(): 风险巡航
    - run_poc_service(): PoC扫描
    """
    
    def __init__(self, ip_target=None, task_id=None, options=None):
        """
        初始化IP扫描任务
        
        参数：
            ip_target: 扫描目标IP（空格分隔的IP或IP段）
            task_id: 任务ID
            options: 扫描选项配置
        """
        super().__init__(task_id=task_id)

        self.ip_target = ip_target
        self.task_id = task_id
        self.options = options
        self.ip_info_list = []  # IP信息列表
        self.ip_set = set()  # IP集合（去重）
        self.site_list = []  # 站点列表
        self.cert_map = {}  # 证书映射
        self.service_info_list = []  # 服务信息列表
        self.npoc_service_target_set = set()  # PoC目标集合
        # 用来区分是正常任务还是监控任务
        self.task_tag = "task"

        self.scope_id = None  # 资产组ID（监控任务使用）
        self.task_name = None  # 任务名称
        self.asset_ip_port_set = set()  # 资产IP端口集合
        self.asset_ip_info_map = dict()  # 资产IP信息映射
        self.base_update_task = BaseUpdateTask(self.task_id)

    @staticmethod
    def _is_low_conf_service(port_info):
        """
        判断端口服务识别是否低置信度。
        低置信度端口优先走协议识别（sniffer）。
        """
        service_name = str(port_info.get("service_name", "")).strip().lower()
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
            ip = str(ip_info.get("ip", "")).strip()
            if not ip:
                continue

            for port_info in ip_info.get("port_info", []):
                port_id = port_info.get("port_id")
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
            ip = str(ip_info.get("ip", "")).strip()
            if not ip:
                continue

            for port_info in ip_info.get("port_info", []):
                port_id = port_info.get("port_id")
                if port_id is None:
                    continue

                key = "{}:{}".format(ip, port_id)
                if key not in scheme_map:
                    continue

                scheme = scheme_map[key]
                curr_service = str(port_info.get("service_name", "")).strip().lower()
                # 服务识别以 sniffer 为准，nmap 结果作为回退
                if curr_service != scheme:
                    updated += 1
                port_info["service_name"] = scheme
                if not str(port_info.get("product", "")).strip() or self._is_low_conf_service(port_info):
                    port_info["product"] = scheme

        return updated

    def set_asset_ip(self):
        """
        获取资产组中的IP信息
        
        说明：
        - 仅在监控模式下使用
        - 从asset_ip表获取已有IP信息
        - 用于增量更新资产数据
        """
        raise NotImplementedError()

    def async_ip_info(self):
        """
        同步IP信息到资产组
        
        说明：
        - 仅在监控模式下使用
        - 同步新发现的IP和端口
        - 更新资产组数据
        """
        raise NotImplementedError()

    def port_scan(self):
        """
        执行端口扫描
        
        说明：
        - 支持多种扫描模式：
          * test: 测试模式（少量常用端口）
          * top100: Top100端口
          * top1000: Top1000端口
          * all: 全端口扫描（1-65535）
          * custom: 自定义端口
        - 支持服务识别和操作系统识别
        - 支持自定义扫描参数（并行度、速率、超时）
        - 自动识别IP类型（公网/内网）
        - 获取IP地理位置和ASN信息
        """
        # 端口扫描模式映射
        scan_port_map = {
            "test": ScanPortType.TEST,
            "top100": ScanPortType.TOP100,
            "top1000": ScanPortType.TOP1000,
            "all": ScanPortType.ALL,
            "custom": self.options.get("port_custom", "80,443")
        }
        
        option_scan_port_type = self.options.get("port_scan_type", "test")
        
        # 构建扫描选项
        scan_port_option = {
            "ports": scan_port_map.get(option_scan_port_type, ScanPortType.TEST),
            # 开启 service_detection 时启用 nmap -sV，用于补充产品/版本信息。
            # 协议识别仍由 npoc(sniffer) 做二次增强。
            "service_detect": bool(self.options.get("service_detection")),
            "os_detect": self.options.get("os_detection", False),  # 操作系统识别
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

        # 解析目标IP列表
        targets = self.ip_target.split()
        
        # 执行端口扫描
        ip_port_result = services.port_scan(targets, **scan_port_option)
        self.ip_info_list.extend(ip_port_result)

        # 监控模式：获取资产组现有IP
        if self.task_tag == 'monitor':
            self.set_asset_ip()

        # 处理扫描结果
        for ip_info in ip_port_result:
            curr_ip = ip_info["ip"]
            self.ip_set.add(curr_ip)
            
            # 检查IP黑名单
            if not utils.not_in_black_ips(curr_ip):
                continue

            # 添加基础信息
            ip_info["task_id"] = self.task_id
            ip_info["ip_type"] = utils.get_ip_type(curr_ip)
            ip_info["geo_asn"] = {}
            ip_info["geo_city"] = {}

            # 公网IP获取地理位置和ASN信息
            if ip_info["ip_type"] == "PUBLIC":
                ip_info["geo_asn"] = utils.get_ip_asn(curr_ip)
                ip_info["geo_city"] = utils.get_ip_city(curr_ip)

            # 任务模式：保存IP信息到数据库
            if self.task_tag == 'task':
                utils.conn_db('ip').insert_one(ip_info)

        # 监控模式：同步IP信息到资产组
        if self.task_tag == 'monitor':
            self.async_ip_info()

    def find_site(self):
        """
        探测HTTP/HTTPS站点
        
        说明：
        - 遍历所有开放端口
        - 构建可能的URL列表
        - 批量探测站点可访问性
        - 获取站点标题、服务器等信息
        """
        url_temp_list = []
        for ip_info in self.ip_info_list:
            for port_info in ip_info["port_info"]:
                curr_ip = ip_info["ip"]

                port_id = port_info["port_id"]
                # 80端口默认HTTP
                if port_id == 80:
                    url_temp = "http://{}".format(curr_ip)
                    url_temp_list.append(url_temp)
                    continue

                # 443端口默认HTTPS
                if port_id == 443:
                    url_temp = "https://{}".format(curr_ip)
                    url_temp_list.append(url_temp)
                    continue

                # 其他端口同时尝试HTTP和HTTPS
                url_temp1 = "http://{}:{}".format(curr_ip, port_id)
                url_temp2 = "https://{}:{}".format(curr_ip, port_id)
                url_temp_list.append(url_temp1)
                url_temp_list.append(url_temp2)

        # 批量检测URL可访问性
        check_map = services.check_http(url_temp_list)

        # 去除https和http相同的，优先保留HTTPS
        alive_site = []
        for x in check_map:
            if x.startswith("https://"):
                alive_site.append(x)

            elif x.startswith("http://"):
                x_temp = "https://" + x[7:]
                if x_temp not in check_map:
                    alive_site.append(x)

        self.site_list.extend(alive_site)

    def ssl_cert(self):
        """
        获取SSL证书信息
        
        说明：
        - 为所有HTTPS服务获取SSL证书
        - 证书信息用于发现域名、组织信息
        - 保存到cert表供后续分析
        """
        if self.options.get("port_scan"):
            self.cert_map = ssl_cert(self.ip_info_list)
        else:
            self.cert_map = ssl_cert(self.ip_set)

        # 同一 endpoint 若已经命中 SNI 证书，则 default 结果仅作兜底不再入库，
        # 避免 CDN 场景下“默认证书”干扰识别。
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

            sni_domain = str(scan_meta.get("sni_domain", "")).strip().lower()
            legacy_server_name = str(scan_meta.get("server_name", "")).strip().lower()
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

        # 保存证书信息到数据库
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

            sni_domain = str(scan_meta.get("sni_domain", "")).strip().lower()
            legacy_server_name = str(scan_meta.get("server_name", "")).strip().lower()
            if not sni_domain and scan_mode == "sni":
                sni_domain = legacy_server_name

            domains = fetchCert.normalize_domains(scan_meta.get("domains", []))
            if sni_domain and sni_domain not in domains:
                domains = fetchCert.normalize_domains(domains + [sni_domain])

            matched_domains = fetchCert.match_cert_domains(cert_data, domains)
            # IP任务在存在域名上下文时，仅保留命中证书域名的记录，避免无关默认证书干扰。
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

    def save_service_info(self):
        """
        保存服务识别信息
        
        说明：
        - 整理所有识别到的服务信息
        - 按服务名称分组
        - 记录每个服务的IP、端口、产品、版本
        - 保存到service表
        """
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
            for port_item in ip_item.get("port_info", []):
                port_total += 1
                _append_item(
                    service_name=port_item.get("service_name", ""),
                    ip=ip_item.get("ip", ""),
                    port_id=port_item.get("port_id", None),
                    product=port_item.get("product", ""),
                    version=port_item.get("version", ""),
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

    def npoc_service_detection(self, full_port=False):
        """
        NPoc服务识别
        
        说明：
        - 使用Python实现的服务识别（sniffer）
        - 对非常见端口进行协议识别
        - 跳过80、443、843等已知端口
        - 识别结果保存到npoc_service表
        - 识别出的服务可用于后续PoC扫描
        """
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

        # 运行服务识别
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

    def brute_config(self):
        """
        弱口令爆破
        
        说明：
        - 根据配置对发现的服务进行弱口令爆破
        - 支持多种服务：SSH、FTP、MySQL、Redis等
        - 使用风险巡航（risk_cruising）框架执行
        - 爆破成功的结果保存到vuln表
        """
        plugins = []
        brute_config = self.options.get("brute_config")
        # 收集启用的插件
        for x in brute_config:
            if not x.get("enable"):
                continue
            plugins.append(x["plugin_name"])

        if not plugins:
            return
        
        # 构建目标列表（站点+服务）
        targets = self.site_list.copy()
        targets += list(self.npoc_service_target_set)
        
        # 执行风险巡航
        result = run_risk_cruising(targets=targets, plugins=plugins)
        for item in result:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db('vuln').insert_one(item)

    def run(self):
        """
        执行IP扫描任务主流程
        
        执行顺序：
        1. 端口扫描 -> 发现开放端口
        2. 服务识别 -> 识别服务类型和版本
        3. SSL证书获取 -> 获取HTTPS证书
        4. 站点探测 -> 发现Web服务
        5. Web信息采集 -> 获取站点详细信息
        6. NPoc服务识别 -> Python实现的服务识别
        7. PoC扫描 -> 漏洞验证
        8. 弱口令爆破 -> 常见服务爆破
        9. 统计信息 -> 生成指纹、C段统计
        10. 资产同步 -> 同步到资产组
        
        说明：
        - 每个步骤可通过options配置开关
        - 每个步骤记录执行时间
        - 更新任务状态供前端展示
        """
        base_update = self.base_update_task
        base_update.update_task_field("start_time", utils.curr_date())
        
        '''***端口扫描开始***'''
        if self.options.get("port_scan"):
            base_update.update_task_field("status", "port_scan")
            t1 = time.time()
            self.port_scan()
            elapse = time.time() - t1
            base_update.update_services("port_scan", elapse)

        '''***证书获取开始***'''
        if self.options.get("ssl_cert"):
            base_update.update_task_field("status", "ssl_cert")
            t1 = time.time()
            self.ssl_cert()
            elapse = time.time() - t1
            base_update.update_services("ssl_cert", elapse)

        # 站点探测
        base_update.update_task_field("status", "find_site")
        t1 = time.time()
        self.find_site()
        elapse = time.time() - t1
        base_update.update_services("find_site", elapse)

        # Web信息采集（标题、指纹、截图等）
        web_site_fetch = WebSiteFetch(task_id=self.task_id,
                                      sites=self.site_list,
                                      options=self.options)
        web_site_fetch.run()

        """服务识别（Python实现）"""
        if self._enable_protocol_detection():
            base_update.update_task_field("status", "npoc_service_detection")
            t1 = time.time()
            # 兼容历史开关：
            # - npoc_service_detection=True: 全端口模式
            # - service_detection=True: 智能模式（只扫低置信度端口）
            self.npoc_service_detection(
                full_port=bool(self.options.get("npoc_service_detection"))
            )
            elapse = time.time() - t1
            base_update.update_services("npoc_service_detection", elapse)

        # 存储服务信息（放到协议识别之后，优先保留更高质量的服务名）
        # 端口扫描已包含基础服务名（nmap service map），即使未开启 -sV / npoc 也应落库。
        if self.options.get("port_scan") or self.options.get("service_detection") or self.options.get("npoc_service_detection"):
            self.save_service_info()

        """ *** NPoc 调用（PoC扫描） """
        if self.options.get("poc_config"):
            base_update.update_task_field("status", "poc_run")
            t1 = time.time()
            web_site_fetch.risk_cruising(self.npoc_service_target_set)
            elapse = time.time() - t1
            base_update.update_services("poc_run", elapse)

        """弱口令爆破服务"""
        if self.options.get("brute_config"):
            base_update.update_task_field("status", "weak_brute")
            t1 = time.time()
            self.brute_config()
            elapse = time.time() - t1
            base_update.update_services("weak_brute", elapse)

        # 加上统计信息
        self.insert_finger_stat()  # 指纹统计
        self.insert_cip_stat()  # C段统计
        self.insert_task_stat()  # 任务统计

        # 如果有关联的资产分组就进行同步
        if self.task_tag == "task":
            self.sync_asset()

        base_update.update_task_field("status", TaskStatus.DONE)
        base_update.update_task_field("end_time", utils.curr_date())
        push_task_finish_notify(self.task_id)


def ip_task(ip_target, task_id, options):
    """
    IP任务入口函数
    
    参数：
        ip_target: 扫描目标（空格分隔的IP或IP段）
        task_id: 任务ID
        options: 扫描选项配置
    
    说明：
    - 创建IPTask实例并执行
    - 捕获异常，标记任务状态为error
    - 被Celery调用执行异步任务
    """
    d = IPTask(ip_target=ip_target, task_id=task_id, options=options)
    try:
        d.run()
    except Exception as e:
        logger.exception(e)
        utils.append_task_error(
            task_id=task_id,
            error=e,
            stage="ip_task",
            traceback_text=traceback.format_exc(),
        )
