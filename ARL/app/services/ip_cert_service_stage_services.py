"""IP 任务证书采集与服务汇总的可恢复 stage service。

功能说明：
- IPCertStageService：HTTPS 端口证书采集、SNI/default 去重与 cert 表幂等落库
- IPServiceSummaryStageService：nmap/NPoC 服务识别结果合并并按任务重建 service 表

这里保留 Python 对网络、Mongo 的控制，只把具体实现从任务类移出；
IPTask 仍通过同名方法提供兼容入口。
"""

from app import utils
from app.services import fetchCert


def fetch_cert_map(ip_info_list):
    """
    批量获取SSL证书信息

    参数：
        ip_info_list: IP信息列表或 IP:Port 集合

    返回：
        dict: IP:Port -> 证书信息的映射

    说明：
    - 遍历所有IP的开放端口
    - 跳过80端口（HTTP不使用SSL）
    - 批量获取HTTPS服务的SSL证书
    - 用于发现证书关联的域名和组织信息
    """
    logger = utils.get_logger()
    try:
        f = fetchCert.SSLCert(ip_info_list)
        return f.run()
    except Exception as e:
        logger.exception(e)

    return {}


class IPCertStageService(object):
    """执行 SSL 证书采集并写回 cert collection。"""

    def __init__(self, task, fetchcert_module=None, utils_module=None, cert_fetcher=None):
        self.task = task
        self.fetchcert = fetchcert_module or fetchCert
        self.utils = utils_module or utils
        self.cert_fetcher = cert_fetcher or fetch_cert_map

    def run(self):
        task = self.task
        if task.options.get("port_scan"):
            task.cert_map = self.cert_fetcher(task.ip_info_list)
        else:
            task.cert_map = self.cert_fetcher(task.ip_set)

        # 同一 endpoint 若已经命中 SNI 证书，则 default 结果仅作兜底不再入库，
        # 避免 CDN 场景下"默认证书"干扰识别。
        sni_success_endpoints = set()
        for target in task.cert_map:
            cert_obj = task.cert_map.get(target, {})
            if not isinstance(cert_obj, dict):
                continue

            cert_data = dict(cert_obj)
            scan_meta = cert_data.pop("_scan_meta", {})
            if not isinstance(scan_meta, dict):
                scan_meta = {}

            endpoint = str(scan_meta.get("endpoint", "")).strip() or str(target).strip()
            ip, port = self.fetchcert.split_host_port(endpoint)
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

            domains = self.fetchcert.normalize_domains(scan_meta.get("domains", []))
            if sni_domain not in domains:
                domains = self.fetchcert.normalize_domains(domains + [sni_domain])

            matched_domains = self.fetchcert.match_cert_domains(cert_data, domains)
            if domains and not matched_domains:
                continue
            if matched_domains and sni_domain not in matched_domains:
                continue

            sni_success_endpoints.add(endpoint)

        # 保存证书信息到数据库
        for target in task.cert_map:
            cert_obj = task.cert_map.get(target, {})
            if not isinstance(cert_obj, dict):
                continue

            cert_data = dict(cert_obj)
            scan_meta = cert_data.pop("_scan_meta", {})
            if not isinstance(scan_meta, dict):
                scan_meta = {}

            endpoint = str(scan_meta.get("endpoint", "")).strip() or str(target).strip()
            ip, port = self.fetchcert.split_host_port(endpoint)
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

            domains = self.fetchcert.normalize_domains(scan_meta.get("domains", []))
            if sni_domain and sni_domain not in domains:
                domains = self.fetchcert.normalize_domains(domains + [sni_domain])

            matched_domains = self.fetchcert.match_cert_domains(cert_data, domains)
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
                "task_id": task.task_id,
            }

            query = {
                "task_id": task.task_id,
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

            self.utils.conn_db("cert").update_one(query, {"$setOnInsert": item}, upsert=True)

        return task.cert_map


class IPServiceSummaryStageService(object):
    """合并 nmap/NPoC 服务识别结果并按任务重建 service 表。"""

    def __init__(self, task, utils_module=None):
        self.task = task
        self.utils = utils_module or utils

    def run(self):
        task = self.task
        logger = utils.get_logger()
        task.service_info_list = []
        service_map = {}
        service_seen = set()
        port_total = 0
        merged_total = 0
        nmap_merged = 0
        npoc_merged = 0

        def _append_item(service_name, ip, port_id, product="", version="", source="",
                         confidence=None, sources=None, conflict=None):
            nonlocal merged_total, nmap_merged, npoc_merged
            raw_name = task._extract_detected_service(
                service_name=service_name,
                product=product,
            )
            service = task._normalize_scheme(raw_name)
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
            doc = {
                "ip": ip,
                "port_id": port_id,
                "product": normalized_product,
                "version": str(version or "").strip(),
            }
            # 计划5 第5阶段增量观测字段（附加式，不改既有字段语义）
            if confidence is not None:
                doc["service_confidence"] = confidence
            if sources:
                doc["service_sources"] = list(sources)
            if conflict:
                doc["service_conflict"] = conflict
            service_map[service].append(doc)
            merged_total += 1
            if source == "nmap":
                nmap_merged += 1
            elif source == "npoc":
                npoc_merged += 1

        # 1) nmap 结果（已被 npoc 回填增强）
        for ip_item in task.ip_info_list:
            for port_item in ip_item.get("port_info", []):
                port_total += 1
                _append_item(
                    service_name=port_item.get("service_name", ""),
                    ip=ip_item.get("ip", ""),
                    port_id=port_item.get("port_id", None),
                    product=port_item.get("product", ""),
                    version=port_item.get("version", ""),
                    source="nmap",
                    confidence=port_item.get("service_confidence"),
                    sources=port_item.get("service_sources"),
                    conflict=port_item.get("service_conflict"),
                )

        # 2) npoc 明细补充（用于兜底合并来源）
        for item in self.utils.conn_db("npoc_service").find({"task_id": task.task_id}):
            _append_item(
                service_name=item.get("scheme", ""),
                ip=item.get("host", ""),
                port_id=item.get("port", None),
                product=item.get("scheme", ""),
                version=item.get("version", ""),
                source="npoc",
            )

        for service_name, info_list in service_map.items():
            task.service_info_list.append({
                "service_name": service_name,
                "service_info": info_list,
                "task_id": task.task_id,
            })

        # 同任务重跑时先清理旧数据，避免重复堆积
        self.utils.conn_db("service").delete_many({"task_id": task.task_id})
        if task.service_info_list:
            self.utils.conn_db("service").insert_many(task.service_info_list)

        logger.info(
            "save_service_info task_id:{} ports:{} merged:{} nmap:{} npoc:{} service_group:{}".format(
                task.task_id, port_total, merged_total, nmap_merged, npoc_merged, len(task.service_info_list)
            )
        )
