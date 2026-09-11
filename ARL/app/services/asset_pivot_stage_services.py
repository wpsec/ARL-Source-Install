"""资产候选关联和 IP 任务闭环阶段。

该模块只承载跨来源的候选校验、证据写入和 IP 任务扩展；域名任务仍由
DomainNetworkStageService 保持原有阶段入口，避免改变历史编排契约。
"""

import hashlib
import socket
from collections import defaultdict

from app import utils
from app.config import Config
from app.services.dns_query import run_query_plugin_by_cert, run_query_plugin_by_ip
from app.services.task_result_write_service import TaskResultWriteService
from app.utils.log_safety import safe_error_text


logger = utils.get_logger()


def _read_field(value, name, default=None):
    """兼容 IP 扫描结果的字典结构和域名任务的模型对象。"""
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _write_field(value, name, content):
    """保持结果容器原有类型，避免跨任务改写公共模型。"""
    if isinstance(value, dict):
        value[name] = content
    else:
        setattr(value, name, content)


def domain_log_summary(domain):
    """日志只保留不可逆摘要，避免把候选域名写入运行日志。"""
    value = str(domain or "").strip().lower()
    if not value:
        return "-"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def normalize_ip_set(values):
    """把 provider/DNS 的地址结果收敛为可比较的字符串集合。"""
    result = set()
    for value in values or []:
        text = str(value or "").strip().strip("[]").rstrip(".")
        if text and utils.is_vaild_ip_target(text):
            result.add(text)
    return result


def is_public_suffix(domain):
    """过滤没有可注册主体的公共后缀，避免生成无界爆破根。"""
    normalized = utils.normalize_domain(domain)
    if not normalized:
        return False
    parsed = utils.domain_parsed(normalized)
    if parsed and parsed.get("domain") == normalized:
        return True
    labels = normalized.split(".")
    if len(labels) != 2:
        return False
    public_second_level = {
        "ac", "co", "com", "edu", "gov", "mil", "net", "org",
    }
    country_tlds = {
        "au", "br", "cn", "hk", "in", "jp", "kr", "nz", "sg",
        "tr", "tw", "uk", "za",
    }
    return labels[0] in public_second_level and labels[1] in country_tlds


def resolve_domain_ips(domain, resolver=None):
    """解析 A/AAAA，并返回最终地址；resolver 便于离线测试注入。"""
    normalized = utils.normalize_domain(domain)
    if not normalized or not utils.is_valid_domain(normalized):
        return set(), "invalid_domain"

    if resolver is not None:
        try:
            return normalize_ip_set(resolver(normalized)), "resolved"
        except Exception as exc:
            logger.warning(
                "asset pivot dns failed domain_hash:{} error:{}".format(
                    domain_log_summary(normalized), safe_error_text(exc)
                )
            )
            return set(), "dns_error"

    try:
        records = socket.getaddrinfo(
            normalized,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
        addresses = {item[4][0] for item in records if item[4]}
        return normalize_ip_set(addresses), "resolved"
    except socket.gaierror:
        return set(), "no_a_aaaa"
    except Exception as exc:
        logger.warning(
            "asset pivot dns failed domain_hash:{} error:{}".format(
                domain_log_summary(normalized), safe_error_text(exc)
            )
        )
        return set(), "dns_error"


def is_scope_domain(domain, scopes=None):
    normalized = utils.normalize_domain(domain)
    if not normalized or not utils.is_valid_domain(normalized):
        return False
    scope_list = [utils.normalize_domain(item) for item in (scopes or [])]
    scope_list = [item for item in scope_list if item]
    if not scope_list:
        return True
    return any(utils.is_in_scope(normalized, item) for item in scope_list)


def validate_domain_binding(
    domain,
    pivot_ips=None,
    scopes=None,
    resolver=None,
    require_ip_match=True,
):
    """判断候选域名是否可以进入主动扫描。

    DNS 暂时失败返回 degraded，避免把一次性 DNS 故障误判为无效资产。
    """
    raw_domain = str(domain or "").strip().lower()
    normalized = utils.normalize_domain(domain)
    pivot_set = normalize_ip_set(pivot_ips)
    if (
        not normalized
        or not utils.is_valid_domain(normalized)
        or is_public_suffix(normalized)
        or raw_domain.startswith("*.")
        or "{fuzz}" in raw_domain
    ):
        return {
            "domain": normalized,
            "status": "rejected",
            "reason": "invalid_domain",
            "resolved_ips": [],
            "matched_ips": [],
        }
    if not is_scope_domain(normalized, scopes):
        return {
            "domain": normalized,
            "status": "rejected",
            "reason": "out_of_scope",
            "resolved_ips": [],
            "matched_ips": [],
        }

    resolved_ips, dns_status = resolve_domain_ips(normalized, resolver=resolver)
    matched_ips = sorted(resolved_ips & pivot_set)
    if dns_status in {"dns_error", "no_a_aaaa"}:
        return {
            "domain": normalized,
            "status": "degraded",
            "reason": dns_status,
            "resolved_ips": sorted(resolved_ips),
            "matched_ips": matched_ips,
        }
    if require_ip_match and not matched_ips:
        return {
            "domain": normalized,
            "status": "evidence_only",
            "reason": "dns_not_match_pivot_ip",
            "resolved_ips": sorted(resolved_ips),
            "matched_ips": [],
        }
    return {
        "domain": normalized,
        "status": "accepted",
        "reason": "dns_match_pivot_ip" if pivot_set else "dns_resolved",
        "resolved_ips": sorted(resolved_ips),
        "matched_ips": matched_ips,
    }


def certificate_identity(cert_obj):
    """生成不包含完整证书正文的稳定证书键。"""
    if not isinstance(cert_obj, dict):
        return ""
    serial = str(cert_obj.get("serial_number") or "").strip()
    fingerprint = cert_obj.get("fingerprint") or {}
    sha1 = ""
    if isinstance(fingerprint, dict):
        sha1 = str(fingerprint.get("sha1") or "").strip().lower()
    if serial and sha1:
        return "{}|{}".format(serial, sha1)
    if serial:
        return "sn:{}".format(serial)
    if sha1:
        return "sha1:{}".format(sha1)
    return ""


def extract_certificate_domains(cert_obj):
    """提取 CN/SAN 中可校验的域名，不把泛域名直接变成扫描目标。"""
    if not isinstance(cert_obj, dict):
        return []
    values = []
    subject = cert_obj.get("subject") or {}
    common_name = subject.get("common_name")
    if common_name:
        values.append(common_name)
    extensions = cert_obj.get("extensions") or {}
    san_text = str(extensions.get("subjectAltName") or "").strip()
    for item in san_text.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            prefix, item = item.split(":", 1)
            if prefix.strip().lower() != "dns":
                continue
        values.append(item)

    result = set()
    for value in values:
        raw_value = str(value or "").strip()
        if raw_value.startswith("*.") or "{fuzz}" in raw_value:
            continue
        normalized = utils.normalize_domain(raw_value)
        if normalized and utils.is_valid_domain(normalized) and not is_public_suffix(normalized):
            result.add(normalized)
    return sorted(result)


def endpoint_ip(endpoint):
    text = str(endpoint or "").strip()
    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")]
    if text.count(":") == 1:
        return text.rsplit(":", 1)[0]
    return text


def should_skip_cdn_waf(ip, task=None):
    if not ip:
        return False
    if task is not None:
        for info in getattr(task, "ip_info_list", []) or []:
            if str(_read_field(info, "ip", "")) == str(ip):
                if str(_read_field(info, "cdn_name", "") or "").strip():
                    return True
    return bool(utils.get_cdn_name_by_ip(ip))


def write_pivot_evidence(
    task,
    *,
    candidate_type,
    value,
    source,
    decision,
    pivot_ip="",
    pivot_endpoint="",
    pivot_cert_key="",
    cdn_waf=False,
):
    """保存候选关系和排除原因；证书正文只保留身份键。"""
    task_id = str(getattr(task, "task_id", "") or "")
    writer = getattr(task, "_result_writer", None) or TaskResultWriteService(task_id)
    domain = str(decision.get("domain") or value or "").strip()
    source_name = str(source or "unknown")
    key = "{}|{}|{}|{}|{}|{}".format(
        candidate_type,
        domain,
        source_name,
        str(pivot_ip or "").strip(),
        str(pivot_endpoint or "").strip(),
        str(pivot_cert_key or "").strip(),
    )
    document = {
        "task_id": task_id,
        "candidate_type": candidate_type,
        "value": domain or str(value or "").strip(),
        "source": source_name,
        "pivot_ip": str(pivot_ip or "").strip(),
        "pivot_endpoint": str(pivot_endpoint or "").strip(),
        "pivot_cert_key": str(pivot_cert_key or "").strip(),
        "resolved_ips": list(decision.get("resolved_ips") or []),
        "matched_ips": list(decision.get("matched_ips") or []),
        "decision": str(decision.get("status") or "degraded"),
        "reason": str(decision.get("reason") or "unknown"),
        "cdn_waf": bool(cdn_waf),
        "save_date": utils.curr_date(),
    }
    writer.upsert_one(
        "asset_pivot_evidence",
        {"task_id": task_id, "pivot_key": key},
        document,
    )


def build_domain_sites(ip_info_list, domain_to_ips):
    """把确认域名挂到已有 Web 端口，供 WebSiteFetch 继续处理。"""
    sites = []
    seen = set()
    ip_map = defaultdict(list)
    for info in ip_info_list or []:
        ip = str(_read_field(info, "ip", "") or "").strip()
        if not ip:
            continue
        port_items = _read_field(info, "port_info_list", None)
        if port_items is None:
            port_items = _read_field(info, "port_info", [])
        for port_info in port_items or []:
            try:
                port = int(_read_field(port_info, "port_id", 0) or 0)
            except (TypeError, ValueError):
                continue
            if port <= 0:
                continue
            service_name = str(_read_field(port_info, "service_name", "") or "").lower()
            ip_map[ip].append((port, service_name))

    for domain, ips in (domain_to_ips or {}).items():
        normalized = utils.normalize_domain(domain)
        if not normalized:
            continue
        for ip in normalize_ip_set(ips):
            port_items = set(ip_map.get(ip, []))
            for port, service_name in sorted(port_items):
                schemes = ["http", "https"] if port not in (80, 443) else [
                    "https" if port == 443 or "https" in service_name else "http"
                ]
                for scheme in schemes:
                    default_port = (
                        (scheme == "http" and port == 80)
                        or (scheme == "https" and port == 443)
                    )
                    target = "{}://{}".format(scheme, normalized)
                    if not default_port:
                        target = "{}:{}".format(target, port)
                    if target in seen:
                        continue
                    seen.add(target)
                    sites.append(target)
    return sites


class UnifiedAssetDiscoveryStageService(object):
    """IP/IP 段任务的测绘、证书、DNS 校验和域名扩展阶段。"""

    def __init__(self, task, resolver=None):
        self.task = task
        self.resolver = resolver
        self.metrics = {
            "ip_candidates": 0,
            "certificate_candidates": 0,
            "provider_results": 0,
            "provider_raw_results": 0,
            "provider_unique_results": 0,
            "accepted": 0,
            "evidence_only": 0,
            "degraded": 0,
            "rejected": 0,
            "new_domains": 0,
            "new_sites": 0,
            "cdn_waf_skipped": 0,
            "provider_failed": 0,
            "provider_degraded": 0,
            "certificate_failed": 0,
            "rounds": 0,
            "round_new_domains": [],
            "round_new_sites": [],
        }

    def _scope(self):
        return []

    def _finish_metrics(self, status=None):
        if status:
            self.metrics["status"] = status
        elif (
            self.metrics.get("degraded", 0)
            or self.metrics.get("provider_failed", 0)
            or self.metrics.get("provider_degraded", 0)
            or self.metrics.get("certificate_failed", 0)
        ):
            self.metrics["status"] = "partial"
            self.metrics["end_reason"] = (
                "provider_failed"
                if self.metrics.get("provider_failed", 0)
                else "provider_degraded"
                if self.metrics.get("provider_degraded", 0)
                else "certificate_failed"
                if self.metrics.get("certificate_failed", 0)
                else "dns_degraded"
            )
        elif getattr(self.task, "_asset_pivot_budget_exhausted", False):
            self.metrics["status"] = "partial"
            self.metrics["end_reason"] = "budget_exhausted"
        else:
            self.metrics["status"] = "success"
        self.task._last_asset_pivot_metrics = dict(self.metrics)
        result = dict(self.metrics)
        result["output_count"] = self.metrics.get("new_domains", 0)
        result["metrics"] = dict(self.metrics)
        return result

    def _record_decision(self, decision):
        status = decision.get("status")
        if status in self.metrics:
            self.metrics[status] += 1

    def _record_provider_metrics(self, results):
        provider_metrics = getattr(results, "metrics", {}) or {}
        self.metrics["provider_raw_results"] += int(
            provider_metrics.get("source_result_count", 0) or 0
        )
        self.metrics["provider_unique_results"] += int(
            provider_metrics.get("unique_result_count", 0)
            or provider_metrics.get("output_count", 0)
            or 0
        )
        self.metrics["provider_failed"] += int(
            provider_metrics.get("failed_count", 0) or 0
        )
        self.metrics["provider_degraded"] += int(
            provider_metrics.get("degraded_count", 0) or 0
        )

    def _accept_result(
        self,
        result,
        source,
        pivot_ip="",
        pivot_endpoint="",
        pivot_cert_key="",
    ):
        domain = result.get("domain") if isinstance(result, dict) else ""
        decision = validate_domain_binding(
            domain,
            pivot_ips=[pivot_ip] if pivot_ip else [],
            scopes=self._scope(),
            resolver=self.resolver,
            require_ip_match=bool(
                getattr(Config, "ASSET_DISCOVERY_REQUIRE_IP_MATCH", True)
            ),
        )
        self._record_decision(decision)
        write_pivot_evidence(
            self.task,
            candidate_type="domain",
            value=domain,
            source=source,
            decision=decision,
            pivot_ip=pivot_ip,
            pivot_endpoint=pivot_endpoint,
            pivot_cert_key=pivot_cert_key,
        )
        return decision

    def _save_domain(self, domain, source, ips=None):
        task = self.task
        domain = utils.normalize_domain(domain)
        if not domain or domain in getattr(task, "_asset_pivot_domains", set()):
            return False
        try:
            normalized_ips = sorted(normalize_ip_set(ips))
            task._result_writer.upsert_one(
                "domain",
                {"task_id": task.task_id, "domain": domain},
                {
                    "task_id": task.task_id,
                    "domain": domain,
                    "type": "A",
                    "record": normalized_ips,
                    "ips": normalized_ips,
                    "source": source,
                    "save_date": utils.curr_date(),
                },
            )
            task._asset_pivot_domains.add(domain)
            return True
        except Exception as exc:
            logger.warning(
                "asset pivot domain save failed task_id:{} error:{}".format(
                    task.task_id, safe_error_text(exc)
                )
            )
            return False

    def _collect_ip_results(self, ip_list):
        if not ip_list or not self.task.options.get("dns_query_plugin"):
            return [], {}
        try:
            results = run_query_plugin_by_ip(
                ip_list=ip_list,
                target_domain="",
                max_domains=int(Config.IP_PIVOT_QUERY_MAX_DOMAINS or 0),
            )
        except Exception as exc:
            self.metrics["provider_failed"] += 1
            logger.warning(
                "asset pivot ip provider failed task_id:{} error:{}".format(
                    self.task.task_id, safe_error_text(exc)
                )
            )
            return [], {}
        self._record_provider_metrics(results)
        self.metrics["provider_results"] += len(results or [])
        accepted = []
        domain_to_ips = defaultdict(set)
        seen_relations = set()
        for result in results or []:
            if not isinstance(result, dict):
                continue
            source = str(result.get("source") or "provider").strip() or "provider"
            pivot_ip = str(result.get("pivot_ip") or "").strip()
            relation_key = (
                source,
                utils.normalize_domain(result.get("domain")),
                pivot_ip,
            )
            if relation_key in seen_relations:
                continue
            seen_relations.add(relation_key)
            decision = self._accept_result(
                result,
                "{}_ip_pivot".format(source),
                pivot_ip=pivot_ip,
            )
            if decision.get("status") != "accepted":
                continue
            accepted.append((decision["domain"], source))
            domain_to_ips[decision["domain"]].update(
                decision.get("matched_ips") or [pivot_ip]
            )
        return accepted, domain_to_ips

    def _collect_certificate_results(self, candidates):
        if not candidates or not self.task.options.get("dns_query_plugin"):
            return [], {}
        try:
            results = run_query_plugin_by_cert(
                cert_list=candidates,
                target_domain="",
                max_domains=int(Config.CERT_PIVOT_QUERY_MAX_DOMAINS or 0),
            )
        except Exception as exc:
            self.metrics["provider_failed"] += 1
            logger.warning(
                "asset pivot certificate provider failed task_id:{} error:{}".format(
                    self.task.task_id, safe_error_text(exc)
                )
            )
            return [], {}
        self._record_provider_metrics(results)
        self.metrics["provider_results"] += len(results or [])
        endpoint_map = {
            str(item.get("cert_key")): {
                "ip": endpoint_ip(item.get("endpoint")),
                "endpoint": str(item.get("endpoint") or ""),
            }
            for item in candidates
        }
        accepted = []
        domain_to_ips = defaultdict(set)
        seen_relations = set()
        for result in results or []:
            if not isinstance(result, dict):
                continue
            cert_key = str(result.get("pivot_cert") or "")
            endpoint_info = endpoint_map.get(cert_key, {})
            pivot_ip = endpoint_info.get("ip", "")
            source = str(result.get("source") or "provider").strip() or "provider"
            relation_key = (
                source,
                cert_key,
                utils.normalize_domain(result.get("domain")),
                pivot_ip,
            )
            if relation_key in seen_relations:
                continue
            seen_relations.add(relation_key)
            decision = self._accept_result(
                result,
                "{}_cert_pivot".format(source),
                pivot_ip=pivot_ip,
                pivot_endpoint=endpoint_info.get("endpoint", ""),
                pivot_cert_key=cert_key,
            )
            if decision.get("status") != "accepted":
                continue
            accepted.append((decision["domain"], source))
            domain_to_ips[decision["domain"]].update(
                decision.get("matched_ips") or [pivot_ip]
            )
        return accepted, domain_to_ips

    def _certificate_candidates(self):
        result = []
        seen = getattr(self.task, "_asset_pivot_seen_certs", set())
        batch_seen = set()
        for observe_id, cert in (getattr(self.task, "cert_map", {}) or {}).items():
            key = certificate_identity(cert) or "observe:{}".format(observe_id)
            if not key or key in seen or key in batch_seen:
                continue
            meta = cert.get("_scan_meta", {}) if isinstance(cert, dict) else {}
            endpoint = str(meta.get("endpoint") or observe_id).strip()
            ip = endpoint_ip(endpoint)
            if not ip:
                continue
            if should_skip_cdn_waf(ip, self.task):
                self.metrics["cdn_waf_skipped"] += 1
                seen.add(key)
                continue
            batch_seen.add(key)
            result.append({
                "cert": cert,
                "cert_key": key,
                "endpoint": endpoint,
                "observe_id": str(observe_id),
            })
        max_certs = int(Config.CERT_PIVOT_QUERY_MAX_CERTS or 0)
        if max_certs > 0:
            remaining = max(max_certs - len(seen), 0)
            result = result[:remaining]
        seen.update(item["cert_key"] for item in result)
        self.metrics["certificate_candidates"] += len(result)
        return result

    def _collect_certificate_identity_domains(self, target_ips):
        accepted = []
        domain_to_ips = defaultdict(set)
        seen = getattr(self.task, "_asset_pivot_seen_cert_domains", set())
        for observe_id, cert in (getattr(self.task, "cert_map", {}) or {}).items():
            key = certificate_identity(cert) or "observe:{}".format(observe_id)
            meta = cert.get("_scan_meta", {}) if isinstance(cert, dict) else {}
            endpoint = str(meta.get("endpoint") or observe_id).strip()
            pivot_ip = endpoint_ip(endpoint)
            if not pivot_ip:
                continue
            if should_skip_cdn_waf(pivot_ip, self.task):
                for domain in extract_certificate_domains(cert):
                    evidence_key = "{}|{}".format(key, domain)
                    if evidence_key in seen:
                        continue
                    seen.add(evidence_key)
                    self.metrics["cdn_waf_skipped"] += 1
                    self.metrics["evidence_only"] += 1
                    write_pivot_evidence(
                        self.task,
                        candidate_type="domain",
                        value=domain,
                        source="certificate_cn_san",
                        decision={
                            "domain": domain,
                            "status": "evidence_only",
                            "reason": "cdn_waf_source",
                            "resolved_ips": [],
                            "matched_ips": [],
                        },
                        pivot_ip=pivot_ip,
                        pivot_endpoint=endpoint,
                        pivot_cert_key=key,
                        cdn_waf=True,
                    )
                continue
            for domain in extract_certificate_domains(cert):
                evidence_key = "{}|{}".format(key, domain)
                if evidence_key in seen:
                    continue
                seen.add(evidence_key)
                decision = validate_domain_binding(
                    domain,
                    pivot_ips=[pivot_ip] if pivot_ip else target_ips,
                    resolver=self.resolver,
                    require_ip_match=bool(
                        getattr(Config, "ASSET_DISCOVERY_REQUIRE_IP_MATCH", True)
                    ),
                )
                self._record_decision(decision)
                write_pivot_evidence(
                    self.task,
                    candidate_type="domain",
                    value=domain,
                    source="certificate_cn_san",
                    decision=decision,
                    pivot_ip=pivot_ip,
                    pivot_endpoint=endpoint,
                    pivot_cert_key=key,
                )
                if decision.get("status") != "accepted":
                    continue
                accepted.append((domain, "certificate_cn_san"))
                domain_to_ips[domain].update(
                    decision.get("matched_ips") or [pivot_ip]
                )
        return accepted, domain_to_ips

    def _merge_domains_on_ip_info(self, domain_to_ips):
        for info in getattr(self.task, "ip_info_list", []) or []:
            ip = str(_read_field(info, "ip", "") or "").strip()
            domains = sorted(
                set(_read_field(info, "domain", []) or [])
                | set(
                    domain
                    for domain, ips in domain_to_ips.items()
                    if ip in normalize_ip_set(ips)
                )
            )
            if domains:
                _write_field(info, "domain", domains)

    def _run_domain_brute(self, roots, target_ips, max_domains=None):
        if not bool(getattr(Config, "ASSET_DISCOVERY_DOMAIN_BRUTE_ENABLE", True)):
            return [], {}
        if max_domains is not None and int(max_domains or 0) <= 0:
            return [], {}
        from app.services.domain_stage_services import domain_brute

        task = self.task
        word_file = task.options.get("domain_dict") or Config.DOMAIN_DICT_2W
        if not hasattr(task, "_asset_pivot_seen_roots"):
            task._asset_pivot_seen_roots = set()
        roots = [
            root for root in roots
            if root and root not in task._asset_pivot_seen_roots
        ]
        max_domains = max(
            int(
                getattr(Config, "ASSET_DISCOVERY_MAX_DOMAINS", 200)
                if max_domains is None
                else max_domains
            ),
            0,
        )
        max_roots = max(
            int(getattr(Config, "ASSET_DISCOVERY_MAX_DOMAIN_ROOTS", 20) or 20),
            0,
        )
        selected_roots = list(roots)[:max_roots]
        if len(selected_roots) < len(roots):
            task._asset_pivot_budget_exhausted = True
        task._asset_pivot_seen_roots.update(selected_roots)
        accepted = []
        domain_to_ips = defaultdict(set)
        for root in selected_roots:
            try:
                brute_items = domain_brute(root, word_file=word_file)
            except Exception as exc:
                logger.warning(
                    "asset pivot domain brute failed root_hash:{} error:{}".format(
                        domain_log_summary(root), safe_error_text(exc)
                    )
                )
                continue
            for item in brute_items or []:
                if len(accepted) >= max_domains > 0:
                    task._asset_pivot_budget_exhausted = True
                    break
                domain = getattr(item, "domain", "")
                decision = validate_domain_binding(
                    domain,
                    pivot_ips=target_ips,
                    resolver=self.resolver,
                    require_ip_match=bool(
                        getattr(Config, "ASSET_DISCOVERY_REQUIRE_IP_MATCH", True)
                    ),
                )
                self._record_decision(decision)
                write_pivot_evidence(
                    task,
                    candidate_type="domain",
                    value=domain,
                    source="domain_brute_ip_pivot",
                    decision=decision,
                    pivot_ip=",".join(target_ips),
                )
                if decision.get("status") != "accepted":
                    continue
                accepted.append((decision["domain"], "domain_brute"))
                domain_to_ips[decision["domain"]].update(
                    decision.get("matched_ips") or target_ips
                )
        return accepted, domain_to_ips

    def _run_once(self, target_ips):
        pending_ips = [
            ip for ip in target_ips if ip not in self.task._asset_pivot_seen_ips
        ]
        max_ips = max(int(Config.IP_PIVOT_QUERY_MAX_IPS or 0), 0)
        if max_ips > 0:
            remaining = max(
                max_ips - len(self.task._asset_pivot_seen_ips),
                0,
            )
            if len(pending_ips) > remaining:
                pending_ips = pending_ips[:remaining]
                self.task._asset_pivot_budget_exhausted = True
        self.task._asset_pivot_seen_ips.update(pending_ips)
        accepted, domain_to_ips = self._collect_ip_results(pending_ips)
        cert_identity_accepted, cert_identity_ips = (
            self._collect_certificate_identity_domains(target_ips)
        )
        accepted.extend(cert_identity_accepted)
        for domain, ips in cert_identity_ips.items():
            domain_to_ips.setdefault(domain, set()).update(ips)

        cert_candidates = []
        if bool(getattr(Config, "CERT_PIVOT_QUERY_ENABLE", True)):
            cert_candidates = self._certificate_candidates()
        cert_accepted, cert_domain_to_ips = self._collect_certificate_results(
            cert_candidates
        )
        accepted.extend(cert_accepted)
        for domain, ips in cert_domain_to_ips.items():
            domain_to_ips.setdefault(domain, set()).update(ips)

        roots = {utils.get_fld(domain) for domain, _ in accepted}
        roots.discard(None)
        roots.discard("")
        max_domain_limit = max(
            int(getattr(Config, "ASSET_DISCOVERY_MAX_DOMAINS", 200) or 200),
            0,
        )
        reserved_domains = {domain for domain, _ in accepted}
        existing_domains = getattr(self.task, "_asset_pivot_domains", set())
        if max_domain_limit > 0:
            brute_budget = max(
                max_domain_limit - len(existing_domains) - len(reserved_domains),
                0,
            )
            if roots and brute_budget <= 0:
                self.task._asset_pivot_budget_exhausted = True
        else:
            brute_budget = 0
        brute_accepted, brute_domain_to_ips = self._run_domain_brute(
            sorted(roots),
            target_ips,
            max_domains=brute_budget if max_domain_limit > 0 else None,
        )
        accepted.extend(brute_accepted)
        for domain, ips in brute_domain_to_ips.items():
            domain_to_ips.setdefault(domain, set()).update(ips)
        return accepted, domain_to_ips

    def run(self):
        task = self.task
        if not bool(getattr(Config, "ASSET_DISCOVERY_ENABLE", True)):
            return self._finish_metrics("skipped")
        if not task.options.get("dns_query_plugin"):
            logger.info(
                "skip asset pivot provider queries because dns_query_plugin=false"
            )

        if not hasattr(task, "_asset_pivot_domains"):
            task._asset_pivot_domains = set()
        if not hasattr(task, "_asset_pivot_seen_ips"):
            task._asset_pivot_seen_ips = set()
        if not hasattr(task, "_asset_pivot_seen_certs"):
            task._asset_pivot_seen_certs = set()

        target_ips = sorted(getattr(task, "ip_set", set()) or set())
        target_ips = [ip for ip in target_ips if utils.is_vaild_ip_target(ip)]
        self.metrics["ip_candidates"] = len(target_ips)
        if not target_ips:
            return self._finish_metrics()

        max_rounds = max(
            int(getattr(Config, "ASSET_DISCOVERY_MAX_ROUNDS", 1) or 1),
            1,
        )
        new_domains = set()
        new_sites = []
        for _ in range(max_rounds):
            self.metrics["rounds"] += 1
            accepted, domain_to_ips = self._run_once(target_ips)
            round_domains = set()
            max_domains = max(
                int(getattr(Config, "ASSET_DISCOVERY_MAX_DOMAINS", 200) or 200),
                0,
            )
            for domain, source in accepted:
                if max_domains > 0 and len(new_domains) >= max_domains:
                    break
                if self._save_domain(
                    domain,
                    source,
                    domain_to_ips.get(domain, []),
                ):
                    round_domains.add(domain)
            if not round_domains:
                self.metrics["round_new_domains"].append(0)
                self.metrics["round_new_sites"].append(0)
                break
            new_domains.update(round_domains)
            self._merge_domains_on_ip_info(domain_to_ips)
            if hasattr(task, "ssl_cert"):
                try:
                    task.ssl_cert()
                except Exception as exc:
                    self.metrics["certificate_failed"] += 1
                    logger.warning(
                        "asset pivot certificate collection failed task_id:{} error:{}".format(
                            task.task_id, safe_error_text(exc)
                        )
                    )
            for site in build_domain_sites(task.ip_info_list, domain_to_ips):
                if site not in task.site_list:
                    task.site_list.append(site)
                    new_sites.append(site)
            self.metrics["round_new_domains"].append(len(round_domains))
            self.metrics["round_new_sites"].append(
                len(new_sites) - sum(self.metrics["round_new_sites"])
            )
            if max_domains > 0 and len(new_domains) >= max_domains:
                break
        self.metrics["new_domains"] = len(new_domains)
        self.metrics["new_sites"] = len(new_sites)
        logger.info(
            "ip asset pivot task_id:{} ips:{} certs:{} accepted:{} evidence:{} sites:{}".format(
                task.task_id,
                self.metrics["ip_candidates"],
                self.metrics["certificate_candidates"],
                self.metrics["accepted"],
                self.metrics["evidence_only"],
                self.metrics["new_sites"],
            )
        )
        return self._finish_metrics()
