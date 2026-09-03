"""
DNS查询和解析
"""
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait

from app import utils
from app.config import Config
from app.utils.log_safety import safe_error_text, sanitize_log_text
from app.utils.provider_http import (
    acquire_provider_slot,
    current_stage_remaining_sec,
    provider_request_context,
    stage_execution_context,
)


PREFERRED_MEASURE_QUERY_SOURCES = ("fofa", "shodan")


class QueryPluginResult(list):
    """保持查询结果列表兼容，同时携带本次 provider 批次指标。"""

    def __init__(self, values=None, metrics=None):
        super().__init__(values or [])
        self.metrics = dict(metrics or {})


def _build_query_metrics(provider_stats, input_count, output_count, unique_count):
    stats = list(provider_stats or [])
    http_metrics = {}
    for item in stats:
        _merge_provider_http_metrics(http_metrics, item.get("http_metrics") or {})
    failed_count = len(
        [item for item in stats if str(item.get("status") or "") == "error"]
    )
    degraded_count = len(
        [item for item in stats if str(item.get("status") or "") in {"warning", "partial"}]
    )
    return {
        "input_count": max(int(input_count or 0), 0),
        "output_count": max(int(output_count or 0), 0),
        "provider_count": len(stats),
        "provider_success_count": len(
            [item for item in stats if str(item.get("status") or "") == "success"]
        ),
        "failed_count": failed_count,
        "degraded_count": degraded_count,
        "dedup_count": max(int(sum(int(item.get("source_result_count") or 0) for item in stats) - int(unique_count or 0)), 0),
        "request_count": int(http_metrics.get("request_count") or 0),
        "timeout_count": int(http_metrics.get("timeout_count") or 0),
        "retry_count": int(http_metrics.get("retry_count") or 0),
        "network_wait_sec": float(http_metrics.get("network_wait_sec") or 0.0),
        "provider_status": [
            {
                "provider": str(item.get("source") or ""),
                "status": str(item.get("status") or ""),
                "reason": str(item.get("reason") or ""),
                "result_count": int(item.get("source_result_count") or 0),
                "new_count": int(item.get("new_count") or 0),
            }
            for item in stats
        ],
    }


class DNSQueryBase(object):
    def __init__(self):
        self.source_name = None
        self.logger = utils.get_logger()
        # 插件是否支持按IP反查子域名，默认关闭
        self.support_ip_query = False
        # 插件是否支持按证书反查子域名，默认关闭
        self.support_cert_query = False
        # 请求频率受限常见关键词（中英文）
        self._rate_limit_keywords = (
            "rate limit", "too many", "429", "q3005", "频繁", "请求太多", "过于频繁", "稍后再试",
        )
        self.last_query_state = {}
        self._reset_last_query_state()

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

    def sub_domains_by_ip(self, ip):
        """
        根据IP查询子域名（默认插件不实现）
        :param ip:
        :return:
        """
        return []

    def sub_domains_by_cert(self, cert):
        """
        根据证书查询子域名（默认插件不实现）
        :param cert:
        :return:
        """
        return []

    def _reset_last_query_state(self, mode="", target=""):
        self.last_query_state = {
            "status": "idle",
            "reason": "",
            "detail": "",
            "mode": str(mode or ""),
            "target": str(target or ""),
            "source_result_count": 0,
            "result_count": 0,
            "http_metrics": {},
        }

    def _execute_provider_call(self, mode, target, func):
        """在不改变插件接口的前提下，为一次 provider 调用收集网络指标。"""
        with provider_request_context(
            self.source_name,
            mode=mode,
            target=target,
            stage_timeout_sec=current_stage_remaining_sec(),
        ) as metrics:
            try:
                return func()
            finally:
                self.last_query_state["http_metrics"] = dict(metrics)

    def _set_last_query_state(
        self,
        status="success",
        reason="ok",
        detail="",
        mode=None,
        target=None,
        source_result_count=None,
        result_count=None,
    ):
        if mode is not None:
            self.last_query_state["mode"] = str(mode or "")
        if target is not None:
            self.last_query_state["target"] = str(target or "")
        self.last_query_state["status"] = str(status or "")
        self.last_query_state["reason"] = str(reason or "")
        self.last_query_state["detail"] = sanitize_log_text(detail)
        if source_result_count is not None:
            self.last_query_state["source_result_count"] = int(self._safe_to_int(source_result_count, 0))
        if result_count is not None:
            self.last_query_state["result_count"] = int(self._safe_to_int(result_count, 0))

    def _classify_query_issue(self, status_code=0, data=None, message="", error_text=""):
        """
        统一识别“配额不足 / 限频 / 鉴权失败 / 空响应 / 未知异常”等场景。
        """
        safe_status_code = self._safe_to_int(status_code, 0)
        data_code = ""
        data_message = ""
        raw_text = ""
        if isinstance(data, dict):
            data_code = str(data.get("code", "")).strip().lower()
            data_message = str(data.get("message") or data.get("error") or "").strip()
            raw_text = str(data.get("_raw_text") or "").strip()

        merged_message = " ".join(
            [
                str(error_text or "").strip(),
                str(message or "").strip(),
                data_code,
                data_message,
                raw_text,
            ]
        ).strip()
        merged_lower = merged_message.lower()

        quota_keywords = (
            "q2001",
            "积分不足",
            "credit not enough",
            "quota not enough",
            "quota exceeded",
            "insufficient",
        )
        auth_keywords = (
            "unauthorized",
            "forbidden",
            "invalid key",
            "invalid token",
            "invalid api key",
            "apikey",
            "api key",
            "鉴权",
            "认证失败",
            "token无效",
            "权限不足",
        )

        if any(keyword in merged_lower for keyword in quota_keywords):
            return {"status": "warning", "reason": "quota_exhausted"}

        if self._is_rate_limited(status_code=safe_status_code, data=data, message=merged_message):
            return {"status": "warning", "reason": "rate_limited"}

        if safe_status_code in (401, 403) or any(keyword in merged_lower for keyword in auth_keywords):
            return {"status": "warning", "reason": "auth_failed"}

        if not merged_lower or merged_lower == "{}":
            return {"status": "warning", "reason": "empty_response"}

        if safe_status_code >= 500:
            return {"status": "error", "reason": "server_error"}

        return {"status": "error", "reason": "unexpected_error"}

    def _mark_query_issue(self, status_code=0, data=None, message="", error_text=""):
        issue = self._classify_query_issue(
            status_code=status_code,
            data=data,
            message=message,
            error_text=error_text,
        )
        current_status = str(self.last_query_state.get("status") or "")
        if current_status != "error":
            self._set_last_query_state(
                status=issue["status"],
                reason=issue["reason"],
                detail=(safe_error_text(message).strip() or safe_error_text(error_text).strip()),
            )
        return issue

    def _log_query_issue(self, issue, log_text):
        issue_status = str((issue or {}).get("status") or "error")
        if issue_status == "warning":
            self.logger.warning(log_text)
        else:
            self.logger.error(log_text)

    def _normalize_domains(self, domains, target="", scope_domain=""):
        """
        标准化并过滤插件返回的域名列表
        """
        subdomains = []
        # 旧链路使用 target，新链路使用 scope_domain（两者二选一）
        target_domain = utils.normalize_domain(target) if target else ""
        scope_domain = utils.normalize_domain(scope_domain) if scope_domain else ""
        base_domain = target_domain or scope_domain
        for domain in domains:
            if not isinstance(domain, str):
                continue

            domain = str(domain or "").strip(" \t\r\n")
            domain = utils.normalize_domain(domain)
            if not domain:
                continue

            if target_domain:
                if not domain.endswith(".{}".format(target_domain)):
                    continue

            if scope_domain:
                if not utils.is_in_scope(domain, scope_domain):
                    continue

            # 删除掉过长的域名
            if base_domain and domain != base_domain:
                if len(domain) - len(base_domain) >= Config.DOMAIN_MAX_LEN:
                    continue

            if not utils.is_valid_domain(domain):
                continue

            # 屏蔽和谐域名和黑名单域名
            if utils.check_domain_black(domain):
                continue

            if utils.domain_parsed(domain):
                subdomains.append(domain)

        return list(set(subdomains))

    def query(self, target):
        self._reset_last_query_state(mode="domain", target=target)
        t1 = time.time()
        self.logger.info("start query {} on {}".format(target, self.source_name))
        try:
            domains = self._execute_provider_call(
                "domain", target, lambda: self.sub_domains(target)
            )
        except Exception as e:
            error_text = safe_error_text(e)
            issue = self._mark_query_issue(error_text=error_text)
            self._log_query_issue(
                issue,
                "{} {}: {}".format(self.source_name, issue.get("reason", "unexpected_error"), error_text),
            )
            return []

        if not isinstance(domains, list):
            self._set_last_query_state(
                status="warning",
                reason="invalid_response",
                detail="return value is not list",
            )
            self.logger.warning("{} is not list".format(domains))
            return []

        subdomains = self._normalize_domains(domains, target=target)

        if str(self.last_query_state.get("status") or "") not in {"warning", "error"}:
            if subdomains:
                self._set_last_query_state(
                    status="success",
                    reason="ok",
                    source_result_count=len(domains),
                    result_count=len(subdomains),
                )
            else:
                self._set_last_query_state(
                    status="empty",
                    reason="no_result",
                    source_result_count=len(domains),
                    result_count=0,
                )
        else:
            self._set_last_query_state(
                source_result_count=len(domains),
                result_count=len(subdomains),
            )

        t2 = time.time()
        self.logger.info("end query {} on {}, source result:{}, real result:{} ({:.2f}s)".format(
            target, self.source_name, len(domains), len(subdomains), t2 - t1))

        return subdomains

    def query_by_ip(self, ip, target_domain=""):
        """
        按IP反查域名，target_domain用于范围约束
        """
        self._reset_last_query_state(mode="ip", target=ip)
        t1 = time.time()
        self.logger.info("start query ip {} on {}".format(ip, self.source_name))
        try:
            domains = self._execute_provider_call(
                "ip", ip, lambda: self.sub_domains_by_ip(ip)
            )
        except Exception as e:
            error_text = safe_error_text(e)
            issue = self._mark_query_issue(error_text=error_text)
            self._log_query_issue(
                issue,
                "{} ip {} {}: {}".format(
                    self.source_name, ip, issue.get("reason", "unexpected_error"), error_text
                ),
            )
            return []

        if not isinstance(domains, list):
            self._set_last_query_state(
                status="warning",
                reason="invalid_response",
                detail="return value is not list",
            )
            self.logger.warning("{} is not list".format(domains))
            return []

        subdomains = self._normalize_domains(domains, scope_domain=target_domain)
        if str(self.last_query_state.get("status") or "") not in {"warning", "error"}:
            if subdomains:
                self._set_last_query_state(
                    status="success",
                    reason="ok",
                    source_result_count=len(domains),
                    result_count=len(subdomains),
                )
            else:
                self._set_last_query_state(
                    status="empty",
                    reason="no_result",
                    source_result_count=len(domains),
                    result_count=0,
                )
        else:
            self._set_last_query_state(
                source_result_count=len(domains),
                result_count=len(subdomains),
            )
        t2 = time.time()
        self.logger.info(
            "end query ip {} on {}, source result:{}, real result:{} ({:.2f}s)".format(
                ip, self.source_name, len(domains), len(subdomains), t2 - t1
            )
        )
        return subdomains

    def query_by_cert(self, cert, target_domain="", cert_id=""):
        """
        按证书反查域名，target_domain用于范围约束
        """
        show_cert_id = cert_id or "-"
        self._reset_last_query_state(mode="cert", target=show_cert_id)
        t1 = time.time()
        self.logger.info("start query cert {} on {}".format(show_cert_id, self.source_name))
        try:
            domains = self._execute_provider_call(
                "cert", show_cert_id, lambda: self.sub_domains_by_cert(cert)
            )
        except Exception as e:
            error_text = safe_error_text(e)
            issue = self._mark_query_issue(error_text=error_text)
            self._log_query_issue(
                issue,
                "{} cert {} {}: {}".format(
                    self.source_name, show_cert_id, issue.get("reason", "unexpected_error"), error_text
                ),
            )
            return []

        if not isinstance(domains, list):
            self._set_last_query_state(
                status="warning",
                reason="invalid_response",
                detail="return value is not list",
            )
            self.logger.warning("{} is not list".format(domains))
            return []

        subdomains = self._normalize_domains(domains, scope_domain=target_domain)
        if str(self.last_query_state.get("status") or "") not in {"warning", "error"}:
            if subdomains:
                self._set_last_query_state(
                    status="success",
                    reason="ok",
                    source_result_count=len(domains),
                    result_count=len(subdomains),
                )
            else:
                self._set_last_query_state(
                    status="empty",
                    reason="no_result",
                    source_result_count=len(domains),
                    result_count=0,
                )
        else:
            self._set_last_query_state(
                source_result_count=len(domains),
                result_count=len(subdomains),
            )
        t2 = time.time()
        self.logger.info(
            "end query cert {} on {}, source result:{}, real result:{} ({:.2f}s)".format(
                show_cert_id, self.source_name, len(domains), len(subdomains), t2 - t1
            )
        )
        return subdomains

    @staticmethod
    def _safe_to_int(value, default=0):
        try:
            return int(str(value).strip())
        except Exception:
            return default

    @staticmethod
    def _safe_to_float(value, default=0.0):
        try:
            return float(str(value).strip())
        except Exception:
            return default

    def _is_rate_limited(self, status_code=0, data=None, message=""):
        """
        判断当前响应是否属于“请求频率受限”。
        """
        if self._safe_to_int(status_code, 0) == 429:
            return True

        data_code = ""
        data_message = ""
        if isinstance(data, dict):
            data_code = str(data.get("code", "")).strip().lower()
            data_message = str(data.get("message", "")).strip().lower()

        merged = "{} {} {}".format(str(message).lower(), data_code, data_message)
        for keyword in self._rate_limit_keywords:
            if keyword in merged:
                return True

        return False

    def _calc_retry_sleep(self, attempt=1, conn=None, data=None, base=2, cap=120):
        """
        计算重试等待时长，优先使用服务端 Retry-After。
        """
        base = max(self._safe_to_int(base, 2), 1)
        cap = max(self._safe_to_int(cap, 120), base)
        attempt = max(self._safe_to_int(attempt, 1), 1)

        retry_after = 0
        if conn is not None:
            try:
                retry_after = self._safe_to_int(conn.headers.get("Retry-After", 0), 0)
            except Exception:
                retry_after = 0

        if retry_after <= 0 and isinstance(data, dict):
            retry_after = self._safe_to_int(data.get("retry_after", 0), 0)
            if retry_after <= 0 and isinstance(data.get("data"), dict):
                retry_after = self._safe_to_int(data["data"].get("retry_after", 0), 0)

        if retry_after > 0:
            return min(max(retry_after + 1, base), cap)

        sleep_time = max(base, base * (2 ** max(attempt - 1, 0)))
        return min(sleep_time, cap)


def _prepare_query_plugin(p, source_filter_set, query_key, logger):
    """
    统一处理插件筛选、启停和密钥初始化

    返回:
        (should_run: bool, skip_reason: str)
    """
    source_name = p.source_name
    if source_filter_set and source_name not in source_filter_set:
        return False, "source_filter"

    # FOFA 使用全局 FOFA 配置，不在 QUERY_PLUGIN 节点重复填写凭据。
    if source_name == "fofa" and (not Config.FOFA_EMAIL or not Config.FOFA_KEY):
        return False, "required_config_missing"

    if query_key.get(source_name):
        source_conf = query_key[source_name]
        if not isinstance(source_conf, dict):
            logger.warning("{} config {} is not dict".format(source_name, source_conf))
            return False, "invalid_config"

        source_kwargs = source_conf.copy()
        plugin_enable_flag = source_kwargs.pop("enable", None)
        if plugin_enable_flag is not None and not plugin_enable_flag:
            return False, "enable=false"

        if source_kwargs:
            if all(source_kwargs.values()):
                p.init_key(**source_kwargs)
            else:
                miss_keys = [k for k, v in source_kwargs.items() if not v]
                logger.warning(
                    "skip query plugin {} because required config missing: {}".format(
                        source_name, ",".join(miss_keys)
                    )
                )
                return False, "required_config_missing"

    return True, ""


def _get_auto_enabled_sources(query_key):
    """
    从 QUERY_PLUGIN 配置中提取 enable=true 的来源
    """
    enabled = set()
    if not isinstance(query_key, dict):
        return enabled

    for source_name, source_conf in query_key.items():
        if not isinstance(source_conf, dict):
            continue

        if source_conf.get("enable", None) is False:
            continue

        enabled.add(source_name)

    return enabled


def _sort_plugins_for_auto_mode(plugins):
    """
    自动模式下固定优先级，确保 FOFA / Shodan 先执行。
    """
    priority_map = {
        source_name: index
        for index, source_name in enumerate(PREFERRED_MEASURE_QUERY_SOURCES)
    }
    return sorted(
        plugins,
        key=lambda plugin: (
            priority_map.get(str(getattr(plugin, "source_name", "") or "").strip(), 100),
            str(getattr(plugin, "source_name", "") or "").strip(),
        ),
    )


def _clone_query_plugin(plugin, query_key):
    """为并发 IP 反查创建独立插件实例，避免 last_query_state 相互覆盖。"""
    try:
        clone = plugin.__class__()
    except Exception:
        return None

    source_name = str(getattr(plugin, "source_name", "") or "").strip()
    source_conf = query_key.get(source_name) if isinstance(query_key, dict) else None
    if isinstance(source_conf, dict):
        source_kwargs = dict(source_conf)
        source_kwargs.pop("enable", None)
        if source_kwargs:
            try:
                clone.init_key(**source_kwargs)
            except Exception:
                # 原实例已经通过 _prepare_query_plugin 校验；初始化失败交给调用方记录。
                return None
    return clone


def _run_ip_query_worker(plugin, ip, target_domain, stage_timeout_sec=None, source_name=""):
    source_name = str(source_name or getattr(plugin, "source_name", "") or "-")
    if plugin is None:
        return [], {
            "source": source_name,
            "status": "error",
            "reason": "plugin_clone_failed",
            "source_result_count": 0,
            "result_count": 0,
            "new_count": 0,
            "detail": "provider plugin isolation failed",
            "http_metrics": {},
        }, "provider plugin isolation failed"

    interval = getattr(plugin, "request_interval", 0.0)
    acquire_provider_slot(source_name, interval)
    try:
        with stage_execution_context("dns_ip_query", stage_timeout_sec):
            results = plugin.query_by_ip(ip, target_domain=target_domain)
        return list(results or []), _read_plugin_state(plugin, result_count=len(results or [])), ""
    except Exception as exc:
        return [], {
            "source": source_name,
            "status": "error",
            "reason": "worker_exception",
            "source_result_count": 0,
            "result_count": 0,
            "new_count": 0,
            "detail": safe_error_text(exc, max_length=240),
            "http_metrics": {},
        }, safe_error_text(exc),


def _run_domain_query_worker(plugin, target, stage_timeout_sec=None):
    source_name = str(getattr(plugin, "source_name", "") or "-")
    try:
        with stage_execution_context("dns_query_provider", stage_timeout_sec):
            results = list(plugin.query(target) or [])
        return results, _read_plugin_state(plugin, result_count=len(results)), ""
    except Exception as exc:
        error_text = safe_error_text(exc, max_length=240)
        return [], {
            "source": source_name,
            "status": "error",
            "reason": "worker_exception",
            "source_result_count": 0,
            "result_count": 0,
            "new_count": 0,
            "detail": error_text,
            "http_metrics": {},
        }, error_text


def _merge_provider_http_metrics(total, current):
    if not isinstance(current, dict):
        return
    for key, value in current.items():
        if key == "elapsed_sec":
            try:
                total[key] = round(max(float(total.get(key, 0.0)), float(value or 0.0)), 6)
            except (TypeError, ValueError):
                continue
            continue
        try:
            total[key] = total.get(key, 0) + int(value or 0)
        except (TypeError, ValueError):
            try:
                total[key] = total.get(key, 0.0) + float(value or 0.0)
            except (TypeError, ValueError):
                continue


def _read_plugin_state(plugin, result_count=0, new_count=0):
    state = getattr(plugin, "last_query_state", {})
    if not isinstance(state, dict):
        state = {}
    status = str(state.get("status") or ("success" if result_count > 0 else "empty"))
    reason = str(state.get("reason") or ("ok" if result_count > 0 else "no_result"))
    return {
        "source": str(getattr(plugin, "source_name", "") or "-"),
        "status": status,
        "reason": reason,
        "source_result_count": int(state.get("source_result_count") or result_count or 0),
        "result_count": int(state.get("result_count") or result_count or 0),
        "new_count": int(new_count or 0),
        "detail": str(state.get("detail") or ""),
        "http_metrics": dict(state.get("http_metrics") or {})
        if isinstance(state.get("http_metrics"), dict) else {},
    }


def _format_provider_summary(provider_stats):
    parts = []
    for item in provider_stats:
        source = str(item.get("source") or "-")
        status = str(item.get("status") or "-")
        reason = str(item.get("reason") or "-")
        source_result_count = int(item.get("source_result_count") or 0)
        new_count = int(item.get("new_count") or 0)
        detail = str(item.get("detail") or "").strip()
        http_metrics = item.get("http_metrics") or {}
        timeout_count = int(http_metrics.get("timeout_count") or 0)
        retry_count = int(http_metrics.get("retry_count") or 0)
        metric_suffix = ""
        if timeout_count or retry_count:
            metric_suffix = ",timeout={},retry={}".format(timeout_count, retry_count)
        part = "{}:{}:{}({}/{}){}".format(
            source, status, reason, new_count, source_result_count, metric_suffix
        )
        if detail:
            part = "{}[{}]".format(part, sanitize_log_text(detail, max_length=120))
        parts.append(part)
    return " | ".join(parts) if parts else "-"


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
    source_filter_set = set([x.strip() for x in sources if isinstance(x, str) and x.strip()])
    auto_source_mode = not source_filter_set

    plugins = utils.load_query_plugins(Config.dns_query_plugin_path)
    query_key = Config.QUERY_PLUGIN_CONFIG
    logger = utils.get_logger()
    if auto_source_mode:
        source_filter_set = _get_auto_enabled_sources(query_key)
        logger.info(
            "domain query auto source mode enabled sources:{}".format(
                ",".join(sorted(source_filter_set)) if source_filter_set else "-"
            )
        )
        if not source_filter_set:
            logger.warning("domain query auto source mode no enabled source found in QUERY_PLUGIN")
            return []
        plugins = _sort_plugins_for_auto_mode(plugins)
    ret = []
    # 保留“域名 + 来源”关系；域名本身仍单独去重用于任务统计。
    source_domain_pairs = set()
    subdomains = set()
    t1 = time.time()
    run_count = 0
    skip_count = 0
    error_count = 0
    warning_count = 0
    provider_stats = []
    runnable_plugins = []
    for plugin_index, p in enumerate(plugins):
        source_name = str(getattr(p, "source_name", "") or "-")
        try:
            should_run, reason = _prepare_query_plugin(p, source_filter_set, query_key, logger)
            if not should_run:
                skip_count += 1
                provider_stats.append({
                    "_order": plugin_index,
                    "source": source_name,
                    "status": "skip",
                    "reason": reason,
                    "source_result_count": 0,
                    "new_count": 0,
                    "detail": "",
                })
                if reason == "source_filter":
                    logger.info("skip query plugin {} by source filter".format(source_name))
                elif reason == "enable=false":
                    logger.info("skip query plugin {} because enable=false".format(source_name))
                continue
            runnable_plugins.append((plugin_index, p))
        except Exception as exc:
            error_str = safe_error_text(exc)
            if "please set fofa key" in error_str:
                logger.debug(error_str)
            else:
                logger.error("{} prepare error {} {}".format(source_name, type(exc), error_str))
            error_count += 1
            provider_stats.append({
                "_order": plugin_index,
                "source": source_name,
                "status": "error",
                "reason": "prepare_failed",
                "source_result_count": 0,
                "new_count": 0,
                "detail": error_str,
            })

    run_count = len(runnable_plugins)
    if runnable_plugins:
        try:
            provider_concurrency = max(
                1,
                int(getattr(Config, "SEARCH_PROVIDER_CONCURRENCY", 4) or 4),
            )
        except (TypeError, ValueError):
            provider_concurrency = 4
        provider_concurrency = min(provider_concurrency, len(runnable_plugins))
        stage_remaining = current_stage_remaining_sec()
        executor = ThreadPoolExecutor(max_workers=provider_concurrency)
        future_map = {
            executor.submit(
                _run_domain_query_worker,
                plugin,
                target,
                stage_remaining,
            ): (plugin_index, plugin)
            for plugin_index, plugin in runnable_plugins
        }
        pending = set(future_map)
        timed_out = False
        try:
            remaining = stage_remaining
            try:
                for future in as_completed(pending, timeout=remaining):
                    pending.remove(future)
                    plugin_index, plugin = future_map[future]
                    source_name = str(getattr(plugin, "source_name", "") or "-")
                    try:
                        results, provider_state, worker_error = future.result()
                    except Exception as exc:
                        results = []
                        provider_state = {
                            "source": source_name,
                            "status": "error",
                            "reason": "worker_exception",
                            "source_result_count": 0,
                            "new_count": 0,
                            "detail": safe_error_text(exc, max_length=240),
                        }
                        worker_error = provider_state["detail"]

                    source_new_cnt = 0
                    for result in results:
                        pair_key = (source_name, result)
                        if pair_key in source_domain_pairs:
                            continue
                        item = {
                            "domain": result,
                            "source": source_name,
                        }
                        ret.append(item)
                        source_domain_pairs.add(pair_key)
                        subdomains.add(result)
                        source_new_cnt += 1

                    provider_state = dict(provider_state or {})
                    provider_state["_order"] = plugin_index
                    provider_state["source"] = source_name
                    provider_state["new_count"] = source_new_cnt
                    if worker_error and provider_state.get("status") not in {"warning", "error"}:
                        provider_state["status"] = "error"
                        provider_state["reason"] = "worker_exception"
                    provider_stats.append(provider_state)
                    if provider_state.get("status") in {"warning", "partial"}:
                        warning_count += 1
                    elif provider_state.get("status") == "error":
                        error_count += 1
                    logger.info(
                        "end query plugin {} status:{} reason:{} source_result:{} new_result:{}".format(
                            source_name,
                            provider_state.get("status", "error"),
                            provider_state.get("reason", "worker_exception"),
                            len(results),
                            source_new_cnt,
                        )
                    )
            except TimeoutError:
                timed_out = True
        finally:
            if timed_out:
                for future in pending:
                    future.cancel()
            executor.shutdown(wait=not timed_out, cancel_futures=timed_out)

        if timed_out:
            for future in pending:
                plugin_index, plugin = future_map[future]
                source_name = str(getattr(plugin, "source_name", "") or "-")
                provider_stats.append({
                    "_order": plugin_index,
                    "source": source_name,
                    "status": "partial",
                    "reason": "stage_timeout",
                    "source_result_count": 0,
                    "new_count": 0,
                    "detail": "provider call pending at stage deadline",
                })
                warning_count += 1

    provider_stats.sort(key=lambda item: int(item.get("_order", 0)))
    for item in provider_stats:
        item.pop("_order", None)

    t2 = time.time()
    logger.info(
        "{} subdomains result:{} source_relation:{} run:{} skip:{} warning:{} error:{} ({:.2f}s) provider_summary:{}".format(
            target,
            len(subdomains),
            len(source_domain_pairs),
            run_count,
            skip_count,
            warning_count,
            error_count,
            t2 - t1,
            _format_provider_summary(provider_stats),
        )
    )
    return QueryPluginResult(
        ret,
        metrics=_build_query_metrics(
            provider_stats,
            input_count=1,
            output_count=len(ret),
            unique_count=len(subdomains),
        ),
    )


def run_query_plugin_by_ip(ip_list, target_domain="", sources=None, max_domains=0):
    """
    对公网IP进行三方反查，获取同域名范围内的新增域名

    参数:
        ip_list: 待反查IP列表
        target_domain: 域名范围约束（为空时不过滤范围）
        sources: 指定数据源（为空时按配置自动）
        max_domains: 最大返回域名数（<=0 表示不限制）
    """
    if sources is None:
        sources = []

    normalized_ip_list = []
    for ip in ip_list:
        ip = str(ip or "").strip()
        if not ip:
            continue
        if not utils.is_vaild_ip_target(ip):
            continue
        normalized_ip_list.append(ip)
    normalized_ip_list = list(dict.fromkeys(normalized_ip_list))
    if not normalized_ip_list:
        return []

    plugins = utils.load_query_plugins(Config.dns_query_plugin_path)
    query_key = Config.QUERY_PLUGIN_CONFIG
    logger = utils.get_logger()
    source_filter_set = set([x.strip() for x in sources if isinstance(x, str) and x.strip()])
    if not source_filter_set:
        source_filter_set = _get_auto_enabled_sources(query_key)
        logger.info(
            "ip query auto source mode enabled sources:{}".format(
                ",".join(sorted(source_filter_set)) if source_filter_set else "-"
            )
        )
        if not source_filter_set:
            logger.warning("ip query auto source mode no enabled source found in QUERY_PLUGIN")
            return []
        plugins = _sort_plugins_for_auto_mode(plugins)

    ret = []
    source_domain_pairs = set()
    subdomains = set()
    t1 = time.time()
    run_count = 0
    skip_count = 0
    error_count = 0
    warning_count = 0
    limit_hit = False
    provider_stats = []

    for p in plugins:
        source_name = p.source_name
        try:
            should_run, reason = _prepare_query_plugin(p, source_filter_set, query_key, logger)
            if not should_run:
                skip_count += 1
                provider_stats.append({
                    "source": source_name,
                    "status": "skip",
                    "reason": reason,
                    "source_result_count": 0,
                    "new_count": 0,
                    "detail": "",
                })
                if reason == "source_filter":
                    logger.info("skip ip query plugin {} by source filter".format(source_name))
                elif reason == "enable=false":
                    logger.info("skip ip query plugin {} because enable=false".format(source_name))
                continue

            if not getattr(p, "support_ip_query", False):
                skip_count += 1
                provider_stats.append({
                    "source": source_name,
                    "status": "skip",
                    "reason": "support_ip_query=false",
                    "source_result_count": 0,
                    "new_count": 0,
                    "detail": "",
                })
                logger.info("skip ip query plugin {} because support_ip_query=false".format(source_name))
                continue

            run_count += 1
            source_result_cnt = 0
            source_new_cnt = 0
            failed_calls = 0
            timeout_calls = 0
            pending_calls = 0
            consecutive_failures = 0
            circuit_open = False
            circuit_threshold = max(
                1,
                int(getattr(Config, "SEARCH_PROVIDER_CIRCUIT_BREAKER_THRESHOLD", 3) or 3),
            )
            provider_http_metrics = {}
            provider_stage_start = time.monotonic()
            provider_stage_budget = max(
                0,
                int(getattr(Config, "SEARCH_PROVIDER_STAGE_TIMEOUT_SEC", 300) or 0),
            )
            provider_concurrency = max(
                1,
                int(getattr(Config, "SEARCH_PROVIDER_CONCURRENCY", 4) or 4),
            )
            executor = ThreadPoolExecutor(max_workers=provider_concurrency)
            future_map = {}
            pending = set()
            next_ip_index = 0
            stop_scheduling = False

            def submit_next_ip():
                """只保持一个并发窗口，避免熔断前把所有 IP 压入线程池。"""
                nonlocal next_ip_index
                if next_ip_index >= len(normalized_ip_list):
                    return False
                ip = normalized_ip_list[next_ip_index]
                next_ip_index += 1
                worker_plugin = _clone_query_plugin(p, query_key)
                remaining_budget = None
                if provider_stage_budget > 0:
                    remaining_budget = provider_stage_budget - (
                        time.monotonic() - provider_stage_start
                    )
                    if remaining_budget <= 0:
                        next_ip_index -= 1
                        return False
                future = executor.submit(
                    _run_ip_query_worker,
                    worker_plugin,
                    ip,
                    target_domain,
                    remaining_budget,
                    source_name,
                )
                future_map[future] = ip
                pending.add(future)
                return True

            try:
                for _ in range(min(provider_concurrency, len(normalized_ip_list))):
                    submit_next_ip()

                while pending:
                    remaining = None
                    if provider_stage_budget > 0:
                        remaining = provider_stage_budget - (time.monotonic() - provider_stage_start)
                        if remaining <= 0:
                            pending_calls += len(pending) + max(
                                len(normalized_ip_list) - next_ip_index,
                                0,
                            )
                            stop_scheduling = True
                            break
                    completed_set, pending = wait(
                        pending,
                        timeout=remaining,
                        return_when=FIRST_COMPLETED,
                    )
                    if not completed_set:
                        pending_calls += len(pending) + max(
                            len(normalized_ip_list) - next_ip_index,
                            0,
                        )
                        stop_scheduling = True
                        break

                    completed_list = list(completed_set)
                    for completed_index, completed in enumerate(completed_list):
                        ip = future_map[completed]
                        results, call_state, worker_error = completed.result()
                        call_status = str(call_state.get("status") or "")
                        call_failed = bool(worker_error) or call_status in {"error", "warning"}
                        if call_failed:
                            failed_calls += 1
                            consecutive_failures += 1
                            logger.warning(
                                "ip query provider worker failed source:{} target:{} error:{}".format(
                                    source_name,
                                    ip,
                                    (worker_error or call_state.get("reason") or "request_failed")[:240],
                                )
                            )
                        else:
                            consecutive_failures = 0
                        http_metrics = call_state.get("http_metrics") or {}
                        timeout_calls += int(http_metrics.get("timeout_count") or 0)
                        _merge_provider_http_metrics(provider_http_metrics, http_metrics)
                        source_result_cnt += len(results)
                        for result in results:
                            pair_key = (source_name, result)
                            if pair_key in source_domain_pairs:
                                continue

                            item = {
                                "domain": result,
                                "source": source_name,
                                "pivot_ip": ip
                            }
                            ret.append(item)
                            source_domain_pairs.add(pair_key)
                            source_new_cnt += 1
                            subdomains.add(result)

                            if max_domains > 0 and len(subdomains) >= max_domains:
                                limit_hit = True
                                stop_scheduling = True
                                break

                        if limit_hit:
                            unprocessed_done = len(completed_list) - completed_index - 1
                            pending_calls += unprocessed_done + len(pending) + max(
                                len(normalized_ip_list) - next_ip_index,
                                0,
                            )
                            break
                        if consecutive_failures >= circuit_threshold:
                            circuit_open = True
                            stop_scheduling = True
                            unprocessed_done = len(completed_list) - completed_index - 1
                            pending_calls += unprocessed_done + len(pending) + max(
                                len(normalized_ip_list) - next_ip_index,
                                0,
                            )
                            logger.warning(
                                "ip query provider circuit open source:{} consecutive_failures:{} pending_calls:{}".format(
                                    source_name,
                                    consecutive_failures,
                                    pending_calls,
                                )
                            )
                            break

                    if stop_scheduling:
                        break

                    while len(pending) < provider_concurrency and submit_next_ip():
                        pass
            finally:
                for future in future_map:
                    if not future.done():
                        future.cancel()
                executor.shutdown(
                    wait=not stop_scheduling,
                    cancel_futures=stop_scheduling,
                )

            if circuit_open:
                provider_status = "partial"
                provider_reason = "circuit_open"
            elif pending_calls:
                provider_status = "partial"
                provider_reason = "stage_timeout" if provider_stage_budget > 0 else "pending_cancelled"
            elif failed_calls:
                provider_status = "warning" if source_result_cnt or source_new_cnt else "error"
                provider_reason = "request_failed"
            elif source_result_cnt:
                provider_status = "success"
                provider_reason = "ok"
            else:
                provider_status = "empty"
                provider_reason = "no_result"
            provider_state = {
                "source": source_name,
                "status": provider_status,
                "reason": provider_reason,
                "source_result_count": source_result_cnt,
                "result_count": source_result_cnt,
                "new_count": source_new_cnt,
                "detail": "pending_calls:{} failed_calls:{} timeout_calls:{}".format(
                    pending_calls, failed_calls, timeout_calls
                ) if pending_calls or failed_calls or timeout_calls else "",
                "http_metrics": provider_http_metrics,
            }
            provider_stats.append(provider_state)
            if provider_state["status"] in {"warning", "partial"}:
                warning_count += 1
            elif provider_state["status"] == "error":
                error_count += 1
            logger.info(
                "end ip query plugin {} status:{} reason:{} source_result:{} new_result:{}".format(
                    source_name,
                    provider_state["status"],
                    provider_state["reason"],
                    source_result_cnt,
                    source_new_cnt,
                )
            )

            if limit_hit:
                logger.info("ip query plugin reach max_domains {} stop".format(max_domains))
                break

        except Exception as e:
            error_str = safe_error_text(e)
            if "please set fofa key" in error_str:
                logger.debug(error_str)
            else:
                logger.error("{} ip query error {} {}".format(source_name, type(e), error_str))
            error_count += 1
            provider_stats.append({
                "source": source_name,
                "status": "error",
                "reason": "unexpected_error",
                "source_result_count": 0,
                "new_count": 0,
                "detail": error_str,
            })

    t2 = time.time()
    logger.info(
        "ip_query target_domain:{} ip:{} result:{} source_relation:{} run:{} skip:{} warning:{} error:{} ({:.2f}s) provider_summary:{}".format(
            target_domain or "-",
            len(normalized_ip_list),
            len(subdomains),
            len(source_domain_pairs),
            run_count,
            skip_count,
            warning_count,
            error_count,
            t2 - t1,
            _format_provider_summary(provider_stats),
        )
    )
    return QueryPluginResult(
        ret,
        metrics=_build_query_metrics(
            provider_stats,
            input_count=len(normalized_ip_list),
            output_count=len(ret),
            unique_count=len(subdomains),
        ),
    )


def _build_cert_query_key(cert):
    """
    构建证书唯一标识，优先 serial + sha1
    """
    if not isinstance(cert, dict):
        return ""

    serial_number = str(cert.get("serial_number") or "").strip()
    fingerprint = cert.get("fingerprint") or {}
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


def run_query_plugin_by_cert(cert_list, target_domain="", sources=None, max_domains=0):
    """
    对证书进行三方反查，获取同域名范围内的新增域名

    参数:
        cert_list: 证书列表，支持两种格式
            - 证书对象(dict)
            - {"cert": 证书对象, "cert_key": "证书唯一标识"}
        target_domain: 域名范围约束（为空时不过滤范围）
        sources: 指定数据源（为空时按配置自动）
        max_domains: 最大返回域名数（<=0 表示不限制）
    """
    if sources is None:
        sources = []

    normalized_cert_list = []
    seen_cert_key = set()
    for item in cert_list:
        cert_obj = item
        cert_key = ""

        if isinstance(item, dict) and isinstance(item.get("cert"), dict):
            cert_obj = item["cert"]
            cert_key = str(item.get("cert_key") or "").strip()

        if not isinstance(cert_obj, dict):
            continue

        if not cert_key:
            cert_key = _build_cert_query_key(cert_obj)

        if not cert_key:
            continue

        if cert_key in seen_cert_key:
            continue

        seen_cert_key.add(cert_key)
        normalized_cert_list.append({
            "cert": cert_obj,
            "cert_key": cert_key
        })

    if not normalized_cert_list:
        return []

    plugins = utils.load_query_plugins(Config.dns_query_plugin_path)
    query_key = Config.QUERY_PLUGIN_CONFIG
    logger = utils.get_logger()
    source_filter_set = set([x.strip() for x in sources if isinstance(x, str) and x.strip()])
    if not source_filter_set:
        source_filter_set = _get_auto_enabled_sources(query_key)
        logger.info(
            "cert query auto source mode enabled sources:{}".format(
                ",".join(sorted(source_filter_set)) if source_filter_set else "-"
            )
        )
        if not source_filter_set:
            logger.warning("cert query auto source mode no enabled source found in QUERY_PLUGIN")
            return []
        plugins = _sort_plugins_for_auto_mode(plugins)

    ret = []
    source_domain_pairs = set()
    subdomains = set()
    t1 = time.time()
    run_count = 0
    skip_count = 0
    error_count = 0
    warning_count = 0
    limit_hit = False
    provider_stats = []

    for p in plugins:
        source_name = p.source_name
        try:
            should_run, reason = _prepare_query_plugin(p, source_filter_set, query_key, logger)
            if not should_run:
                skip_count += 1
                provider_stats.append({
                    "source": source_name,
                    "status": "skip",
                    "reason": reason,
                    "source_result_count": 0,
                    "new_count": 0,
                    "detail": "",
                })
                if reason == "source_filter":
                    logger.info("skip cert query plugin {} by source filter".format(source_name))
                elif reason == "enable=false":
                    logger.info("skip cert query plugin {} because enable=false".format(source_name))
                continue

            if not getattr(p, "support_cert_query", False):
                skip_count += 1
                provider_stats.append({
                    "source": source_name,
                    "status": "skip",
                    "reason": "support_cert_query=false",
                    "source_result_count": 0,
                    "new_count": 0,
                    "detail": "",
                })
                logger.info("skip cert query plugin {} because support_cert_query=false".format(source_name))
                continue

            run_count += 1
            source_result_cnt = 0
            source_new_cnt = 0
            for cert_item in normalized_cert_list:
                cert_obj = cert_item["cert"]
                cert_key = cert_item["cert_key"]
                logger.info("start cert query plugin {} target:{}".format(source_name, cert_key))
                results = p.query_by_cert(cert_obj, target_domain=target_domain, cert_id=cert_key)
                source_result_cnt += len(results)
                for result in results:
                    pair_key = (source_name, result)
                    if pair_key in source_domain_pairs:
                        continue

                    item = {
                        "domain": result,
                        "source": source_name,
                        "pivot_cert": cert_key
                    }
                    ret.append(item)
                    source_domain_pairs.add(pair_key)
                    source_new_cnt += 1

                    if result not in subdomains:
                        subdomains.add(result)

                    if max_domains > 0 and len(subdomains) >= max_domains:
                        limit_hit = True
                        break

                if limit_hit:
                    break

            provider_state = _read_plugin_state(p, result_count=source_result_cnt, new_count=source_new_cnt)
            provider_stats.append(provider_state)
            if provider_state["status"] == "warning":
                warning_count += 1
            elif provider_state["status"] == "error":
                error_count += 1
            logger.info(
                "end cert query plugin {} status:{} reason:{} source_result:{} new_result:{}".format(
                    source_name,
                    provider_state["status"],
                    provider_state["reason"],
                    source_result_cnt,
                    source_new_cnt,
                )
            )

            if limit_hit:
                logger.info("cert query plugin reach max_domains {} stop".format(max_domains))
                break

        except Exception as e:
            error_str = safe_error_text(e)
            if "please set fofa key" in error_str:
                logger.debug(error_str)
            else:
                logger.error("{} cert query error {} {}".format(source_name, type(e), error_str))
            error_count += 1
            provider_stats.append({
                "source": source_name,
                "status": "error",
                "reason": "unexpected_error",
                "source_result_count": 0,
                "new_count": 0,
                "detail": error_str,
            })

    t2 = time.time()
    logger.info(
        "cert_query target_domain:{} cert:{} result:{} source_relation:{} run:{} skip:{} warning:{} error:{} ({:.2f}s) provider_summary:{}".format(
            target_domain or "-",
            len(normalized_cert_list),
            len(subdomains),
            len(source_domain_pairs),
            run_count,
            skip_count,
            warning_count,
            error_count,
            t2 - t1,
            _format_provider_summary(provider_stats),
        )
    )
    return QueryPluginResult(
        ret,
        metrics=_build_query_metrics(
            provider_stats,
            input_count=len(normalized_cert_list),
            output_count=len(ret),
            unique_count=len(subdomains),
        ),
    )
