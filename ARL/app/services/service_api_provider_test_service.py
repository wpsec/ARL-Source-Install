"""第三方服务 API Provider 测试服务。

Provider 测试是外部网络副作用，但不是配置路由职责；本服务统一小样本、
凭据校验和结果结构，避免单项与批量接口出现不同的测试语义。
"""

from datetime import datetime

from app.services.fofaClient import FofaClient
from app.utils.log_safety import safe_error_text


class ServiceApiProviderTestService(object):
    """提供单项和批量 Provider 连通性测试。"""

    def __init__(self, config, service_api_config_service, utils_module, logger=None):
        self.config = config
        self.service_api_config_service = service_api_config_service
        self.utils = utils_module
        self.logger = logger

    @staticmethod
    def _safe_int(value, default=0, minimum=0):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return int(default)
        return parsed if parsed >= minimum else int(default)

    @staticmethod
    def normalize_provider(provider):
        normalized = str(provider or "").strip().lower()
        return {
            "hunter": "hunter_qax",
            "quake": "quake_360",
        }.get(normalized, normalized)

    def normalize_target(self, test_target):
        candidate = str(test_target or "").strip().lower().rstrip(".")
        if candidate and self.utils.is_valid_domain(candidate):
            return candidate
        return "example.com"

    @staticmethod
    def provider_specs():
        return [
            {"provider": "fofa", "label": "FOFA", "required_fields": ["fofa_email", "fofa_key"]},
            {"provider": "hunter", "label": "Hunter", "required_fields": ["hunter_api_key"]},
            {"provider": "hunter_how", "label": "hunter.how", "required_fields": ["hunter_how_api_key"]},
            {"provider": "shodan", "label": "Shodan", "required_fields": ["shodan_api_key"]},
            {"provider": "quake", "label": "Quake360", "required_fields": ["quake_token"]},
            {"provider": "zoomeye", "label": "Zoomeye", "required_fields": ["zoomeye_api_key"]},
            {"provider": "securitytrails", "label": "SecurityTrails", "required_fields": ["securitytrails_api_key"]},
            {"provider": "virustotal", "label": "VirusTotal", "required_fields": ["virustotal_api_key"]},
            {"provider": "chaos", "label": "Chaos", "required_fields": ["chaos_api_key"]},
            {"provider": "github", "label": "GitHub", "required_fields": ["github_token"]},
        ]

    def configured_providers(self, service_api):
        value = service_api if isinstance(service_api, dict) else {}
        configured = []
        for spec in self.provider_specs():
            required = spec.get("required_fields", [])
            if all(str(value.get(field, "") or "").strip() for field in required):
                configured.append(dict(spec))
        return configured

    def _build_runtime_config(self, service_api):
        runtime_config = {
            "FOFA": {},
            "QUERY_PLUGIN": {},
            "RISKIQ": {},
            "GITHUB": {},
        }
        return self.service_api_config_service.merge(runtime_config, service_api)

    def _find_query_plugin(self, source_name):
        plugins = self.utils.load_query_plugins(self.config.dns_query_plugin_path)
        for plugin in plugins:
            if getattr(plugin, "source_name", "") == source_name:
                return plugin
        return None

    def _test_fofa(self, service_api):
        fofa_url = str(service_api.get("fofa_url", "") or "").strip() or "https://fofa.info"
        email = str(service_api.get("fofa_email", "") or "").strip()
        key = str(service_api.get("fofa_key", "") or "").strip()
        if not email or not key:
            return False, "FOFA 测试失败：请填写邮箱和 KEY", {}
        try:
            client = FofaClient(email, key, page_size=1)
            client.base_url = fofa_url
            profile = client.info_my() or {}
            if not isinstance(profile, dict):
                return False, "FOFA 测试失败：返回数据格式异常", {}
            if profile.get("error"):
                return False, "FOFA 测试失败：{}".format(profile.get("errmsg") or "未知错误"), {}
            return True, "FOFA 测试成功", {
                "email": str(profile.get("email") or ""),
                "fcoin": profile.get("fcoin", 0),
                "isvip": bool(profile.get("isvip", False)),
            }
        except Exception as exc:
            return False, "FOFA 测试失败：{}".format(safe_error_text(exc)), {}

    def _test_github(self, service_api):
        token = str(service_api.get("github_token", "") or "").strip()
        if not token:
            return False, "GitHub 测试失败：请填写 TOKEN", {}
        try:
            conn = self.utils.http_req(
                "https://api.github.com/user",
                "get",
                headers={
                    "Authorization": "Bearer {}".format(token),
                    "Accept": "application/vnd.github+json",
                },
                timeout=(10, 20),
            )
            data = conn.json() if conn is not None else {}
            status_code = int(getattr(conn, "status_code", 0) or 0)
            if status_code != 200:
                message = str(data.get("message") or "") if isinstance(data, dict) else ""
                return False, "GitHub 测试失败：HTTP {} {}".format(status_code, message), {}
            return True, "GitHub 测试成功", {
                "login": str(data.get("login") or "") if isinstance(data, dict) else "",
            }
        except Exception as exc:
            return False, "GitHub 测试失败：{}".format(safe_error_text(exc)), {}

    def _test_virustotal(self, service_api, test_target):
        api_key = str(service_api.get("virustotal_api_key", "") or "").strip()
        if not api_key:
            return False, "VirusTotal 测试失败：请填写 API KEY", {}
        target = self.normalize_target(test_target)
        try:
            conn = self.utils.http_req(
                "https://www.virustotal.com/api/v3/domains/{}".format(target),
                "get",
                headers={"x-apikey": api_key},
                timeout=(10, 20),
            )
            status_code = int(getattr(conn, "status_code", 0) or 0)
            try:
                data = conn.json() if conn is not None else {}
            except Exception:
                data = {}
            if status_code != 200:
                error_message = ""
                if isinstance(data, dict):
                    error_obj = data.get("error")
                    if isinstance(error_obj, dict):
                        error_message = str(error_obj.get("message") or "")
                    error_message = error_message or str(data.get("message") or "")
                if self.logger:
                    self.logger.warning(
                        "virustotal lightweight test failed status:%s target:%s message:%s",
                        status_code,
                        target,
                        safe_error_text(error_message),
                    )
                return False, "VirusTotal 测试失败：HTTP {} {}".format(status_code, error_message).strip(), {}
            payload = data.get("data") if isinstance(data, dict) else {}
            payload = payload if isinstance(payload, dict) else {}
            attributes = payload.get("attributes") if isinstance(payload.get("attributes"), dict) else {}
            stats = attributes.get("last_analysis_stats") if isinstance(attributes.get("last_analysis_stats"), dict) else {}
            return True, "VirusTotal 测试成功", {
                "domain": str(payload.get("id") or target),
                "reputation": attributes.get("reputation", ""),
                "harmless": stats.get("harmless", ""),
                "suspicious": stats.get("suspicious", ""),
                "malicious": stats.get("malicious", ""),
            }
        except Exception as exc:
            if self.logger:
                self.logger.warning(
                    "virustotal lightweight test error target:%s err:%s",
                    target,
                    safe_error_text(exc),
                )
            return False, "VirusTotal 测试失败：{}".format(safe_error_text(exc)), {}

    def _test_query_plugin(self, provider, service_api, test_target):
        source_name = self.normalize_provider(provider)
        runtime_config = self._build_runtime_config(service_api)
        query_plugin_conf = runtime_config.get("QUERY_PLUGIN", {})
        plugin_conf = query_plugin_conf.get(source_name, {}) if isinstance(query_plugin_conf, dict) else {}
        plugin_conf = plugin_conf if isinstance(plugin_conf, dict) else {}
        required_conf_fields = {
            "hunter_qax": ["api_key"],
            "hunter_how": ["api_key"],
            "shodan": ["api_key"],
            "quake_360": ["quake_token"],
            "zoomeye": ["api_key"],
            "securitytrails": ["api_key"],
            "virustotal": ["api_key"],
            "chaos": ["api_key"],
        }
        missing = [
            field for field in required_conf_fields.get(source_name, [])
            if not str(plugin_conf.get(field, "") or "").strip()
        ]
        if missing:
            return False, "{} 测试失败：缺少配置 {}".format(source_name, ",".join(missing)), {}

        plugin = self._find_query_plugin(source_name)
        if not plugin:
            return False, "{} 测试失败：插件未加载".format(source_name), {}
        init_kwargs = plugin_conf.copy()
        init_kwargs.pop("enable", None)
        if source_name in ("hunter_qax", "hunter_how"):
            init_kwargs["max_page"] = 1
            init_kwargs["page_size"] = min(self._safe_int(init_kwargs.get("page_size"), 20, 1), 20)
        elif source_name in ("zoomeye", "shodan"):
            init_kwargs["max_page"] = 1
        elif source_name == "quake_360":
            init_kwargs["max_size"] = min(self._safe_int(init_kwargs.get("max_size"), 50, 1), 50)
        try:
            if init_kwargs:
                plugin.init_key(**init_kwargs)
            domains = plugin.query(self.normalize_target(test_target))
            domains = domains if isinstance(domains, list) else []
            return True, "{} 测试成功".format(source_name), {
                "result_count": len(domains),
                "sample": domains[:5],
            }
        except Exception as exc:
            return False, "{} 测试失败：{}".format(source_name, safe_error_text(exc)), {}

    def test_provider(self, provider, service_api, test_target):
        normalized_provider = self.normalize_provider(provider)
        normalized_target = self.normalize_target(test_target)
        value = service_api if isinstance(service_api, dict) else {}
        if normalized_provider == "fofa":
            ok, message, detail = self._test_fofa(value)
        elif normalized_provider == "github":
            ok, message, detail = self._test_github(value)
        elif normalized_provider == "virustotal":
            ok, message, detail = self._test_virustotal(value, normalized_target)
        else:
            ok, message, detail = self._test_query_plugin(
                normalized_provider, value, normalized_target
            )
        return {
            "provider": normalized_provider,
            "ok": bool(ok),
            "message": str(message or ""),
            "test_target": normalized_target,
            "detail": detail if isinstance(detail, dict) else {},
            "tested_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
