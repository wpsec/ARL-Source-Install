"""第三方服务 API 配置域服务。

这里集中处理配置文件结构与前端表单结构之间的转换，并提供敏感字段保护；
provider 的网络测试仍由路由层调用既有测试适配器执行。
"""

from app.config import Config


SERVICE_API_SENSITIVE_FIELDS = (
    "fofa_key",
    "hunter_api_key",
    "hunter_how_api_key",
    "shodan_api_key",
    "quake_token",
    "zoomeye_api_key",
    "securitytrails_api_key",
    "virustotal_api_key",
    "chaos_api_key",
    "passivetotal_key",
    "github_token",
)


class ServiceApiConfigService(object):
    """负责第三方 API 配置的读取、脱敏、回填和持久化结构合并。"""

    @staticmethod
    def _safe_int(value, default_value, min_value=1):
        try:
            parsed = int(value)
        except Exception:
            return int(default_value)
        return parsed if parsed >= min_value else int(default_value)

    @staticmethod
    def _safe_float(value, default_value, min_value=0.0):
        try:
            parsed = float(value)
        except Exception:
            return float(default_value)
        return parsed if parsed >= min_value else float(default_value)

    @staticmethod
    def _safe_bool(value, default_value=False):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "y", "on")
        return bool(default_value)

    @staticmethod
    def _section(config_obj, name):
        section = config_obj.get(name, {}) if isinstance(config_obj, dict) else {}
        return section if isinstance(section, dict) else {}

    @staticmethod
    def _plugin_config(query_plugin, name):
        plugin = query_plugin.get(name, {}) if isinstance(query_plugin, dict) else {}
        return plugin if isinstance(plugin, dict) else {}

    def extract(self, config_obj):
        fofa_conf = self._section(config_obj, "FOFA")
        riskiq_conf = self._section(config_obj, "RISKIQ")
        query_plugin = self._section(config_obj, "QUERY_PLUGIN")
        github_conf = self._section(config_obj, "GITHUB")

        fofa_plugin = self._plugin_config(query_plugin, "fofa")
        certspotter_plugin = self._plugin_config(query_plugin, "certspotter")
        hunter_plugin = self._plugin_config(query_plugin, "hunter_qax")
        hunter_how_plugin = self._plugin_config(query_plugin, "hunter_how")
        shodan_plugin = self._plugin_config(query_plugin, "shodan")
        quake_plugin = self._plugin_config(query_plugin, "quake_360")
        zoomeye_plugin = self._plugin_config(query_plugin, "zoomeye")
        securitytrails_plugin = self._plugin_config(query_plugin, "securitytrails")
        virustotal_plugin = self._plugin_config(query_plugin, "virustotal")
        chaos_plugin = self._plugin_config(query_plugin, "chaos")
        passivetotal_plugin = self._plugin_config(query_plugin, "passivetotal")

        def string_value(container, key, default=""):
            return str(container.get(key) or default).strip()

        def int_value(container, key, default, min_value=1):
            return self._safe_int(container.get(key), default, min_value=min_value)

        def float_value(container, key, default):
            return self._safe_float(container.get(key), default, min_value=0.0)

        return {
            "fofa_url": string_value(fofa_conf, "URL", Config.FOFA_URL or "https://fofa.info"),
            "fofa_email": string_value(fofa_conf, "EMAIL", Config.FOFA_EMAIL or ""),
            "fofa_key": string_value(fofa_conf, "KEY", Config.FOFA_KEY or ""),
            "fofa_enable": self._safe_bool(fofa_plugin.get("enable"), True),
            "certspotter_enable": self._safe_bool(certspotter_plugin.get("enable"), True),
            "hunter_api_key": string_value(hunter_plugin, "api_key"),
            "hunter_enable": self._safe_bool(hunter_plugin.get("enable"), True),
            "hunter_request_interval": float_value(hunter_plugin, "request_interval", 1.0),
            "hunter_rate_limit_retry": int_value(hunter_plugin, "rate_limit_retry", 4, min_value=0),
            "hunter_rate_limit_backoff": int_value(hunter_plugin, "rate_limit_backoff", 2),
            "hunter_rate_limit_max_sleep": int_value(hunter_plugin, "rate_limit_max_sleep", 60),
            "hunter_how_api_key": string_value(hunter_how_plugin, "api_key"),
            "hunter_how_enable": self._safe_bool(hunter_how_plugin.get("enable"), False),
            "hunter_how_page_size": int_value(hunter_how_plugin, "page_size", 100),
            "hunter_how_max_page": int_value(hunter_how_plugin, "max_page", 5),
            "hunter_how_request_interval": float_value(hunter_how_plugin, "request_interval", 1.0),
            "hunter_how_rate_limit_retry": int_value(hunter_how_plugin, "rate_limit_retry", 4, min_value=0),
            "hunter_how_rate_limit_backoff": int_value(hunter_how_plugin, "rate_limit_backoff", 2),
            "hunter_how_rate_limit_max_sleep": int_value(hunter_how_plugin, "rate_limit_max_sleep", 60),
            "shodan_api_key": string_value(shodan_plugin, "api_key"),
            "shodan_enable": self._safe_bool(shodan_plugin.get("enable"), False),
            "shodan_max_page": int_value(shodan_plugin, "max_page", 20),
            "shodan_request_interval": float_value(shodan_plugin, "request_interval", 1.0),
            "shodan_rate_limit_retry": int_value(shodan_plugin, "rate_limit_retry", 4, min_value=0),
            "shodan_rate_limit_backoff": int_value(shodan_plugin, "rate_limit_backoff", 2),
            "shodan_rate_limit_max_sleep": int_value(shodan_plugin, "rate_limit_max_sleep", 60),
            "quake_token": string_value(quake_plugin, "quake_token"),
            "quake_enable": self._safe_bool(quake_plugin.get("enable"), True),
            "quake_rate_limit_retry": int_value(quake_plugin, "rate_limit_retry", 4, min_value=0),
            "quake_rate_limit_backoff": int_value(quake_plugin, "rate_limit_backoff", 3),
            "quake_rate_limit_max_sleep": int_value(quake_plugin, "rate_limit_max_sleep", 90),
            "zoomeye_api_key": string_value(zoomeye_plugin, "api_key"),
            "zoomeye_enable": self._safe_bool(zoomeye_plugin.get("enable"), True),
            "zoomeye_max_page": int_value(zoomeye_plugin, "max_page", 20),
            "zoomeye_request_interval": float_value(zoomeye_plugin, "request_interval", 1.0),
            "zoomeye_rate_limit_retry": int_value(zoomeye_plugin, "rate_limit_retry", 4, min_value=0),
            "zoomeye_rate_limit_backoff": int_value(zoomeye_plugin, "rate_limit_backoff", 2),
            "zoomeye_rate_limit_max_sleep": int_value(zoomeye_plugin, "rate_limit_max_sleep", 60),
            "securitytrails_api_key": string_value(securitytrails_plugin, "api_key"),
            "securitytrails_enable": self._safe_bool(securitytrails_plugin.get("enable"), False),
            "virustotal_api_key": string_value(virustotal_plugin, "api_key"),
            "virustotal_enable": self._safe_bool(virustotal_plugin.get("enable"), True),
            "chaos_api_key": string_value(chaos_plugin, "api_key"),
            "chaos_enable": self._safe_bool(chaos_plugin.get("enable"), False),
            "passivetotal_email": string_value(
                passivetotal_plugin,
                "auth_email",
                string_value(riskiq_conf, "EMAIL"),
            ),
            "passivetotal_key": string_value(
                passivetotal_plugin,
                "auth_key",
                string_value(riskiq_conf, "KEY"),
            ),
            "passivetotal_enable": self._safe_bool(passivetotal_plugin.get("enable"), False),
            "github_token": string_value(github_conf, "TOKEN", Config.GITHUB_TOKEN or ""),
        }

    def sensitive_configured(self, service_api):
        service_api = service_api if isinstance(service_api, dict) else {}
        return {
            field_name: bool(str(service_api.get(field_name, "") or "").strip())
            for field_name in SERVICE_API_SENSITIVE_FIELDS
        }

    def sanitize(self, service_api):
        safe_service_api = dict(service_api or {})
        configured = self.sensitive_configured(safe_service_api)
        for field_name in SERVICE_API_SENSITIVE_FIELDS:
            safe_service_api[field_name] = ""
        return safe_service_api, configured

    def fill_missing_sensitive(self, service_api, config_obj):
        if not isinstance(service_api, dict):
            raise ValueError("service_api 必须为对象")

        merged_service_api = dict(service_api)
        current_service_api = self.extract(config_obj if isinstance(config_obj, dict) else {})
        for field_name in SERVICE_API_SENSITIVE_FIELDS:
            if field_name not in merged_service_api:
                merged_service_api[field_name] = current_service_api.get(field_name, "")
        return merged_service_api

    def merge(self, config_obj, service_api):
        if not isinstance(service_api, dict):
            raise ValueError("service_api 必须为对象")

        for section_name in ("FOFA", "QUERY_PLUGIN", "RISKIQ", "GITHUB"):
            if not isinstance(config_obj.get(section_name), dict):
                config_obj[section_name] = {}

        query_plugin = config_obj["QUERY_PLUGIN"]

        def ensure_plugin(name):
            plugin = query_plugin.get(name)
            if not isinstance(plugin, dict):
                plugin = {}
            query_plugin[name] = plugin
            return plugin

        def text(key, default=""):
            return str(service_api.get(key, default) or "").strip()

        def boolean(key, default):
            return self._safe_bool(service_api.get(key), default)

        def integer(key, default, min_value=1):
            return self._safe_int(service_api.get(key), default, min_value=min_value)

        def decimal(key, default):
            return self._safe_float(service_api.get(key), default, min_value=0.0)

        config_obj["FOFA"].update(
            {
                "URL": text("fofa_url") or "https://fofa.info",
                "EMAIL": text("fofa_email"),
                "KEY": text("fofa_key"),
            }
        )

        plugin_specs = {
            "fofa": {
                "enable": ("fofa_enable", True, "bool"),
            },
            "certspotter": {
                "enable": ("certspotter_enable", True, "bool"),
            },
            "hunter_qax": {
                "api_key": ("hunter_api_key", "", "text"),
                "enable": ("hunter_enable", True, "bool"),
                "request_interval": ("hunter_request_interval", 1.0, "float"),
                "rate_limit_retry": ("hunter_rate_limit_retry", 4, "int0"),
                "rate_limit_backoff": ("hunter_rate_limit_backoff", 2, "int"),
                "rate_limit_max_sleep": ("hunter_rate_limit_max_sleep", 60, "int"),
            },
            "hunter_how": {
                "api_key": ("hunter_how_api_key", "", "text"),
                "enable": ("hunter_how_enable", False, "bool"),
                "page_size": ("hunter_how_page_size", 100, "int"),
                "max_page": ("hunter_how_max_page", 5, "int"),
                "request_interval": ("hunter_how_request_interval", 1.0, "float"),
                "rate_limit_retry": ("hunter_how_rate_limit_retry", 4, "int0"),
                "rate_limit_backoff": ("hunter_how_rate_limit_backoff", 2, "int"),
                "rate_limit_max_sleep": ("hunter_how_rate_limit_max_sleep", 60, "int"),
            },
            "shodan": {
                "api_key": ("shodan_api_key", "", "text"),
                "enable": ("shodan_enable", False, "bool"),
                "max_page": ("shodan_max_page", 20, "int"),
                "request_interval": ("shodan_request_interval", 1.0, "float"),
                "rate_limit_retry": ("shodan_rate_limit_retry", 4, "int0"),
                "rate_limit_backoff": ("shodan_rate_limit_backoff", 2, "int"),
                "rate_limit_max_sleep": ("shodan_rate_limit_max_sleep", 60, "int"),
            },
            "quake_360": {
                "quake_token": ("quake_token", "", "text"),
                "enable": ("quake_enable", True, "bool"),
                "rate_limit_retry": ("quake_rate_limit_retry", 4, "int0"),
                "rate_limit_backoff": ("quake_rate_limit_backoff", 3, "int"),
                "rate_limit_max_sleep": ("quake_rate_limit_max_sleep", 90, "int"),
            },
            "zoomeye": {
                "api_key": ("zoomeye_api_key", "", "text"),
                "enable": ("zoomeye_enable", True, "bool"),
                "max_page": ("zoomeye_max_page", 20, "int"),
                "request_interval": ("zoomeye_request_interval", 1.0, "float"),
                "rate_limit_retry": ("zoomeye_rate_limit_retry", 4, "int0"),
                "rate_limit_backoff": ("zoomeye_rate_limit_backoff", 2, "int"),
                "rate_limit_max_sleep": ("zoomeye_rate_limit_max_sleep", 60, "int"),
            },
            "securitytrails": {
                "api_key": ("securitytrails_api_key", "", "text"),
                "enable": ("securitytrails_enable", False, "bool"),
            },
            "virustotal": {
                "api_key": ("virustotal_api_key", "", "text"),
                "enable": ("virustotal_enable", True, "bool"),
            },
            "chaos": {
                "api_key": ("chaos_api_key", "", "text"),
                "enable": ("chaos_enable", False, "bool"),
            },
        }

        for plugin_name, field_specs in plugin_specs.items():
            plugin = ensure_plugin(plugin_name)
            for field_name, (service_key, default, value_type) in field_specs.items():
                if value_type == "text":
                    plugin[field_name] = text(service_key)
                elif value_type == "bool":
                    plugin[field_name] = boolean(service_key, plugin.get(field_name, default))
                elif value_type == "float":
                    plugin[field_name] = decimal(service_key, plugin.get(field_name, default))
                elif value_type == "int0":
                    plugin[field_name] = integer(service_key, plugin.get(field_name, default), min_value=0)
                else:
                    plugin[field_name] = integer(service_key, plugin.get(field_name, default))

        passivetotal_plugin = ensure_plugin("passivetotal")
        passivetotal_email = text("passivetotal_email")
        passivetotal_key = text("passivetotal_key")
        passivetotal_plugin["auth_email"] = passivetotal_email
        passivetotal_plugin["auth_key"] = passivetotal_key
        passivetotal_plugin["enable"] = boolean(
            "passivetotal_enable",
            passivetotal_plugin.get("enable", False),
        )
        config_obj["RISKIQ"].update({"EMAIL": passivetotal_email, "KEY": passivetotal_key})
        config_obj["GITHUB"]["TOKEN"] = text("github_token")
        return config_obj
