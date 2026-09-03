"""AI 管理配置域服务。

配置结构兼容和敏感字段保护属于业务边界；提示词文件写入与 provider 网络测试
通过回调保留在路由层，避免这个服务产生文件或网络副作用。
"""


class AIConfigService(object):
    """负责 AI 配置的结构转换、脱敏、回填和合并。"""

    def __init__(
        self,
        config,
        normalize_model_profiles,
        pick_active_model_profile,
        normalize_prompt_templates,
        normalize_denoise_modules,
        normalize_denoise_prompt_ids,
        normalize_custom_providers,
        persist_prompt_templates,
    ):
        self.config = config
        self.normalize_model_profiles = normalize_model_profiles
        self.pick_active_model_profile = pick_active_model_profile
        self.normalize_prompt_templates = normalize_prompt_templates
        self.normalize_denoise_modules = normalize_denoise_modules
        self.normalize_denoise_prompt_ids = normalize_denoise_prompt_ids
        self.normalize_custom_providers = normalize_custom_providers
        self.persist_prompt_templates = persist_prompt_templates

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
    def _text(value, default=""):
        return str(value or default).strip()

    def extract(self, config_obj):
        ai_conf = self._section(config_obj, "AI")
        arl_conf = self._section(config_obj, "ARL")
        model_profiles = self.normalize_model_profiles(
            ai_conf.get("MODEL_PROFILES"),
            legacy_ai_conf=ai_conf,
        )
        active_model_profile_id = self._text(ai_conf.get("ACTIVE_MODEL_PROFILE_ID"))
        active_profile = self.pick_active_model_profile(
            model_profiles,
            active_model_profile_id,
        )
        if active_profile:
            active_model_profile_id = self._text(active_profile.get("id"))

        prompt_templates = self.normalize_prompt_templates(ai_conf.get("PROMPT_TEMPLATES"))
        prompt_ids = [item.get("id") for item in prompt_templates if item.get("id")]
        active_prompt_id = self._text(ai_conf.get("ACTIVE_PROMPT_ID"))
        if active_prompt_id not in prompt_ids:
            active_prompt_id = prompt_ids[0] if prompt_ids else ""
        ai_denoise_modules = self.normalize_denoise_modules(ai_conf.get("AI_DENOISE_MODULES"))
        ai_denoise_prompt_ids = self.normalize_denoise_prompt_ids(
            ai_conf.get("AI_DENOISE_PROMPT_IDS"),
            prompt_templates,
        )

        return {
            "enable": self._safe_bool(ai_conf.get("ENABLE"), True),
            "active_model_profile_id": active_model_profile_id,
            "model_profiles": model_profiles,
            "provider": self._text(active_profile.get("provider"), "openai"),
            "custom_provider_name": self._text(
                ai_conf.get("CUSTOM_PROVIDER_NAME") or active_profile.get("name")
            ),
            "base_url": self._text(active_profile.get("base_url")),
            "api_key": self._text(active_profile.get("api_key")),
            "model": self._text(active_profile.get("model")),
            "reasoning_model": self._text(
                active_profile.get("reasoning_model")
                or ai_conf.get("REASONING_MODEL")
                or active_profile.get("model")
            ),
            "proxy_url": self._text(
                active_profile.get("proxy") or ai_conf.get("PROXY_URL")
            ),
            "timeout_sec": self._safe_int(active_profile.get("timeout_sec"), 40, min_value=1),
            "temperature": self._safe_float(active_profile.get("temperature"), 0.2),
            "max_tokens": self._safe_int(active_profile.get("max_tokens"), 4000, min_value=1),
            "dialog_system_prompt": self._text(ai_conf.get("DIALOG_SYSTEM_PROMPT")),
            "dialog_style": self._text(ai_conf.get("DIALOG_STYLE"), "专业"),
            "dialog_language": self._text(ai_conf.get("DIALOG_LANGUAGE"), "zh-CN"),
            "dialog_context_messages": self._safe_int(
                ai_conf.get("DIALOG_CONTEXT_MESSAGES"), 8, min_value=1
            ),
            "request_delay_ms": self._safe_int(
                ai_conf.get("REQUEST_DELAY_MS"), 0, min_value=0
            ),
            "wih_endpoint_ai_fill_max_targets": self._safe_int(
                arl_conf.get("WIH_ENDPOINT_AI_FILL_MAX_TARGETS"),
                self.config.WIH_ENDPOINT_AI_FILL_MAX_TARGETS,
                min_value=1,
            ),
            "active_prompt_id": active_prompt_id,
            "prompt_templates": prompt_templates,
            "custom_compat_providers": self.normalize_custom_providers(
                ai_conf.get("CUSTOM_COMPAT_PROVIDERS")
            ),
            "ai_poc_scan_enable": self._safe_bool(
                ai_conf.get("AI_POC_SCAN_ENABLE"), True
            ),
            "ai_denoise_enable": self._safe_bool(
                ai_conf.get("AI_DENOISE_ENABLE"), True
            ),
            "ai_wih_endpoint_fill_enable": self._safe_bool(
                ai_conf.get("AI_WIH_ENDPOINT_FILL_ENABLE"), True
            ),
            "ai_denoise_modules": ai_denoise_modules,
            "ai_denoise_prompt_ids": ai_denoise_prompt_ids,
        }

    def sensitive_configured(self, ai_config):
        ai_config = ai_config if isinstance(ai_config, dict) else {}
        profiles = ai_config.get("model_profiles")
        profiles = profiles if isinstance(profiles, list) else []
        profile_keys = {}
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            profile_id = self._text(profile.get("id"))
            if profile_id:
                profile_keys[profile_id] = bool(self._text(profile.get("api_key")))

        active_profile = self.pick_active_model_profile(
            profiles,
            self._text(ai_config.get("active_model_profile_id")),
        )
        return {
            "api_key": bool(
                isinstance(active_profile, dict)
                and self._text(active_profile.get("api_key"))
            ),
            "model_profile_api_keys": profile_keys,
        }

    def sanitize(self, ai_config):
        safe_config = dict(ai_config or {})
        configured = self.sensitive_configured(safe_config)
        safe_profiles = []
        profiles = safe_config.get("model_profiles")
        if isinstance(profiles, list):
            for item in profiles:
                if not isinstance(item, dict):
                    continue
                profile = dict(item)
                profile["api_key"] = ""
                safe_profiles.append(profile)
        safe_config["model_profiles"] = safe_profiles
        safe_config["api_key"] = ""
        return safe_config, configured

    def fill_missing_sensitive(self, ai_config, config_obj):
        if not isinstance(ai_config, dict):
            raise ValueError("ai_config 必须为对象")

        merged_config = dict(ai_config)
        current_config = self.extract(config_obj if isinstance(config_obj, dict) else {})
        current_keys = {}
        current_profiles = current_config.get("model_profiles")
        if isinstance(current_profiles, list):
            for item in current_profiles:
                if not isinstance(item, dict):
                    continue
                profile_id = self._text(item.get("id"))
                if profile_id:
                    current_keys[profile_id] = self._text(item.get("api_key"))

        submitted_profiles = ai_config.get("model_profiles")
        if isinstance(submitted_profiles, list):
            merged_profiles = []
            for item in submitted_profiles:
                if not isinstance(item, dict):
                    continue
                profile = dict(item)
                profile_id = self._text(profile.get("id"))
                if "api_key" not in profile and profile_id:
                    profile["api_key"] = current_keys.get(profile_id, "")
                merged_profiles.append(profile)
            merged_config["model_profiles"] = merged_profiles

        if "api_key" not in merged_config:
            active_profile_id = self._text(
                merged_config.get("active_model_profile_id")
            )
            if active_profile_id:
                merged_config["api_key"] = current_keys.get(active_profile_id, "")
            else:
                merged_config["api_key"] = self._text(current_config.get("api_key"))
        return merged_config

    def merge(self, config_obj, ai_config):
        if not isinstance(ai_config, dict):
            raise ValueError("ai_config 必须为对象")

        if not isinstance(config_obj.get("AI"), dict):
            config_obj["AI"] = {}
        if not isinstance(config_obj.get("ARL"), dict):
            config_obj["ARL"] = {}
        ai_conf = config_obj["AI"]
        arl_conf = config_obj["ARL"]
        existing_templates = (
            ai_conf.get("PROMPT_TEMPLATES")
            if isinstance(ai_conf.get("PROMPT_TEMPLATES"), list)
            else []
        )

        model_profiles = self.normalize_model_profiles(
            ai_config.get("model_profiles"),
            legacy_ai_conf=ai_config,
        )
        active_model_profile_id = self._text(
            ai_config.get("active_model_profile_id")
        )
        active_profile = self.pick_active_model_profile(
            model_profiles,
            active_model_profile_id,
        )
        if active_profile:
            active_model_profile_id = self._text(active_profile.get("id"))

        prompt_templates = self.normalize_prompt_templates(ai_config.get("prompt_templates"))
        prompt_ids = [item.get("id") for item in prompt_templates if item.get("id")]
        active_prompt_id = self._text(ai_config.get("active_prompt_id"))
        if active_prompt_id not in prompt_ids:
            active_prompt_id = prompt_ids[0] if prompt_ids else ""
        ai_denoise_modules = self.normalize_denoise_modules(
            ai_config.get("ai_denoise_modules")
        )
        ai_denoise_prompt_ids = self.normalize_denoise_prompt_ids(
            ai_config.get("ai_denoise_prompt_ids"),
            prompt_templates,
        )

        ai_conf["ENABLE"] = self._safe_bool(ai_config.get("enable"), True)
        ai_conf["MODEL_PROFILES"] = model_profiles
        ai_conf["ACTIVE_MODEL_PROFILE_ID"] = active_model_profile_id
        ai_conf["PROVIDER"] = self._text(active_profile.get("provider"), "openai")
        ai_conf["CUSTOM_PROVIDER_NAME"] = self._text(
            ai_config.get("custom_provider_name") or active_profile.get("name")
        )
        ai_conf["BASE_URL"] = self._text(active_profile.get("base_url"))
        ai_conf["API_KEY"] = self._text(active_profile.get("api_key"))
        ai_conf["MODEL"] = self._text(active_profile.get("model"))
        ai_conf["REASONING_MODEL"] = self._text(
            active_profile.get("reasoning_model") or active_profile.get("model")
        )
        ai_conf["PROXY_URL"] = self._text(active_profile.get("proxy"))
        ai_conf["TIMEOUT_SEC"] = self._safe_int(
            active_profile.get("timeout_sec"), 40, min_value=1
        )
        ai_conf["TEMPERATURE"] = self._safe_float(
            active_profile.get("temperature"), 0.2
        )
        ai_conf["MAX_TOKENS"] = self._safe_int(
            active_profile.get("max_tokens"), 4000, min_value=1
        )
        ai_conf["DIALOG_SYSTEM_PROMPT"] = self._text(
            ai_config.get("dialog_system_prompt")
        )
        ai_conf["DIALOG_STYLE"] = self._text(ai_config.get("dialog_style"), "专业")
        ai_conf["DIALOG_LANGUAGE"] = self._text(
            ai_config.get("dialog_language"), "zh-CN"
        )
        ai_conf["DIALOG_CONTEXT_MESSAGES"] = self._safe_int(
            ai_config.get("dialog_context_messages"), 8, min_value=1
        )
        ai_conf["REQUEST_DELAY_MS"] = self._safe_int(
            ai_config.get("request_delay_ms"), 0, min_value=0
        )
        arl_conf["WIH_ENDPOINT_AI_FILL_MAX_TARGETS"] = max(
            0,
            min(
                5000,
                self._safe_int(
                    ai_config.get("wih_endpoint_ai_fill_max_targets"),
                    0,
                    min_value=0,
                ),
            ),
        )
        ai_conf["ACTIVE_PROMPT_ID"] = active_prompt_id
        ai_conf["PROMPT_TEMPLATES"] = self.persist_prompt_templates(
            prompt_templates,
            existing_templates,
        )
        ai_conf["CUSTOM_COMPAT_PROVIDERS"] = self.normalize_custom_providers(
            ai_config.get("custom_compat_providers")
        )
        ai_conf["AI_POC_SCAN_ENABLE"] = self._safe_bool(
            ai_config.get("ai_poc_scan_enable"), True
        )
        ai_conf["AI_DENOISE_ENABLE"] = self._safe_bool(
            ai_config.get("ai_denoise_enable"), True
        )
        ai_conf["AI_WIH_ENDPOINT_FILL_ENABLE"] = self._safe_bool(
            ai_config.get("ai_wih_endpoint_fill_enable"), True
        )
        ai_conf["AI_DENOISE_MODULES"] = ai_denoise_modules
        ai_conf["AI_DENOISE_PROMPT_IDS"] = ai_denoise_prompt_ids
        return config_obj
