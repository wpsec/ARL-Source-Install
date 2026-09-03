"""扫描配置域服务。

扫描配置的默认值、预设档位和持久化字段映射集中在这里，路由只负责请求解析、
字典选项组装和响应序列化。
"""

import os

from app.config import Config, normalize_dict_path_compat


SCAN_PROFILE_ITEMS = [
    {
        "id": "low_performance",
        "label": "低性能配置",
        "description": "适用于低资源主机，单次并行约 1 个目标，优先保证系统可访问性",
        "cpu_cores": 2,
        "memory_gb": 2,
        "bandwidth_mbps": 3,
        "values": {
            "domain_brute_concurrent": 48,
            "alt_dns_concurrent": 160,
            "web_gunicorn_workers": 1,
            "celery_task_worker_concurrency": 1,
            "celery_github_worker_concurrency": 1,
            "celery_heavy_worker_concurrency": 1,
            "celery_web_worker_concurrency": 1,
            "celery_prefetch_multiplier": 1,
            "celery_max_tasks_per_child": 16,
            "celery_max_memory_per_child": 200000,
            "nuclei_single_target_timeout_sec": 3600,
            "nuclei_rate_limit": 3,
            "nuclei_concurrency": 1,
            "nuclei_bulk_size": 2,
            "afrog_concurrency": 3,
            "afrog_rate_limit": 3,
            "urlfinder_url_probe_enable": True,
            "urlfinder_url_probe_max_targets": 150,
            "urlfinder_url_probe_concurrency": 3,
            "host_timeout_type": "default",
            "host_timeout": 1200,
            "port_parallelism": 10,
            "port_min_rate": 32,
        },
    },
    {
        "id": "medium_performance",
        "label": "中性能配置",
        "description": "适用于中等资源主机，单次并行约 2 个目标，在稳定性与扫描速度之间平衡。",
        "cpu_cores": 4,
        "memory_gb": 4,
        "bandwidth_mbps": 5,
        "values": {
            "domain_brute_concurrent": 96,
            "alt_dns_concurrent": 320,
            "web_gunicorn_workers": 2,
            "celery_task_worker_concurrency": 2,
            "celery_github_worker_concurrency": 1,
            "celery_heavy_worker_concurrency": 2,
            "celery_web_worker_concurrency": 2,
            "celery_prefetch_multiplier": 1,
            "celery_max_tasks_per_child": 20,
            "celery_max_memory_per_child": 280000,
            "nuclei_single_target_timeout_sec": 7200,
            "nuclei_rate_limit": 4,
            "nuclei_concurrency": 2,
            "nuclei_bulk_size": 3,
            "afrog_concurrency": 8,
            "afrog_rate_limit": 8,
            "urlfinder_url_probe_enable": True,
            "urlfinder_url_probe_max_targets": 220,
            "urlfinder_url_probe_concurrency": 4,
            "host_timeout_type": "default",
            "host_timeout": 1200,
            "port_parallelism": 16,
            "port_min_rate": 48,
        },
    },
    {
        "id": "high_performance",
        "label": "高性能配置",
        "description": "适用于高资源主机，单次并行约 3 个目标，在保证稳定性的前提下提升吞吐。",
        "cpu_cores": 8,
        "memory_gb": 16,
        "bandwidth_mbps": 10,
        "values": {
            "domain_brute_concurrent": 360,
            "alt_dns_concurrent": 1400,
            "web_gunicorn_workers": 6,
            "celery_task_worker_concurrency": 3,
            "celery_github_worker_concurrency": 2,
            "celery_heavy_worker_concurrency": 3,
            "celery_web_worker_concurrency": 3,
            "celery_prefetch_multiplier": 1,
            "celery_max_tasks_per_child": 32,
            "celery_max_memory_per_child": 720000,
            "nuclei_single_target_timeout_sec": 900,
            "nuclei_rate_limit": 50,
            "nuclei_concurrency": 24,
            "nuclei_bulk_size": 30,
            "afrog_concurrency": 30,
            "afrog_rate_limit": 30,
            "urlfinder_url_probe_enable": True,
            "urlfinder_url_probe_max_targets": 800,
            "urlfinder_url_probe_concurrency": 20,
            "host_timeout_type": "default",
            "host_timeout": 1500,
            "port_parallelism": 64,
            "port_min_rate": 260,
        },
    },
]
SCAN_PROFILE_MAP = {item["id"]: item for item in SCAN_PROFILE_ITEMS}
SCAN_PROFILE_ID_ALIASES = {
    "2c2g3m": "low_performance",
    "4c4g5m": "medium_performance",
    "8c16g10m": "high_performance",
}


class ScanConfigService(object):
    """负责扫描配置的领域校验、读模型和写模型转换。"""

    @staticmethod
    def _safe_int(value, default_value, min_value=1):
        try:
            parsed = int(value)
        except Exception:
            return int(default_value)
        return parsed if parsed >= min_value else int(default_value)

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
    def _normalize_host_timeout_type(value, default_value="default"):
        normalized = str(value or default_value).strip().lower()
        if normalized not in ("default", "custom"):
            normalized = str(default_value or "default").strip().lower()
        return normalized if normalized in ("default", "custom") else "default"

    @staticmethod
    def _normalize_string_list(raw_value):
        if raw_value is None:
            return []
        if isinstance(raw_value, list):
            values = raw_value
        elif isinstance(raw_value, str):
            values = raw_value.replace(",", "\n").split("\n")
        else:
            try:
                values = list(raw_value)
            except Exception:
                values = [raw_value]

        result = []
        seen = set()
        for item in values:
            value = str(item or "").strip()
            if value and value not in seen:
                result.append(value)
                seen.add(value)
        return result

    @staticmethod
    def extract_profile_id(scan_config):
        if not isinstance(scan_config, dict):
            return ""
        for profile in SCAN_PROFILE_ITEMS:
            if all(scan_config.get(key) == value for key, value in profile["values"].items()):
                return profile["id"]
        return ""

    @staticmethod
    def build_profiles_payload(active_profile_id=""):
        return [
            {
                "id": profile["id"],
                "label": profile["label"],
                "description": profile["description"],
                "cpu_cores": profile["cpu_cores"],
                "memory_gb": profile["memory_gb"],
                "bandwidth_mbps": profile["bandwidth_mbps"],
                "selected": bool(active_profile_id and active_profile_id == profile["id"]),
                "values": dict(profile.get("values", {})),
            }
            for profile in SCAN_PROFILE_ITEMS
        ]

    @staticmethod
    def apply_profile_overrides(scan_config):
        if not isinstance(scan_config, dict):
            raise ValueError("scan_config 必须为对象")

        normalized = dict(scan_config)
        profile_id_raw = str(normalized.get("scan_profile_id", "") or "").strip().lower()
        if not profile_id_raw:
            return normalized, ""

        profile_id = SCAN_PROFILE_ID_ALIASES.get(profile_id_raw, profile_id_raw)
        profile = SCAN_PROFILE_MAP.get(profile_id)
        if profile is None:
            raise ValueError("未知扫描预定义配置: {}".format(profile_id_raw))

        merged_config = dict(profile.get("values", {}))
        merged_config.update(normalized)
        merged_config["scan_profile_id"] = profile_id
        return merged_config, profile_id

    def extract(self, config_obj):
        arl_config = config_obj.get("ARL", {}) if isinstance(config_obj, dict) else {}
        if not isinstance(arl_config, dict):
            arl_config = {}

        def value_int(key, default):
            return self._safe_int(arl_config.get(key), default)

        scan_config = {
            "domain_dict": normalize_dict_path_compat(
                arl_config.get("DOMAIN_DICT") or Config.DOMAIN_DICT_2W
            ),
            "file_leak_dict": normalize_dict_path_compat(
                arl_config.get("FILE_LEAK_DICT") or Config.FILE_LEAK_TOP_2k
            ),
            "domain_brute_concurrent": value_int("DOMAIN_BRUTE_CONCURRENT", Config.DOMAIN_BRUTE_CONCURRENT),
            "alt_dns_concurrent": value_int("ALT_DNS_CONCURRENT", Config.ALT_DNS_CONCURRENT),
            "web_gunicorn_workers": value_int("WEB_GUNICORN_WORKERS", Config.WEB_GUNICORN_WORKERS),
            "celery_task_worker_concurrency": value_int("CELERY_TASK_WORKER_CONCURRENCY", Config.CELERY_TASK_WORKER_CONCURRENCY),
            "celery_github_worker_concurrency": value_int("CELERY_GITHUB_WORKER_CONCURRENCY", Config.CELERY_GITHUB_WORKER_CONCURRENCY),
            "celery_heavy_worker_concurrency": value_int("CELERY_HEAVY_WORKER_CONCURRENCY", Config.CELERY_HEAVY_WORKER_CONCURRENCY),
            "celery_web_worker_concurrency": value_int("CELERY_WEB_WORKER_CONCURRENCY", Config.CELERY_WEB_WORKER_CONCURRENCY),
            "celery_prefetch_multiplier": value_int("CELERY_PREFETCH_MULTIPLIER", Config.CELERY_PREFETCH_MULTIPLIER),
            "celery_max_tasks_per_child": value_int("CELERY_MAX_TASKS_PER_CHILD", Config.CELERY_MAX_TASKS_PER_CHILD),
            "celery_max_memory_per_child": value_int("CELERY_MAX_MEMORY_PER_CHILD", Config.CELERY_MAX_MEMORY_PER_CHILD),
            "nuclei_single_target_timeout_sec": value_int("NUCLEI_SINGLE_TARGET_TIMEOUT_SEC", Config.NUCLEI_SINGLE_TARGET_TIMEOUT_SEC),
            "nuclei_rate_limit": value_int("NUCLEI_RATE_LIMIT", Config.NUCLEI_RATE_LIMIT),
            "nuclei_concurrency": value_int("NUCLEI_CONCURRENCY", Config.NUCLEI_CONCURRENCY),
            "nuclei_bulk_size": value_int("NUCLEI_BULK_SIZE", Config.NUCLEI_BULK_SIZE),
            "afrog_concurrency": value_int("AFROG_CONCURRENCY", Config.AFROG_CONCURRENCY),
            "afrog_rate_limit": value_int("AFROG_RATE_LIMIT", Config.AFROG_RATE_LIMIT),
            "poc_update_proxy": str(arl_config.get("POC_UPDATE_PROXY") or getattr(Config, "POC_UPDATE_PROXY", "") or "").strip(),
            "urlfinder_url_probe_enable": self._safe_bool(arl_config.get("URLFINDER_URL_PROBE_ENABLE"), Config.URLFINDER_URL_PROBE_ENABLE),
            "urlfinder_url_probe_max_targets": value_int("URLFINDER_URL_PROBE_MAX_TARGETS", Config.URLFINDER_URL_PROBE_MAX_TARGETS),
            "urlfinder_url_probe_concurrency": value_int("URLFINDER_URL_PROBE_CONCURRENCY", Config.URLFINDER_URL_PROBE_CONCURRENCY),
            "host_timeout_type": self._normalize_host_timeout_type(arl_config.get("HOST_TIMEOUT_TYPE"), Config.HOST_TIMEOUT_TYPE),
            "host_timeout": value_int("HOST_TIMEOUT", Config.HOST_TIMEOUT),
            "port_parallelism": value_int("PORT_PARALLELISM", Config.PORT_PARALLELISM),
            "port_min_rate": value_int("PORT_MIN_RATE", Config.PORT_MIN_RATE),
            "black_ips": self._normalize_string_list(arl_config.get("BLACK_IPS", Config.BLACK_IPS)) or self._normalize_string_list(Config.BLACK_IPS),
            "dns_resolvers": self._normalize_string_list(arl_config.get("DNS_RESOLVERS", Config.DNS_RESOLVERS)),
        }
        scan_config["scan_profile_id"] = self.extract_profile_id(scan_config)
        return scan_config

    def merge(self, config_obj, scan_config):
        scan_config, _ = self.apply_profile_overrides(scan_config)
        domain_dict = str(normalize_dict_path_compat(scan_config.get("domain_dict", "")) or "").strip()
        if not domain_dict:
            raise ValueError("请先选择域名爆破字典")
        if not os.path.isfile(domain_dict):
            raise ValueError("所选域名字典文件不存在，请重新选择")

        arl_config = config_obj.get("ARL", {})
        if not isinstance(arl_config, dict):
            arl_config = {}
        file_leak_dict = str(
            normalize_dict_path_compat(
                scan_config.get("file_leak_dict", "")
                or arl_config.get("FILE_LEAK_DICT")
                or Config.FILE_LEAK_TOP_2k
            )
            or ""
        ).strip()
        if not file_leak_dict:
            raise ValueError("请先选择敏感文件泄漏字典")
        if not os.path.isfile(file_leak_dict):
            raise ValueError("所选敏感文件泄漏字典文件不存在，请重新选择")

        def value_int(key, default):
            return self._safe_int(scan_config.get(key), default)

        black_ips = self._normalize_string_list(scan_config.get("black_ips"))
        if not black_ips:
            raise ValueError("黑名单IP配置不能为空")

        if not isinstance(config_obj.get("ARL"), dict):
            config_obj["ARL"] = {}
        config_obj["ARL"].update(
            {
                "DOMAIN_DICT": domain_dict,
                "FILE_LEAK_DICT": file_leak_dict,
                "DOMAIN_BRUTE_CONCURRENT": value_int("domain_brute_concurrent", Config.DOMAIN_BRUTE_CONCURRENT),
                "ALT_DNS_CONCURRENT": value_int("alt_dns_concurrent", Config.ALT_DNS_CONCURRENT),
                "WEB_GUNICORN_WORKERS": value_int("web_gunicorn_workers", Config.WEB_GUNICORN_WORKERS),
                "CELERY_TASK_WORKER_CONCURRENCY": value_int("celery_task_worker_concurrency", Config.CELERY_TASK_WORKER_CONCURRENCY),
                "CELERY_GITHUB_WORKER_CONCURRENCY": value_int("celery_github_worker_concurrency", Config.CELERY_GITHUB_WORKER_CONCURRENCY),
                "CELERY_HEAVY_WORKER_CONCURRENCY": value_int("celery_heavy_worker_concurrency", Config.CELERY_HEAVY_WORKER_CONCURRENCY),
                "CELERY_WEB_WORKER_CONCURRENCY": value_int("celery_web_worker_concurrency", Config.CELERY_WEB_WORKER_CONCURRENCY),
                "CELERY_PREFETCH_MULTIPLIER": value_int("celery_prefetch_multiplier", Config.CELERY_PREFETCH_MULTIPLIER),
                "CELERY_MAX_TASKS_PER_CHILD": value_int("celery_max_tasks_per_child", Config.CELERY_MAX_TASKS_PER_CHILD),
                "CELERY_MAX_MEMORY_PER_CHILD": value_int("celery_max_memory_per_child", Config.CELERY_MAX_MEMORY_PER_CHILD),
                "NUCLEI_SINGLE_TARGET_TIMEOUT_SEC": value_int("nuclei_single_target_timeout_sec", Config.NUCLEI_SINGLE_TARGET_TIMEOUT_SEC),
                "NUCLEI_RATE_LIMIT": value_int("nuclei_rate_limit", Config.NUCLEI_RATE_LIMIT),
                "NUCLEI_CONCURRENCY": value_int("nuclei_concurrency", Config.NUCLEI_CONCURRENCY),
                "NUCLEI_BULK_SIZE": value_int("nuclei_bulk_size", Config.NUCLEI_BULK_SIZE),
                "AFROG_CONCURRENCY": value_int("afrog_concurrency", Config.AFROG_CONCURRENCY),
                "AFROG_RATE_LIMIT": value_int("afrog_rate_limit", Config.AFROG_RATE_LIMIT),
                "POC_UPDATE_PROXY": str(scan_config.get("poc_update_proxy") or "").strip(),
                "URLFINDER_URL_PROBE_ENABLE": self._safe_bool(scan_config.get("urlfinder_url_probe_enable"), Config.URLFINDER_URL_PROBE_ENABLE),
                "URLFINDER_URL_PROBE_MAX_TARGETS": value_int("urlfinder_url_probe_max_targets", Config.URLFINDER_URL_PROBE_MAX_TARGETS),
                "URLFINDER_URL_PROBE_CONCURRENCY": value_int("urlfinder_url_probe_concurrency", Config.URLFINDER_URL_PROBE_CONCURRENCY),
                "HOST_TIMEOUT_TYPE": self._normalize_host_timeout_type(scan_config.get("host_timeout_type"), Config.HOST_TIMEOUT_TYPE),
                "HOST_TIMEOUT": value_int("host_timeout", Config.HOST_TIMEOUT),
                "PORT_PARALLELISM": value_int("port_parallelism", Config.PORT_PARALLELISM),
                "PORT_MIN_RATE": value_int("port_min_rate", Config.PORT_MIN_RATE),
                "BLACK_IPS": black_ips,
                "DNS_RESOLVERS": self._normalize_string_list(scan_config.get("dns_resolvers")),
            }
        )
        return config_obj
