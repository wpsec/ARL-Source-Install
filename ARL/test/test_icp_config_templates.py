"""ICP 查询配置模板与 Python 默认值的一致性回归测试。"""

import re
import unittest
from pathlib import Path

import yaml


ARL_ROOT = Path(__file__).resolve().parents[1]
ICP_DEFAULTS = {
    "ICP_QUERY_ENABLE": True,
    "ICP_QUERY_TLS_VERIFY": True,
    "ICP_QUERY_TIMEOUT_SEC": 30,
    "ICP_QUERY_RETRY": 2,
    "ICP_QUERY_BATCH_CONCURRENCY": 2,
    "ICP_QUERY_PAGE_SIZE": 26,
    "ICP_QUERY_MAX_ITEMS": 200,
    "ICP_QUERY_MAX_PAGES": 100,
    "ICP_QUERY_KEYWORD_MAX_LENGTH": 255,
    "ICP_QUERY_HISTORY_RETENTION_DAYS": 30,
    "ICP_QUERY_LOG_RETENTION_DAYS": 7,
}
ICP_ENV_KEYS = tuple("ARL_{}".format(key) for key in ICP_DEFAULTS)
ICP_PROXY_DEFAULTS = {
    "IPV6_ENABLE": False,
    "IPV6_REFRESH_SEC": 60,
    "TUNNEL.URL": "",
    "EXTRA_API.URL": "",
    "EXTRA_API.REFRESH_SEC": 180,
    "EXTRA_API.POOL_SIZE": 20,
    "EXTRA_API.CHECK": True,
    "EXTRA_API.CHECK_TIMEOUT_SEC": 5,
    "EXTRA_API.CHECK_CONCURRENCY": 4,
}


class IcpConfigTemplateTest(unittest.TestCase):
    def test_runtime_templates_contain_the_same_icp_defaults(self):
        for relative_path in ("app/config.yaml.example", "docker/config-docker.yaml"):
            path = ARL_ROOT / relative_path
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            arl_config = document.get("ARL") or {}
            for key, expected in ICP_DEFAULTS.items():
                self.assertEqual(
                    expected,
                    arl_config.get(key),
                    "{} 缺少或错误的 {}".format(relative_path, key),
                )

    def test_python_class_defaults_match_template_values(self):
        source = (ARL_ROOT / "app/config.py").read_text(encoding="utf-8")
        for key, expected in ICP_DEFAULTS.items():
            literal = "True" if expected is True else str(expected)
            self.assertRegex(
                source,
                re.compile(r"^\s+{} = {}$".format(key, literal), re.MULTILINE),
                "config.py 缺少 {} 的默认值".format(key),
            )

    def test_icp_proxy_defaults_are_present_in_both_templates(self):
        for relative_path in ("app/config.yaml.example", "docker/config-docker.yaml"):
            path = ARL_ROOT / relative_path
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            proxy = document.get("PROXY") or {}
            icp_proxy = proxy.get("ICP") or {}
            extra_api = icp_proxy.get("EXTRA_API") or {}
            tunnel = icp_proxy.get("TUNNEL") or {}
            actual = {
                "IPV6_ENABLE": icp_proxy.get("IPV6_ENABLE"),
                "IPV6_REFRESH_SEC": icp_proxy.get("IPV6_REFRESH_SEC"),
                "TUNNEL.URL": tunnel.get("URL"),
                "EXTRA_API.URL": extra_api.get("URL"),
                "EXTRA_API.REFRESH_SEC": extra_api.get("REFRESH_SEC"),
                "EXTRA_API.POOL_SIZE": extra_api.get("POOL_SIZE"),
                "EXTRA_API.CHECK": extra_api.get("CHECK"),
                "EXTRA_API.CHECK_TIMEOUT_SEC": extra_api.get("CHECK_TIMEOUT_SEC"),
                "EXTRA_API.CHECK_CONCURRENCY": extra_api.get("CHECK_CONCURRENCY"),
            }
            self.assertEqual(ICP_PROXY_DEFAULTS, actual, relative_path)

    def test_compose_passes_icp_overrides_to_all_runtime_services(self):
        compose = yaml.safe_load(
            (ARL_ROOT / "docker/docker-compose.yml").read_text(encoding="utf-8")
        )
        for service_name in ("web", "worker_1", "worker_2", "scheduler"):
            environment = compose["services"][service_name].get("environment", [])
            lines = environment if isinstance(environment, list) else [
                "{}={}".format(key, value) for key, value in environment.items()
            ]
            for key in ICP_ENV_KEYS:
                self.assertIn(
                    "{}=${{{}-}}".format(key, key),
                    lines,
                    "{} 缺少可选 ICP 环境变量透传 {}".format(service_name, key),
                )


if __name__ == "__main__":
    unittest.main()
