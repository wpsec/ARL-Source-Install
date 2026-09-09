"""ICP 查询配置模板与 Python 默认值的一致性回归测试。"""

import re
import unittest
from pathlib import Path

import yaml


ARL_ROOT = Path(__file__).resolve().parents[1]
ICP_DEFAULTS = {
    "ICP_QUERY_ENABLE": True,
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
