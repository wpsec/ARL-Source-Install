"""端口扫描 effective config 收敛回归(报告§4 前置4)。

三层优先级(默认 < runtime YAML < compose env)曾是漂移根源:
docker-compose 里重复声明 ARL_PORT_SCAN_ALL_TARGET_BATCH_SIZE/BATCH_CONCURRENCY,
会静默压过挂载的 config-runtime.yaml 值,导致性能实验不可复现。
本测试只检查受版本控制的声明面;config-runtime.yaml 是不进 git 的部署文件,不在此读取。
"""

import re
import sys
import unittest
from pathlib import Path

ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))

CONVERGED_KEYS = (
    "ARL_PORT_SCAN_ALL_TARGET_BATCH_SIZE",
    "ARL_PORT_SCAN_BATCH_CONCURRENCY",
)

_DRIFT_ENV_RE = re.compile(
    r"^\s*-\s+(ARL_PORT_SCAN_ALL_TARGET_BATCH_SIZE|ARL_PORT_SCAN_BATCH_CONCURRENCY)\s*="
)


class ComposeNoDuplicateEnvTest(unittest.TestCase):
    def test_compose_does_not_redeclare_batch_keys(self):
        compose = (ARL_ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
        offenders = [line for line in compose.splitlines() if _DRIFT_ENV_RE.match(line)]
        self.assertEqual(
            offenders,
            [],
            "docker-compose 不得重复声明已收敛到 runtime YAML 的端口批次键",
        )


class ExampleYamlMatchesDefaultsTest(unittest.TestCase):
    def test_example_documents_keys_equal_python_defaults(self):
        import yaml

        # 从 app/config.py 源码取默认值:全量运行期 sys.modules["app.config"]
        # 可能是他用例留下的 fake,不能依赖其属性。
        source = (ARL_ROOT / "app" / "config.py").read_text(encoding="utf-8")

        def default_of(key):
            match = re.search(r"^\s+{} = (\d+)$".format(key), source, re.MULTILINE)
            self.assertIsNotNone(match, "config.py 缺少默认值声明 {}".format(key))
            return int(match.group(1))

        example = yaml.safe_load(
            (ARL_ROOT / "app" / "config.yaml.example").read_text(encoding="utf-8")
        )
        arl_section = example.get("ARL") or {}
        self.assertEqual(
            arl_section.get("PORT_SCAN_ALL_TARGET_BATCH_SIZE"),
            default_of("PORT_SCAN_ALL_TARGET_BATCH_SIZE"),
        )
        self.assertEqual(
            arl_section.get("PORT_SCAN_BATCH_CONCURRENCY"),
            default_of("PORT_SCAN_BATCH_CONCURRENCY"),
        )


class EffectiveConfigLogTest(unittest.TestCase):
    def test_config_source_emits_whitelisted_effective_log(self):
        source = (ARL_ROOT / "app" / "config.py").read_text(encoding="utf-8")
        self.assertIn("EFFECTIVE_SCAN_CONFIG", source)
        for key in ("PORT_SCAN_ALL_TARGET_BATCH_SIZE", "PORT_SCAN_BATCH_CONCURRENCY",
                    "TASK_FINALIZER_ENABLE"):
            self.assertIn('"{}"'.format(key), source)

    def test_effective_log_carries_no_secret_bearing_keys(self):
        # 白名单只允许数值/布尔型扫描与预算键;对源码元组内容做静态约束。
        source = (ARL_ROOT / "app" / "config.py").read_text(encoding="utf-8")
        block = source[source.index("_effective_scan_config = {"):]
        block = block[: block.index("\n    print")]
        keys_in_block = re.findall(r'"([A-Z_]+)"', block)
        self.assertGreaterEqual(len(keys_in_block), 10)
        for key in keys_in_block:
            self.assertFalse(
                any(token in key for token in ("KEY", "TOKEN", "PASSWORD", "SECRET", "URI", "URL")),
                "effective config 白名单混入敏感键: {}".format(key),
            )


if __name__ == "__main__":
    unittest.main()
