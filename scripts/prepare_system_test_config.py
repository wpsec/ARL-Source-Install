#!/usr/bin/env python3
"""在一次性快照内生成配置，避免改写宿主部署配置。"""

import os
import re
import sys
from pathlib import Path

import yaml


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: prepare_system_test_config.py PROJECT_NAME")
    project_name = sys.argv[1]
    if not re.fullmatch(r"arl-system-test-[a-z0-9-]+", project_name):
        raise SystemExit("invalid isolated test project name")

    source_root = Path(__file__).resolve().parents[1]
    marker = source_root / ".arl-system-test-snapshot"
    if not marker.is_file():
        raise SystemExit("test snapshot marker is missing")

    rabbit_user = os.environ.get("ARL_TEST_RABBIT_USER", "")
    rabbit_password = os.environ.get("ARL_TEST_RABBIT_PASSWORD", "")
    if not re.fullmatch(r"arltest_[a-f0-9]{16}", rabbit_user):
        raise SystemExit("generated test broker identity is invalid")
    if not re.fullmatch(r"[a-f0-9]{64}", rabbit_password):
        raise SystemExit("generated test broker secret is invalid")

    template_path = source_root / "ARL" / "app" / "config.yaml.example"
    config_path = source_root / "ARL" / "app" / "config.yaml"
    config = yaml.safe_load(template_path.read_text(encoding="utf-8")) or {}
    config.setdefault("MONGO", {})["URI"] = "mongodb://mongodb:27017/arl_system_test"
    config["MONGO"]["DB"] = "arl_system_test"
    config.setdefault("CELERY", {})["BROKER_URL"] = (
        "amqp://{}:{}@rabbitmq:5672/arl-system-test".format(
            rabbit_user, rabbit_password
        )
    )
    redis_config = config.setdefault("REDIS", {})
    redis_config.update({
        "ENABLE": True,
        "HOST": "redis",
        "PORT": 6379,
        "DB": 13,
        "PASSWORD": "",
    })
    config.setdefault("ARL", {})["AUTH"] = True
    config["ARL"]["WEB_GUNICORN_WORKERS"] = 1

    config_path.write_text(
        yaml.safe_dump(config, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    print("已生成隔离测试配置；Mongo、Redis、RabbitMQ 均指向本次 Compose 项目。")


if __name__ == "__main__":
    main()
