"""
配置文件存储服务。

配置域的校验和合并由配置中心负责；这里仅处理路径解析、YAML 读写和备份，
避免不同配置域重复实现文件一致性策略。
"""

from pathlib import Path
from datetime import datetime
import errno
import os
import tempfile

import yaml


class ConfigFileStore(object):
    def __init__(self, logger=None):
        self.logger = logger

    def resolve_path(self):
        custom_path = os.environ.get("ARL_CONFIG_EDIT_PATH", "").strip()
        candidates = [
            Path(custom_path) if custom_path else None,
            Path("/code/app/config.yaml"),
            Path(__file__).resolve().parents[2] / "docker" / "config-docker.yaml",
        ]
        for item in candidates:
            if item and item.exists() and item.is_file():
                return item
        return Path(__file__).resolve().parents[2] / "docker" / "config-docker.yaml"

    @staticmethod
    def load(config_path):
        if not config_path.exists():
            return {}

        with config_path.open("r", encoding="utf-8") as file_obj:
            loaded = yaml.safe_load(file_obj) or {}
        if not isinstance(loaded, dict):
            raise ValueError("配置文件根节点必须为对象")
        return loaded

    def atomic_write(self, config_path, config_obj):
        config_path.parent.mkdir(parents=True, exist_ok=True)
        yaml_text = yaml.safe_dump(
            config_obj,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                delete=False,
                dir=str(config_path.parent),
                suffix=".tmp",
                encoding="utf-8",
            ) as tmp_file:
                tmp_file.write(yaml_text)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
                tmp_path = Path(tmp_file.name)
            tmp_path.replace(config_path)
        except OSError as exc:
            if exc.errno not in (errno.EBUSY, errno.EXDEV, errno.EPERM):
                raise
            if self.logger:
                self.logger.warning(
                    "atomic replace failed on mounted config, fallback to direct write: %s",
                    exc,
                )
            with config_path.open("w", encoding="utf-8") as file_obj:
                file_obj.write(yaml_text)
                file_obj.flush()
                os.fsync(file_obj.fileno())
        finally:
            if tmp_path and tmp_path.exists():
                tmp_path.unlink()

    @staticmethod
    def backup(config_path):
        if not config_path.exists():
            return ""
        stamp = datetime.now().strftime("%Y%m%d%H%M%S")
        backup_path = config_path.with_name("{}.bak.{}".format(config_path.name, stamp))
        backup_path.write_text(config_path.read_text(encoding="utf-8"), encoding="utf-8")
        return str(backup_path)
