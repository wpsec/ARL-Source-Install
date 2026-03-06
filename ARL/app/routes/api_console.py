"""
配置中心接口

用途：
- 在浏览器中读取与修改 ARL 运行配置
- 将配置变更同步到容器挂载的配置文件，避免手工进容器编辑
"""
from datetime import datetime
from pathlib import Path
import json
import os
import tempfile
import threading

import yaml
from flask import request
from flask_restx import Namespace, fields

from app import utils
from app.modules import ErrorMsg
from app.utils import auth, get_logger
from . import ARLResource

ns = Namespace('api_console', description="配置中心")

logger = get_logger()
CONFIG_LOCK = threading.Lock()

save_config_fields = ns.model(
    'SaveDockerConfig',
    {
        'config': fields.Raw(required=True, description='完整配置对象'),
    },
)


def _resolve_config_path() -> Path:
    """
    解析配置文件路径。

    优先级：
    1. 环境变量 ARL_CONFIG_EDIT_PATH（便于定制部署）
    2. 容器运行默认路径 /code/app/config.yaml（compose 挂载自 config-docker.yaml）
    3. 源码仓库路径 ARL/docker/config-docker.yaml（本地开发）
    """
    custom_path = os.environ.get('ARL_CONFIG_EDIT_PATH', '').strip()
    candidates = [
        Path(custom_path) if custom_path else None,
        Path('/code/app/config.yaml'),
        Path(__file__).resolve().parents[2] / 'docker' / 'config-docker.yaml',
    ]

    for item in candidates:
        if not item:
            continue
        if item.exists() and item.is_file():
            return item

    # 所有候选均不存在时，返回本地开发路径用于首写
    return Path(__file__).resolve().parents[2] / 'docker' / 'config-docker.yaml'


def _load_config_from_file(config_path: Path):
    """
    读取 YAML 配置文件，返回字典对象。
    """
    if not config_path.exists():
        return {}

    with config_path.open('r', encoding='utf-8') as file_obj:
        loaded = yaml.safe_load(file_obj) or {}

    if not isinstance(loaded, dict):
        raise ValueError('配置文件根节点必须为对象')

    return loaded


def _ensure_json_like_config(config_obj):
    """
    校验配置对象可序列化，避免写入非法 Python 对象。
    """
    if not isinstance(config_obj, dict):
        raise ValueError('配置必须为对象类型')

    try:
        json.dumps(config_obj, ensure_ascii=False)
    except Exception as exc:
        raise ValueError('配置包含不可序列化内容') from exc


def _atomic_write_yaml(config_path: Path, config_obj: dict):
    """
    原子写入 YAML 文件，避免中途失败导致配置损坏。
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # 先写临时文件，再 replace
    with tempfile.NamedTemporaryFile('w', delete=False, dir=str(config_path.parent), suffix='.tmp', encoding='utf-8') as tmp_file:
        yaml.safe_dump(
            config_obj,
            tmp_file,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
        tmp_path = Path(tmp_file.name)

    tmp_path.replace(config_path)


def _backup_config_file(config_path: Path) -> str:
    """
    创建配置快照备份，返回备份路径。
    """
    if not config_path.exists():
        return ''

    stamp = datetime.now().strftime('%Y%m%d%H%M%S')
    backup_path = config_path.with_name(f'{config_path.name}.bak.{stamp}')
    backup_path.write_text(config_path.read_text(encoding='utf-8'), encoding='utf-8')
    return str(backup_path)


@ns.route('/config/')
class ApiConsoleConfig(ARLResource):
    """
    配置读取与保存接口
    """

    @auth
    def get(self):
        """
        读取当前配置
        """
        config_path = _resolve_config_path()
        try:
            config_obj = _load_config_from_file(config_path)
            data = {
                'config': config_obj,
                'config_path': str(config_path),
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
            return utils.build_ret(ErrorMsg.Success, data)
        except Exception as exc:
            logger.exception('load config failed: %s', exc)
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': str(exc),
                    'config_path': str(config_path),
                }
            )

    @auth
    @ns.expect(save_config_fields)
    def post(self):
        """
        保存配置
        """
        payload = request.get_json(silent=True) or {}
        config_obj = payload.get('config')
        config_path = _resolve_config_path()

        try:
            _ensure_json_like_config(config_obj)
        except Exception as exc:
            return utils.build_ret(ErrorMsg.Error, {'error': str(exc)})

        with CONFIG_LOCK:
            try:
                backup_path = _backup_config_file(config_path)
                _atomic_write_yaml(config_path, config_obj)
            except Exception as exc:
                logger.exception('save config failed: %s', exc)
                return utils.build_ret(
                    ErrorMsg.Error,
                    {
                        'error': str(exc),
                        'config_path': str(config_path),
                    }
                )

        return utils.build_ret(
            ErrorMsg.Success,
            {
                'saved': True,
                'config_path': str(config_path),
                'backup_path': backup_path,
                'saved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
        )
