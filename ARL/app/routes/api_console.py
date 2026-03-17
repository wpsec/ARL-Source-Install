"""
配置中心接口

用途：
- 在浏览器中读取与修改 ARL 运行配置
- 将配置变更同步到容器挂载的配置文件，避免手工进容器编辑
"""
from datetime import datetime
from pathlib import Path
import errno
import json
import os
import tempfile
import threading

import yaml
from flask import request
from flask_restx import Namespace, fields
from werkzeug.utils import secure_filename

from app import utils
from app.config import Config, normalize_dict_path_compat
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

save_scan_config_fields = ns.model(
    'SaveScanConfig',
    {
        'scan_config': fields.Raw(required=True, description='扫描配置对象'),
    },
)

save_service_api_fields = ns.model(
    'SaveServiceApiConfig',
    {
        'service_api': fields.Raw(required=True, description='三方 API 配置对象'),
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
    yaml_text = yaml.safe_dump(
        config_obj,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )

    tmp_path = None
    try:
        # 优先使用临时文件 + replace 的原子写入路径
        with tempfile.NamedTemporaryFile('w', delete=False, dir=str(config_path.parent), suffix='.tmp', encoding='utf-8') as tmp_file:
            tmp_file.write(yaml_text)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            tmp_path = Path(tmp_file.name)

        tmp_path.replace(config_path)
    except OSError as exc:
        # 某些部署里 /code/app/config.yaml 是容器挂载文件，rename 到挂载点会返回 EBUSY
        if exc.errno in (errno.EBUSY, errno.EXDEV, errno.EPERM):
            logger.warning('atomic replace failed on mounted config, fallback to direct write: %s', exc)
            with config_path.open('w', encoding='utf-8') as file_obj:
                file_obj.write(yaml_text)
                file_obj.flush()
                os.fsync(file_obj.fileno())
            return
        raise
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()


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


def _safe_int(value, default_value, min_value=1):
    try:
        parsed = int(value)
    except Exception:
        return int(default_value)

    if parsed < min_value:
        return int(default_value)

    return parsed


def _safe_float(value, default_value, min_value=0.0):
    try:
        parsed = float(value)
    except Exception:
        return float(default_value)

    if parsed < min_value:
        return float(default_value)

    return parsed


def _safe_bool(value, default_value=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'y', 'on')
    return bool(default_value)


def _normalize_host_timeout_type(value, default_value="default"):
    """
    规范化主机超时策略，仅允许 default/custom。
    """
    normalized = str(value or default_value).strip().lower()
    if normalized not in ("default", "custom"):
        normalized = str(default_value or "default").strip().lower()
    if normalized not in ("default", "custom"):
        normalized = "default"
    return normalized


def _normalize_string_list(raw_value):
    """
    兼容 list / str / 其他可迭代输入，输出清洗后的字符串列表。
    """
    if raw_value is None:
        return []

    values = []
    if isinstance(raw_value, list):
        values = raw_value
    elif isinstance(raw_value, str):
        values = raw_value.replace(',', '\n').split('\n')
    else:
        try:
            values = list(raw_value)
        except Exception:
            values = [raw_value]

    cleaned = []
    for item in values:
        item_str = str(item or '').strip()
        if not item_str:
            continue
        cleaned.append(item_str)

    # 去重并保留顺序
    uniq = []
    seen = set()
    for item in cleaned:
        if item in seen:
            continue
        seen.add(item)
        uniq.append(item)

    return uniq


SCAN_PROFILE_ITEMS = [
    {
        'id': '2c2g3m',
        'label': '2核2G3M 保守',
        'description': '适用于低配云主机，优先保证系统可访问性，扫描速度较慢，但能避免CPU、带宽占用过高',
        'cpu_cores': 2,
        'memory_gb': 2,
        'bandwidth_mbps': 3,
        'values': {
            'domain_brute_concurrent': 36,
            'alt_dns_concurrent': 120,
            'web_gunicorn_workers': 1,
            'celery_task_worker_concurrency': 1,
            'celery_github_worker_concurrency': 1,
            'celery_prefetch_multiplier': 1,
            'celery_max_tasks_per_child': 16,
            'celery_max_memory_per_child': 200000,
            'nuclei_single_target_timeout_sec': 3600,
            'nuclei_rate_limit': 2,
            'nuclei_concurrency': 1,
            'nuclei_bulk_size': 2,
            'urlfinder_url_probe_enable': True,
            'urlfinder_url_probe_max_targets': 120,
            'urlfinder_url_probe_concurrency': 2,
            'host_timeout_type': 'default',
            'host_timeout': 1200,
            'port_parallelism': 8,
            'port_min_rate': 24,
        },
    },
    {
        'id': '4c4g5m',
        'label': '4核4G5M 平衡',
        'description': '适用于中配主机，在可用性与扫描速度之间平衡，适合常规生产巡检。',
        'cpu_cores': 4,
        'memory_gb': 4,
        'bandwidth_mbps': 5,
        'values': {
            'domain_brute_concurrent': 96,
            'alt_dns_concurrent': 320,
            'web_gunicorn_workers': 2,
            'celery_task_worker_concurrency': 2,
            'celery_github_worker_concurrency': 1,
            'celery_prefetch_multiplier': 1,
            'celery_max_tasks_per_child': 20,
            'celery_max_memory_per_child': 280000,
            'nuclei_single_target_timeout_sec': 7200,
            'nuclei_rate_limit': 4,
            'nuclei_concurrency': 2,
            'nuclei_bulk_size': 3,
            'urlfinder_url_probe_enable': True,
            'urlfinder_url_probe_max_targets': 220,
            'urlfinder_url_probe_concurrency': 4,
            'host_timeout_type': 'default',
            'host_timeout': 1200,
            'port_parallelism': 16,
            'port_min_rate': 48,
        },
    },
    {
        'id': '8c16g10m',
        'label': '8核16G10M 高性能',
        'description': '适用于高配主机，提升扫描吞吐并保持管理面可用，不建议继续无限加并发。',
        'cpu_cores': 8,
        'memory_gb': 16,
        'bandwidth_mbps': 10,
        'values': {
            'domain_brute_concurrent': 180,
            'alt_dns_concurrent': 640,
            'web_gunicorn_workers': 3,
            'celery_task_worker_concurrency': 4,
            'celery_github_worker_concurrency': 2,
            'celery_prefetch_multiplier': 1,
            'celery_max_tasks_per_child': 30,
            'celery_max_memory_per_child': 420000,
            'nuclei_single_target_timeout_sec': 10800,
            'nuclei_rate_limit': 8,
            'nuclei_concurrency': 4,
            'nuclei_bulk_size': 5,
            'urlfinder_url_probe_enable': True,
            'urlfinder_url_probe_max_targets': 300,
            'urlfinder_url_probe_concurrency': 8,
            'host_timeout_type': 'default',
            'host_timeout': 1500,
            'port_parallelism': 28,
            'port_min_rate': 96,
        },
    },
]
SCAN_PROFILE_MAP = {item['id']: item for item in SCAN_PROFILE_ITEMS}


def _extract_scan_profile_id(scan_config):
    """
    根据当前扫描参数匹配预定义硬件配置，完全匹配时返回 profile id。
    """
    if not isinstance(scan_config, dict):
        return ''

    for profile in SCAN_PROFILE_ITEMS:
        profile_values = profile.get('values', {})
        matched = True
        for key, value in profile_values.items():
            if scan_config.get(key) != value:
                matched = False
                break
        if matched:
            return profile['id']
    return ''


def _build_scan_profiles_payload(active_profile_id=''):
    """
    组装扫描预定义配置返回结构，供前端展示与一键应用。
    """
    payload = []
    for profile in SCAN_PROFILE_ITEMS:
        payload.append(
            {
                'id': profile['id'],
                'label': profile['label'],
                'description': profile['description'],
                'cpu_cores': profile['cpu_cores'],
                'memory_gb': profile['memory_gb'],
                'bandwidth_mbps': profile['bandwidth_mbps'],
                'selected': bool(active_profile_id and active_profile_id == profile['id']),
                'values': dict(profile.get('values', {})),
            }
        )
    return payload


def _apply_scan_profile_overrides(scan_config):
    """
    若提交了 scan_profile_id，则先注入预定义参数，再应用请求中的显式覆盖项。
    """
    if not isinstance(scan_config, dict):
        raise ValueError('scan_config 必须为对象')

    normalized = dict(scan_config)
    profile_id = str(normalized.get('scan_profile_id', '') or '').strip().lower()
    if not profile_id:
        return normalized, ''

    profile = SCAN_PROFILE_MAP.get(profile_id)
    if profile is None:
        raise ValueError(f'未知扫描预定义配置: {profile_id}')

    merged_config = dict(profile.get('values', {}))
    merged_config.update(normalized)
    merged_config['scan_profile_id'] = profile_id
    return merged_config, profile_id


def _resolve_domain_dict_custom_dir() -> Path:
    """
    解析域名爆破自定义字典目录。
    优先读取环境变量，未配置时回落到内置域名字典目录。
    """
    custom_path = os.environ.get('ARL_DOMAIN_DICT_CUSTOM_DIR', '').strip()
    if custom_path:
        return Path(custom_path)

    return Path(Config.DOMAIN_DICT_TEST).resolve().parent


def _resolve_domain_dict_upload_dir() -> Path:
    """
    解析扫描字典上传目录。
    默认使用“自定义字典目录/uploaded”，可通过环境变量覆盖。
    """
    custom_path = os.environ.get('ARL_DOMAIN_DICT_UPLOAD_DIR', '').strip()
    if custom_path:
        return Path(custom_path)

    return _resolve_domain_dict_custom_dir() / 'uploaded'


def _resolve_file_leak_dict_custom_dir() -> Path:
    """
    解析敏感文件泄漏自定义字典目录。
    优先读取环境变量，未配置时回落到内置字典目录。
    """
    custom_path = os.environ.get('ARL_FILE_LEAK_DICT_CUSTOM_DIR', '').strip()
    if custom_path:
        return Path(custom_path)

    return Path(Config.FILE_LEAK_TOP_200).resolve().parent


def _resolve_file_leak_dict_upload_dir() -> Path:
    """
    解析敏感文件泄漏字典上传目录。
    默认使用“自定义字典目录/uploaded”，可通过环境变量覆盖。
    """
    custom_path = os.environ.get('ARL_FILE_LEAK_DICT_UPLOAD_DIR', '').strip()
    if custom_path:
        return Path(custom_path)

    return _resolve_file_leak_dict_custom_dir() / 'uploaded'


def _safe_resolve_path(path_obj: Path) -> Path:
    """
    尝试 resolve 绝对路径；失败时回退原路径，避免因权限/软链异常中断。
    """
    try:
        return path_obj.resolve()
    except Exception:
        return path_obj


def _is_path_within(path_obj: Path, root_obj: Path) -> bool:
    """
    判断路径是否位于指定根目录下（兼容 Python 3.8+）。
    """
    try:
        _safe_resolve_path(path_obj).relative_to(_safe_resolve_path(root_obj))
        return True
    except Exception:
        return False


def _collect_domain_dict_options(current_path=''):
    """
    收集可选域名爆破字典列表：
    - 内置字典
    - 上传目录字典
    - 当前配置引用但未收录的字典
    """
    current_path = str(current_path or '').strip()
    options = []
    seen = set()

    builtin_domain_dir = _safe_resolve_path(Path(Config.DOMAIN_DICT_TEST).parent)
    custom_domain_dir = _safe_resolve_path(_resolve_domain_dict_custom_dir())
    upload_dir = _safe_resolve_path(_resolve_domain_dict_upload_dir())

    def add_option(path_obj: Path, source='custom', label=''):
        path_obj = _safe_resolve_path(path_obj)
        path_str = str(path_obj)
        if path_str in seen:
            return
        seen.add(path_str)

        exists = path_obj.exists() and path_obj.is_file()
        file_size = 0
        if exists:
            try:
                file_size = int(path_obj.stat().st_size)
            except Exception:
                file_size = 0

        # 将目录结构折叠进标签，避免同名字典无法区分。
        option_label = label or path_obj.name or path_str
        if not label and source in {'custom', 'uploaded'}:
            relative_name = ''
            base_dir = upload_dir if source == 'uploaded' else custom_domain_dir
            try:
                relative_name = str(path_obj.relative_to(base_dir))
            except Exception:
                relative_name = path_obj.name
            if relative_name:
                option_label = relative_name

        option = {
            'label': option_label,
            'path': path_str,
            'source': source,
            'exists': exists,
            'size': file_size,
            'selected': bool(current_path and current_path == path_str),
        }
        options.append(option)

    builtin_test_path = _safe_resolve_path(Path(Config.DOMAIN_DICT_TEST))
    builtin_large_path = _safe_resolve_path(builtin_domain_dir / 'domain_2w.txt')
    add_option(builtin_test_path, source='builtin', label='测试字典 (domain_dict_test.txt)')
    add_option(builtin_large_path, source='builtin', label='大字典 (domain_2w.txt)')

    if upload_dir.exists() and upload_dir.is_dir():
        for dict_file in sorted(upload_dir.rglob('*.txt')):
            if dict_file.is_file():
                add_option(dict_file, source='uploaded')

    custom_scan_dirs = [custom_domain_dir]
    if str(builtin_domain_dir) != str(custom_domain_dir):
        custom_scan_dirs.append(builtin_domain_dir)

    for scan_dir in custom_scan_dirs:
        if not scan_dir.exists() or not scan_dir.is_dir():
            continue
        for dict_file in sorted(scan_dir.rglob('*.txt')):
            if not dict_file.is_file():
                continue
            if _is_path_within(dict_file, upload_dir):
                continue
            if _is_path_within(dict_file, builtin_domain_dir):
                file_name = dict_file.name.lower()
                if file_name in {'domain_dict_test.txt', 'domain_2w.txt'}:
                    continue
            add_option(dict_file, source='custom')

    if current_path and current_path not in seen:
        add_option(Path(current_path), source='custom')

    return options


def _collect_file_leak_dict_options(current_path=''):
    """
    收集可选敏感文件泄漏字典列表：
    - 内置字典
    - 上传目录字典
    - 当前配置引用但未收录的字典
    """
    current_path = str(current_path or '').strip()
    options = []
    seen = set()

    builtin_file_leak_dir = _safe_resolve_path(Path(Config.FILE_LEAK_TOP_200).parent)
    custom_file_leak_dir = _safe_resolve_path(_resolve_file_leak_dict_custom_dir())
    upload_dir = _safe_resolve_path(_resolve_file_leak_dict_upload_dir())

    def add_option(path_obj: Path, source='custom', label=''):
        path_obj = _safe_resolve_path(path_obj)
        path_str = str(path_obj)
        if path_str in seen:
            return
        seen.add(path_str)

        exists = path_obj.exists() and path_obj.is_file()
        file_size = 0
        if exists:
            try:
                file_size = int(path_obj.stat().st_size)
            except Exception:
                file_size = 0

        option_label = label or path_obj.name or path_str
        if not label and source in {'custom', 'uploaded'}:
            relative_name = ''
            base_dir = upload_dir if source == 'uploaded' else custom_file_leak_dir
            try:
                relative_name = str(path_obj.relative_to(base_dir))
            except Exception:
                relative_name = path_obj.name
            if relative_name:
                option_label = relative_name

        option = {
            'label': option_label,
            'path': path_str,
            'source': source,
            'exists': exists,
            'size': file_size,
            'selected': bool(current_path and current_path == path_str),
        }
        options.append(option)

    builtin_test_path = _safe_resolve_path(Path(Config.FILE_LEAK_TOP_200).parent / 'file_test.txt')
    builtin_quick_path = _safe_resolve_path(Path(Config.FILE_LEAK_TOP_200))
    builtin_full_path = _safe_resolve_path(Path(Config.FILE_LEAK_TOP_2k))
    add_option(builtin_test_path, source='builtin', label='测试字典 (file_test.txt)')
    add_option(builtin_quick_path, source='builtin', label='快速字典 (file_top_200.txt)')
    add_option(builtin_full_path, source='builtin', label='完整字典 (file_top_2000.txt)')

    if upload_dir.exists() and upload_dir.is_dir():
        for dict_file in sorted(upload_dir.rglob('*.txt')):
            if dict_file.is_file():
                add_option(dict_file, source='uploaded')

    custom_scan_dirs = [custom_file_leak_dir]
    if str(builtin_file_leak_dir) != str(custom_file_leak_dir):
        custom_scan_dirs.append(builtin_file_leak_dir)

    for scan_dir in custom_scan_dirs:
        if not scan_dir.exists() or not scan_dir.is_dir():
            continue
        for dict_file in sorted(scan_dir.rglob('*.txt')):
            if not dict_file.is_file():
                continue
            if _is_path_within(dict_file, upload_dir):
                continue
            if _is_path_within(dict_file, builtin_file_leak_dir):
                file_name = dict_file.name.lower()
                if file_name in {'file_test.txt', 'file_top_200.txt', 'file_top_2000.txt'}:
                    continue
            add_option(dict_file, source='custom')

    if current_path and current_path not in seen:
        add_option(Path(current_path), source='custom')

    return options


def _extract_service_api_config(config_obj):
    """
    从完整配置中提取 FOFA / Hunter / Zoomeye 等 API 配置。
    """
    fofa_conf = config_obj.get('FOFA', {})
    if not isinstance(fofa_conf, dict):
        fofa_conf = {}

    riskiq_conf = config_obj.get('RISKIQ', {})
    if not isinstance(riskiq_conf, dict):
        riskiq_conf = {}

    query_plugin = config_obj.get('QUERY_PLUGIN', {})
    if not isinstance(query_plugin, dict):
        query_plugin = {}
    github_conf = config_obj.get('GITHUB', {})
    if not isinstance(github_conf, dict):
        github_conf = {}

    def plugin_config(name):
        plugin = query_plugin.get(name, {})
        if not isinstance(plugin, dict):
            return {}
        return plugin

    fofa_plugin = plugin_config('fofa')
    certspotter_plugin = plugin_config('certspotter')
    hunter_plugin = plugin_config('hunter_qax')
    quake_plugin = plugin_config('quake_360')
    zoomeye_plugin = plugin_config('zoomeye')
    securitytrails_plugin = plugin_config('securitytrails')
    virustotal_plugin = plugin_config('virustotal')
    chaos_plugin = plugin_config('chaos')
    passivetotal_plugin = plugin_config('passivetotal')

    passivetotal_email = str(
        passivetotal_plugin.get('auth_email') or
        riskiq_conf.get('EMAIL') or
        ''
    )
    passivetotal_key = str(
        passivetotal_plugin.get('auth_key') or
        riskiq_conf.get('KEY') or
        ''
    )

    return {
        'fofa_url': str(fofa_conf.get('URL') or Config.FOFA_URL or 'https://fofa.info'),
        'fofa_email': str(fofa_conf.get('EMAIL') or Config.FOFA_EMAIL or ''),
        'fofa_key': str(fofa_conf.get('KEY') or Config.FOFA_KEY or ''),
        'fofa_enable': _safe_bool(fofa_plugin.get('enable'), True),
        'certspotter_enable': _safe_bool(certspotter_plugin.get('enable'), True),
        'hunter_api_key': str(hunter_plugin.get('api_key') or ''),
        'hunter_enable': _safe_bool(hunter_plugin.get('enable'), True),
        'hunter_request_interval': _safe_float(hunter_plugin.get('request_interval'), 1.0, min_value=0.0),
        'hunter_rate_limit_retry': _safe_int(hunter_plugin.get('rate_limit_retry'), 4, min_value=0),
        'hunter_rate_limit_backoff': _safe_int(hunter_plugin.get('rate_limit_backoff'), 2, min_value=1),
        'hunter_rate_limit_max_sleep': _safe_int(hunter_plugin.get('rate_limit_max_sleep'), 60, min_value=1),
        'quake_token': str(quake_plugin.get('quake_token') or ''),
        'quake_enable': _safe_bool(quake_plugin.get('enable'), True),
        'quake_rate_limit_retry': _safe_int(quake_plugin.get('rate_limit_retry'), 4, min_value=0),
        'quake_rate_limit_backoff': _safe_int(quake_plugin.get('rate_limit_backoff'), 3, min_value=1),
        'quake_rate_limit_max_sleep': _safe_int(quake_plugin.get('rate_limit_max_sleep'), 90, min_value=1),
        'zoomeye_api_key': str(zoomeye_plugin.get('api_key') or ''),
        'zoomeye_enable': _safe_bool(zoomeye_plugin.get('enable'), True),
        'securitytrails_api_key': str(securitytrails_plugin.get('api_key') or ''),
        'securitytrails_enable': _safe_bool(securitytrails_plugin.get('enable'), False),
        'virustotal_api_key': str(virustotal_plugin.get('api_key') or ''),
        'virustotal_enable': _safe_bool(virustotal_plugin.get('enable'), True),
        'chaos_api_key': str(chaos_plugin.get('api_key') or ''),
        'chaos_enable': _safe_bool(chaos_plugin.get('enable'), False),
        'passivetotal_email': passivetotal_email,
        'passivetotal_key': passivetotal_key,
        'passivetotal_enable': _safe_bool(passivetotal_plugin.get('enable'), False),
        # GitHub 搜索独立走 GITHUB.TOKEN，不属于 QUERY_PLUGIN。
        'github_token': str(github_conf.get('TOKEN') or Config.GITHUB_TOKEN or ''),
    }


def _merge_service_api_config(config_obj, service_api):
    """
    将三方 API 配置写回完整配置对象。
    """
    if not isinstance(service_api, dict):
        raise ValueError('service_api 必须为对象')

    if not isinstance(config_obj.get('FOFA'), dict):
        config_obj['FOFA'] = {}
    if not isinstance(config_obj.get('QUERY_PLUGIN'), dict):
        config_obj['QUERY_PLUGIN'] = {}
    if not isinstance(config_obj.get('RISKIQ'), dict):
        config_obj['RISKIQ'] = {}
    if not isinstance(config_obj.get('GITHUB'), dict):
        config_obj['GITHUB'] = {}

    query_plugin = config_obj['QUERY_PLUGIN']

    def ensure_plugin(name):
        plugin = query_plugin.get(name)
        if not isinstance(plugin, dict):
            plugin = {}
        query_plugin[name] = plugin
        return plugin

    fofa_url = str(service_api.get('fofa_url', '')).strip() or 'https://fofa.info'
    fofa_email = str(service_api.get('fofa_email', '')).strip()
    fofa_key = str(service_api.get('fofa_key', '')).strip()

    config_obj['FOFA']['URL'] = fofa_url
    config_obj['FOFA']['EMAIL'] = fofa_email
    config_obj['FOFA']['KEY'] = fofa_key

    fofa_plugin = ensure_plugin('fofa')
    fofa_plugin['enable'] = _safe_bool(service_api.get('fofa_enable'), fofa_plugin.get('enable', True))

    certspotter_plugin = ensure_plugin('certspotter')
    certspotter_plugin['enable'] = _safe_bool(service_api.get('certspotter_enable'), certspotter_plugin.get('enable', True))

    hunter_plugin = ensure_plugin('hunter_qax')
    hunter_plugin['api_key'] = str(service_api.get('hunter_api_key', '')).strip()
    hunter_plugin['enable'] = _safe_bool(service_api.get('hunter_enable'), hunter_plugin.get('enable', True))
    hunter_plugin['request_interval'] = _safe_float(
        service_api.get('hunter_request_interval'),
        hunter_plugin.get('request_interval', 1.0),
        min_value=0.0
    )
    hunter_plugin['rate_limit_retry'] = _safe_int(
        service_api.get('hunter_rate_limit_retry'),
        hunter_plugin.get('rate_limit_retry', 4),
        min_value=0
    )
    hunter_plugin['rate_limit_backoff'] = _safe_int(
        service_api.get('hunter_rate_limit_backoff'),
        hunter_plugin.get('rate_limit_backoff', 2),
        min_value=1
    )
    hunter_plugin['rate_limit_max_sleep'] = _safe_int(
        service_api.get('hunter_rate_limit_max_sleep'),
        hunter_plugin.get('rate_limit_max_sleep', 60),
        min_value=1
    )

    quake_plugin = ensure_plugin('quake_360')
    quake_plugin['quake_token'] = str(service_api.get('quake_token', '')).strip()
    quake_plugin['enable'] = _safe_bool(service_api.get('quake_enable'), quake_plugin.get('enable', True))
    quake_plugin['rate_limit_retry'] = _safe_int(
        service_api.get('quake_rate_limit_retry'),
        quake_plugin.get('rate_limit_retry', 4),
        min_value=0
    )
    quake_plugin['rate_limit_backoff'] = _safe_int(
        service_api.get('quake_rate_limit_backoff'),
        quake_plugin.get('rate_limit_backoff', 3),
        min_value=1
    )
    quake_plugin['rate_limit_max_sleep'] = _safe_int(
        service_api.get('quake_rate_limit_max_sleep'),
        quake_plugin.get('rate_limit_max_sleep', 90),
        min_value=1
    )

    zoomeye_plugin = ensure_plugin('zoomeye')
    zoomeye_plugin['api_key'] = str(service_api.get('zoomeye_api_key', '')).strip()
    zoomeye_plugin['enable'] = _safe_bool(service_api.get('zoomeye_enable'), zoomeye_plugin.get('enable', True))

    securitytrails_plugin = ensure_plugin('securitytrails')
    securitytrails_plugin['api_key'] = str(service_api.get('securitytrails_api_key', '')).strip()
    securitytrails_plugin['enable'] = _safe_bool(
        service_api.get('securitytrails_enable'),
        securitytrails_plugin.get('enable', False)
    )

    virustotal_plugin = ensure_plugin('virustotal')
    virustotal_plugin['api_key'] = str(service_api.get('virustotal_api_key', '')).strip()
    virustotal_plugin['enable'] = _safe_bool(service_api.get('virustotal_enable'), virustotal_plugin.get('enable', True))

    chaos_plugin = ensure_plugin('chaos')
    chaos_plugin['api_key'] = str(service_api.get('chaos_api_key', '')).strip()
    chaos_plugin['enable'] = _safe_bool(service_api.get('chaos_enable'), chaos_plugin.get('enable', False))

    passivetotal_email = str(service_api.get('passivetotal_email', '')).strip()
    passivetotal_key = str(service_api.get('passivetotal_key', '')).strip()
    passivetotal_plugin = ensure_plugin('passivetotal')
    passivetotal_plugin['auth_email'] = passivetotal_email
    passivetotal_plugin['auth_key'] = passivetotal_key
    passivetotal_plugin['enable'] = _safe_bool(
        service_api.get('passivetotal_enable'),
        passivetotal_plugin.get('enable', False)
    )

    # 保留对旧字段的兼容（某些部署仍沿用 RISKIQ）
    config_obj['RISKIQ']['EMAIL'] = passivetotal_email
    config_obj['RISKIQ']['KEY'] = passivetotal_key

    # GitHub 搜索任务凭据（用于 github_task / github_scheduler）。
    config_obj['GITHUB']['TOKEN'] = str(service_api.get('github_token', '')).strip()

    return config_obj


def _extract_scan_config(config_obj):
    """
    从完整配置中提取扫描配置子集。
    """
    arl_config = config_obj.get('ARL', {})
    if not isinstance(arl_config, dict):
        arl_config = {}

    # 兼容历史路径：页面展示时统一折叠到当前可用路径。
    domain_dict = normalize_dict_path_compat(arl_config.get('DOMAIN_DICT') or Config.DOMAIN_DICT_2W)
    file_leak_dict = normalize_dict_path_compat(arl_config.get('FILE_LEAK_DICT') or Config.FILE_LEAK_TOP_2k)
    domain_brute_concurrent = _safe_int(
        arl_config.get('DOMAIN_BRUTE_CONCURRENT'),
        Config.DOMAIN_BRUTE_CONCURRENT
    )
    alt_dns_concurrent = _safe_int(
        arl_config.get('ALT_DNS_CONCURRENT'),
        Config.ALT_DNS_CONCURRENT
    )
    web_gunicorn_workers = _safe_int(
        arl_config.get('WEB_GUNICORN_WORKERS'),
        Config.WEB_GUNICORN_WORKERS
    )
    celery_task_worker_concurrency = _safe_int(
        arl_config.get('CELERY_TASK_WORKER_CONCURRENCY'),
        Config.CELERY_TASK_WORKER_CONCURRENCY
    )
    celery_github_worker_concurrency = _safe_int(
        arl_config.get('CELERY_GITHUB_WORKER_CONCURRENCY'),
        Config.CELERY_GITHUB_WORKER_CONCURRENCY
    )
    celery_prefetch_multiplier = _safe_int(
        arl_config.get('CELERY_PREFETCH_MULTIPLIER'),
        Config.CELERY_PREFETCH_MULTIPLIER
    )
    celery_max_tasks_per_child = _safe_int(
        arl_config.get('CELERY_MAX_TASKS_PER_CHILD'),
        Config.CELERY_MAX_TASKS_PER_CHILD
    )
    celery_max_memory_per_child = _safe_int(
        arl_config.get('CELERY_MAX_MEMORY_PER_CHILD'),
        Config.CELERY_MAX_MEMORY_PER_CHILD
    )
    nuclei_single_target_timeout_sec = _safe_int(
        arl_config.get('NUCLEI_SINGLE_TARGET_TIMEOUT_SEC'),
        Config.NUCLEI_SINGLE_TARGET_TIMEOUT_SEC
    )
    nuclei_rate_limit = _safe_int(
        arl_config.get('NUCLEI_RATE_LIMIT'),
        Config.NUCLEI_RATE_LIMIT
    )
    nuclei_concurrency = _safe_int(
        arl_config.get('NUCLEI_CONCURRENCY'),
        Config.NUCLEI_CONCURRENCY
    )
    nuclei_bulk_size = _safe_int(
        arl_config.get('NUCLEI_BULK_SIZE'),
        Config.NUCLEI_BULK_SIZE
    )
    urlfinder_url_probe_enable = _safe_bool(
        arl_config.get('URLFINDER_URL_PROBE_ENABLE'),
        Config.URLFINDER_URL_PROBE_ENABLE
    )
    urlfinder_url_probe_max_targets = _safe_int(
        arl_config.get('URLFINDER_URL_PROBE_MAX_TARGETS'),
        Config.URLFINDER_URL_PROBE_MAX_TARGETS
    )
    urlfinder_url_probe_concurrency = _safe_int(
        arl_config.get('URLFINDER_URL_PROBE_CONCURRENCY'),
        Config.URLFINDER_URL_PROBE_CONCURRENCY
    )
    host_timeout_type = _normalize_host_timeout_type(
        arl_config.get('HOST_TIMEOUT_TYPE'),
        Config.HOST_TIMEOUT_TYPE
    )
    host_timeout = _safe_int(
        arl_config.get('HOST_TIMEOUT'),
        Config.HOST_TIMEOUT
    )
    port_parallelism = _safe_int(
        arl_config.get('PORT_PARALLELISM'),
        Config.PORT_PARALLELISM
    )
    port_min_rate = _safe_int(
        arl_config.get('PORT_MIN_RATE'),
        Config.PORT_MIN_RATE
    )
    black_ips = _normalize_string_list(arl_config.get('BLACK_IPS', Config.BLACK_IPS))
    if not black_ips:
        black_ips = _normalize_string_list(Config.BLACK_IPS)
    dns_resolvers = _normalize_string_list(arl_config.get('DNS_RESOLVERS', Config.DNS_RESOLVERS))

    scan_config = {
        'domain_dict': domain_dict,
        'file_leak_dict': file_leak_dict,
        'domain_brute_concurrent': domain_brute_concurrent,
        'alt_dns_concurrent': alt_dns_concurrent,
        'web_gunicorn_workers': web_gunicorn_workers,
        'celery_task_worker_concurrency': celery_task_worker_concurrency,
        'celery_github_worker_concurrency': celery_github_worker_concurrency,
        'celery_prefetch_multiplier': celery_prefetch_multiplier,
        'celery_max_tasks_per_child': celery_max_tasks_per_child,
        'celery_max_memory_per_child': celery_max_memory_per_child,
        'nuclei_single_target_timeout_sec': nuclei_single_target_timeout_sec,
        'nuclei_rate_limit': nuclei_rate_limit,
        'nuclei_concurrency': nuclei_concurrency,
        'nuclei_bulk_size': nuclei_bulk_size,
        'urlfinder_url_probe_enable': urlfinder_url_probe_enable,
        'urlfinder_url_probe_max_targets': urlfinder_url_probe_max_targets,
        'urlfinder_url_probe_concurrency': urlfinder_url_probe_concurrency,
        'host_timeout_type': host_timeout_type,
        'host_timeout': host_timeout,
        'port_parallelism': port_parallelism,
        'port_min_rate': port_min_rate,
        'black_ips': black_ips,
        'dns_resolvers': dns_resolvers,
    }

    scan_config['scan_profile_id'] = _extract_scan_profile_id(scan_config)
    return scan_config


def _merge_scan_config(config_obj, scan_config):
    """
    将扫描配置写回完整配置对象（仅修改 ARL 下指定字段）。
    """
    scan_config, _ = _apply_scan_profile_overrides(scan_config)

    domain_dict = normalize_dict_path_compat(scan_config.get('domain_dict', ''))
    domain_dict = str(domain_dict or '').strip()
    if not domain_dict:
        raise ValueError('请先选择域名爆破字典')
    if not os.path.isfile(domain_dict):
        raise ValueError('所选域名字典文件不存在，请重新选择')

    arl_config = config_obj.get('ARL', {})
    if not isinstance(arl_config, dict):
        arl_config = {}

    file_leak_dict = normalize_dict_path_compat(
        scan_config.get('file_leak_dict', '') or
        arl_config.get('FILE_LEAK_DICT') or
        Config.FILE_LEAK_TOP_2k
    )
    file_leak_dict = str(file_leak_dict or '').strip()
    if not file_leak_dict:
        raise ValueError('请先选择敏感文件泄漏字典')
    if not os.path.isfile(file_leak_dict):
        raise ValueError('所选敏感文件泄漏字典文件不存在，请重新选择')

    domain_brute_concurrent = _safe_int(
        scan_config.get('domain_brute_concurrent'),
        Config.DOMAIN_BRUTE_CONCURRENT
    )
    alt_dns_concurrent = _safe_int(
        scan_config.get('alt_dns_concurrent'),
        Config.ALT_DNS_CONCURRENT
    )
    web_gunicorn_workers = _safe_int(
        scan_config.get('web_gunicorn_workers'),
        Config.WEB_GUNICORN_WORKERS
    )
    celery_task_worker_concurrency = _safe_int(
        scan_config.get('celery_task_worker_concurrency'),
        Config.CELERY_TASK_WORKER_CONCURRENCY
    )
    celery_github_worker_concurrency = _safe_int(
        scan_config.get('celery_github_worker_concurrency'),
        Config.CELERY_GITHUB_WORKER_CONCURRENCY
    )
    celery_prefetch_multiplier = _safe_int(
        scan_config.get('celery_prefetch_multiplier'),
        Config.CELERY_PREFETCH_MULTIPLIER
    )
    celery_max_tasks_per_child = _safe_int(
        scan_config.get('celery_max_tasks_per_child'),
        Config.CELERY_MAX_TASKS_PER_CHILD
    )
    celery_max_memory_per_child = _safe_int(
        scan_config.get('celery_max_memory_per_child'),
        Config.CELERY_MAX_MEMORY_PER_CHILD
    )
    nuclei_single_target_timeout_sec = _safe_int(
        scan_config.get('nuclei_single_target_timeout_sec'),
        Config.NUCLEI_SINGLE_TARGET_TIMEOUT_SEC
    )
    nuclei_rate_limit = _safe_int(
        scan_config.get('nuclei_rate_limit'),
        Config.NUCLEI_RATE_LIMIT
    )
    nuclei_concurrency = _safe_int(
        scan_config.get('nuclei_concurrency'),
        Config.NUCLEI_CONCURRENCY
    )
    nuclei_bulk_size = _safe_int(
        scan_config.get('nuclei_bulk_size'),
        Config.NUCLEI_BULK_SIZE
    )
    urlfinder_url_probe_enable = _safe_bool(
        scan_config.get('urlfinder_url_probe_enable'),
        Config.URLFINDER_URL_PROBE_ENABLE
    )
    urlfinder_url_probe_max_targets = _safe_int(
        scan_config.get('urlfinder_url_probe_max_targets'),
        Config.URLFINDER_URL_PROBE_MAX_TARGETS
    )
    urlfinder_url_probe_concurrency = _safe_int(
        scan_config.get('urlfinder_url_probe_concurrency'),
        Config.URLFINDER_URL_PROBE_CONCURRENCY
    )
    host_timeout_type = _normalize_host_timeout_type(
        scan_config.get('host_timeout_type'),
        Config.HOST_TIMEOUT_TYPE
    )
    host_timeout = _safe_int(
        scan_config.get('host_timeout'),
        Config.HOST_TIMEOUT
    )
    port_parallelism = _safe_int(
        scan_config.get('port_parallelism'),
        Config.PORT_PARALLELISM
    )
    port_min_rate = _safe_int(
        scan_config.get('port_min_rate'),
        Config.PORT_MIN_RATE
    )
    black_ips = _normalize_string_list(scan_config.get('black_ips'))
    dns_resolvers = _normalize_string_list(scan_config.get('dns_resolvers'))

    if not black_ips:
        raise ValueError('黑名单IP配置不能为空')

    if not isinstance(config_obj.get('ARL'), dict):
        config_obj['ARL'] = {}

    config_obj['ARL']['DOMAIN_DICT'] = domain_dict
    config_obj['ARL']['FILE_LEAK_DICT'] = file_leak_dict
    config_obj['ARL']['DOMAIN_BRUTE_CONCURRENT'] = domain_brute_concurrent
    config_obj['ARL']['ALT_DNS_CONCURRENT'] = alt_dns_concurrent
    config_obj['ARL']['WEB_GUNICORN_WORKERS'] = web_gunicorn_workers
    config_obj['ARL']['CELERY_TASK_WORKER_CONCURRENCY'] = celery_task_worker_concurrency
    config_obj['ARL']['CELERY_GITHUB_WORKER_CONCURRENCY'] = celery_github_worker_concurrency
    config_obj['ARL']['CELERY_PREFETCH_MULTIPLIER'] = celery_prefetch_multiplier
    config_obj['ARL']['CELERY_MAX_TASKS_PER_CHILD'] = celery_max_tasks_per_child
    config_obj['ARL']['CELERY_MAX_MEMORY_PER_CHILD'] = celery_max_memory_per_child
    config_obj['ARL']['NUCLEI_SINGLE_TARGET_TIMEOUT_SEC'] = nuclei_single_target_timeout_sec
    config_obj['ARL']['NUCLEI_RATE_LIMIT'] = nuclei_rate_limit
    config_obj['ARL']['NUCLEI_CONCURRENCY'] = nuclei_concurrency
    config_obj['ARL']['NUCLEI_BULK_SIZE'] = nuclei_bulk_size
    config_obj['ARL']['URLFINDER_URL_PROBE_ENABLE'] = urlfinder_url_probe_enable
    config_obj['ARL']['URLFINDER_URL_PROBE_MAX_TARGETS'] = urlfinder_url_probe_max_targets
    config_obj['ARL']['URLFINDER_URL_PROBE_CONCURRENCY'] = urlfinder_url_probe_concurrency
    config_obj['ARL']['HOST_TIMEOUT_TYPE'] = host_timeout_type
    config_obj['ARL']['HOST_TIMEOUT'] = host_timeout
    config_obj['ARL']['PORT_PARALLELISM'] = port_parallelism
    config_obj['ARL']['PORT_MIN_RATE'] = port_min_rate
    config_obj['ARL']['BLACK_IPS'] = black_ips
    config_obj['ARL']['DNS_RESOLVERS'] = dns_resolvers

    return config_obj


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


@ns.route('/service_api/')
class ApiConsoleServiceApi(ARLResource):
    """
    三方 API 配置读取与保存接口
    """

    @auth
    def get(self):
        config_path = _resolve_config_path()
        try:
            config_obj = _load_config_from_file(config_path)
            service_api = _extract_service_api_config(config_obj)
            return utils.build_ret(
                ErrorMsg.Success,
                {
                    'service_api': service_api,
                    'config_path': str(config_path),
                    'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                }
            )
        except Exception as exc:
            logger.exception('load service_api failed: %s', exc)
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': str(exc),
                    'config_path': str(config_path),
                }
            )

    @auth
    @ns.expect(save_service_api_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        service_api = payload.get('service_api')
        config_path = _resolve_config_path()

        with CONFIG_LOCK:
            try:
                config_obj = _load_config_from_file(config_path)
                config_obj = _merge_service_api_config(config_obj, service_api)
                _ensure_json_like_config(config_obj)
                backup_path = _backup_config_file(config_path)
                _atomic_write_yaml(config_path, config_obj)
                saved_service_api = _extract_service_api_config(config_obj)
            except Exception as exc:
                logger.exception('save service_api failed: %s', exc)
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
                'service_api': saved_service_api,
                'config_path': str(config_path),
                'backup_path': backup_path,
                'saved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
        )


@ns.route('/scan_config/')
class ApiConsoleScanConfig(ARLResource):
    """
    扫描配置读取与保存接口
    """

    @auth
    def get(self):
        config_path = _resolve_config_path()
        try:
            config_obj = _load_config_from_file(config_path)
            scan_config = _extract_scan_config(config_obj)
            active_scan_profile = str(scan_config.get('scan_profile_id', '') or '')
            domain_options = _collect_domain_dict_options(scan_config.get('domain_dict'))
            file_leak_options = _collect_file_leak_dict_options(scan_config.get('file_leak_dict'))
            return utils.build_ret(
                ErrorMsg.Success,
                {
                    'scan_config': scan_config,
                    'active_scan_profile': active_scan_profile,
                    'scan_profiles': _build_scan_profiles_payload(active_scan_profile),
                    'available_domain_dicts': domain_options,
                    'available_file_leak_dicts': file_leak_options,
                    'config_path': str(config_path),
                    'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                }
            )
        except Exception as exc:
            logger.exception('load scan_config failed: %s', exc)
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': str(exc),
                    'config_path': str(config_path),
                }
            )

    @auth
    @ns.expect(save_scan_config_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        scan_config = payload.get('scan_config')
        config_path = _resolve_config_path()

        with CONFIG_LOCK:
            try:
                config_obj = _load_config_from_file(config_path)
                config_obj = _merge_scan_config(config_obj, scan_config)
                _ensure_json_like_config(config_obj)
                backup_path = _backup_config_file(config_path)
                _atomic_write_yaml(config_path, config_obj)
                saved_scan_config = _extract_scan_config(config_obj)
                active_scan_profile = str(saved_scan_config.get('scan_profile_id', '') or '')
                domain_options = _collect_domain_dict_options(saved_scan_config.get('domain_dict'))
                file_leak_options = _collect_file_leak_dict_options(saved_scan_config.get('file_leak_dict'))
            except Exception as exc:
                logger.exception('save scan_config failed: %s', exc)
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
                'scan_config': saved_scan_config,
                'active_scan_profile': active_scan_profile,
                'scan_profiles': _build_scan_profiles_payload(active_scan_profile),
                'available_domain_dicts': domain_options,
                'available_file_leak_dicts': file_leak_options,
                'config_path': str(config_path),
                'backup_path': backup_path,
                'saved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
        )


@ns.route('/scan_config/domain_dict/upload/')
class ApiConsoleDomainDictUpload(ARLResource):
    """
    域名爆破字典上传接口
    """

    @auth
    def post(self):
        upload_file = request.files.get('file')
        if upload_file is None:
            return utils.build_ret(ErrorMsg.Error, {'error': '请上传字典文件（file）'})

        filename = secure_filename(upload_file.filename or '')
        if not filename:
            return utils.build_ret(ErrorMsg.Error, {'error': '字典文件名不能为空'})

        lower_name = filename.lower()
        if not lower_name.endswith('.txt'):
            return utils.build_ret(ErrorMsg.Error, {'error': '仅支持 .txt 字典文件'})

        file_bytes = upload_file.read()
        if not file_bytes:
            return utils.build_ret(ErrorMsg.Error, {'error': '上传文件为空'})

        # 单文件限制 5MB，避免误上传超大文件拖慢 worker
        if len(file_bytes) > 5 * 1024 * 1024:
            return utils.build_ret(ErrorMsg.Error, {'error': '字典文件过大（最大 5MB）'})

        upload_dir = _resolve_domain_dict_upload_dir()
        upload_dir.mkdir(parents=True, exist_ok=True)

        save_path = upload_dir / filename
        if save_path.exists():
            stamp = datetime.now().strftime('%Y%m%d%H%M%S')
            save_path = upload_dir / f'{save_path.stem}_{stamp}{save_path.suffix}'

        try:
            with save_path.open('wb') as file_obj:
                file_obj.write(file_bytes)
        except Exception as exc:
            logger.exception('save domain dict upload failed: %s', exc)
            return utils.build_ret(ErrorMsg.Error, {'error': str(exc)})

        options = _collect_domain_dict_options(str(save_path))
        return utils.build_ret(
            ErrorMsg.Success,
            {
                'uploaded': True,
                'domain_dict_path': str(save_path),
                'available_domain_dicts': options,
                'saved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
        )


@ns.route('/scan_config/file_leak_dict/upload/')
class ApiConsoleFileLeakDictUpload(ARLResource):
    """
    敏感文件泄漏字典上传接口
    """

    @auth
    def post(self):
        upload_file = request.files.get('file')
        if upload_file is None:
            return utils.build_ret(ErrorMsg.Error, {'error': '请上传字典文件（file）'})

        filename = secure_filename(upload_file.filename or '')
        if not filename:
            return utils.build_ret(ErrorMsg.Error, {'error': '字典文件名不能为空'})

        lower_name = filename.lower()
        if not lower_name.endswith('.txt'):
            return utils.build_ret(ErrorMsg.Error, {'error': '仅支持 .txt 字典文件'})

        file_bytes = upload_file.read()
        if not file_bytes:
            return utils.build_ret(ErrorMsg.Error, {'error': '上传文件为空'})

        if len(file_bytes) > 5 * 1024 * 1024:
            return utils.build_ret(ErrorMsg.Error, {'error': '字典文件过大（最大 5MB）'})

        upload_dir = _resolve_file_leak_dict_upload_dir()
        upload_dir.mkdir(parents=True, exist_ok=True)

        save_path = upload_dir / filename
        if save_path.exists():
            stamp = datetime.now().strftime('%Y%m%d%H%M%S')
            save_path = upload_dir / f'{save_path.stem}_{stamp}{save_path.suffix}'

        try:
            with save_path.open('wb') as file_obj:
                file_obj.write(file_bytes)
        except Exception as exc:
            logger.exception('save file leak dict upload failed: %s', exc)
            return utils.build_ret(ErrorMsg.Error, {'error': str(exc)})

        options = _collect_file_leak_dict_options(str(save_path))
        return utils.build_ret(
            ErrorMsg.Success,
            {
                'uploaded': True,
                'file_leak_dict_path': str(save_path),
                'available_file_leak_dicts': options,
                'saved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
        )
