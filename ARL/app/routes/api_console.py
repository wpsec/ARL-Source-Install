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
import subprocess
import tempfile
import threading

import yaml
from flask import request
from flask_restx import Namespace, fields
from werkzeug.utils import secure_filename

from app import utils
from app.config import Config, normalize_dict_path_compat, refresh_runtime_config_best_effort
from app.services.fofaClient import FofaClient
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

test_service_api_fields = ns.model(
    'TestServiceApiConfig',
    {
        'provider': fields.String(required=True, description='需要测试的 provider 标识'),
        'service_api': fields.Raw(required=True, description='三方 API 配置对象（使用当前表单值，不落盘）'),
        'test_target': fields.String(required=False, description='可选测试域名，默认 example.com'),
    },
)

test_service_api_batch_fields = ns.model(
    'BatchTestServiceApiConfig',
    {
        'service_api': fields.Raw(required=True, description='三方 API 配置对象（使用当前表单值，不落盘）'),
        'test_target': fields.String(required=False, description='可选测试域名，默认 example.com'),
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
            'domain_brute_concurrent': 48,
            'alt_dns_concurrent': 160,
            'web_gunicorn_workers': 1,
            'celery_task_worker_concurrency': 1,
            'celery_github_worker_concurrency': 1,
            'celery_heavy_worker_concurrency': 1,
            'celery_web_worker_concurrency': 1,
            'celery_prefetch_multiplier': 1,
            'celery_max_tasks_per_child': 16,
            'celery_max_memory_per_child': 200000,
            'nuclei_single_target_timeout_sec': 3600,
            'nuclei_rate_limit': 3,
            'nuclei_concurrency': 1,
            'nuclei_bulk_size': 2,
            'urlfinder_url_probe_enable': True,
            'urlfinder_url_probe_max_targets': 150,
            'urlfinder_url_probe_concurrency': 3,
            'host_timeout_type': 'default',
            'host_timeout': 1200,
            'port_parallelism': 10,
            'port_min_rate': 32,
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
            'celery_heavy_worker_concurrency': 1,
            'celery_web_worker_concurrency': 1,
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
        'description': '适用于 8C16G 高配主机，兼顾准确性与吞吐，优先保证长任务稳态运行。',
        'cpu_cores': 8,
        'memory_gb': 16,
        'bandwidth_mbps': 10,
        'values': {
            'domain_brute_concurrent': 260,
            'alt_dns_concurrent': 900,
            'web_gunicorn_workers': 4,
            'celery_task_worker_concurrency': 5,
            'celery_github_worker_concurrency': 2,
            'celery_heavy_worker_concurrency': 2,
            'celery_web_worker_concurrency': 3,
            'celery_prefetch_multiplier': 1,
            'celery_max_tasks_per_child': 24,
            'celery_max_memory_per_child': 520000,
            'nuclei_single_target_timeout_sec': 900,
            'nuclei_rate_limit': 30,
            'nuclei_concurrency': 16,
            'nuclei_bulk_size': 20,
            'afrog_concurrency': 20,
            'afrog_rate_limit': 20,
            'urlfinder_url_probe_enable': True,
            'urlfinder_url_probe_max_targets': 500,
            'urlfinder_url_probe_concurrency': 12,
            'host_timeout_type': 'default',
            'host_timeout': 1500,
            'port_parallelism': 40,
            'port_min_rate': 160,
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


POC_REPO_UPDATE_TIMEOUT_SEC = 12 * 60
NUCLEI_TEMPLATE_REPO_URL = 'https://github.com/projectdiscovery/nuclei-templates.git'
AFROG_POC_REPO_URL = 'https://github.com/zan8in/afrog-pocs.git'


def _normalize_git_remote_url(remote_url: str) -> str:
    """
    归一化远程地址，便于判断 origin 是否与预期仓库一致。
    """
    url = str(remote_url or '').strip()
    if not url:
        return ''
    if url.endswith('/'):
        url = url[:-1]
    if url.endswith('.git'):
        url = url[:-4]
    return url.lower()


def _run_git_command(git_bin: str, args: list, cwd: Path = None, timeout: int = POC_REPO_UPDATE_TIMEOUT_SEC):
    """
    执行 git 命令并返回 (rc, stdout, stderr)。
    """
    command = [git_bin] + list(args or [])
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=max(30, int(timeout or POC_REPO_UPDATE_TIMEOUT_SEC)),
    )
    stdout = completed.stdout.decode('utf-8', errors='ignore').strip() if completed.stdout else ''
    stderr = completed.stderr.decode('utf-8', errors='ignore').strip() if completed.stderr else ''
    return int(completed.returncode), stdout, stderr


def _resolve_poc_repo_dir(repo_type: str) -> Path:
    """
    解析 PoC 仓库目录，优先使用当前配置路径，回落到 tools 默认目录。
    """
    project_root = Path(__file__).resolve().parents[2]
    default_root = project_root / 'tools'
    allowed_roots = [_safe_resolve_path(default_root), Path('/code/tools')]

    def is_allowed(path_obj: Path) -> bool:
        resolved = _safe_resolve_path(path_obj)
        for root in allowed_roots:
            if _is_path_within(resolved, root):
                return True
        return False

    candidate_paths = []
    if repo_type == 'nuclei':
        configured = str(getattr(Config, 'NUCLEI_TEMPLATE_DIR', '') or '').strip()
        if configured:
            candidate_paths.append(Path(configured))
        candidate_paths.append(project_root / 'tools' / 'nuclei' / 'nuclei-templates')
        candidate_paths.append(project_root / 'tools' / 'nuclei-templates')
    elif repo_type == 'afrog':
        configured = str(getattr(Config, 'AFROG_POCS_DIR', '') or '').strip()
        if configured:
            candidate_paths.append(Path(configured))
        candidate_paths.append(project_root / 'tools' / 'afrog' / 'afrog-pocs')
    else:
        raise ValueError('未知 PoC 仓库类型')

    # 优先选择“存在且可写”的候选目录。
    for candidate in candidate_paths:
        if not candidate:
            continue
        resolved = _safe_resolve_path(candidate)
        if not is_allowed(resolved):
            continue
        if resolved.exists():
            return resolved

    # 都不存在时，使用首个有效候选作为目标目录。
    for candidate in candidate_paths:
        if not candidate:
            continue
        resolved = _safe_resolve_path(candidate)
        if is_allowed(resolved):
            return resolved

    raise ValueError('未找到可用的 PoC 仓库目录')


def _resolve_remote_default_branch(git_bin: str, repo_dir: Path) -> str:
    """
    解析 origin 默认分支（origin/main -> main），失败时回落 main。
    """
    rc, stdout, _ = _run_git_command(
        git_bin,
        ['symbolic-ref', '--short', 'refs/remotes/origin/HEAD'],
        cwd=repo_dir,
        timeout=30,
    )
    if rc != 0 or not stdout:
        return 'main'

    branch = stdout.strip()
    if branch.startswith('origin/'):
        branch = branch.split('/', 1)[1]
    branch = str(branch or '').strip()
    return branch or 'main'


def _collect_repo_head(git_bin: str, repo_dir: Path):
    """
    获取仓库当前 HEAD 信息，用于返回给前端展示。
    """
    commit_hash = ''
    commit_time = ''
    commit_subject = ''
    branch = ''

    rc, stdout, _ = _run_git_command(git_bin, ['rev-parse', '--abbrev-ref', 'HEAD'], cwd=repo_dir, timeout=30)
    if rc == 0:
        branch = str(stdout or '').strip()
        if branch == 'HEAD':
            branch = ''

    rc, stdout, _ = _run_git_command(
        git_bin,
        ['log', '-1', '--pretty=format:%H%n%ci%n%s'],
        cwd=repo_dir,
        timeout=30,
    )
    if rc == 0 and stdout:
        lines = stdout.splitlines()
        if len(lines) > 0:
            commit_hash = str(lines[0] or '').strip()
        if len(lines) > 1:
            commit_time = str(lines[1] or '').strip()
        if len(lines) > 2:
            commit_subject = str(lines[2] or '').strip()

    return {
        'branch': branch,
        'commit': commit_hash,
        'commit_time': commit_time,
        'commit_subject': commit_subject,
    }


def _sync_poc_repo(repo_type: str, repo_url: str):
    """
    使用 git 更新 PoC 仓库：
    - 已存在 git 仓库：fetch + pull
    - 不存在：clone
    """
    git_bin = utils.resolve_executable('git')
    if not git_bin:
        raise RuntimeError('未找到 git 命令，请先在容器中安装 git')

    repo_dir = _resolve_poc_repo_dir(repo_type)
    repo_dir.parent.mkdir(parents=True, exist_ok=True)

    operations = []
    current_remote = ''
    remote_changed = False
    repo_exists = repo_dir.exists()
    is_git_repo = repo_exists and (repo_dir / '.git').is_dir()

    if repo_exists and not repo_dir.is_dir():
        raise ValueError('目标路径不是目录: {}'.format(repo_dir))

    backup_path = ''
    if repo_exists and (not is_git_repo):
        try:
            has_content = any(repo_dir.iterdir())
        except Exception:
            has_content = True
        if has_content:
            # 兼容“历史解压目录”：自动备份后重新按 git 仓库拉取，避免要求用户手工清理目录。
            stamp = datetime.now().strftime('%Y%m%d%H%M%S')
            backup_dir = repo_dir.with_name('{}.bak.{}'.format(repo_dir.name, stamp))
            repo_dir.rename(backup_dir)
            backup_path = str(backup_dir)
            operations.append('backup-non-git-dir')
            repo_exists = False

    if not is_git_repo:
        rc, stdout, stderr = _run_git_command(
            git_bin,
            ['clone', '--depth', '1', repo_url, str(repo_dir)],
            timeout=POC_REPO_UPDATE_TIMEOUT_SEC,
        )
        operations.append('clone')
        if rc != 0:
            raise RuntimeError('git clone 失败: {}'.format(stderr or stdout or 'unknown error'))
    else:
        rc, stdout, stderr = _run_git_command(
            git_bin,
            ['remote', 'get-url', 'origin'],
            cwd=repo_dir,
            timeout=30,
        )
        if rc == 0:
            current_remote = str(stdout or '').strip()
        else:
            current_remote = ''

        expected_remote = _normalize_git_remote_url(repo_url)
        actual_remote = _normalize_git_remote_url(current_remote)
        if (not actual_remote) or (actual_remote != expected_remote):
            if current_remote:
                rc, stdout, stderr = _run_git_command(
                    git_bin,
                    ['remote', 'set-url', 'origin', repo_url],
                    cwd=repo_dir,
                    timeout=30,
                )
                operations.append('set-origin-url')
            else:
                rc, stdout, stderr = _run_git_command(
                    git_bin,
                    ['remote', 'add', 'origin', repo_url],
                    cwd=repo_dir,
                    timeout=30,
                )
                operations.append('add-origin')
            if rc != 0:
                raise RuntimeError('设置 origin 失败: {}'.format(stderr or stdout or 'unknown error'))
            remote_changed = True
            current_remote = repo_url

        rc, stdout, stderr = _run_git_command(
            git_bin,
            ['fetch', 'origin', '--prune'],
            cwd=repo_dir,
            timeout=POC_REPO_UPDATE_TIMEOUT_SEC,
        )
        operations.append('fetch')
        if rc != 0:
            raise RuntimeError('git fetch 失败: {}'.format(stderr or stdout or 'unknown error'))

        branch = _resolve_remote_default_branch(git_bin, repo_dir)

        rc, current_branch, _ = _run_git_command(
            git_bin,
            ['rev-parse', '--abbrev-ref', 'HEAD'],
            cwd=repo_dir,
            timeout=30,
        )
        current_branch = str(current_branch or '').strip() if rc == 0 else ''
        if (not current_branch) or current_branch == 'HEAD':
            rc, stdout, stderr = _run_git_command(
                git_bin,
                ['checkout', branch],
                cwd=repo_dir,
                timeout=60,
            )
            if rc != 0:
                rc, stdout, stderr = _run_git_command(
                    git_bin,
                    ['checkout', '-b', branch, '--track', 'origin/{}'.format(branch)],
                    cwd=repo_dir,
                    timeout=60,
                )
            operations.append('checkout')
            if rc != 0:
                raise RuntimeError('切换分支失败: {}'.format(stderr or stdout or 'unknown error'))

        rc, stdout, stderr = _run_git_command(
            git_bin,
            ['pull', '--ff-only', 'origin', branch],
            cwd=repo_dir,
            timeout=POC_REPO_UPDATE_TIMEOUT_SEC,
        )
        operations.append('pull')
        if rc != 0:
            raise RuntimeError('git pull 失败: {}'.format(stderr or stdout or 'unknown error'))

    head = _collect_repo_head(git_bin, repo_dir)
    if not current_remote:
        rc, stdout, _ = _run_git_command(git_bin, ['remote', 'get-url', 'origin'], cwd=repo_dir, timeout=30)
        if rc == 0:
            current_remote = str(stdout or '').strip()

    return {
        'repo_type': repo_type,
        'repo_dir': str(repo_dir),
        'repo_url': current_remote or repo_url,
        'branch': head.get('branch', ''),
        'commit': head.get('commit', ''),
        'commit_time': head.get('commit_time', ''),
        'commit_subject': head.get('commit_subject', ''),
        'operations': operations,
        'repo_created': bool(not repo_exists),
        'remote_changed': remote_changed,
        'backup_path': backup_path,
    }


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
    hunter_how_plugin = plugin_config('hunter_how')
    shodan_plugin = plugin_config('shodan')
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
        'hunter_how_api_key': str(hunter_how_plugin.get('api_key') or ''),
        'hunter_how_enable': _safe_bool(hunter_how_plugin.get('enable'), False),
        'hunter_how_page_size': _safe_int(hunter_how_plugin.get('page_size'), 100, min_value=1),
        'hunter_how_max_page': _safe_int(hunter_how_plugin.get('max_page'), 5, min_value=1),
        'hunter_how_request_interval': _safe_float(hunter_how_plugin.get('request_interval'), 1.0, min_value=0.0),
        'hunter_how_rate_limit_retry': _safe_int(hunter_how_plugin.get('rate_limit_retry'), 4, min_value=0),
        'hunter_how_rate_limit_backoff': _safe_int(hunter_how_plugin.get('rate_limit_backoff'), 2, min_value=1),
        'hunter_how_rate_limit_max_sleep': _safe_int(hunter_how_plugin.get('rate_limit_max_sleep'), 60, min_value=1),
        'shodan_api_key': str(shodan_plugin.get('api_key') or ''),
        'shodan_enable': _safe_bool(shodan_plugin.get('enable'), False),
        'shodan_max_page': _safe_int(shodan_plugin.get('max_page'), 20, min_value=1),
        'shodan_request_interval': _safe_float(shodan_plugin.get('request_interval'), 1.0, min_value=0.0),
        'shodan_rate_limit_retry': _safe_int(shodan_plugin.get('rate_limit_retry'), 4, min_value=0),
        'shodan_rate_limit_backoff': _safe_int(shodan_plugin.get('rate_limit_backoff'), 2, min_value=1),
        'shodan_rate_limit_max_sleep': _safe_int(shodan_plugin.get('rate_limit_max_sleep'), 60, min_value=1),
        'quake_token': str(quake_plugin.get('quake_token') or ''),
        'quake_enable': _safe_bool(quake_plugin.get('enable'), True),
        'quake_rate_limit_retry': _safe_int(quake_plugin.get('rate_limit_retry'), 4, min_value=0),
        'quake_rate_limit_backoff': _safe_int(quake_plugin.get('rate_limit_backoff'), 3, min_value=1),
        'quake_rate_limit_max_sleep': _safe_int(quake_plugin.get('rate_limit_max_sleep'), 90, min_value=1),
        'zoomeye_api_key': str(zoomeye_plugin.get('api_key') or ''),
        'zoomeye_enable': _safe_bool(zoomeye_plugin.get('enable'), True),
        'zoomeye_max_page': _safe_int(zoomeye_plugin.get('max_page'), 20, min_value=1),
        'zoomeye_request_interval': _safe_float(zoomeye_plugin.get('request_interval'), 1.0, min_value=0.0),
        'zoomeye_rate_limit_retry': _safe_int(zoomeye_plugin.get('rate_limit_retry'), 4, min_value=0),
        'zoomeye_rate_limit_backoff': _safe_int(zoomeye_plugin.get('rate_limit_backoff'), 2, min_value=1),
        'zoomeye_rate_limit_max_sleep': _safe_int(zoomeye_plugin.get('rate_limit_max_sleep'), 60, min_value=1),
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

    hunter_how_plugin = ensure_plugin('hunter_how')
    hunter_how_plugin['api_key'] = str(service_api.get('hunter_how_api_key', '')).strip()
    hunter_how_plugin['enable'] = _safe_bool(service_api.get('hunter_how_enable'), hunter_how_plugin.get('enable', False))
    hunter_how_plugin['page_size'] = _safe_int(
        service_api.get('hunter_how_page_size'),
        hunter_how_plugin.get('page_size', 100),
        min_value=1
    )
    hunter_how_plugin['max_page'] = _safe_int(
        service_api.get('hunter_how_max_page'),
        hunter_how_plugin.get('max_page', 5),
        min_value=1
    )
    hunter_how_plugin['request_interval'] = _safe_float(
        service_api.get('hunter_how_request_interval'),
        hunter_how_plugin.get('request_interval', 1.0),
        min_value=0.0
    )
    hunter_how_plugin['rate_limit_retry'] = _safe_int(
        service_api.get('hunter_how_rate_limit_retry'),
        hunter_how_plugin.get('rate_limit_retry', 4),
        min_value=0
    )
    hunter_how_plugin['rate_limit_backoff'] = _safe_int(
        service_api.get('hunter_how_rate_limit_backoff'),
        hunter_how_plugin.get('rate_limit_backoff', 2),
        min_value=1
    )
    hunter_how_plugin['rate_limit_max_sleep'] = _safe_int(
        service_api.get('hunter_how_rate_limit_max_sleep'),
        hunter_how_plugin.get('rate_limit_max_sleep', 60),
        min_value=1
    )

    shodan_plugin = ensure_plugin('shodan')
    shodan_plugin['api_key'] = str(service_api.get('shodan_api_key', '')).strip()
    shodan_plugin['enable'] = _safe_bool(service_api.get('shodan_enable'), shodan_plugin.get('enable', False))
    shodan_plugin['max_page'] = _safe_int(
        service_api.get('shodan_max_page'),
        shodan_plugin.get('max_page', 20),
        min_value=1
    )
    shodan_plugin['request_interval'] = _safe_float(
        service_api.get('shodan_request_interval'),
        shodan_plugin.get('request_interval', 1.0),
        min_value=0.0
    )
    shodan_plugin['rate_limit_retry'] = _safe_int(
        service_api.get('shodan_rate_limit_retry'),
        shodan_plugin.get('rate_limit_retry', 4),
        min_value=0
    )
    shodan_plugin['rate_limit_backoff'] = _safe_int(
        service_api.get('shodan_rate_limit_backoff'),
        shodan_plugin.get('rate_limit_backoff', 2),
        min_value=1
    )
    shodan_plugin['rate_limit_max_sleep'] = _safe_int(
        service_api.get('shodan_rate_limit_max_sleep'),
        shodan_plugin.get('rate_limit_max_sleep', 60),
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
    zoomeye_plugin['max_page'] = _safe_int(
        service_api.get('zoomeye_max_page'),
        zoomeye_plugin.get('max_page', 20),
        min_value=1
    )
    zoomeye_plugin['request_interval'] = _safe_float(
        service_api.get('zoomeye_request_interval'),
        zoomeye_plugin.get('request_interval', 1.0),
        min_value=0.0
    )
    zoomeye_plugin['rate_limit_retry'] = _safe_int(
        service_api.get('zoomeye_rate_limit_retry'),
        zoomeye_plugin.get('rate_limit_retry', 4),
        min_value=0
    )
    zoomeye_plugin['rate_limit_backoff'] = _safe_int(
        service_api.get('zoomeye_rate_limit_backoff'),
        zoomeye_plugin.get('rate_limit_backoff', 2),
        min_value=1
    )
    zoomeye_plugin['rate_limit_max_sleep'] = _safe_int(
        service_api.get('zoomeye_rate_limit_max_sleep'),
        zoomeye_plugin.get('rate_limit_max_sleep', 60),
        min_value=1
    )

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


def _normalize_service_api_provider(provider: str) -> str:
    """
    规范化 provider 标识，兼容前端别名与插件 source_name。
    """
    normalized = str(provider or '').strip().lower()
    provider_alias = {
        'hunter': 'hunter_qax',
        'quake': 'quake_360',
    }
    return provider_alias.get(normalized, normalized)


def _normalize_test_target_domain(test_target: str) -> str:
    """
    规范化 API 测试域名；输入无效时回退 example.com。
    """
    candidate = str(test_target or '').strip().lower().rstrip('.')
    if candidate and utils.is_valid_domain(candidate):
        return candidate
    return 'example.com'


def _get_service_api_test_provider_specs():
    """
    定义支持批量测试的 provider 及其必填凭据字段。
    """
    return [
        {'provider': 'fofa', 'label': 'FOFA', 'required_fields': ['fofa_email', 'fofa_key']},
        {'provider': 'hunter', 'label': 'Hunter', 'required_fields': ['hunter_api_key']},
        {'provider': 'hunter_how', 'label': 'hunter.how', 'required_fields': ['hunter_how_api_key']},
        {'provider': 'shodan', 'label': 'Shodan', 'required_fields': ['shodan_api_key']},
        {'provider': 'quake', 'label': 'Quake360', 'required_fields': ['quake_token']},
        {'provider': 'zoomeye', 'label': 'Zoomeye', 'required_fields': ['zoomeye_api_key']},
        {'provider': 'securitytrails', 'label': 'SecurityTrails', 'required_fields': ['securitytrails_api_key']},
        {'provider': 'virustotal', 'label': 'VirusTotal', 'required_fields': ['virustotal_api_key']},
        {'provider': 'chaos', 'label': 'Chaos', 'required_fields': ['chaos_api_key']},
        {'provider': 'github', 'label': 'GitHub', 'required_fields': ['github_token']},
    ]


def _collect_configured_service_api_providers(service_api: dict):
    """
    找出当前表单里已经填写完必需凭据的 provider。
    """
    configured_specs = []
    for spec in _get_service_api_test_provider_specs():
        required_fields = spec.get('required_fields', [])
        if all(str(service_api.get(field, '') or '').strip() for field in required_fields):
            configured_specs.append(spec)
    return configured_specs


def _build_runtime_service_api_config_for_test(service_api: dict) -> dict:
    """
    根据当前表单值构建运行期配置对象，仅用于测试，不会写入磁盘。
    """
    runtime_config = {
        'FOFA': {},
        'QUERY_PLUGIN': {},
        'RISKIQ': {},
        'GITHUB': {},
    }
    return _merge_service_api_config(runtime_config, service_api)


def _find_query_plugin_by_source(source_name: str):
    """
    动态加载并定位指定 source_name 的查询插件实例。
    """
    plugins = utils.load_query_plugins(Config.dns_query_plugin_path)
    for plugin in plugins:
        if getattr(plugin, 'source_name', '') == source_name:
            return plugin
    return None


def _test_fofa_provider(service_api: dict):
    """
    测试 FOFA 凭据是否有效，使用 info_my 轻量接口避免大结果查询。
    """
    fofa_url = str(service_api.get('fofa_url', '') or '').strip() or 'https://fofa.info'
    fofa_email = str(service_api.get('fofa_email', '') or '').strip()
    fofa_key = str(service_api.get('fofa_key', '') or '').strip()

    if not fofa_email or not fofa_key:
        return False, 'FOFA 测试失败：请填写邮箱和 KEY', {}

    try:
        client = FofaClient(fofa_email, fofa_key, page_size=1)
        client.base_url = fofa_url
        profile = client.info_my() or {}
        if not isinstance(profile, dict):
            return False, 'FOFA 测试失败：返回数据格式异常', {}

        is_error = bool(profile.get('error'))
        if is_error:
            return False, 'FOFA 测试失败：{}'.format(profile.get('errmsg') or '未知错误'), {}

        email = str(profile.get('email') or '')
        fcoin = profile.get('fcoin', 0)
        is_vip = bool(profile.get('isvip', False))
        return True, 'FOFA 测试成功', {'email': email, 'fcoin': fcoin, 'isvip': is_vip}
    except Exception as exc:
        return False, 'FOFA 测试失败：{}'.format(exc), {}


def _test_github_provider(service_api: dict):
    """
    测试 GitHub Token 可用性，调用 /user 接口获取当前账号。
    """
    github_token = str(service_api.get('github_token', '') or '').strip()
    if not github_token:
        return False, 'GitHub 测试失败：请填写 TOKEN', {}

    headers = {
        'Authorization': 'Bearer {}'.format(github_token),
        'Accept': 'application/vnd.github+json',
    }
    try:
        conn = utils.http_req('https://api.github.com/user', 'get', headers=headers, timeout=(10, 20))
        data = conn.json() if conn is not None else {}
        if int(getattr(conn, 'status_code', 0) or 0) != 200:
            message = ''
            if isinstance(data, dict):
                message = str(data.get('message') or '')
            return False, 'GitHub 测试失败：HTTP {} {}'.format(getattr(conn, 'status_code', 0), message), {}

        login = ''
        if isinstance(data, dict):
            login = str(data.get('login') or '')
        return True, 'GitHub 测试成功', {'login': login}
    except Exception as exc:
        return False, 'GitHub 测试失败：{}'.format(exc), {}


def _test_virustotal_provider(service_api: dict, test_target: str):
    """
    轻量测试 VirusTotal 凭据可用性，避免走完整子域名分页查询导致 502。
    """
    api_key = str(service_api.get('virustotal_api_key', '') or '').strip()
    if not api_key:
        return False, 'VirusTotal 测试失败：请填写 API KEY', {}

    normalized_target = _normalize_test_target_domain(test_target)
    request_url = 'https://www.virustotal.com/api/v3/domains/{}'.format(normalized_target)
    headers = {
        'x-apikey': api_key,
    }

    try:
        conn = utils.http_req(request_url, 'get', headers=headers, timeout=(10, 20))
        status_code = int(getattr(conn, 'status_code', 0) or 0)
        try:
            data = conn.json() if conn is not None else {}
        except Exception:
            data = {}

        if status_code != 200:
            error_message = ''
            if isinstance(data, dict):
                error_obj = data.get('error')
                if isinstance(error_obj, dict):
                    error_message = str(error_obj.get('message') or '')
                error_message = error_message or str(data.get('message') or '')
            logger.warning(
                'virustotal lightweight test failed status:%s target:%s message:%s',
                status_code,
                normalized_target,
                error_message,
            )
            return False, 'VirusTotal 测试失败：HTTP {} {}'.format(status_code, error_message).strip(), {}

        payload = data.get('data') if isinstance(data, dict) else {}
        if not isinstance(payload, dict):
            payload = {}
        attributes = payload.get('attributes') if isinstance(payload.get('attributes'), dict) else {}
        stats = attributes.get('last_analysis_stats') if isinstance(attributes.get('last_analysis_stats'), dict) else {}
        detail = {
            'domain': str(payload.get('id') or normalized_target),
            'reputation': attributes.get('reputation', ''),
            'harmless': stats.get('harmless', ''),
            'suspicious': stats.get('suspicious', ''),
            'malicious': stats.get('malicious', ''),
        }
        logger.info('virustotal lightweight test success target:%s', normalized_target)
        return True, 'VirusTotal 测试成功', detail
    except Exception as exc:
        logger.exception('virustotal lightweight test error target:%s err:%s', normalized_target, exc)
        return False, 'VirusTotal 测试失败：{}'.format(exc), {}


def _test_query_plugin_provider(provider: str, service_api: dict, test_target: str):
    """
    通用查询插件测试：
    - 用当前表单值构建临时 QUERY_PLUGIN 配置
    - 仅执行 1 页/小样本探测，降低测试开销
    """
    source_name = _normalize_service_api_provider(provider)
    runtime_config = _build_runtime_service_api_config_for_test(service_api)
    query_plugin_conf = runtime_config.get('QUERY_PLUGIN', {}) if isinstance(runtime_config, dict) else {}
    plugin_conf = query_plugin_conf.get(source_name, {}) if isinstance(query_plugin_conf, dict) else {}
    if not isinstance(plugin_conf, dict):
        plugin_conf = {}

    required_conf_fields = {
        'hunter_qax': ['api_key'],
        'hunter_how': ['api_key'],
        'shodan': ['api_key'],
        'quake_360': ['quake_token'],
        'zoomeye': ['api_key'],
        'securitytrails': ['api_key'],
        'virustotal': ['api_key'],
        'chaos': ['api_key'],
    }
    required_fields = required_conf_fields.get(source_name, [])
    missing_fields = [k for k in required_fields if not str(plugin_conf.get(k, '') or '').strip()]
    if missing_fields:
        return False, '{} 测试失败：缺少配置 {}'.format(source_name, ','.join(missing_fields)), {}

    plugin = _find_query_plugin_by_source(source_name)
    if not plugin:
        return False, '{} 测试失败：插件未加载'.format(source_name), {}

    init_kwargs = plugin_conf.copy()
    init_kwargs.pop('enable', None)

    # 测试场景使用小样本配置，避免大页数导致按钮响应过慢。
    if source_name in ('hunter_qax', 'hunter_how'):
        init_kwargs['max_page'] = 1
        init_kwargs['page_size'] = min(_safe_int(init_kwargs.get('page_size'), 20, min_value=1), 20)
    elif source_name == 'zoomeye':
        init_kwargs['max_page'] = 1
    elif source_name == 'shodan':
        init_kwargs['max_page'] = 1
    elif source_name == 'quake_360':
        init_kwargs['max_size'] = min(_safe_int(init_kwargs.get('max_size'), 50, min_value=1), 50)

    try:
        if init_kwargs:
            plugin.init_key(**init_kwargs)
        domains = plugin.query(test_target)
        if not isinstance(domains, list):
            domains = []
        sample = domains[:5]
        return True, '{} 测试成功'.format(source_name), {'result_count': len(domains), 'sample': sample}
    except Exception as exc:
        return False, '{} 测试失败：{}'.format(source_name, exc), {}


def _run_service_api_provider_test(provider: str, service_api: dict, test_target: str):
    """
    按 provider 分发测试逻辑，并统一返回结构。
    """
    normalized_provider = _normalize_service_api_provider(provider)
    normalized_target = _normalize_test_target_domain(test_target)

    if normalized_provider == 'fofa':
        ok, message, detail = _test_fofa_provider(service_api)
    elif normalized_provider == 'github':
        ok, message, detail = _test_github_provider(service_api)
    elif normalized_provider == 'virustotal':
        ok, message, detail = _test_virustotal_provider(service_api, normalized_target)
    else:
        ok, message, detail = _test_query_plugin_provider(
            provider=normalized_provider,
            service_api=service_api,
            test_target=normalized_target,
        )

    return {
        'provider': normalized_provider,
        'ok': bool(ok),
        'message': str(message or ''),
        'test_target': normalized_target,
        'detail': detail if isinstance(detail, dict) else {},
        'tested_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }


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
    celery_heavy_worker_concurrency = _safe_int(
        arl_config.get('CELERY_HEAVY_WORKER_CONCURRENCY'),
        Config.CELERY_HEAVY_WORKER_CONCURRENCY
    )
    celery_web_worker_concurrency = _safe_int(
        arl_config.get('CELERY_WEB_WORKER_CONCURRENCY'),
        Config.CELERY_WEB_WORKER_CONCURRENCY
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
    afrog_concurrency = _safe_int(
        arl_config.get('AFROG_CONCURRENCY'),
        Config.AFROG_CONCURRENCY
    )
    afrog_rate_limit = _safe_int(
        arl_config.get('AFROG_RATE_LIMIT'),
        Config.AFROG_RATE_LIMIT
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
        'celery_heavy_worker_concurrency': celery_heavy_worker_concurrency,
        'celery_web_worker_concurrency': celery_web_worker_concurrency,
        'celery_prefetch_multiplier': celery_prefetch_multiplier,
        'celery_max_tasks_per_child': celery_max_tasks_per_child,
        'celery_max_memory_per_child': celery_max_memory_per_child,
        'nuclei_single_target_timeout_sec': nuclei_single_target_timeout_sec,
        'nuclei_rate_limit': nuclei_rate_limit,
        'nuclei_concurrency': nuclei_concurrency,
        'nuclei_bulk_size': nuclei_bulk_size,
        'afrog_concurrency': afrog_concurrency,
        'afrog_rate_limit': afrog_rate_limit,
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
    celery_heavy_worker_concurrency = _safe_int(
        scan_config.get('celery_heavy_worker_concurrency'),
        Config.CELERY_HEAVY_WORKER_CONCURRENCY
    )
    celery_web_worker_concurrency = _safe_int(
        scan_config.get('celery_web_worker_concurrency'),
        Config.CELERY_WEB_WORKER_CONCURRENCY
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
    afrog_concurrency = _safe_int(
        scan_config.get('afrog_concurrency'),
        Config.AFROG_CONCURRENCY
    )
    afrog_rate_limit = _safe_int(
        scan_config.get('afrog_rate_limit'),
        Config.AFROG_RATE_LIMIT
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
    config_obj['ARL']['CELERY_HEAVY_WORKER_CONCURRENCY'] = celery_heavy_worker_concurrency
    config_obj['ARL']['CELERY_WEB_WORKER_CONCURRENCY'] = celery_web_worker_concurrency
    config_obj['ARL']['CELERY_PREFETCH_MULTIPLIER'] = celery_prefetch_multiplier
    config_obj['ARL']['CELERY_MAX_TASKS_PER_CHILD'] = celery_max_tasks_per_child
    config_obj['ARL']['CELERY_MAX_MEMORY_PER_CHILD'] = celery_max_memory_per_child
    config_obj['ARL']['NUCLEI_SINGLE_TARGET_TIMEOUT_SEC'] = nuclei_single_target_timeout_sec
    config_obj['ARL']['NUCLEI_RATE_LIMIT'] = nuclei_rate_limit
    config_obj['ARL']['NUCLEI_CONCURRENCY'] = nuclei_concurrency
    config_obj['ARL']['NUCLEI_BULK_SIZE'] = nuclei_bulk_size
    config_obj['ARL']['AFROG_CONCURRENCY'] = afrog_concurrency
    config_obj['ARL']['AFROG_RATE_LIMIT'] = afrog_rate_limit
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
                refresh_runtime_config_best_effort(force=True)
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
                refresh_runtime_config_best_effort(force=True)
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


@ns.route('/service_api/test/')
class ApiConsoleServiceApiTest(ARLResource):
    """
    三方 API 单项测试接口（基于当前表单值实时测试，不落盘）。
    """

    @auth
    @ns.expect(test_service_api_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        provider = str(payload.get('provider') or '').strip()
        service_api = payload.get('service_api') or {}
        test_target = str(payload.get('test_target') or '').strip()

        if not provider:
            return utils.build_ret(
                ErrorMsg.Error,
                {'error': 'provider 不能为空'}
            )
        if not isinstance(service_api, dict):
            return utils.build_ret(
                ErrorMsg.Error,
                {'error': 'service_api 必须为对象'}
            )

        try:
            result = _run_service_api_provider_test(
                provider=provider,
                service_api=service_api,
                test_target=test_target,
            )
            return utils.build_ret(ErrorMsg.Success, result)
        except Exception as exc:
            logger.exception('service_api provider test failed provider:%s err:%s', provider, exc)
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': str(exc),
                    'provider': provider,
                }
            )


@ns.route('/service_api/test_batch/')
class ApiConsoleServiceApiBatchTest(ARLResource):
    """
    三方 API 批量测试接口，仅验证已填写凭据的 provider。
    """

    @auth
    @ns.expect(test_service_api_batch_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        service_api = payload.get('service_api') or {}
        test_target = str(payload.get('test_target') or '').strip()

        if not isinstance(service_api, dict):
            return utils.build_ret(
                ErrorMsg.Error,
                {'error': 'service_api 必须为对象'}
            )

        configured_specs = _collect_configured_service_api_providers(service_api)
        logger.info(
            'service_api batch test start providers:%s target:%s',
            [item.get('provider') for item in configured_specs],
            _normalize_test_target_domain(test_target),
        )

        items = []
        success_count = 0
        fail_count = 0
        for spec in configured_specs:
            provider = str(spec.get('provider') or '').strip()
            if not provider:
                continue

            try:
                item = _run_service_api_provider_test(
                    provider=provider,
                    service_api=service_api,
                    test_target=test_target,
                )
            except Exception as exc:
                logger.exception('service_api batch test failed provider:%s err:%s', provider, exc)
                item = {
                    'provider': provider,
                    'ok': False,
                    'message': '{} 测试失败：{}'.format(spec.get('label') or provider, exc),
                    'test_target': _normalize_test_target_domain(test_target),
                    'detail': {},
                    'tested_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                }

            item['provider'] = provider
            item['label'] = str(spec.get('label') or provider)
            items.append(item)

            if item.get('ok'):
                success_count += 1
            else:
                fail_count += 1

        batch_payload = {
            'items': items,
            'total': len(items),
            'success_count': success_count,
            'fail_count': fail_count,
            'message': '未检测到已配置的 API，无需验证' if not items else '批量验证完成',
            'tested_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
        return utils.build_ret(ErrorMsg.Success, batch_payload)


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
                refresh_runtime_config_best_effort(force=True)
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


@ns.route('/scan_config/nuclei_poc/update/')
class ApiConsoleNucleiPocUpdate(ARLResource):
    """
    nuclei-templates 仓库更新接口（git clone/pull）。
    """

    @auth
    def post(self):
        try:
            with CONFIG_LOCK:
                update_info = _sync_poc_repo('nuclei', NUCLEI_TEMPLATE_REPO_URL)
        except Exception as exc:
            logger.exception('update nuclei poc failed: %s', exc)
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': str(exc),
                    'repo_type': 'nuclei',
                    'repo_url': NUCLEI_TEMPLATE_REPO_URL,
                }
            )

        logger.info(
            'update nuclei poc done dir:%s branch:%s commit:%s',
            update_info.get('repo_dir', ''),
            update_info.get('branch', ''),
            update_info.get('commit', ''),
        )
        update_info['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return utils.build_ret(ErrorMsg.Success, update_info)


@ns.route('/scan_config/afrog_poc/update/')
class ApiConsoleAfrogPocUpdate(ARLResource):
    """
    afrog-pocs 仓库更新接口（git clone/pull）。
    """

    @auth
    def post(self):
        try:
            with CONFIG_LOCK:
                update_info = _sync_poc_repo('afrog', AFROG_POC_REPO_URL)
        except Exception as exc:
            logger.exception('update afrog poc failed: %s', exc)
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': str(exc),
                    'repo_type': 'afrog',
                    'repo_url': AFROG_POC_REPO_URL,
                }
            )

        logger.info(
            'update afrog poc done dir:%s branch:%s commit:%s',
            update_info.get('repo_dir', ''),
            update_info.get('branch', ''),
            update_info.get('commit', ''),
        )
        update_info['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return utils.build_ret(ErrorMsg.Success, update_info)


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
