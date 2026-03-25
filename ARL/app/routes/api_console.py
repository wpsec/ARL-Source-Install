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
import re
import subprocess
import tempfile
import threading

import yaml
from bson import ObjectId
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

save_ai_config_fields = ns.model(
    'SaveAiConfig',
    {
        'ai_config': fields.Raw(required=True, description='AI 配置对象'),
    },
)

test_ai_config_fields = ns.model(
    'TestAiConfig',
    {
        'ai_config': fields.Raw(required=True, description='AI 配置对象（使用当前表单值，不落盘）'),
    },
)

analyze_ai_denoise_fields = ns.model(
    'AnalyzeAiDenoise',
    {
        'module_id': fields.String(required=True, description='模块ID（site/fileleak/cert/url/vuln/nuclei_result）'),
        'items': fields.List(fields.Raw, required=True, description='待分析的数据行列表'),
        'prefer_ai': fields.Boolean(required=False, description='是否优先使用已配置模型（单条详情建议开启）'),
    },
)

verify_sensitive_fields = ns.model(
    'VerifySensitiveAccess',
    {
        'username': fields.String(required=True, description='当前登录账号'),
        'password': fields.String(required=True, description='当前登录密码'),
    },
)

SERVICE_API_SENSITIVE_FIELDS = (
    'fofa_key',
    'hunter_api_key',
    'hunter_how_api_key',
    'shodan_api_key',
    'quake_token',
    'zoomeye_api_key',
    'securitytrails_api_key',
    'virustotal_api_key',
    'chaos_api_key',
    'passivetotal_key',
    'github_token',
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
        'id': 'low_performance',
        'label': '低性能配置',
        'description': '适用于低资源主机，单次并行约 1 个目标，优先保证系统可访问性',
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
            'afrog_concurrency': 3,
            'afrog_rate_limit': 3,
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
        'id': 'medium_performance',
        'label': '中性能配置',
        'description': '适用于中等资源主机，单次并行约 2 个目标，在稳定性与扫描速度之间平衡。',
        'cpu_cores': 4,
        'memory_gb': 4,
        'bandwidth_mbps': 5,
        'values': {
            'domain_brute_concurrent': 96,
            'alt_dns_concurrent': 320,
            'web_gunicorn_workers': 2,
            'celery_task_worker_concurrency': 2,
            'celery_github_worker_concurrency': 1,
            'celery_heavy_worker_concurrency': 2,
            'celery_web_worker_concurrency': 2,
            'celery_prefetch_multiplier': 1,
            'celery_max_tasks_per_child': 20,
            'celery_max_memory_per_child': 280000,
            'nuclei_single_target_timeout_sec': 7200,
            'nuclei_rate_limit': 4,
            'nuclei_concurrency': 2,
            'nuclei_bulk_size': 3,
            'afrog_concurrency': 8,
            'afrog_rate_limit': 8,
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
        'id': 'high_performance',
        'label': '高性能配置',
        'description': '适用于高资源主机，单次并行约 3 个目标，在保证稳定性的前提下提升吞吐。',
        'cpu_cores': 8,
        'memory_gb': 16,
        'bandwidth_mbps': 10,
        'values': {
            'domain_brute_concurrent': 360,
            'alt_dns_concurrent': 1400,
            'web_gunicorn_workers': 6,
            'celery_task_worker_concurrency': 3,
            'celery_github_worker_concurrency': 2,
            'celery_heavy_worker_concurrency': 3,
            'celery_web_worker_concurrency': 3,
            'celery_prefetch_multiplier': 1,
            'celery_max_tasks_per_child': 32,
            'celery_max_memory_per_child': 720000,
            'nuclei_single_target_timeout_sec': 900,
            'nuclei_rate_limit': 50,
            'nuclei_concurrency': 24,
            'nuclei_bulk_size': 30,
            'afrog_concurrency': 30,
            'afrog_rate_limit': 30,
            'urlfinder_url_probe_enable': True,
            'urlfinder_url_probe_max_targets': 800,
            'urlfinder_url_probe_concurrency': 20,
            'host_timeout_type': 'default',
            'host_timeout': 1500,
            'port_parallelism': 64,
            'port_min_rate': 260,
        },
    },
]
SCAN_PROFILE_MAP = {item['id']: item for item in SCAN_PROFILE_ITEMS}
SCAN_PROFILE_ID_ALIASES = {
    '2c2g3m': 'low_performance',
    '4c4g5m': 'medium_performance',
    '8c16g10m': 'high_performance',
}

AI_PROVIDER_PRESETS = [
    {
        'id': 'qwen',
        'label': '通义千问',
        'base_url': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
        'default_model': 'qwen-plus',
    },
    {
        'id': 'kimi',
        'label': 'Kimi',
        'base_url': 'https://api.moonshot.cn/v1',
        'default_model': 'moonshot-v1-8k',
    },
    {
        'id': 'openai',
        'label': 'OpenAI',
        'base_url': 'https://api.openai.com/v1',
        'default_model': 'gpt-4o-mini',
    },
    {
        'id': 'glm',
        'label': '智谱 GLM',
        'base_url': 'https://open.bigmodel.cn/api/paas/v4',
        'default_model': 'glm-4-flash',
    },
    {
        'id': 'deepseek',
        'label': 'DeepSeek',
        'base_url': 'https://api.deepseek.com/v1',
        'default_model': 'deepseek-chat',
    },
    {
        'id': 'custom_compatible',
        'label': 'OpenAI 兼容接口',
        'base_url': '',
        'default_model': '',
    },
]
AI_PROVIDER_PRESET_MAP = {item.get('id'): item for item in AI_PROVIDER_PRESETS}
AI_PROVIDER_IDS = set(item.get('id') for item in AI_PROVIDER_PRESETS if item.get('id'))

AI_DENOISE_MODULE_SCENE_MAP = {
    'site': 'ai_denoise_site',
    'fileleak': 'ai_denoise_fileleak',
    'cert': 'ai_denoise_cert',
    'url': 'ai_denoise_url',
    'vuln': 'ai_denoise_vuln',
    'nuclei_result': 'ai_denoise_nuclei_result',
}

AI_DENOISE_MODULE_LABEL_MAP = {
    'site': '站点',
    'fileleak': '目录扫描',
    'cert': 'SSL证书',
    'url': 'URL信息',
    'vuln': '风险',
    'nuclei_result': 'PoC风险',
}

AI_DENOISE_MAX_ITEMS = 120
AI_DENOISE_MAX_ITEM_TEXT_LEN = 5000
AI_DENOISE_RESULT_LEVEL_WEIGHT = {
    'disabled': -1,
    'safe': 0,
    'suspicious': 1,
    'danger': 2,
}


def _default_ai_prompt_templates():
    """
    默认提示词模板（覆盖 AI 报告与误报复核两类场景）。
    """
    return [
        {
            'id': 'default_ai_report',
            'name': '默认AI报告模板',
            'scene': 'ai_report_export',
            'content': (
                "你是互联网资产自动化收集系统的安全分析助手。"
                "请基于输入数据输出结构化研判：任务概览、关键资产、风险聚类、疑似误报、优先修复建议、复测建议。"
                "要求结论可执行、避免夸大风险、避免输出不存在的数据。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_fp_review',
            'name': '默认误报复核模板',
            'scene': 'false_positive_review',
            'content': (
                "你是安全误报复核助手。"
                "请根据规则命中、上下文证据、影响面和可复现性进行评分，输出 pass/suspected_fp/manual_review 三档。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_site',
            'name': '默认AI去噪-站点',
            'scene': 'ai_denoise_site',
            'content': (
                "你是站点价值分析助手。请基于站点URL、标题、响应头、状态码与指纹信息，"
                "输出正常/可疑/危险结论，并给出AI研判后的指纹结果、证据与处置建议。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_fileleak',
            'name': '默认AI去噪-目录扫描',
            'scene': 'ai_denoise_fileleak',
            'content': (
                "你是目录扫描去噪助手。请基于URL路径、状态码、标题和返回体长度，输出风险结论：正常/可疑/危险。"
                "必须给出证据要点与修复建议，避免夸大。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_cert',
            'name': '默认AI去噪-SSL证书',
            'scene': 'ai_denoise_cert',
            'content': (
                "你是证书安全分析助手。请基于证书有效期、签发信息、协议与套件特征，给出证书安全结论，"
                "并输出到期风险依据与处置建议。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_url',
            'name': '默认AI去噪-URL信息',
            'scene': 'ai_denoise_url',
            'content': (
                "你是URL风险去噪助手。请基于URL路径、状态码、标题和上下文，输出安全/可疑/危险结论，"
                "并给出依据与建议。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_vuln',
            'name': '默认AI去噪-风险',
            'scene': 'ai_denoise_vuln',
            'content': (
                "你是漏洞误报复核助手。请根据风险等级、目标、验证证据与规则上下文，判断可信或疑似误报，"
                "并输出处置建议。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_poc',
            'name': '默认AI去噪-PoC风险',
            'scene': 'ai_denoise_nuclei_result',
            'content': (
                "你是PoC风险复核助手。请结合扫描器、规则ID、风险等级、命中URL与验证信息判断可信度，"
                "识别疑似误报并给出复测建议。"
            ),
            'updated_at': '',
        },
    ]


def _normalize_ai_provider_id(raw_provider):
    """
    规范化 AI 提供方标识。
    """
    provider_id = str(raw_provider or '').strip().lower()
    provider_alias = {
        'tongyi': 'qwen',
        'qianwen': 'qwen',
        'moonshot': 'kimi',
        'openai_compatible': 'custom_compatible',
        'compatible': 'custom_compatible',
    }
    provider_id = provider_alias.get(provider_id, provider_id)
    if provider_id not in AI_PROVIDER_IDS:
        return 'openai'
    return provider_id


def _normalize_ai_custom_providers(raw_items):
    """
    规范化 OpenAI 兼容自定义提供方列表。
    """
    if not isinstance(raw_items, list):
        return []

    items = []
    seen = set()
    for item in raw_items:
        if not isinstance(item, dict):
            continue

        provider_id = str(item.get('id') or '').strip()
        name = str(item.get('name') or '').strip()
        base_url = str(item.get('base_url') or '').strip()
        model = str(item.get('model') or '').strip()
        if not provider_id:
            provider_id = 'custom_{}'.format(len(items) + 1)
        if not name:
            name = provider_id
        if provider_id in seen:
            continue
        seen.add(provider_id)
        items.append(
            {
                'id': provider_id,
                'name': name,
                'base_url': base_url,
                'model': model,
            }
        )

    return items


def _normalize_ai_prompt_templates(raw_templates):
    """
    规范化提示词模板，若为空则回落默认模板。
    """
    templates = []
    seen = set()

    if isinstance(raw_templates, list):
        for item in raw_templates:
            if not isinstance(item, dict):
                continue
            prompt_id = str(item.get('id') or '').strip()
            name = str(item.get('name') or '').strip()
            scene = str(item.get('scene') or '').strip() or 'ai_report_export'
            content = str(item.get('content') or '').strip()
            updated_at = str(item.get('updated_at') or '').strip()
            if not prompt_id:
                prompt_id = 'prompt_{}'.format(len(templates) + 1)
            if not name:
                name = prompt_id
            if not content:
                continue
            if prompt_id in seen:
                continue
            seen.add(prompt_id)
            templates.append(
                {
                    'id': prompt_id,
                    'name': name,
                    'scene': scene,
                    'content': content,
                    'updated_at': updated_at,
                }
            )

    default_templates = _default_ai_prompt_templates()
    if not templates:
        return default_templates

    existing_ids = set(str(item.get('id') or '').strip() for item in templates if item.get('id'))
    for item in default_templates:
        template_id = str(item.get('id') or '').strip()
        if not template_id or template_id in existing_ids:
            continue
        templates.append(dict(item))
        existing_ids.add(template_id)

    return templates


def _default_ai_model_profiles():
    """
    默认模型配置（单模型生效，多模型可配置）。
    """
    preset = AI_PROVIDER_PRESET_MAP.get('openai', {})
    return [
        {
            'id': 'default_model',
            'name': '默认模型',
            'provider': 'openai',
            'base_url': str(preset.get('base_url') or ''),
            'api_key': '',
            'model': str(preset.get('default_model') or ''),
            'timeout_sec': 40,
            'temperature': 0.2,
            'max_tokens': 4000,
        }
    ]


def _normalize_ai_model_profiles(raw_profiles, legacy_ai_conf=None):
    """
    规范化模型配置列表，兼容旧版单模型字段。
    """
    profiles = []
    seen = set()

    if isinstance(raw_profiles, list):
        for index, item in enumerate(raw_profiles):
            if not isinstance(item, dict):
                continue

            profile_id = str(item.get('id') or '').strip() or 'model_{}'.format(index + 1)
            if profile_id in seen:
                continue
            seen.add(profile_id)

            provider_id = _normalize_ai_provider_id(item.get('provider'))
            provider_preset = AI_PROVIDER_PRESET_MAP.get(provider_id, {})
            base_url = str(item.get('base_url') or '').strip() or str(provider_preset.get('base_url') or '')
            model = str(item.get('model') or '').strip() or str(provider_preset.get('default_model') or '')

            profiles.append(
                {
                    'id': profile_id,
                    'name': str(item.get('name') or profile_id).strip(),
                    'provider': provider_id,
                    'base_url': base_url,
                    'api_key': str(item.get('api_key') or '').strip(),
                    'model': model,
                    'timeout_sec': _safe_int(item.get('timeout_sec'), 40, min_value=1),
                    'temperature': _safe_float(item.get('temperature'), 0.2, min_value=0.0),
                    'max_tokens': _safe_int(item.get('max_tokens'), 4000, min_value=1),
                }
            )

    # 兼容旧版单模型字段，自动转换为 profiles[0]
    if not profiles and isinstance(legacy_ai_conf, dict):
        provider_id = _normalize_ai_provider_id(legacy_ai_conf.get('PROVIDER', 'openai'))
        provider_preset = AI_PROVIDER_PRESET_MAP.get(provider_id, {})
        profiles = [
            {
                'id': 'default_model',
                'name': '默认模型',
                'provider': provider_id,
                'base_url': str(legacy_ai_conf.get('BASE_URL') or '').strip() or str(provider_preset.get('base_url') or ''),
                'api_key': str(legacy_ai_conf.get('API_KEY') or '').strip(),
                'model': str(legacy_ai_conf.get('MODEL') or '').strip() or str(provider_preset.get('default_model') or ''),
                'timeout_sec': _safe_int(legacy_ai_conf.get('TIMEOUT_SEC'), 40, min_value=1),
                'temperature': _safe_float(legacy_ai_conf.get('TEMPERATURE'), 0.2, min_value=0.0),
                'max_tokens': _safe_int(legacy_ai_conf.get('MAX_TOKENS'), 4000, min_value=1),
            }
        ]

    if profiles:
        return profiles
    return _default_ai_model_profiles()


def _pick_active_ai_model_profile(model_profiles, active_profile_id=''):
    """
    从模型列表中选出当前生效模型，若未匹配则回退首项。
    """
    profiles = model_profiles if isinstance(model_profiles, list) else []
    if not profiles:
        return {}

    target_id = str(active_profile_id or '').strip()
    if target_id:
        for item in profiles:
            if str(item.get('id') or '').strip() == target_id:
                return item

    return profiles[0]


def _normalize_ai_denoise_modules(raw_modules):
    """
    规范化 AI 去噪模块开关（默认全部开启）。
    """
    normalized = {}
    source = raw_modules if isinstance(raw_modules, dict) else {}
    for module_id in AI_DENOISE_MODULE_SCENE_MAP:
        if module_id in source:
            normalized[module_id] = _safe_bool(source.get(module_id), True)
        else:
            normalized[module_id] = True
    return normalized


def _normalize_ai_denoise_prompt_ids(raw_prompt_ids, prompt_templates):
    """
    规范化 AI 去噪模块提示词绑定。
    """
    source = raw_prompt_ids if isinstance(raw_prompt_ids, dict) else {}
    template_id_set = set()
    scene_prompt_ids = {}
    for item in prompt_templates or []:
        if not isinstance(item, dict):
            continue
        prompt_id = str(item.get('id') or '').strip()
        scene = str(item.get('scene') or '').strip()
        if not prompt_id:
            continue
        template_id_set.add(prompt_id)
        if scene and scene not in scene_prompt_ids:
            scene_prompt_ids[scene] = prompt_id

    fallback_prompt_id = ''
    if prompt_templates:
        fallback_prompt_id = str((prompt_templates[0] or {}).get('id') or '').strip()

    normalized = {}
    for module_id, scene in AI_DENOISE_MODULE_SCENE_MAP.items():
        candidate = str(source.get(module_id) or '').strip()
        if candidate and candidate in template_id_set:
            normalized[module_id] = candidate
            continue
        scene_prompt_id = str(scene_prompt_ids.get(scene) or '').strip()
        if scene_prompt_id:
            normalized[module_id] = scene_prompt_id
            continue
        normalized[module_id] = fallback_prompt_id

    return normalized


def _extract_ai_config(config_obj):
    """
    从完整配置中提取 AI 管理配置。
    """
    ai_conf = config_obj.get('AI', {})
    if not isinstance(ai_conf, dict):
        ai_conf = {}

    model_profiles = _normalize_ai_model_profiles(ai_conf.get('MODEL_PROFILES'), legacy_ai_conf=ai_conf)
    active_model_profile_id = str(ai_conf.get('ACTIVE_MODEL_PROFILE_ID') or '').strip()
    active_profile = _pick_active_ai_model_profile(model_profiles, active_model_profile_id)
    if active_profile:
        active_model_profile_id = str(active_profile.get('id') or '').strip()

    prompt_templates = _normalize_ai_prompt_templates(ai_conf.get('PROMPT_TEMPLATES'))
    prompt_ids = [item.get('id') for item in prompt_templates if item.get('id')]
    active_prompt_id = str(ai_conf.get('ACTIVE_PROMPT_ID') or '').strip()
    if active_prompt_id not in prompt_ids:
        active_prompt_id = prompt_ids[0] if prompt_ids else ''
    ai_denoise_modules = _normalize_ai_denoise_modules(ai_conf.get('AI_DENOISE_MODULES'))
    ai_denoise_prompt_ids = _normalize_ai_denoise_prompt_ids(
        ai_conf.get('AI_DENOISE_PROMPT_IDS'),
        prompt_templates,
    )

    return {
        'enable': _safe_bool(ai_conf.get('ENABLE'), True),
        'active_model_profile_id': active_model_profile_id,
        'model_profiles': model_profiles,
        # 向后兼容：保留单模型字段，前端旧版与历史调用可继续读取
        'provider': str(active_profile.get('provider') or 'openai'),
        'custom_provider_name': str(ai_conf.get('CUSTOM_PROVIDER_NAME') or active_profile.get('name') or '').strip(),
        'base_url': str(active_profile.get('base_url') or '').strip(),
        'api_key': str(active_profile.get('api_key') or '').strip(),
        'model': str(active_profile.get('model') or '').strip(),
        'timeout_sec': _safe_int(active_profile.get('timeout_sec'), 40, min_value=1),
        'temperature': _safe_float(active_profile.get('temperature'), 0.2, min_value=0.0),
        'max_tokens': _safe_int(active_profile.get('max_tokens'), 4000, min_value=1),
        'dialog_system_prompt': str(ai_conf.get('DIALOG_SYSTEM_PROMPT') or '').strip(),
        'dialog_style': str(ai_conf.get('DIALOG_STYLE') or '专业').strip(),
        'dialog_language': str(ai_conf.get('DIALOG_LANGUAGE') or 'zh-CN').strip(),
        'dialog_context_messages': _safe_int(ai_conf.get('DIALOG_CONTEXT_MESSAGES'), 8, min_value=1),
        'active_prompt_id': active_prompt_id,
        'prompt_templates': prompt_templates,
        'custom_compat_providers': _normalize_ai_custom_providers(ai_conf.get('CUSTOM_COMPAT_PROVIDERS')),
        'ai_denoise_enable': _safe_bool(ai_conf.get('AI_DENOISE_ENABLE'), True),
        'ai_denoise_modules': ai_denoise_modules,
        'ai_denoise_prompt_ids': ai_denoise_prompt_ids,
    }


def _build_ai_sensitive_configured_map(ai_config: dict):
    """
    基于 ai_config 计算敏感字段（API Key）是否已配置。
    """
    if not isinstance(ai_config, dict):
        ai_config = {}

    model_profiles = ai_config.get('model_profiles')
    profile_list = model_profiles if isinstance(model_profiles, list) else []
    model_profile_api_keys = {}
    for item in profile_list:
        if not isinstance(item, dict):
            continue
        profile_id = str(item.get('id') or '').strip()
        if not profile_id:
            continue
        model_profile_api_keys[profile_id] = bool(str(item.get('api_key') or '').strip())

    active_profile = _pick_active_ai_model_profile(
        profile_list,
        str(ai_config.get('active_model_profile_id') or '').strip(),
    )
    active_api_key_configured = False
    if isinstance(active_profile, dict):
        active_api_key_configured = bool(str(active_profile.get('api_key') or '').strip())

    return {
        'api_key': active_api_key_configured,
        'model_profile_api_keys': model_profile_api_keys,
    }


def _sanitize_ai_config_for_client(ai_config: dict):
    """
    返回给前端时抹除 AI Key 明文，并附带是否已配置状态。
    """
    safe_ai_config = dict(ai_config or {})
    sensitive_configured = _build_ai_sensitive_configured_map(safe_ai_config)

    safe_profiles = []
    raw_profiles = safe_ai_config.get('model_profiles')
    if isinstance(raw_profiles, list):
        for item in raw_profiles:
            if not isinstance(item, dict):
                continue
            profile = dict(item)
            profile['api_key'] = ''
            safe_profiles.append(profile)
    safe_ai_config['model_profiles'] = safe_profiles
    safe_ai_config['api_key'] = ''
    return safe_ai_config, sensitive_configured


def _fill_missing_sensitive_ai_fields(ai_config: dict, config_obj: dict):
    """
    对未提交的 AI Key 回填当前配置值，避免前端“未改动字段”被误清空。
    """
    if not isinstance(ai_config, dict):
        raise ValueError('ai_config 必须为对象')

    merged_ai_config = dict(ai_config)
    current_ai_config = _extract_ai_config(config_obj if isinstance(config_obj, dict) else {})

    current_profile_key_map = {}
    current_profiles = current_ai_config.get('model_profiles')
    if isinstance(current_profiles, list):
        for item in current_profiles:
            if not isinstance(item, dict):
                continue
            profile_id = str(item.get('id') or '').strip()
            if not profile_id:
                continue
            current_profile_key_map[profile_id] = str(item.get('api_key') or '').strip()

    submitted_profiles = ai_config.get('model_profiles')
    if isinstance(submitted_profiles, list):
        merged_profiles = []
        for item in submitted_profiles:
            if not isinstance(item, dict):
                continue
            profile = dict(item)
            profile_id = str(profile.get('id') or '').strip()
            if 'api_key' not in profile and profile_id:
                profile['api_key'] = current_profile_key_map.get(profile_id, '')
            merged_profiles.append(profile)
        merged_ai_config['model_profiles'] = merged_profiles

    if 'api_key' not in merged_ai_config:
        active_profile_id = str(merged_ai_config.get('active_model_profile_id') or '').strip()
        if active_profile_id:
            merged_ai_config['api_key'] = current_profile_key_map.get(active_profile_id, '')
        else:
            merged_ai_config['api_key'] = str(current_ai_config.get('api_key') or '').strip()

    return merged_ai_config


def _merge_ai_config(config_obj, ai_config):
    """
    将 AI 管理配置写回完整配置对象。
    """
    if not isinstance(ai_config, dict):
        raise ValueError('ai_config 必须为对象')

    if not isinstance(config_obj.get('AI'), dict):
        config_obj['AI'] = {}
    ai_conf = config_obj['AI']

    model_profiles = _normalize_ai_model_profiles(ai_config.get('model_profiles'), legacy_ai_conf=ai_config)
    active_model_profile_id = str(ai_config.get('active_model_profile_id') or '').strip()
    active_profile = _pick_active_ai_model_profile(model_profiles, active_model_profile_id)
    if active_profile:
        active_model_profile_id = str(active_profile.get('id') or '').strip()

    prompt_templates = _normalize_ai_prompt_templates(ai_config.get('prompt_templates'))
    prompt_ids = [item.get('id') for item in prompt_templates if item.get('id')]

    active_prompt_id = str(ai_config.get('active_prompt_id') or '').strip()
    if active_prompt_id not in prompt_ids:
        active_prompt_id = prompt_ids[0] if prompt_ids else ''
    ai_denoise_modules = _normalize_ai_denoise_modules(ai_config.get('ai_denoise_modules'))
    ai_denoise_prompt_ids = _normalize_ai_denoise_prompt_ids(
        ai_config.get('ai_denoise_prompt_ids'),
        prompt_templates,
    )

    ai_conf['ENABLE'] = _safe_bool(ai_config.get('enable'), True)
    ai_conf['MODEL_PROFILES'] = model_profiles
    ai_conf['ACTIVE_MODEL_PROFILE_ID'] = active_model_profile_id
    # 向后兼容：保留单模型字段，运行期组件可继续复用
    ai_conf['PROVIDER'] = str(active_profile.get('provider') or 'openai')
    ai_conf['CUSTOM_PROVIDER_NAME'] = str(ai_config.get('custom_provider_name') or active_profile.get('name') or '').strip()
    ai_conf['BASE_URL'] = str(active_profile.get('base_url') or '').strip()
    ai_conf['API_KEY'] = str(active_profile.get('api_key') or '').strip()
    ai_conf['MODEL'] = str(active_profile.get('model') or '').strip()
    ai_conf['TIMEOUT_SEC'] = _safe_int(active_profile.get('timeout_sec'), 40, min_value=1)
    ai_conf['TEMPERATURE'] = _safe_float(active_profile.get('temperature'), 0.2, min_value=0.0)
    ai_conf['MAX_TOKENS'] = _safe_int(active_profile.get('max_tokens'), 4000, min_value=1)
    ai_conf['DIALOG_SYSTEM_PROMPT'] = str(ai_config.get('dialog_system_prompt') or '').strip()
    ai_conf['DIALOG_STYLE'] = str(ai_config.get('dialog_style') or '专业').strip()
    ai_conf['DIALOG_LANGUAGE'] = str(ai_config.get('dialog_language') or 'zh-CN').strip()
    ai_conf['DIALOG_CONTEXT_MESSAGES'] = _safe_int(ai_config.get('dialog_context_messages'), 8, min_value=1)
    ai_conf['ACTIVE_PROMPT_ID'] = active_prompt_id
    ai_conf['PROMPT_TEMPLATES'] = prompt_templates
    ai_conf['CUSTOM_COMPAT_PROVIDERS'] = _normalize_ai_custom_providers(
        ai_config.get('custom_compat_providers')
    )
    ai_conf['AI_DENOISE_ENABLE'] = _safe_bool(ai_config.get('ai_denoise_enable'), True)
    ai_conf['AI_DENOISE_MODULES'] = ai_denoise_modules
    ai_conf['AI_DENOISE_PROMPT_IDS'] = ai_denoise_prompt_ids

    return config_obj


def _test_ai_config_connectivity(ai_config):
    """
    测试 AI 连接可用性（发送固定问候语，校验真实对话链路）。
    """
    if not isinstance(ai_config, dict):
        raise ValueError('ai_config 必须为对象')

    model_profiles = _normalize_ai_model_profiles(ai_config.get('model_profiles'), legacy_ai_conf=ai_config)
    active_model_profile_id = str(ai_config.get('active_model_profile_id') or '').strip()
    active_profile = _pick_active_ai_model_profile(model_profiles, active_model_profile_id)

    provider_id = str(active_profile.get('provider') or 'openai')
    base_url = str(active_profile.get('base_url') or '').strip()
    api_key = str(active_profile.get('api_key') or '').strip()
    model_name = str(active_profile.get('model') or '').strip()
    profile_name = str(active_profile.get('name') or active_profile.get('id') or '').strip()
    timeout_sec = _safe_int(active_profile.get('timeout_sec'), 40, min_value=5)
    request_text = '你好呀～'

    if not api_key:
        return {
            'ok': False,
            'message': '未配置 API Key，已跳过连通性测试',
            'provider': provider_id,
            'detail': {
                'model': model_name,
                'profile': profile_name,
                'request_text': request_text,
                'reply_text': '',
            },
            'tested_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
    if not base_url:
        return {
            'ok': False,
            'message': '未配置 Base URL，已跳过连通性测试',
            'provider': provider_id,
            'detail': {
                'model': model_name,
                'profile': profile_name,
                'request_text': request_text,
                'reply_text': '',
            },
            'tested_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }

    models_url = '{}/models'.format(base_url.rstrip('/'))
    headers = {
        'Authorization': 'Bearer {}'.format(api_key),
        'Content-Type': 'application/json',
    }

    try:
        conn = utils.http_req(models_url, 'get', headers=headers, timeout=(8, timeout_sec))
        status_code = int(getattr(conn, 'status_code', 0) or 0)
        try:
            payload = conn.json() if conn is not None else {}
        except Exception:
            payload = {}

        if status_code != 200:
            err_message = ''
            if isinstance(payload, dict):
                error_obj = payload.get('error')
                if isinstance(error_obj, dict):
                    err_message = str(error_obj.get('message') or '')
                err_message = err_message or str(payload.get('message') or '')
            err_message = err_message or 'HTTP {}'.format(status_code)
            return {
                'ok': False,
                'message': 'AI 测试失败：{}'.format(err_message),
                'provider': provider_id,
                'detail': {
                    'status_code': status_code,
                    'base_url': base_url,
                    'model': model_name,
                    'profile': profile_name,
                    'request_text': request_text,
                    'reply_text': '',
                },
                'tested_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }

        models = payload.get('data', []) if isinstance(payload, dict) else []
        model_count = len(models) if isinstance(models, list) else 0
        first_model = ''
        if isinstance(models, list) and models:
            first_model = str((models[0] or {}).get('id') or '').strip()

        test_model = model_name or first_model
        if not test_model:
            return {
                'ok': False,
                'message': 'AI 测试失败：未发现可用模型',
                'provider': provider_id,
                'detail': {
                    'base_url': base_url,
                    'model_count': model_count,
                    'first_model': first_model,
                    'model': model_name,
                    'profile': profile_name,
                    'request_text': request_text,
                    'reply_text': '',
                },
                'tested_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }

        chat_url = '{}/chat/completions'.format(base_url.rstrip('/'))
        request_body = {
            'model': test_model,
            'temperature': min(max(_safe_float(active_profile.get('temperature'), 0.2, min_value=0.0), 0.0), 1.0),
            'max_tokens': max(64, min(_safe_int(active_profile.get('max_tokens'), 128, min_value=32), 512)),
            'messages': [
                {
                    'role': 'user',
                    'content': request_text,
                }
            ],
        }

        chat_conn = utils.http_req(chat_url, 'post', headers=headers, json=request_body, timeout=(8, timeout_sec))
        chat_status_code = int(getattr(chat_conn, 'status_code', 0) or 0)
        try:
            chat_payload = chat_conn.json() if chat_conn is not None else {}
        except Exception:
            chat_payload = {}

        if chat_status_code != 200:
            err_message = ''
            if isinstance(chat_payload, dict):
                error_obj = chat_payload.get('error')
                if isinstance(error_obj, dict):
                    err_message = str(error_obj.get('message') or '').strip()
                if not err_message:
                    err_message = str(chat_payload.get('message') or '').strip()
            err_message = err_message or 'HTTP {}'.format(chat_status_code)
            return {
                'ok': False,
                'message': 'AI 测试失败：{}'.format(err_message),
                'provider': provider_id,
                'detail': {
                    'status_code': chat_status_code,
                    'base_url': base_url,
                    'model_count': model_count,
                    'first_model': first_model,
                    'model': test_model,
                    'profile': profile_name,
                    'request_text': request_text,
                    'reply_text': '',
                },
                'tested_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }

        reply_text = ''
        choices = chat_payload.get('choices', []) if isinstance(chat_payload, dict) else []
        message_obj = choices[0].get('message') if isinstance(choices, list) and choices else {}
        if isinstance(message_obj, dict):
            content_obj = message_obj.get('content')
            if isinstance(content_obj, str):
                reply_text = content_obj.strip()
            elif isinstance(content_obj, list):
                text_parts = []
                for fragment in content_obj:
                    if isinstance(fragment, dict) and str(fragment.get('type') or '').strip() == 'text':
                        text_value = str(fragment.get('text') or '').strip()
                        if text_value:
                            text_parts.append(text_value)
                reply_text = '\n'.join(text_parts).strip()

        if not reply_text:
            reply_text = '（接口已响应，但返回内容为空）'

        return {
            'ok': True,
            'message': 'AI 测试成功',
            'provider': provider_id,
            'detail': {
                'base_url': base_url,
                'model_count': model_count,
                'first_model': first_model,
                'model': test_model,
                'profile': profile_name,
                'request_text': request_text,
                'reply_text': reply_text,
            },
            'tested_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
    except Exception as exc:
        return {
            'ok': False,
            'message': 'AI 测试失败：{}'.format(exc),
            'provider': provider_id,
            'detail': {
                'base_url': base_url,
                'model': model_name,
                'profile': profile_name,
                'request_text': request_text,
                'reply_text': '',
            },
            'tested_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }


def _safe_int_any(value, default_value=0):
    try:
        if isinstance(value, str) and not value.strip():
            return int(default_value)
        return int(float(value))
    except Exception:
        return int(default_value)


def _safe_float_any(value, default_value=0.0):
    try:
        if isinstance(value, str) and not value.strip():
            return float(default_value)
        return float(value)
    except Exception:
        return float(default_value)


def _truncate_text(text, max_length=220):
    value = str(text or '').strip()
    if not value:
        return ''
    if len(value) <= max_length:
        return value
    return '{}...'.format(value[:max_length])


def _normalize_string_list_value(value, max_items=6, max_item_len=180):
    if value is None:
        return []

    items = []
    if isinstance(value, list):
        items = value
    elif isinstance(value, tuple):
        items = list(value)
    elif isinstance(value, str):
        items = [item for item in re.split(r'[\r\n]+', value) if str(item or '').strip()]
    else:
        items = [value]

    cleaned = []
    seen = set()
    for item in items:
        if isinstance(item, dict):
            text = _truncate_text(json.dumps(item, ensure_ascii=False), max_item_len)
        elif isinstance(item, (list, tuple)):
            text = _truncate_text(', '.join(str(x or '').strip() for x in item if str(x or '').strip()), max_item_len)
        else:
            text = _truncate_text(str(item or '').strip(), max_item_len)
        if not text or text in seen:
            continue
        seen.add(text)
        cleaned.append(text)
        if len(cleaned) >= max_items:
            break
    return cleaned


def _normalize_dialogue_role(value):
    role = str(value or '').strip().lower()
    if role in ('system', 'user', 'assistant', 'tool'):
        return role
    return 'assistant'


def _normalize_dialogue_records(records, max_items=10, max_len=2600):
    if not isinstance(records, list):
        return []

    normalized = []
    for item in records:
        if len(normalized) >= max_items:
            break
        if isinstance(item, dict):
            role = _normalize_dialogue_role(item.get('role'))
            content = _normalize_item_text(item.get('content') or item.get('message') or '', max_len)
        else:
            role = 'assistant'
            content = _normalize_item_text(item, max_len)
        if not content:
            continue
        normalized.append(
            {
                'role': role,
                'content': content,
            }
        )
    return normalized


def _build_rule_dialogue_records(module_id, item, rule_result, note=''):
    module_label = AI_DENOISE_MODULE_LABEL_MAP.get(module_id) or module_id
    context = _build_ai_denoise_context(module_id, item)
    assistant_lines = [
        '最终结论：{}'.format(rule_result.get('display_text') or '-'),
        '摘要：{}'.format(rule_result.get('summary') or '-'),
    ]
    evidence_items = _normalize_string_list_value(rule_result.get('evidence'), max_items=4, max_item_len=160)
    if evidence_items:
        assistant_lines.append('依据：{}'.format('；'.join(evidence_items)))
    suggestion_items = _normalize_string_list_value(rule_result.get('suggestions'), max_items=4, max_item_len=160)
    if suggestion_items:
        assistant_lines.append('建议：{}'.format('；'.join(suggestion_items)))
    if note:
        assistant_lines.append('说明：{}'.format(_truncate_text(note, 180)))

    return _normalize_dialogue_records(
        [
            {
                'role': 'system',
                'content': '站在安全运营视角，对“{}”进行去噪与价值研判。'.format(module_label),
            },
            {
                'role': 'user',
                'content': json.dumps(context, ensure_ascii=False),
            },
            {
                'role': 'assistant',
                'content': '\n'.join(assistant_lines),
            },
        ]
    )


def _normalize_item_text(value, max_length=AI_DENOISE_MAX_ITEM_TEXT_LEN):
    if value is None:
        return ''
    if isinstance(value, str):
        return _truncate_text(value, max_length)
    if isinstance(value, (int, float, bool)):
        return _truncate_text(str(value), max_length)
    try:
        return _truncate_text(json.dumps(value, ensure_ascii=False), max_length)
    except Exception:
        return _truncate_text(str(value), max_length)


def _extract_row_key(item, index=0):
    if isinstance(item, dict):
        for key in ('_row_key', '_id', 'id', 'task_id', 'job_id'):
            value = item.get(key)
            if isinstance(value, ObjectId):
                return str(value)
            if isinstance(value, dict):
                oid = str(value.get('$oid') or value.get('oid') or '').strip()
                if oid:
                    return oid
            if isinstance(value, (str, int, float)):
                text = str(value).strip()
                if text:
                    return text
    return 'row_{}'.format(index + 1)


def _extract_task_id_from_item(item):
    if not isinstance(item, dict):
        return ''
    for key in ('task_id', '_task_id', 'taskId'):
        value = item.get(key)
        if isinstance(value, ObjectId):
            return str(value)
        if isinstance(value, (str, int, float)):
            text = str(value).strip()
            if text:
                return text
        if isinstance(value, dict):
            oid = str(value.get('$oid') or value.get('oid') or value.get('_id') or '').strip()
            if oid:
                return oid
    return ''


def _resolve_task_ai_denoise_flag(task_id, cache_dict):
    task_id_text = str(task_id or '').strip()
    if not task_id_text:
        return True
    if task_id_text in cache_dict:
        return cache_dict[task_id_text]

    query_id = task_id_text
    if ObjectId.is_valid(task_id_text):
        query_id = ObjectId(task_id_text)

    task_doc = utils.conn_db('task').find_one(
        {'_id': query_id},
        {'_id': 1, 'options.ai_denoise': 1}
    )
    if not isinstance(task_doc, dict):
        cache_dict[task_id_text] = None
        return None

    options = task_doc.get('options') if isinstance(task_doc.get('options'), dict) else {}
    if 'ai_denoise' not in options:
        # 历史任务未包含该字段，按“旧资产未分析”处理。
        cache_dict[task_id_text] = None
        return None

    enabled = bool(options.get('ai_denoise'))
    cache_dict[task_id_text] = enabled
    return enabled


def _normalize_ai_denoise_result_level(value, default_value='safe'):
    text = str(value or '').strip().lower()
    if text in ('disabled', 'close', 'off', '关闭', '已关闭'):
        return 'disabled'
    if text in ('danger', 'high', 'critical', '严重', '危险', '高危', '危急'):
        return 'danger'
    if text in ('suspicious', 'medium', 'manual_review', '可疑', '中危', '待复核'):
        return 'suspicious'
    if text in ('safe', 'normal', 'low', 'pass', '安全', '正常', '低危', '可信'):
        return 'safe'
    return default_value


def _merge_ai_denoise_result_level(current_level, next_level):
    current = _normalize_ai_denoise_result_level(current_level, 'safe')
    candidate = _normalize_ai_denoise_result_level(next_level, 'safe')
    if AI_DENOISE_RESULT_LEVEL_WEIGHT.get(candidate, 0) > AI_DENOISE_RESULT_LEVEL_WEIGHT.get(current, 0):
        return candidate
    return current


def _normalize_risk_level_text(value):
    text = str(value or '').strip().lower()
    if any(word in text for word in ('critical', '严重', 'critical', 'urgent')):
        return '严重'
    if any(word in text for word in ('high', '高', '危急')):
        return '高'
    if any(word in text for word in ('medium', '中')):
        return '中'
    if any(word in text for word in ('low', '低', 'info', '信息')):
        return '低'
    return '中'


def _normalize_trust_level_text(value):
    text = str(value or '').strip().lower()
    if any(word in text for word in ('fp', '误报', 'suspected', '疑似')):
        return '疑似误报'
    return '可信'


def _build_ai_denoise_display_text(module_id, result_level, risk_level='中', trust='可信', cert_expire_days=None):
    if result_level == 'disabled':
        return '已关闭'

    module_id = str(module_id or '').strip()
    if module_id == 'fileleak':
        mapping = {'safe': '正常', 'suspicious': '可疑', 'danger': '危险'}
        return mapping.get(result_level, '正常')
    if module_id == 'site':
        mapping = {'safe': '正常', 'suspicious': '可疑', 'danger': '危险'}
        return mapping.get(result_level, '正常')
    if module_id == 'url':
        mapping = {'safe': '安全', 'suspicious': '可疑', 'danger': '危险'}
        return mapping.get(result_level, '安全')
    if module_id == 'cert':
        mapping = {'safe': '安全', 'suspicious': '可疑', 'danger': '危险'}
        base = mapping.get(result_level, '安全')
        if cert_expire_days is None:
            return base
        days_text = '已过期' if cert_expire_days < 0 else '剩余{}天'.format(cert_expire_days)
        return '{}（{}）'.format(base, days_text)
    if module_id in ('vuln', 'nuclei_result'):
        return '{}/{}'.format(risk_level or '中', trust or '可信')
    return '已分析'


def _parse_datetime_text(value):
    text = str(value or '').strip()
    if not text:
        return None

    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%d',
    ]
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt)
        except Exception:
            continue

    normalized = text
    if normalized.endswith('Z'):
        normalized = normalized[:-1] + '+00:00'
    try:
        return datetime.fromisoformat(normalized)
    except Exception:
        return None


def _extract_site_finger_names(value):
    if value is None:
        return []

    names = []
    if isinstance(value, dict):
        candidate_name = str(value.get('name') or value.get('finger') or '').strip()
        if candidate_name:
            names.append(candidate_name)
        for nested_key in ('finger', 'fingers', 'items'):
            nested_value = value.get(nested_key)
            if isinstance(nested_value, list):
                names.extend(_extract_site_finger_names(nested_value))
    elif isinstance(value, list):
        for item in value:
            names.extend(_extract_site_finger_names(item))
    elif isinstance(value, str):
        raw_text = value.strip()
        if not raw_text:
            return []
        parsed = None
        if raw_text.startswith('{') or raw_text.startswith('['):
            try:
                parsed = json.loads(raw_text)
            except Exception:
                parsed = None
        if parsed is not None:
            names.extend(_extract_site_finger_names(parsed))
        else:
            for item in re.split(r'[\r\n,;/]+', raw_text):
                text = str(item or '').strip()
                if text and text not in ('-', 'null', 'None'):
                    names.append(text)
    else:
        text = str(value).strip()
        if text:
            names.append(text)

    cleaned = []
    seen = set()
    for item in names:
        text = _truncate_text(str(item or '').strip(), 80)
        if not text:
            continue
        normalized = text.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        cleaned.append(text)
        if len(cleaned) >= 20:
            break
    return cleaned


def _normalize_header_text(value):
    if value is None:
        return ''
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            key_text = str(key or '').strip()
            item_text = _normalize_item_text(item, 260)
            if key_text and item_text:
                lines.append('{}: {}'.format(key_text, item_text))
        return '\n'.join(lines[:40])
    return _normalize_item_text(value, 2000)


def _rule_analyze_site_item(item):
    site_url = _normalize_item_text(item.get('site') or item.get('url') or item.get('host'), 900)
    title_text = _normalize_item_text(item.get('title'), 320)
    header_text = _normalize_header_text(item.get('headers'))
    finger_names = _extract_site_finger_names(item.get('finger'))
    status_code = _safe_int_any(item.get('status_code') or item.get('status'), 0)

    lower_title = title_text.lower()
    lower_headers = header_text.lower()
    lower_fingers = [name.lower() for name in finger_names]

    high_value_title_keywords = (
        'admin', '后台', '管理', 'console', 'dashboard', 'jenkins', 'grafana', 'kibana',
        'swagger', 'phpinfo', 'index of', 'actuator'
    )
    high_value_header_keywords = (
        'x-powered-by', 'server:', 'set-cookie', 'x-aspnet-version', 'x-generator'
    )
    high_value_finger_keywords = (
        'wordpress', 'drupal', 'jenkins', 'grafana', 'phpmyadmin', 'elasticsearch',
        'weblogic', 'struts', 'spring', 'tomcat', 'nginx', 'apache'
    )

    result_level = 'safe'
    evidence = []
    ai_finger_result = list(finger_names)

    if status_code in (401, 403):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('站点返回鉴权状态码 {}，可能存在后台入口。'.format(status_code))

    if status_code in (200, 201, 206):
        if any(keyword in lower_title for keyword in high_value_title_keywords):
            result_level = _merge_ai_denoise_result_level(result_level, 'danger')
            evidence.append('标题命中高价值资产特征（后台/组件/调试入口）。')

    if any(keyword in lower_headers for keyword in high_value_header_keywords):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('响应头暴露技术栈特征，可用于后续攻击面研判。')

    if any(any(keyword in finger for keyword in high_value_finger_keywords) for finger in lower_fingers):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('指纹命中高价值中间件或常见攻击面组件。')

    if not finger_names:
        evidence.append('未识别到稳定指纹，建议结合截图与源码二次确认。')
    else:
        evidence.append('识别到指纹 {} 个。'.format(len(finger_names)))

    if not evidence:
        evidence.append('未发现明显高价值站点特征。')

    suggestions = []
    if result_level == 'danger':
        suggestions.extend([
            '建议优先纳入人工复核，检查后台鉴权、默认口令与敏感接口暴露。',
            '结合 PoC 扫描与手工验证确认可利用性后再推进修复闭环。',
        ])
    elif result_level == 'suspicious':
        suggestions.extend([
            '建议补充目录、URL、证书与端口信息交叉分析，提高价值判定准确率。',
            '对命中组件持续关注版本与漏洞情报，必要时优先复测。',
        ])
    else:
        suggestions.append('站点整体风险信号较弱，建议维持常规巡检与指纹更新。')

    display_text = _build_ai_denoise_display_text('site', result_level)
    summary = '站点价值分析结果：{}。站点：{}'.format(display_text, site_url or '-')
    return {
        'result_level': result_level,
        'risk_level': '高' if result_level == 'danger' else ('中' if result_level == 'suspicious' else '低'),
        'trust': '-',
        'summary': summary,
        'evidence': evidence[:8],
        'suggestions': suggestions[:6],
        'display_text': display_text,
        'finger_result': ai_finger_result[:12],
    }


def _rule_analyze_fileleak_item(item):
    url_text = _normalize_item_text(item.get('url'), 900)
    title_text = _normalize_item_text(item.get('title'), 300)
    status_code = _safe_int_any(item.get('status_code'), 0)
    content_length = _safe_int_any(item.get('content_length'), 0)
    lower_url = url_text.lower()
    lower_title = title_text.lower()

    sensitive_keywords = (
        'admin', 'backup', 'bak', '.sql', '.zip', '.tar', '.gz', '.7z', '.env',
        'config', 'secret', 'token', 'password', 'passwd', 'credential', 'swagger', 'actuator', '.git'
    )

    result_level = 'safe'
    evidence = []
    if any(keyword in lower_url for keyword in sensitive_keywords) and status_code in (200, 201, 206):
        result_level = 'danger'
        evidence.append('URL 含敏感路径关键字且返回 {}。'.format(status_code))
    elif any(keyword in lower_url for keyword in sensitive_keywords) and status_code in (401, 403):
        result_level = 'suspicious'
        evidence.append('敏感路径被鉴权拦截（{}），建议进一步验证。'.format(status_code))

    if 'index of' in lower_title and status_code in (200, 206):
        result_level = _merge_ai_denoise_result_level(result_level, 'danger')
        evidence.append('页面标题存在目录索引特征。')

    if content_length >= 2 * 1024 * 1024 and status_code in (200, 206):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('响应体积较大（{} 字节），可能存在打包文件暴露。'.format(content_length))

    if not evidence:
        evidence.append('未发现显著敏感目录暴露特征。')

    suggestions = []
    if result_level == 'danger':
        suggestions.extend([
            '立即下线相关目录并核查是否包含备份/配置/密钥文件。',
            '为目录访问添加鉴权和最小暴露策略，补充WAF规则。',
        ])
    elif result_level == 'suspicious':
        suggestions.extend([
            '使用认证账户与不同来源IP复测，确认是否存在越权访问。',
            '对疑似目录启用访问日志审计并限制目录遍历。',
        ])
    else:
        suggestions.append('保持当前最小暴露策略，定期巡检目录字典命中结果。')

    display_text = _build_ai_denoise_display_text('fileleak', result_level)
    summary = '目录扫描分析结果：{}。URL: {}'.format(display_text, url_text or '-')
    return {
        'result_level': result_level,
        'risk_level': '高' if result_level == 'danger' else ('中' if result_level == 'suspicious' else '低'),
        'trust': '-',
        'summary': summary,
        'evidence': evidence[:6],
        'suggestions': suggestions[:6],
        'display_text': display_text,
    }


def _rule_analyze_url_item(item):
    url_text = _normalize_item_text(item.get('url'), 900)
    title_text = _normalize_item_text(item.get('title'), 300)
    status_code = _safe_int_any(item.get('status_code'), 0)
    lower_url = url_text.lower()
    lower_title = title_text.lower()

    dangerous_patterns = (
        'token=', 'apikey=', 'api_key=', 'password=', 'passwd=', 'secret=', 'debug=1',
        '/.git', '/swagger', '/v2/api-docs', '/actuator', '/phpinfo', '/admin'
    )
    suspicious_patterns = (
        '/login', '/manage', '/console', '/upload', '/download', '/backup', '/test'
    )

    result_level = 'safe'
    evidence = []
    if any(pattern in lower_url for pattern in dangerous_patterns) and status_code in (200, 201, 206):
        result_level = 'danger'
        evidence.append('URL 命中敏感参数/路径特征并返回 {}。'.format(status_code))
    elif any(pattern in lower_url for pattern in suspicious_patterns) and status_code in (200, 401, 403):
        result_level = 'suspicious'
        evidence.append('URL 命中管理/调试路径特征，建议人工复核。')

    if 'index of' in lower_title or 'swagger ui' in lower_title:
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('标题包含目录索引或接口文档特征。')

    if not evidence:
        evidence.append('未发现明显的高风险 URL 特征。')

    suggestions = []
    if result_level == 'danger':
        suggestions.extend([
            '立即限制敏感 URL 访问并核查是否存在凭据泄漏。',
            '对外暴露接口加鉴权、限流与最小权限控制。',
        ])
    elif result_level == 'suspicious':
        suggestions.extend([
            '结合请求头、鉴权状态和业务上下文做二次验证。',
            '确认是否为测试接口或历史遗留调试入口。',
        ])
    else:
        suggestions.append('保持 URL 最小暴露策略并持续监控新增路径。')

    display_text = _build_ai_denoise_display_text('url', result_level)
    summary = 'URL 分析结果：{}。URL: {}'.format(display_text, url_text or '-')
    return {
        'result_level': result_level,
        'risk_level': '高' if result_level == 'danger' else ('中' if result_level == 'suspicious' else '低'),
        'trust': '-',
        'summary': summary,
        'evidence': evidence[:6],
        'suggestions': suggestions[:6],
        'display_text': display_text,
    }


def _rule_analyze_cert_item(item):
    cert_obj = item.get('cert') if isinstance(item.get('cert'), dict) else {}
    validity = cert_obj.get('validity') if isinstance(cert_obj.get('validity'), dict) else {}
    expire_text = str(validity.get('end') or '').strip()
    expire_time = _parse_datetime_text(expire_text)
    expire_days = None
    if expire_time:
        expire_days = int((expire_time - datetime.now(expire_time.tzinfo)).total_seconds() // 86400)

    result_level = 'safe'
    evidence = []
    if expire_days is not None:
        if expire_days < 0:
            result_level = 'danger'
            evidence.append('证书已过期 {} 天。'.format(abs(expire_days)))
        elif expire_days <= 30:
            result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
            evidence.append('证书将在 {} 天内过期。'.format(expire_days))
        else:
            evidence.append('证书有效期剩余 {} 天。'.format(expire_days))
    else:
        evidence.append('未识别到证书到期时间字段。')

    ssl_security = cert_obj.get('ssl_security') if isinstance(cert_obj.get('ssl_security'), dict) else {}
    protocol_names = []
    if isinstance(ssl_security.get('protocol_names'), list):
        protocol_names.extend(_normalize_string_list_value(ssl_security.get('protocol_names'), max_items=12))
    if isinstance(ssl_security.get('protocols'), list):
        for entry in ssl_security.get('protocols'):
            if isinstance(entry, dict):
                text = str(entry.get('name') or '').strip()
                if text:
                    protocol_names.append(text)

    weak_protocols = []
    for protocol in protocol_names:
        lower_protocol = protocol.lower()
        if lower_protocol in ('sslv2', 'sslv3'):
            weak_protocols.append(protocol)
        elif lower_protocol in ('tlsv1', 'tlsv1.0', 'tlsv1.1'):
            weak_protocols.append(protocol)
    if weak_protocols:
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('检测到弱协议：{}。'.format(', '.join(sorted(set(weak_protocols)))))

    least_strength = str(ssl_security.get('least_strength') or '').strip().lower()
    if least_strength in ('weak', 'low'):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('最弱套件强度为 {}。'.format(least_strength))

    suggestions = []
    if result_level == 'danger':
        suggestions.extend([
            '立即替换或续签证书，避免业务中断与中间人风险。',
            '同步检查证书链和自动续签任务，确保下次更新前完成部署。',
        ])
    elif result_level == 'suspicious':
        suggestions.extend([
            '建议关闭 TLS1.0/1.1 与 SSLv3 等弱协议，仅保留现代协议。',
            '按基线收敛弱加密套件，优先启用 ECDHE + AEAD 套件。',
        ])
    else:
        suggestions.append('证书状态整体正常，建议保持定期轮换与到期预警。')

    display_text = _build_ai_denoise_display_text('cert', result_level, cert_expire_days=expire_days)
    summary = '证书分析结果：{}。到期时间：{}'.format(display_text, expire_text or '-')
    return {
        'result_level': result_level,
        'risk_level': '高' if result_level == 'danger' else ('中' if result_level == 'suspicious' else '低'),
        'trust': '-',
        'summary': summary,
        'evidence': evidence[:8],
        'suggestions': suggestions[:6],
        'display_text': display_text,
        'cert_expire_days': expire_days,
        'cert_expire_at': expire_text or '-',
    }


def _rule_analyze_vuln_item(item, module_id='vuln'):
    vul_name = _normalize_item_text(item.get('vul_name') or item.get('vuln_name'), 320)
    target_text = _normalize_item_text(item.get('target') or item.get('vuln_url') or '-', 420)
    verify_text = _normalize_item_text(
        item.get('verify_data') or item.get('credential') or item.get('verify_obj') or '',
        600
    )
    severity_candidates = [
        item.get('vuln_severity'),
        item.get('severity'),
        item.get('risk_level'),
        item.get('level'),
        item.get('plg_type'),
    ]
    risk_level = '中'
    for candidate in severity_candidates:
        normalized = _normalize_risk_level_text(candidate)
        if normalized:
            risk_level = normalized
            break

    result_level = 'suspicious'
    if risk_level in ('高', '严重'):
        result_level = 'danger'
    elif risk_level == '低':
        result_level = 'safe'

    trust = '可信'
    lower_name = vul_name.lower()
    if not verify_text or verify_text == '-':
        if 'afrog 漏洞' in vul_name or '可能存在' in vul_name or 'suspected' in lower_name:
            trust = '疑似误报'
            result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
    if target_text in ('', '-'):
        trust = '疑似误报'
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')

    evidence = [
        '风险名称：{}。'.format(vul_name or '-'),
        '风险等级：{}。'.format(risk_level),
    ]
    if verify_text and verify_text != '-':
        evidence.append('存在验证信息，长度 {}。'.format(len(verify_text)))
    else:
        evidence.append('缺少明确验证信息。')

    suggestions = []
    if trust == '疑似误报':
        suggestions.extend([
            '建议使用原始插件或手工 PoC 二次复测，确认是否真实可利用。',
            '结合业务鉴权与返回差异补充证据后再定级。',
        ])
    else:
        suggestions.extend([
            '按风险等级优先修复并保留复现截图/请求响应证据。',
            '修复后执行复测任务，确保风险状态可闭环。',
        ])

    display_text = _build_ai_denoise_display_text(module_id, result_level, risk_level=risk_level, trust=trust)
    summary = '{} 分析结果：{}。目标：{}'.format(
        AI_DENOISE_MODULE_LABEL_MAP.get(module_id) or '风险',
        display_text,
        target_text or '-',
    )
    return {
        'result_level': result_level,
        'risk_level': risk_level,
        'trust': trust,
        'summary': summary,
        'evidence': evidence[:8],
        'suggestions': suggestions[:6],
        'display_text': display_text,
    }


def _build_ai_denoise_rule_result(module_id, item):
    if module_id == 'site':
        return _rule_analyze_site_item(item)
    if module_id == 'fileleak':
        return _rule_analyze_fileleak_item(item)
    if module_id == 'cert':
        return _rule_analyze_cert_item(item)
    if module_id == 'url':
        return _rule_analyze_url_item(item)
    if module_id == 'vuln':
        return _rule_analyze_vuln_item(item, module_id='vuln')
    if module_id == 'nuclei_result':
        return _rule_analyze_vuln_item(item, module_id='nuclei_result')
    return {
        'result_level': 'safe',
        'risk_level': '低',
        'trust': '-',
        'summary': '未匹配到模块分析器，已回退为安全判定。',
        'evidence': ['模块 {} 暂无分析规则。'.format(module_id)],
        'suggestions': ['请在 AI 管理中补充该模块提示词并开启功能。'],
        'display_text': '已分析',
    }


def _resolve_ai_prompt_content(prompt_templates, prompt_id, module_id):
    if not isinstance(prompt_templates, list):
        prompt_templates = []

    for item in prompt_templates:
        if not isinstance(item, dict):
            continue
        if str(item.get('id') or '').strip() == str(prompt_id or '').strip():
            return str(item.get('content') or '').strip()

    target_scene = AI_DENOISE_MODULE_SCENE_MAP.get(module_id, '')
    for item in prompt_templates:
        if not isinstance(item, dict):
            continue
        if str(item.get('scene') or '').strip() == target_scene:
            return str(item.get('content') or '').strip()
    return ''


def _extract_json_object_from_text(raw_text):
    text = str(raw_text or '').strip()
    if not text:
        return None

    fence_match = re.search(r'```(?:json)?\s*(\{[\s\S]*\})\s*```', text, re.IGNORECASE)
    if fence_match:
        text = fence_match.group(1).strip()

    start = text.find('{')
    end = text.rfind('}')
    if start >= 0 and end > start:
        candidate = text[start:end + 1]
    else:
        candidate = text

    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None
    return None


def _build_ai_denoise_context(module_id, item):
    if module_id == 'site':
        return {
            'site': _normalize_item_text(item.get('site') or item.get('url') or item.get('host'), 1200),
            'title': _normalize_item_text(item.get('title'), 420),
            'status_code': _safe_int_any(item.get('status_code') or item.get('status'), 0),
            'headers': _normalize_header_text(item.get('headers')),
            'finger': _extract_site_finger_names(item.get('finger')),
        }
    if module_id == 'fileleak':
        return {
            'url': _normalize_item_text(item.get('url'), 1200),
            'title': _normalize_item_text(item.get('title'), 400),
            'status_code': _safe_int_any(item.get('status_code'), 0),
            'content_length': _safe_int_any(item.get('content_length'), 0),
            'source': _normalize_item_text(item.get('source'), 200),
        }
    if module_id == 'url':
        return {
            'url': _normalize_item_text(item.get('url'), 1200),
            'title': _normalize_item_text(item.get('title'), 400),
            'status_code': _safe_int_any(item.get('status_code'), 0),
            'content_length': _safe_int_any(item.get('content_length'), 0),
            'source': _normalize_item_text(item.get('source'), 200),
        }
    if module_id == 'cert':
        cert_obj = item.get('cert') if isinstance(item.get('cert'), dict) else {}
        validity = cert_obj.get('validity') if isinstance(cert_obj.get('validity'), dict) else {}
        ssl_security = cert_obj.get('ssl_security') if isinstance(cert_obj.get('ssl_security'), dict) else {}
        return {
            'host': _normalize_item_text(item.get('host') or item.get('ip'), 260),
            'domain': _normalize_item_text(item.get('domain') or item.get('sni_domain'), 260),
            'validity_start': _normalize_item_text(validity.get('start'), 60),
            'validity_end': _normalize_item_text(validity.get('end'), 60),
            'least_strength': _normalize_item_text(ssl_security.get('least_strength'), 80),
            'protocol_names': _normalize_string_list_value(ssl_security.get('protocol_names'), max_items=10),
            'issuer_dn': _normalize_item_text(cert_obj.get('issuer_dn'), 420),
            'subject_dn': _normalize_item_text(cert_obj.get('subject_dn'), 420),
        }
    if module_id == 'vuln':
        return {
            'vul_name': _normalize_item_text(item.get('vul_name'), 260),
            'plg_type': _normalize_item_text(item.get('plg_type'), 120),
            'target': _normalize_item_text(item.get('target'), 420),
            'credential': _normalize_item_text(item.get('credential'), 800),
            'save_date': _normalize_item_text(item.get('save_date'), 60),
        }
    if module_id == 'nuclei_result':
        return {
            'scanner_type': _normalize_item_text(item.get('scanner_type'), 80),
            'rule_id': _normalize_item_text(item.get('rule_id'), 200),
            'target': _normalize_item_text(item.get('target'), 420),
            'vuln_url': _normalize_item_text(item.get('vuln_url'), 420),
            'vuln_name': _normalize_item_text(item.get('vuln_name'), 260),
            'vuln_severity': _normalize_item_text(item.get('vuln_severity'), 60),
            'verify_data': _normalize_item_text(item.get('verify_data'), 1200),
        }
    return {'raw': _normalize_item_text(item, 1800)}


def _try_run_ai_denoise(module_id, item, ai_prompt, active_profile, rule_result):
    base_url = str(active_profile.get('base_url') or '').strip()
    api_key = str(active_profile.get('api_key') or '').strip()
    model_name = str(active_profile.get('model') or '').strip()
    timeout_sec = _safe_int(active_profile.get('timeout_sec'), 40, min_value=8)
    dialogue_records = []
    if not base_url or not api_key or not model_name:
        dialogue_records = _normalize_dialogue_records(
            [
                {'role': 'system', 'content': 'AI 去噪详情分析请求被拒绝。'},
                {'role': 'assistant', 'content': '模型配置不完整，无法调用 AI。'},
            ]
        )
        return None, '模型配置不完整', dialogue_records

    prompt_text = str(ai_prompt or '').strip()
    if not prompt_text:
        prompt_text = '你是网络资产风险分析助手，请输出结构化审计结论。'

    context = _build_ai_denoise_context(module_id, item)
    user_payload = {
        'module_id': module_id,
        'module_label': AI_DENOISE_MODULE_LABEL_MAP.get(module_id) or module_id,
        'item': context,
        'rule_reference': {
            'result_level': rule_result.get('result_level'),
            'risk_level': rule_result.get('risk_level'),
            'trust': rule_result.get('trust'),
            'summary': rule_result.get('summary'),
        },
        'output_requirement': {
            'language': 'zh-CN',
            'format': {
                'result_level': 'safe|suspicious|danger',
                'risk_level': '低|中|高|严重',
                'trust': '可信|疑似误报',
                'summary': '一句话结论',
                'evidence': ['证据1', '证据2'],
                'suggestions': ['建议1', '建议2'],
                'finger_result': ['AI修正后的指纹1', 'AI修正后的指纹2'],
            },
        },
    }
    system_content = '{}\n仅输出 JSON 对象，不要输出 Markdown 或解释文本。'.format(prompt_text)
    user_content = json.dumps(user_payload, ensure_ascii=False)
    request_body = {
        'model': model_name,
        'temperature': min(max(_safe_float(active_profile.get('temperature'), 0.2, min_value=0.0), 0.0), 1.0),
        'max_tokens': max(400, min(_safe_int(active_profile.get('max_tokens'), 1200, min_value=200), 1800)),
        'messages': [
            {
                'role': 'system',
                'content': system_content,
            },
            {
                'role': 'user',
                'content': user_content,
            },
        ],
    }
    dialogue_records = _normalize_dialogue_records(
        [
            {'role': 'system', 'content': system_content},
            {'role': 'user', 'content': user_content},
        ]
    )
    request_url = '{}/chat/completions'.format(base_url.rstrip('/'))
    headers = {
        'Authorization': 'Bearer {}'.format(api_key),
        'Content-Type': 'application/json',
    }

    try:
        conn = utils.http_req(request_url, 'post', headers=headers, json=request_body, timeout=(8, timeout_sec))
        status_code = _safe_int_any(getattr(conn, 'status_code', 0), 0)
        payload = {}
        try:
            payload = conn.json() if conn is not None else {}
        except Exception:
            payload = {}

        if status_code != 200:
            err_message = ''
            if isinstance(payload, dict):
                error_obj = payload.get('error')
                if isinstance(error_obj, dict):
                    err_message = str(error_obj.get('message') or '').strip()
                if not err_message:
                    err_message = str(payload.get('message') or '').strip()
            message = err_message or 'HTTP {}'.format(status_code)
            dialogue_records.extend(
                _normalize_dialogue_records(
                    [{'role': 'assistant', 'content': 'AI接口调用失败：{}'.format(message)}],
                    max_items=2,
                )
            )
            return None, message, dialogue_records

        choices = payload.get('choices', []) if isinstance(payload, dict) else []
        message_obj = choices[0].get('message') if isinstance(choices, list) and choices else {}
        content_text = ''
        if isinstance(message_obj, dict):
            content_text = str(message_obj.get('content') or '').strip()
        if content_text:
            dialogue_records.extend(
                _normalize_dialogue_records(
                    [{'role': 'assistant', 'content': content_text}],
                    max_items=2,
                    max_len=3200,
                )
            )
        parsed = _extract_json_object_from_text(content_text)
        if not isinstance(parsed, dict):
            dialogue_records.extend(
                _normalize_dialogue_records(
                    [{'role': 'assistant', 'content': 'AI 返回格式不可解析，回退规则分析。'}],
                    max_items=2,
                )
            )
            return None, 'AI 返回格式不可解析', dialogue_records
        return parsed, '', dialogue_records
    except Exception as exc:
        message = str(exc)
        dialogue_records.extend(
            _normalize_dialogue_records(
                [{'role': 'assistant', 'content': 'AI请求异常：{}'.format(_truncate_text(message, 240))}],
                max_items=2,
            )
        )
        return None, message, dialogue_records


def _normalize_ai_denoise_output(module_id, ai_output, rule_result):
    if not isinstance(ai_output, dict):
        return dict(rule_result)

    merged = dict(rule_result)
    merged['result_level'] = _normalize_ai_denoise_result_level(
        ai_output.get('result_level') or ai_output.get('level') or ai_output.get('status'),
        rule_result.get('result_level', 'safe')
    )
    merged['risk_level'] = _normalize_risk_level_text(
        ai_output.get('risk_level') or ai_output.get('severity') or rule_result.get('risk_level')
    )
    if module_id in ('vuln', 'nuclei_result'):
        merged['trust'] = _normalize_trust_level_text(ai_output.get('trust') or ai_output.get('review_status'))
    else:
        merged['trust'] = rule_result.get('trust', '-')

    summary = _normalize_item_text(ai_output.get('summary') or ai_output.get('analysis') or '', 600)
    if summary:
        merged['summary'] = summary

    evidence = _normalize_string_list_value(
        ai_output.get('evidence') if ai_output.get('evidence') is not None else ai_output.get('basis'),
        max_items=8,
        max_item_len=260
    )
    suggestions = _normalize_string_list_value(
        ai_output.get('suggestions') if ai_output.get('suggestions') is not None else ai_output.get('advice'),
        max_items=8,
        max_item_len=260
    )
    if evidence:
        merged['evidence'] = evidence
    if suggestions:
        merged['suggestions'] = suggestions

    if module_id == 'site':
        ai_finger_result = _normalize_string_list_value(
            ai_output.get('finger_result') if ai_output.get('finger_result') is not None else ai_output.get('finger'),
            max_items=12,
            max_item_len=80
        )
        if ai_finger_result:
            merged['finger_result'] = ai_finger_result
        else:
            merged['finger_result'] = _normalize_string_list_value(rule_result.get('finger_result'), max_items=12, max_item_len=80)

    merged['display_text'] = _build_ai_denoise_display_text(
        module_id,
        merged.get('result_level'),
        risk_level=merged.get('risk_level', '中'),
        trust=merged.get('trust', '可信'),
        cert_expire_days=merged.get('cert_expire_days'),
    )
    return merged


def _normalize_ai_denoise_items(raw_items):
    if not isinstance(raw_items, list):
        return []
    items = []
    for item in raw_items:
        if isinstance(item, dict):
            items.append(item)
        else:
            items.append({'value': _normalize_item_text(item, 1200)})
        if len(items) >= AI_DENOISE_MAX_ITEMS:
            break
    return items


def _analyze_ai_denoise_batch(ai_config, module_id, items, prefer_ai=False):
    module_id = str(module_id or '').strip()
    normalized_items = _normalize_ai_denoise_items(items)

    ai_denoise_enable = _safe_bool(ai_config.get('ai_denoise_enable'), True)
    module_flags = _normalize_ai_denoise_modules(ai_config.get('ai_denoise_modules'))
    module_enabled = bool(module_flags.get(module_id, True))
    prompt_templates = _normalize_ai_prompt_templates(ai_config.get('prompt_templates'))
    prompt_ids = _normalize_ai_denoise_prompt_ids(ai_config.get('ai_denoise_prompt_ids'), prompt_templates)
    prompt_id = str(prompt_ids.get(module_id) or '').strip()
    prompt_content = _resolve_ai_prompt_content(prompt_templates, prompt_id, module_id)

    model_profiles = _normalize_ai_model_profiles(ai_config.get('model_profiles'), legacy_ai_conf=ai_config)
    active_model_profile_id = str(ai_config.get('active_model_profile_id') or '').strip()
    active_profile = _pick_active_ai_model_profile(model_profiles, active_model_profile_id)
    ai_model_ready = bool(
        _safe_bool(ai_config.get('enable'), True)
        and str(active_profile.get('base_url') or '').strip()
        and str(active_profile.get('api_key') or '').strip()
        and str(active_profile.get('model') or '').strip()
    )

    # 列表批量分析默认走规则，详情场景（单条）按需尝试模型，避免列表页被外部接口阻塞。
    try_use_ai = bool(prefer_ai and ai_model_ready and ai_denoise_enable and module_enabled and len(normalized_items) <= 3)
    now_text = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    task_flag_cache = {}

    results = []
    for index, item in enumerate(normalized_items):
        row_key = _extract_row_key(item, index)
        rule_result = _build_ai_denoise_rule_result(module_id, item)
        source = 'rule'
        dialogue_records = _build_rule_dialogue_records(module_id, item, rule_result, note='当前为规则分析模式。')
        task_id = _extract_task_id_from_item(item)
        task_ai_denoise_flag = _resolve_task_ai_denoise_flag(task_id, task_flag_cache)

        if not ai_denoise_enable or not module_enabled:
            disabled_summary = 'AI 去噪功能已关闭，可在 AI 管理中开启后重试。'
            dialogue_records = _normalize_dialogue_records(
                [
                    {
                        'role': 'system',
                        'content': '当前模块 AI 去噪未启用。',
                    },
                    {
                        'role': 'assistant',
                        'content': disabled_summary,
                    },
                ]
            )
            results.append(
                {
                    'row_key': row_key,
                    'module_id': module_id,
                    'module_label': AI_DENOISE_MODULE_LABEL_MAP.get(module_id) or module_id,
                    'result_level': 'disabled',
                    'risk_level': rule_result.get('risk_level', '低'),
                    'trust': rule_result.get('trust', '-'),
                    'display_text': '已关闭',
                    'summary': disabled_summary,
                    'evidence': ['当前模块或全局 AI 去噪开关关闭。'],
                    'suggestions': ['前往 AI 管理开启对应模块后可继续分析。'],
                    'source': 'disabled',
                    'prompt_id': prompt_id,
                    'analyzed_at': now_text,
                    'finger_result': _normalize_string_list_value(rule_result.get('finger_result'), max_items=12, max_item_len=80),
                    'dialogue_records': dialogue_records,
                }
            )
            continue

        if task_ai_denoise_flag is None:
            summary_text = '当前资产来自旧任务（未启用 AI 去噪），统一标记为未分析。'
            dialogue_records = _normalize_dialogue_records(
                [
                    {'role': 'system', 'content': '检测到旧任务资产，未具备 AI 去噪分析上下文。'},
                    {'role': 'assistant', 'content': summary_text},
                ]
            )
            results.append(
                {
                    'row_key': row_key,
                    'module_id': module_id,
                    'module_label': AI_DENOISE_MODULE_LABEL_MAP.get(module_id) or module_id,
                    'result_level': 'disabled',
                    'risk_level': '-',
                    'trust': '-',
                    'display_text': '未分析',
                    'summary': summary_text,
                    'evidence': ['该资产对应任务缺少 ai_denoise 选项（历史任务）。'],
                    'suggestions': ['建议对该任务重新扫描并开启 AI 去噪分析。'],
                    'source': 'disabled',
                    'prompt_id': prompt_id,
                    'analyzed_at': now_text,
                    'finger_result': _normalize_string_list_value(rule_result.get('finger_result'), max_items=12, max_item_len=80),
                    'dialogue_records': dialogue_records,
                }
            )
            continue

        if task_ai_denoise_flag is False:
            summary_text = '该任务未开启 AI 去噪，当前资产标记为未分析。'
            dialogue_records = _normalize_dialogue_records(
                [
                    {'role': 'system', 'content': '任务配置未开启 AI 去噪。'},
                    {'role': 'assistant', 'content': summary_text},
                ]
            )
            results.append(
                {
                    'row_key': row_key,
                    'module_id': module_id,
                    'module_label': AI_DENOISE_MODULE_LABEL_MAP.get(module_id) or module_id,
                    'result_level': 'disabled',
                    'risk_level': '-',
                    'trust': '-',
                    'display_text': '未分析',
                    'summary': summary_text,
                    'evidence': ['任务 options.ai_denoise 为关闭状态。'],
                    'suggestions': ['重新创建任务并开启 AI 去噪分析后再查看。'],
                    'source': 'disabled',
                    'prompt_id': prompt_id,
                    'analyzed_at': now_text,
                    'finger_result': _normalize_string_list_value(rule_result.get('finger_result'), max_items=12, max_item_len=80),
                    'dialogue_records': dialogue_records,
                }
            )
            continue

        if not ai_model_ready:
            summary_text = 'AI 模型配置不完整（未配置可用 API Key/Model/BaseURL），当前标记为未分析。'
            dialogue_records = _normalize_dialogue_records(
                [
                    {'role': 'system', 'content': 'AI 模型配置校验未通过。'},
                    {'role': 'assistant', 'content': summary_text},
                ]
            )
            results.append(
                {
                    'row_key': row_key,
                    'module_id': module_id,
                    'module_label': AI_DENOISE_MODULE_LABEL_MAP.get(module_id) or module_id,
                    'result_level': 'disabled',
                    'risk_level': '-',
                    'trust': '-',
                    'display_text': '未分析',
                    'summary': summary_text,
                    'evidence': ['AI 管理中缺少可用的 API Key / 模型 / 地址配置。'],
                    'suggestions': ['请在 AI 管理完成模型配置并保存后重试。'],
                    'source': 'disabled',
                    'prompt_id': prompt_id,
                    'analyzed_at': now_text,
                    'finger_result': _normalize_string_list_value(rule_result.get('finger_result'), max_items=12, max_item_len=80),
                    'dialogue_records': dialogue_records,
                }
            )
            continue

        final_result = dict(rule_result)
        if try_use_ai:
            ai_output, ai_error, ai_dialogue_records = _try_run_ai_denoise(
                module_id=module_id,
                item=item,
                ai_prompt=prompt_content,
                active_profile=active_profile,
                rule_result=rule_result,
            )
            if ai_output:
                final_result = _normalize_ai_denoise_output(module_id, ai_output, rule_result)
                source = 'ai'
                dialogue_records = _normalize_dialogue_records(
                    (ai_dialogue_records or []) + [
                        {
                            'role': 'assistant',
                            'content': '最终结构化结论：{}'.format(final_result.get('display_text') or final_result.get('summary') or '已完成分析'),
                        },
                    ]
                )
            else:
                source = 'rule'
                fallback_note = ''
                if ai_error:
                    fallback_evidence = _normalize_string_list_value(final_result.get('evidence'), max_items=6)
                    fallback_evidence.insert(0, 'AI 调用失败，已回退规则分析：{}'.format(_truncate_text(ai_error, 120)))
                    final_result['evidence'] = fallback_evidence[:8]
                    fallback_note = 'AI 调用失败，已自动回退规则分析：{}'.format(_truncate_text(ai_error, 160))
                dialogue_records = _build_rule_dialogue_records(module_id, item, final_result, note=fallback_note or 'AI 未返回有效结构化内容，已回退规则分析。')
                if ai_dialogue_records:
                    dialogue_records = _normalize_dialogue_records(
                        (ai_dialogue_records or []) + [
                            {
                                'role': 'assistant',
                                'content': 'AI 结果不可用，回退规则结论：{}'.format(final_result.get('display_text') or final_result.get('summary') or '-'),
                            },
                        ]
                    )
        else:
            fallback_note = ''
            if prefer_ai and not ai_model_ready:
                fallback_note = 'AI 模型配置不可用，已回退规则分析。'
            elif not prefer_ai:
                fallback_note = '当前为列表批量分析，默认使用规则模式避免阻塞页面。'
            dialogue_records = _build_rule_dialogue_records(module_id, item, final_result, note=fallback_note)

        results.append(
            {
                'row_key': row_key,
                'module_id': module_id,
                'module_label': AI_DENOISE_MODULE_LABEL_MAP.get(module_id) or module_id,
                'result_level': _normalize_ai_denoise_result_level(final_result.get('result_level'), 'safe'),
                'risk_level': final_result.get('risk_level') or '中',
                'trust': final_result.get('trust') or '-',
                'display_text': final_result.get('display_text')
                or _build_ai_denoise_display_text(
                    module_id,
                    final_result.get('result_level'),
                    risk_level=final_result.get('risk_level'),
                    trust=final_result.get('trust'),
                    cert_expire_days=final_result.get('cert_expire_days'),
                ),
                'summary': _normalize_item_text(final_result.get('summary') or '', 900),
                'evidence': _normalize_string_list_value(final_result.get('evidence'), max_items=8, max_item_len=280),
                'suggestions': _normalize_string_list_value(final_result.get('suggestions'), max_items=8, max_item_len=280),
                'source': source,
                'prompt_id': prompt_id,
                'cert_expire_at': final_result.get('cert_expire_at') or '',
                'cert_expire_days': final_result.get('cert_expire_days'),
                'analyzed_at': now_text,
                'finger_result': _normalize_string_list_value(final_result.get('finger_result'), max_items=12, max_item_len=80),
                'dialogue_records': dialogue_records,
            }
        )

    return {
        'module_id': module_id,
        'module_label': AI_DENOISE_MODULE_LABEL_MAP.get(module_id) or module_id,
        'enable': ai_denoise_enable,
        'module_enabled': module_enabled,
        'prompt_id': prompt_id,
        'prefer_ai': bool(prefer_ai),
        'ai_used': bool(try_use_ai),
        'ai_model_ready': bool(ai_model_ready),
        'items': results,
        'analyzed_at': now_text,
    }


def _verify_sensitive_access(username: str, password: str):
    """
    二次验证当前用户身份（仅验证，不刷新登录 token）。
    """
    username = str(username or '').strip()
    password = str(password or '')
    if not username or not password:
        return False, '用户名和密码不能为空'

    login_user = utils.user_login_header()
    if isinstance(login_user, dict) and login_user.get('type') == 'login':
        current_username = str(login_user.get('username') or '').strip()
        if current_username and current_username != username:
            return False, '请使用当前登录账号进行验证'

    password_hash = utils.gen_md5('arlsalt!@#' + password)
    query = {
        'username': username,
        'password': password_hash,
    }
    data = utils.conn_db('user').find_one(query, {'_id': 1})
    if not data:
        return False, '账号或密码错误'

    return True, '验证通过'


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
    profile_id_raw = str(normalized.get('scan_profile_id', '') or '').strip().lower()
    if not profile_id_raw:
        return normalized, ''

    profile_id = SCAN_PROFILE_ID_ALIASES.get(profile_id_raw, profile_id_raw)
    profile = SCAN_PROFILE_MAP.get(profile_id)
    if profile is None:
        raise ValueError(f'未知扫描预定义配置: {profile_id_raw}')

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


def _build_service_api_sensitive_configured_map(service_api: dict):
    """
    基于 service_api 计算敏感字段是否已配置（仅返回布尔状态，不返回明文）。
    """
    if not isinstance(service_api, dict):
        service_api = {}

    configured = {}
    for field_name in SERVICE_API_SENSITIVE_FIELDS:
        configured[field_name] = bool(str(service_api.get(field_name, '') or '').strip())
    return configured


def _sanitize_service_api_for_client(service_api: dict):
    """
    返回给前端时抹除敏感字段明文，并附带是否已配置状态。
    """
    safe_service_api = dict(service_api or {})
    sensitive_configured = _build_service_api_sensitive_configured_map(safe_service_api)
    for field_name in SERVICE_API_SENSITIVE_FIELDS:
        safe_service_api[field_name] = ''
    return safe_service_api, sensitive_configured


def _fill_missing_sensitive_service_api_fields(service_api: dict, config_obj: dict):
    """
    对未提交的敏感字段回填当前配置值，避免前端“未改动字段”被误清空。
    """
    if not isinstance(service_api, dict):
        raise ValueError('service_api 必须为对象')

    merged_service_api = dict(service_api)
    current_service_api = _extract_service_api_config(config_obj if isinstance(config_obj, dict) else {})
    for field_name in SERVICE_API_SENSITIVE_FIELDS:
        if field_name in merged_service_api:
            continue
        merged_service_api[field_name] = current_service_api.get(field_name, '')

    return merged_service_api


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
            raw_service_api = _extract_service_api_config(config_obj)
            service_api, sensitive_configured = _sanitize_service_api_for_client(raw_service_api)
            return utils.build_ret(
                ErrorMsg.Success,
                {
                    'service_api': service_api,
                    'sensitive_configured': sensitive_configured,
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
                merged_service_api = _fill_missing_sensitive_service_api_fields(service_api, config_obj)
                config_obj = _merge_service_api_config(config_obj, merged_service_api)
                _ensure_json_like_config(config_obj)
                backup_path = _backup_config_file(config_path)
                _atomic_write_yaml(config_path, config_obj)
                refresh_runtime_config_best_effort(force=True)
                raw_saved_service_api = _extract_service_api_config(config_obj)
                saved_service_api, sensitive_configured = _sanitize_service_api_for_client(raw_saved_service_api)
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
                'sensitive_configured': sensitive_configured,
                'config_path': str(config_path),
                'backup_path': backup_path,
                'saved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
        )


@ns.route('/service_api/reveal/')
class ApiConsoleServiceApiReveal(ARLResource):
    """
    二次验证后返回敏感字段明文，仅用于“显示 key”场景。
    """

    @auth
    @ns.expect(verify_sensitive_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        username = str(payload.get('username') or '').strip()
        password = str(payload.get('password') or '')

        ok, message = _verify_sensitive_access(username, password)
        if not ok:
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': message,
                }
            )

        config_path = _resolve_config_path()
        try:
            config_obj = _load_config_from_file(config_path)
            service_api = _extract_service_api_config(config_obj)
            sensitive_configured = _build_service_api_sensitive_configured_map(service_api)
        except Exception as exc:
            logger.exception('reveal service_api failed: %s', exc)
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
                'service_api': service_api,
                'sensitive_configured': sensitive_configured,
                'config_path': str(config_path),
                'revealed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': message,
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
            config_obj = _load_config_from_file(_resolve_config_path())
            merged_service_api = _fill_missing_sensitive_service_api_fields(service_api, config_obj)
        except Exception as exc:
            logger.exception('load config for service_api test failed: %s', exc)
            merged_service_api = service_api

        try:
            result = _run_service_api_provider_test(
                provider=provider,
                service_api=merged_service_api,
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

        try:
            config_obj = _load_config_from_file(_resolve_config_path())
            merged_service_api = _fill_missing_sensitive_service_api_fields(service_api, config_obj)
        except Exception as exc:
            logger.exception('load config for service_api batch test failed: %s', exc)
            merged_service_api = service_api

        configured_specs = _collect_configured_service_api_providers(merged_service_api)
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
                    service_api=merged_service_api,
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


@ns.route('/ai_config/')
class ApiConsoleAiConfig(ARLResource):
    """
    AI 管理配置读取与保存接口。
    """

    @auth
    def get(self):
        config_path = _resolve_config_path()
        try:
            config_obj = _load_config_from_file(config_path)
            ai_config_raw = _extract_ai_config(config_obj)
            ai_config, sensitive_configured = _sanitize_ai_config_for_client(ai_config_raw)
            return utils.build_ret(
                ErrorMsg.Success,
                {
                    'ai_config': ai_config,
                    'sensitive_configured': sensitive_configured,
                    'provider_presets': AI_PROVIDER_PRESETS,
                    'config_path': str(config_path),
                    'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                }
            )
        except Exception as exc:
            logger.exception('load ai_config failed: %s', exc)
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': str(exc),
                    'config_path': str(config_path),
                }
            )

    @auth
    @ns.expect(save_ai_config_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        ai_config = payload.get('ai_config')
        config_path = _resolve_config_path()

        with CONFIG_LOCK:
            try:
                config_obj = _load_config_from_file(config_path)
                merged_ai_config = _fill_missing_sensitive_ai_fields(ai_config, config_obj)
                config_obj = _merge_ai_config(config_obj, merged_ai_config)
                _ensure_json_like_config(config_obj)
                backup_path = _backup_config_file(config_path)
                _atomic_write_yaml(config_path, config_obj)
                runtime_refreshed = bool(refresh_runtime_config_best_effort(force=True))
                saved_ai_config_raw = _extract_ai_config(config_obj)
                saved_ai_config, sensitive_configured = _sanitize_ai_config_for_client(saved_ai_config_raw)
            except Exception as exc:
                logger.exception('save ai_config failed: %s', exc)
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
                'ai_config': saved_ai_config,
                'sensitive_configured': sensitive_configured,
                'provider_presets': AI_PROVIDER_PRESETS,
                'config_path': str(config_path),
                'backup_path': backup_path,
                'runtime_refreshed': runtime_refreshed,
                'saved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
        )


@ns.route('/ai_config/reveal/')
class ApiConsoleAiConfigReveal(ARLResource):
    """
    AI 管理敏感字段显示接口（需二次身份验证）。
    """

    @auth
    @ns.expect(verify_sensitive_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        username = str(payload.get('username') or '').strip()
        password = str(payload.get('password') or '')
        config_path = _resolve_config_path()

        ok, message = _verify_sensitive_access(username, password)
        if not ok:
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': message,
                }
            )

        try:
            config_obj = _load_config_from_file(config_path)
            ai_config = _extract_ai_config(config_obj)
            sensitive_configured = _build_ai_sensitive_configured_map(ai_config)
        except Exception as exc:
            logger.exception('reveal ai_config failed: %s', exc)
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
                'revealed': True,
                'ai_config': ai_config,
                'sensitive_configured': sensitive_configured,
                'provider_presets': AI_PROVIDER_PRESETS,
                'config_path': str(config_path),
                'revealed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
        )


@ns.route('/ai_config/test/')
class ApiConsoleAiConfigTest(ARLResource):
    """
    AI 管理连通性测试接口（基于当前表单值，不落盘）。
    """

    @auth
    @ns.expect(test_ai_config_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        ai_config = payload.get('ai_config') or {}
        config_path = _resolve_config_path()

        if not isinstance(ai_config, dict):
            return utils.build_ret(
                ErrorMsg.Error,
                {'error': 'ai_config 必须为对象'}
            )

        try:
            config_obj = _load_config_from_file(config_path)
            merged_ai_config = _fill_missing_sensitive_ai_fields(ai_config, config_obj)
            result = _test_ai_config_connectivity(merged_ai_config)
            return utils.build_ret(ErrorMsg.Success, result)
        except Exception as exc:
            logger.exception('ai_config test failed err:%s', exc)
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': str(exc),
                }
            )


@ns.route('/ai_denoise/analyze/')
class ApiConsoleAiDenoiseAnalyze(ARLResource):
    """
    AI 去噪分析接口（列表批量分析 + 详情按需 AI 分析）。
    """

    @auth
    @ns.expect(analyze_ai_denoise_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        module_id = str(payload.get('module_id') or '').strip()
        raw_items = payload.get('items')
        prefer_ai = _safe_bool(payload.get('prefer_ai'), False)

        if module_id not in AI_DENOISE_MODULE_SCENE_MAP:
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': '不支持的 module_id: {}'.format(module_id),
                }
            )

        if not isinstance(raw_items, list):
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': 'items 必须为数组',
                }
            )

        config_path = _resolve_config_path()
        try:
            config_obj = _load_config_from_file(config_path)
            ai_config = _extract_ai_config(config_obj)
            result = _analyze_ai_denoise_batch(
                ai_config=ai_config,
                module_id=module_id,
                items=raw_items,
                prefer_ai=prefer_ai,
            )
            result['config_path'] = str(config_path)
            result['item_count'] = len(result.get('items') or [])
            return utils.build_ret(ErrorMsg.Success, result)
        except Exception as exc:
            logger.exception('ai_denoise analyze failed module:%s err:%s', module_id, exc)
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': str(exc),
                    'module_id': module_id,
                }
            )


@ns.route('/sensitive_verify/')
class ApiConsoleSensitiveVerify(ARLResource):
    """
    敏感信息显示前的二次身份验证接口。
    """

    @auth
    @ns.expect(verify_sensitive_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        username = str(payload.get('username') or '').strip()
        password = str(payload.get('password') or '')

        ok, message = _verify_sensitive_access(username, password)
        if not ok:
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': message,
                }
            )

        return utils.build_ret(
            ErrorMsg.Success,
            {
                'verified': True,
                'message': message,
                'verified_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
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
