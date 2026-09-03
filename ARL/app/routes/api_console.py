"""
配置中心接口

用途：
- 在浏览器中读取与修改 ARL 运行配置
- 将配置变更同步到容器挂载的配置文件，避免手工进容器编辑
"""
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter
from functools import lru_cache
import json
import os
import re
import subprocess
import threading
import time
from urllib.parse import parse_qsl, urlparse

from bson import ObjectId
from flask import request
from flask_restx import Namespace, fields
from werkzeug.utils import secure_filename

from app import utils
from app.config import Config, refresh_runtime_config_best_effort
from app.services.config_file_store import ConfigFileStore
from app.services.config_center import ConfigCenterService
from app.services.config_domain_service import ConfigDomainService
from app.services.scan_config_service import ScanConfigService
from app.services.service_api_config_service import ServiceApiConfigService
from app.services.ai_config_service import AIConfigService
from app.services.ai_prompt_sop_service import AIPromptSopService
from app.services.service_api_provider_test_service import ServiceApiProviderTestService
from app.services.ai_provider_test_service import AIProviderTestService
from app.modules import ErrorMsg
from app.utils import auth, get_logger
from . import ARLResource

ns = Namespace('api_console', description="配置中心")

logger = get_logger()
CONFIG_LOCK = threading.Lock()
POC_UPDATE_LOCK = threading.Lock()
CONFIG_FILE_STORE = ConfigFileStore(logger=logger)
CONFIG_CENTER = ConfigCenterService(
    CONFIG_FILE_STORE,
    refresh_runtime_config=refresh_runtime_config_best_effort,
)
CONFIG_DOMAIN_SERVICE = ConfigDomainService(
    config_center=CONFIG_CENTER,
    path_resolver=CONFIG_FILE_STORE.resolve_path,
    lock=CONFIG_LOCK,
    logger=logger,
)
SCAN_CONFIG_SERVICE = ScanConfigService()
SERVICE_API_CONFIG_SERVICE = ServiceApiConfigService()

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
        'module_id': fields.String(required=True, description='模块ID（site/fileleak/cert/url/wih_endpoint/vuln/nuclei_result）'),
        'items': fields.List(fields.Raw, required=True, description='待分析的数据行列表'),
        'prefer_ai': fields.Boolean(required=False, description='兼容旧参数，当前接口会忽略该值（避免点击详情触发实时AI调用）'),
    },
)

verify_sensitive_fields = ns.model(
    'VerifySensitiveAccess',
    {
        'username': fields.String(required=True, description='当前登录账号'),
        'password': fields.String(required=True, description='当前登录密码'),
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
    return CONFIG_DOMAIN_SERVICE.resolve_path()


def _load_config_from_file(config_path: Path):
    """
    读取 YAML 配置文件，返回字典对象。
    """
    _, config_obj = CONFIG_DOMAIN_SERVICE.load(config_path)
    return config_obj


def _persist_config(config_path: Path, config_obj: dict):
    return CONFIG_DOMAIN_SERVICE.config_center.persist(config_path, config_obj)


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


AI_PROVIDER_PRESETS = [
    {
        'id': 'qwen',
        'label': '通义千问',
        'base_url': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
        'default_model': 'qwen-plus',
        'default_reasoning_model': 'qwen-plus',
    },
    {
        'id': 'kimi',
        'label': 'Kimi',
        'base_url': 'https://api.moonshot.cn/v1',
        'default_model': 'moonshot-v1-8k',
        'default_reasoning_model': 'moonshot-v1-8k',
    },
    {
        'id': 'openai',
        'label': 'OpenAI-GPT',
        'base_url': 'https://api.openai.com/v1',
        'default_model': 'gpt-4o-mini',
        'default_reasoning_model': 'gpt-4o-mini',
    },
    {
        'id': 'glm',
        'label': '智谱 GLM',
        'base_url': 'https://open.bigmodel.cn/api/paas/v4',
        'default_model': 'glm-4-flash',
        'default_reasoning_model': 'glm-4-flash',
    },
    {
        'id': 'deepseek',
        'label': 'DeepSeek',
        'base_url': 'https://api.deepseek.com/v1',
        'default_model': 'deepseek-chat',
        'default_reasoning_model': 'DeepSeek-R1',
    },
    {
        'id': 'custom_compatible',
        'label': 'OpenAI 兼容接口',
        'base_url': '',
        'default_model': '',
        'default_reasoning_model': '',
    },
]
AI_PROVIDER_PRESET_MAP = {item.get('id'): item for item in AI_PROVIDER_PRESETS}
AI_PROVIDER_IDS = set(item.get('id') for item in AI_PROVIDER_PRESETS if item.get('id'))

AI_DENOISE_MODULE_SCENE_MAP = {
    'site': 'ai_denoise_site',
    'fileleak': 'ai_denoise_fileleak',
    'cert': 'ai_denoise_cert',
    'url': 'ai_denoise_url',
    'wih_endpoint': 'ai_denoise_wih_endpoint',
    'vuln': 'ai_denoise_vuln',
    'nuclei_result': 'ai_denoise_nuclei_result',
}

AI_DENOISE_MODULE_LABEL_MAP = {
    'site': '站点',
    'fileleak': '目录扫描',
    'cert': 'SSL证书',
    'url': 'URL信息',
    'wih_endpoint': 'WIH接口',
    'vuln': '风险',
    'nuclei_result': 'PoC风险',
}

AI_WIH_ENDPOINT_FILL_MODULE_ID = 'wih_endpoint_fill'
AI_WIH_ENDPOINT_FILL_SCENE = 'ai_fill_wih_endpoint'
AI_WIH_ENDPOINT_FILL_PROMPT_ID = 'default_ai_fill_wih_endpoint'
AI_WIH_ENDPOINT_FILL_LABEL = 'WIH接口AI填充'

AI_SOP_MODULE_SCENE_MAP = {
    **AI_DENOISE_MODULE_SCENE_MAP,
    AI_WIH_ENDPOINT_FILL_MODULE_ID: AI_WIH_ENDPOINT_FILL_SCENE,
}
AI_SOP_MODULE_LABEL_MAP = {
    **AI_DENOISE_MODULE_LABEL_MAP,
    AI_WIH_ENDPOINT_FILL_MODULE_ID: AI_WIH_ENDPOINT_FILL_LABEL,
}

AI_DENOISE_MAX_ITEMS = 120
AI_DENOISE_MAX_ITEM_TEXT_LEN = 5000
AI_DENOISE_RESULT_COLLECTION = 'ai_denoise_result'
AI_DENOISE_RESULT_LEVEL_WEIGHT = {
    'disabled': -1,
    'safe': 0,
    'suspicious': 1,
    'danger': 2,
}
_AI_DENOISE_RESULT_INDEX_READY = False
AI_USAGE_LOG_COLLECTION = 'ai_usage_log'
AI_USAGE_LOG_MAX_LIMIT = 200
AI_USAGE_SCENE_LABEL_MAP = {
    'ai_config_test': 'AI测试',
    'ai_poc_scan_plan': 'AI-POC扫描-计划',
    'ai_poc_scan_decision': 'AI-POC扫描-决策',
    'ai_denoise_site': 'AI去噪-站点',
    'ai_denoise_fileleak': 'AI去噪-目录扫描',
    'ai_denoise_cert': 'AI去噪-SSL证书',
    'ai_denoise_url': 'AI去噪-URL信息',
    'ai_denoise_wih_endpoint': 'AI去噪-WIH接口',
    'ai_denoise_vuln': 'AI去噪-风险',
    'ai_denoise_nuclei_result': 'AI去噪-PoC风险',
    'ai_fill_wih_endpoint': 'AI填充-WIH接口',
}

AI_PROJECT_ROOT = Path(__file__).resolve().parents[2]
AI_PROMPT_SOP_DIR = AI_PROJECT_ROOT / 'docker' / 'ai' / 'sop'
AI_PROMPT_TEMPLATE_FILE_MAP = {
    'default_ai_report': 'ai/sop/default_ai_report.yaml',
    'default_fp_review': 'ai/sop/default_fp_review.yaml',
    'default_ai_denoise_site': 'ai/sop/default_ai_denoise_site.yaml',
    'default_ai_denoise_fileleak': 'ai/sop/default_ai_denoise_fileleak.yaml',
    'default_ai_denoise_cert': 'ai/sop/default_ai_denoise_cert.yaml',
    'default_ai_denoise_url': 'ai/sop/default_ai_denoise_url.yaml',
    'default_ai_denoise_wih_endpoint': 'ai/sop/default_ai_denoise_wih_endpoint.yaml',
    'default_ai_denoise_vuln': 'ai/sop/default_ai_denoise_vuln.yaml',
    'default_ai_denoise_poc': 'ai/sop/default_ai_denoise_poc.yaml',
    'default_ai_fill_wih_endpoint': 'ai/sop/default_ai_fill_wih_endpoint.yaml',
}
AI_DENOISE_MODULE_PROMPT_ID_MAP = {
    'site': 'default_ai_denoise_site',
    'fileleak': 'default_ai_denoise_fileleak',
    'cert': 'default_ai_denoise_cert',
    'url': 'default_ai_denoise_url',
    'wih_endpoint': 'default_ai_denoise_wih_endpoint',
    'vuln': 'default_ai_denoise_vuln',
    'nuclei_result': 'default_ai_denoise_poc',
}
AI_SOP_MODULE_PROMPT_ID_MAP = {
    **AI_DENOISE_MODULE_PROMPT_ID_MAP,
    AI_WIH_ENDPOINT_FILL_MODULE_ID: AI_WIH_ENDPOINT_FILL_PROMPT_ID,
}

AI_PROMPT_SOP_SERVICE = AIPromptSopService(
    project_root=AI_PROJECT_ROOT,
    template_file_map=AI_PROMPT_TEMPLATE_FILE_MAP,
    logger=logger,
)


def _normalize_ai_prompt_template_file_ref(raw_file_ref):
    return AI_PROMPT_SOP_SERVICE._normalize_file_ref(raw_file_ref)


def _resolve_ai_prompt_template_file_path(raw_file_ref):
    return AI_PROMPT_SOP_SERVICE.resolve_path(raw_file_ref)


def _read_ai_prompt_template_payload_from_file(raw_file_ref):
    return AI_PROMPT_SOP_SERVICE.load_payload(raw_file_ref)


def _read_ai_prompt_template_content_from_file(raw_file_ref):
    return AI_PROMPT_SOP_SERVICE.read_content(raw_file_ref)


def _write_ai_prompt_template_content_to_file(raw_file_ref, content, prompt_meta=None):
    return AI_PROMPT_SOP_SERVICE.write_content(raw_file_ref, content, prompt_meta=prompt_meta)


def _resolve_ai_prompt_template_file(prompt_id, raw_file_ref=''):
    return AI_PROMPT_SOP_SERVICE.resolve_template_file(prompt_id, raw_file_ref)


def _persist_ai_prompt_templates_for_config(prompt_templates, existing_templates):
    return AI_PROMPT_SOP_SERVICE.persist_templates(prompt_templates, existing_templates)


def _parse_uploaded_ai_sop_yaml(file_bytes):
    return AI_PROMPT_SOP_SERVICE.parse_uploaded(file_bytes)


def _default_ai_prompt_templates():
    """
    默认提示词模板（覆盖 AI 报告与误报复核两类场景）。
    """
    templates = [
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
                "你是渗透测试前置研判助手。请基于站点URL、标题、响应头、状态码与指纹信息，"
                "判断该站点是否值得优先进入渗透测试，并输出："
                "1) 正常/可疑/危险结论；"
                "2) 最可能真实的技术栈/指纹（过滤明显误报）；"
                "3) 可直接执行的验证建议（如目录探测、认证边界测试、WAF绕过前置检查）。"
                "不要仅因标题包含后台、管理、swagger 等关键词就直接判危险；若只是登录壳、401/403、统一认证入口或普通错误页，优先降为正常/可疑。"
                "只有在接口文档、调试面、目录索引、真实管理组件或明确暴露证据出现时，才可提级为危险。"
                "禁止编造不存在的信息。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_fileleak',
            'name': '默认AI去噪-目录扫描',
            'scene': 'ai_denoise_fileleak',
            'content': (
                "你是目录扫描去噪与渗透准备助手。请基于URL路径、状态码、标题、响应体长度判断：正常/可疑/危险，"
                "并补充后续渗透验证优先级："
                "1) 是否存在可利用入口（备份/配置/调试/上传）；"
                "2) 建议先做哪类验证（鉴权绕过、目录遍历、文件读取、上传执行）；"
                "3) 给出2-3条可操作的验证建议。"
                "若仅命中敏感路径但返回 401/403/404、空页面、登录壳或普通错误页，不要直接判危险。"
                "只有在目录索引、接口文档、调试面或真实敏感文件成功返回时，才可提级为危险。"
                "禁止夸大风险，证据不足时明确标注待复核。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_cert',
            'name': '默认AI去噪-SSL证书',
            'scene': 'ai_denoise_cert',
            'content': (
                "你是证书与传输安全评估助手。请基于证书有效期、签发信息、协议与套件特征，"
                "输出结论并判断对渗透测试阶段的影响："
                "1) 是否存在弱协议/弱套件可用于降级或中间人相关测试前置；"
                "2) 证书到期与配置缺陷是否影响攻击面稳定性；"
                "3) 给出优先整改建议与验证步骤。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_url',
            'name': '默认AI去噪-URL信息',
            'scene': 'ai_denoise_url',
            'content': (
                "你是URL攻击面去噪助手。请基于URL路径、参数、状态码、标题与上下文，输出安全/可疑/危险结论，"
                "并围绕渗透测试准备给出："
                "1) 该URL属于登录、管理、调试、接口还是静态资源；"
                "2) 是否值得进一步测试（鉴权、越权、注入、文件读取、重定向等）；"
                "3) 明确下一步验证建议与优先级。"
                "不要只因 URL 包含 admin、debug、swagger、token 等关键词就直接判危险；若只是登录壳、401/403/404、静态资源或普通错误页，应优先降为安全/可疑。"
                "只有在真实开放的接口文档、调试面、目录索引或明显凭据泄漏参数成功暴露时，才可提级为危险。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_wih_endpoint',
            'name': '默认AI去噪-WIH接口',
            'scene': 'ai_denoise_wih_endpoint',
            'content': (
                "你是 WIH 结构化接口价值分析助手。请基于站点线索、页面URL、接口URL、HTTP方法、参数名、请求体形态、"
                "状态码、响应大小、响应语义、响应字段和回复报文摘要，判断该接口是否值得优先进入渗透测试。"
                "你必须关注后台/鉴权/用户/角色/订单/支付/上传/导入导出/配置/租户/令牌/调试类接口，"
                "同时降低新闻、公告、列表、帮助、静态内容、健康检查等低价值接口权重。"
                "必须优先使用回复报文做校正：若响应明确为未登录、权限不足、访问被拒绝、资源不存在、参数校验失败，"
                "不要仅因 POST、import/export、admin 等路径语义就直接判为高价值。"
                "只有在响应已体现真实业务成功、敏感字段、导出地址、用户/租户/权限数据时，才可以提级为高价值。"
                "输出时请给出："
                "1) 高价值/中价值/无价值结论；"
                "2) 关键证据；"
                "3) 推荐优先验证方向（鉴权/越权/业务逻辑/注入/上传/配置变更/敏感数据导出等）。"
                "禁止仅因存在 POST 或 query 参数就夸大为高价值。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_vuln',
            'name': '默认AI去噪-风险',
            'scene': 'ai_denoise_vuln',
            'content': (
                "你是漏洞结果复核助手。请根据风险等级、目标、验证证据与规则上下文判断：可信/疑似误报，"
                "并从渗透测试视角输出："
                "1) 哪些漏洞应优先复测；"
                "2) 复测前置条件与利用链关键点；"
                "3) 若疑似误报，给出最小复核路径。"
                "必须优先参考验证证据和命中URL，若只有模板名称或风险等级、没有利用证据，不要直接判高可信。"
                "若验证信息只体现权限拒绝、未登录、404、网络异常、参数校验失败或纯规则描述，应优先降为疑似误报。"
            ),
            'updated_at': '',
        },
        {
            'id': 'default_ai_denoise_poc',
            'name': '默认AI去噪-PoC风险',
            'scene': 'ai_denoise_nuclei_result',
            'content': (
                "你是PoC命中结果复核助手。请结合扫描器、规则ID、风险等级、命中URL与验证信息判断可信度，"
                "并输出渗透测试可执行建议："
                "1) 是否值得人工复现；"
                "2) 复现路径与关键请求点；"
                "3) 哪些结果应降权为疑似误报。"
                "若验证信息只体现权限拒绝、未登录、404、网络异常、参数校验失败或纯规则描述，应优先降权为疑似误报。"
            ),
            'updated_at': '',
        },
        {
            'id': AI_WIH_ENDPOINT_FILL_PROMPT_ID,
            'name': '默认AI填充-WIH接口',
            'scene': AI_WIH_ENDPOINT_FILL_SCENE,
            'content': (
                "你是 WIH 接口参数补全与安全测试助手。请基于站点信息、页面URL、接口URL、HTTP方法、"
                "请求报文、请求模板、Content-Type、参数名和已有参数值，输出尽可能可用、类型正确、低副作用的请求填充建议。"
                "要求："
                "1) 优先保留原始请求中已有的稳定值，仅填充缺失值、<value> 占位符、空字符串或明显无效值；"
                "2) 输出时必须标注参数位置（query/body/path）、推断类型（string/int/bool/date/id/keyword/enum/url 等）和建议值；"
                "3) GET/POST/HEAD/OPTIONS 可给出 safe 测试建议；DELETE/PUT/PATCH/TRACE/CONNECT 等高风险方法只允许给出 hint_only 提示，不建议自动实测；"
                "4) 对 multipart、文件上传、二进制体、签名/验证码/一次性 token 等高副作用或高不确定参数要保守；"
                "5) 仅输出 JSON 对象，不要输出 Markdown。"
            ),
            'updated_at': '',
        },
    ]

    for item in templates:
        if not isinstance(item, dict):
            continue
        prompt_id = str(item.get('id') or '').strip()
        file_ref = _resolve_ai_prompt_template_file(prompt_id, item.get('file'))
        if not file_ref:
            continue
        item['file'] = file_ref
        file_payload = _read_ai_prompt_template_payload_from_file(file_ref)
        file_content = str(file_payload.get('content') or '').strip()
        if not item.get('name') and file_payload.get('name'):
            item['name'] = str(file_payload.get('name') or '').strip()
        if not item.get('scene') and file_payload.get('scene'):
            item['scene'] = str(file_payload.get('scene') or '').strip()
        if not item.get('updated_at') and file_payload.get('updated_at'):
            item['updated_at'] = str(file_payload.get('updated_at') or '').strip()
        if file_content:
            item['content'] = file_content

    return templates


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


def _normalize_ai_model_name(provider_id, model_name):
    """
    规范化常见模型别名，降低大小写/旧命名带来的误配置概率。
    """
    raw_name = str(model_name or '').strip()
    if not raw_name:
        return ''

    provider = _normalize_ai_provider_id(provider_id)
    normalized = raw_name.lower().replace('_', '-').replace(' ', '')
    normalized = normalized.replace('–', '-').replace('—', '-')

    if provider == 'qwen':
        alias_map = {
            'qwen3.5-plus': 'qwen-plus',
            'qwen-3.5-plus': 'qwen-plus',
            'qwen35-plus': 'qwen-plus',
            'qwen3.5plus': 'qwen-plus',
            'qwen3.5': 'qwen-plus',
            'qwen3-plus': 'qwen-plus',
            'qwen3.5-max': 'qwen-max',
            'qwen-3.5-max': 'qwen-max',
            'qwen35-max': 'qwen-max',
            'qwen3.5max': 'qwen-max',
            'qwen3-max': 'qwen-max',
            'qwen3.5-turbo': 'qwen-turbo',
            'qwen-3.5-turbo': 'qwen-turbo',
            'qwen35-turbo': 'qwen-turbo',
            'qwen3.5turbo': 'qwen-turbo',
            'qwen3-turbo': 'qwen-turbo',
        }
        mapped = alias_map.get(normalized)
        if mapped:
            return mapped

    return raw_name


def _is_ai_model_unavailable_error(message):
    text = str(message or '').strip().lower()
    if not text:
        return False
    keywords = (
        'does not exist',
        'not exist',
        'model not found',
        'you do not have access',
        'no access to model',
        '模型不存在',
        '无权访问',
        '模型不可用',
    )
    return any(keyword in text for keyword in keywords)


def _pick_ai_retry_model(provider_id, current_model):
    provider = _normalize_ai_provider_id(provider_id)
    default_model = str((AI_PROVIDER_PRESET_MAP.get(provider) or {}).get('default_model') or '').strip()
    current = str(current_model or '').strip()
    if not default_model:
        return ''
    if default_model == current:
        return ''
    return default_model


def _build_ai_proxy_dict(proxy_url):
    """
    构建 requests 代理配置（支持 http/https/socks5）。
    """
    value = str(proxy_url or '').strip()
    if not value:
        return None
    lower_value = value.lower()
    if not (
        lower_value.startswith('http://')
        or lower_value.startswith('https://')
        or lower_value.startswith('socks5://')
        or lower_value.startswith('socks5h://')
    ):
        return None
    return {
        'http': value,
        'https': value,
    }


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
            file_ref = _resolve_ai_prompt_template_file(prompt_id, item.get('file'))
            file_payload = _read_ai_prompt_template_payload_from_file(file_ref) if file_ref else {}
            content = str(item.get('content') or '').strip()
            if not content and file_ref:
                content = str(file_payload.get('content') or '').strip()
            if not name and file_payload.get('name'):
                name = str(file_payload.get('name') or '').strip()
            if (not scene or scene == 'ai_report_export') and file_payload.get('scene'):
                scene = str(file_payload.get('scene') or '').strip() or scene
            updated_at = str(item.get('updated_at') or '').strip()
            if not updated_at and file_payload.get('updated_at'):
                updated_at = str(file_payload.get('updated_at') or '').strip()
            if not prompt_id:
                prompt_id = 'prompt_{}'.format(len(templates) + 1)
            if not name:
                name = prompt_id
            if not content:
                continue
            if prompt_id in seen:
                continue
            seen.add(prompt_id)
            template_item = {
                'id': prompt_id,
                'name': name,
                'scene': scene,
                'content': content,
                'updated_at': updated_at,
            }
            if file_ref:
                template_item['file'] = file_ref
            templates.append(template_item)

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
            'reasoning_model': str(preset.get('default_reasoning_model') or preset.get('default_model') or ''),
            'proxy': '',
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
            reasoning_model = str(item.get('reasoning_model') or '').strip()
            if not reasoning_model:
                reasoning_model = str(provider_preset.get('default_reasoning_model') or model or '').strip()

            profiles.append(
                {
                    'id': profile_id,
                    'name': str(item.get('name') or profile_id).strip(),
                    'provider': provider_id,
                    'base_url': base_url,
                    'api_key': str(item.get('api_key') or '').strip(),
                    'model': model,
                    'reasoning_model': reasoning_model,
                    'proxy': str(item.get('proxy') or item.get('proxy_url') or '').strip(),
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
                'reasoning_model': str(legacy_ai_conf.get('REASONING_MODEL') or '').strip() or str(provider_preset.get('default_reasoning_model') or legacy_ai_conf.get('MODEL') or provider_preset.get('default_model') or '').strip(),
                'proxy': str(legacy_ai_conf.get('PROXY_URL') or legacy_ai_conf.get('PROXY') or '').strip(),
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




AI_CONFIG_SERVICE = AIConfigService(
    config=Config,
    normalize_model_profiles=_normalize_ai_model_profiles,
    pick_active_model_profile=_pick_active_ai_model_profile,
    normalize_prompt_templates=_normalize_ai_prompt_templates,
    normalize_denoise_modules=_normalize_ai_denoise_modules,
    normalize_denoise_prompt_ids=_normalize_ai_denoise_prompt_ids,
    normalize_custom_providers=_normalize_ai_custom_providers,
    persist_prompt_templates=_persist_ai_prompt_templates_for_config,
)


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


def _normalize_ai_usage_value(value):
    parsed = _safe_int_any(value, 0)
    if parsed < 0:
        return 0
    return parsed


def _normalize_ai_elapsed_ms(value, max_value=600000):
    parsed = _safe_int_any(value, 0)
    if parsed < 0:
        return 0
    if max_value and parsed > max_value:
        return max_value
    return parsed


def _normalize_ai_error_reason(error_message):
    text = str(error_message or '').strip()
    if not text:
        return ''
    lowered = text.lower()

    if '模型配置不完整' in text:
        return '模型配置不完整'

    if (
        'invalid_api_key' in lowered
        or 'incorrect api key' in lowered
        or 'unauthorized' in lowered
        or 'authentication' in lowered
        or '401' in lowered
        or '鉴权' in text
        or '认证' in text
    ):
        return '鉴权失败'

    if (
        'rate limit' in lowered
        or 'too many requests' in lowered
        or 'quota' in lowered
        or '429' in lowered
        or '限流' in text
        or '频率限制' in text
    ):
        return '频率限制'

    if (
        'timeout' in lowered
        or 'timed out' in lowered
        or 'read timed out' in lowered
        or 'connect timeout' in lowered
        or '超时' in text
    ):
        return '请求超时'

    if (
        ('model' in lowered and ('not exist' in lowered or 'not found' in lowered or 'unavailable' in lowered))
        or ('模型' in text and ('不可用' in text or '不存在' in text))
    ):
        return '模型不可用'

    if '返回格式不可解析' in text or 'only output json' in lowered:
        return '返回格式异常'

    if (
        'connection' in lowered
        or 'name or service not known' in lowered
        or 'dns' in lowered
        or 'proxy' in lowered
        or 'ssl' in lowered
        or '连接' in text
        or '网络' in text
        or '代理' in text
    ):
        return '网络异常'

    if text.startswith('HTTP '):
        return 'HTTP错误'

    return _truncate_text(text, 60)


def _normalize_ai_usage_dict(raw_usage):
    usage = raw_usage if isinstance(raw_usage, dict) else {}
    prompt_tokens = _normalize_ai_usage_value(usage.get('prompt_tokens'))
    completion_tokens = _normalize_ai_usage_value(usage.get('completion_tokens'))
    total_tokens_raw = _normalize_ai_usage_value(usage.get('total_tokens'))
    total_tokens = total_tokens_raw or (prompt_tokens + completion_tokens)
    if total_tokens < 0:
        total_tokens = 0
    return {
        'prompt_tokens': prompt_tokens,
        'completion_tokens': completion_tokens,
        'total_tokens': total_tokens,
    }


def _normalize_ai_usage_scene_label(scene):
    scene_text = str(scene or '').strip()
    return AI_USAGE_SCENE_LABEL_MAP.get(scene_text, scene_text or 'AI调用')


def _build_ai_usage_log_stats_default():
    return {
        'request_count': 0,
        'success_count': 0,
        'error_count': 0,
        'skip_count': 0,
        'prompt_tokens': 0,
        'completion_tokens': 0,
        'total_tokens': 0,
    }


def _normalize_ai_usage_stats_value(raw_value):
    base = _build_ai_usage_log_stats_default()
    value = raw_value if isinstance(raw_value, dict) else {}
    base['request_count'] = _normalize_ai_usage_value(value.get('request_count'))
    base['success_count'] = _normalize_ai_usage_value(value.get('success_count'))
    base['error_count'] = _normalize_ai_usage_value(value.get('error_count'))
    base['skip_count'] = _normalize_ai_usage_value(value.get('skip_count'))
    base['prompt_tokens'] = _normalize_ai_usage_value(value.get('prompt_tokens'))
    base['completion_tokens'] = _normalize_ai_usage_value(value.get('completion_tokens'))
    base['total_tokens'] = _normalize_ai_usage_value(value.get('total_tokens'))
    return base


def _aggregate_ai_usage_stats(match_query=None):
    query = match_query if isinstance(match_query, dict) else {}
    pipeline = []
    if query:
        pipeline.append({'$match': query})
    pipeline.append(
        {
            '$group': {
                '_id': None,
                'request_count': {'$sum': 1},
                'success_count': {'$sum': {'$cond': [{'$eq': ['$status', 'ok']}, 1, 0]}},
                'error_count': {'$sum': {'$cond': [{'$eq': ['$status', 'error']}, 1, 0]}},
                'skip_count': {'$sum': {'$cond': [{'$eq': ['$status', 'skipped']}, 1, 0]}},
                'prompt_tokens': {'$sum': {'$ifNull': ['$usage.prompt_tokens', 0]}},
                'completion_tokens': {'$sum': {'$ifNull': ['$usage.completion_tokens', 0]}},
                'total_tokens': {'$sum': {'$ifNull': ['$usage.total_tokens', 0]}},
            }
        }
    )
    try:
        results = list(utils.conn_db(AI_USAGE_LOG_COLLECTION).aggregate(pipeline))
        if results:
            return _normalize_ai_usage_stats_value(results[0])
    except Exception as exc:
        logger.warning('aggregate ai usage stats failed: %s', exc)
    return _build_ai_usage_log_stats_default()


def _write_ai_usage_log(
    *,
    scene='',
    provider='',
    model='',
    profile='',
    status='ok',
    request_text='',
    reply_text='',
    error_message='',
    elapsed_ms=0,
    usage=None,
    meta=None
):
    now = datetime.now()
    scene_text = str(scene or '').strip() or 'ai_call'
    status_text = str(status or '').strip().lower()
    if status_text not in ('ok', 'error', 'skipped'):
        status_text = 'ok'
    usage_value = _normalize_ai_usage_dict(usage)
    meta_value = meta if isinstance(meta, dict) else {}
    elapsed_value = _normalize_ai_elapsed_ms(elapsed_ms)
    if elapsed_value <= 0 and isinstance(meta_value, dict):
        elapsed_value = _normalize_ai_elapsed_ms(meta_value.get('elapsed_ms'))
    error_reason = _normalize_ai_error_reason(error_message) if status_text == 'error' else ''

    record = {
        'created_at': now,
        'created_at_text': now.strftime('%Y-%m-%d %H:%M:%S'),
        'scene': scene_text,
        'scene_label': _normalize_ai_usage_scene_label(scene_text),
        'provider': _truncate_text(provider, 64),
        'model': _truncate_text(model, 120),
        'profile': _truncate_text(profile, 120),
        'status': status_text,
        'request_text': _truncate_text(request_text, 3200),
        'reply_text': _truncate_text(reply_text, 3200),
        'error_message': _truncate_text(error_message, 320),
        'error_reason': error_reason,
        'elapsed_ms': elapsed_value,
        'usage': usage_value,
        'meta': meta_value,
    }
    try:
        utils.conn_db(AI_USAGE_LOG_COLLECTION).insert_one(record)
    except Exception as exc:
        logger.warning('write ai usage log failed: %s', exc)


AI_PROVIDER_TEST_SERVICE = AIProviderTestService(
    http_req=utils.http_req,
    normalize_profiles=_normalize_ai_model_profiles,
    pick_active_profile=_pick_active_ai_model_profile,
    normalize_provider=_normalize_ai_provider_id,
    normalize_model=_normalize_ai_model_name,
    pick_retry_model=_pick_ai_retry_model,
    is_model_unavailable=_is_ai_model_unavailable_error,
    build_proxy_dict=_build_ai_proxy_dict,
    normalize_usage=_normalize_ai_usage_dict,
    normalize_elapsed_ms=_normalize_ai_elapsed_ms,
    safe_int=_safe_int,
    safe_float=_safe_float,
    usage_logger=_write_ai_usage_log,
    logger=logger,
)


def _test_ai_config_connectivity(ai_config):
    """保留旧入口，实际连通性测试由 AI Provider service 执行。"""
    return AI_PROVIDER_TEST_SERVICE.test(ai_config)


def _serialize_ai_usage_log_record(item):
    if not isinstance(item, dict):
        return {}
    usage_value = _normalize_ai_usage_dict(item.get('usage'))
    created_at_text = str(item.get('created_at_text') or '').strip()
    if not created_at_text:
        created_at = item.get('created_at')
        if isinstance(created_at, datetime):
            created_at_text = created_at.strftime('%Y-%m-%d %H:%M:%S')
    object_id = item.get('_id')
    log_id = str(object_id) if isinstance(object_id, ObjectId) else _truncate_text(object_id, 80)
    scene = str(item.get('scene') or '').strip()
    status_text = str(item.get('status') or '').strip().lower()
    if status_text not in ('ok', 'error', 'skipped'):
        status_text = 'ok'
    return {
        'id': log_id,
        'created_at': created_at_text,
        'scene': scene,
        'scene_label': str(item.get('scene_label') or _normalize_ai_usage_scene_label(scene)),
        'provider': str(item.get('provider') or ''),
        'model': str(item.get('model') or ''),
        'profile': str(item.get('profile') or ''),
        'status': status_text,
        'request_text': _truncate_text(item.get('request_text'), 3200),
        'reply_text': _truncate_text(item.get('reply_text'), 3200),
        'error_message': _truncate_text(item.get('error_message'), 320),
        'error_reason': _normalize_ai_error_reason(item.get('error_reason') or item.get('error_message')),
        'elapsed_ms': _normalize_ai_elapsed_ms(item.get('elapsed_ms')),
        'prompt_tokens': usage_value.get('prompt_tokens', 0),
        'completion_tokens': usage_value.get('completion_tokens', 0),
        'total_tokens': usage_value.get('total_tokens', 0),
        'meta': item.get('meta') if isinstance(item.get('meta'), dict) else {},
    }


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
                'content': (
                    '你是渗透测试前置研判助手。'
                    '请对“{}”做去噪与价值判断，目标是为后续人工渗透测试提供可执行优先级。'
                    '要求：仅基于现有证据，不编造；给出可落地的下一步验证建议。'
                ).format(module_label),
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


def _extract_data_id_from_item(item):
    if not isinstance(item, dict):
        return ''
    for key in ('_id', 'id', '_data_id'):
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


def _ensure_ai_denoise_result_indexes():
    global _AI_DENOISE_RESULT_INDEX_READY
    if _AI_DENOISE_RESULT_INDEX_READY:
        return

    coll = utils.conn_db(AI_DENOISE_RESULT_COLLECTION)
    try:
        coll.create_index(
            [('task_id', 1), ('module_id', 1), ('row_key', 1)],
            unique=True,
            background=True,
            name='uniq_task_module_row',
        )
    except Exception as exc:
        logger.warning('create ai_denoise_result uniq index failed: %s', exc)
    try:
        coll.create_index(
            [('task_id', 1), ('module_id', 1), ('updated_at', -1)],
            background=True,
            name='task_module_updated_at',
        )
    except Exception as exc:
        logger.warning('create ai_denoise_result updated_at index failed: %s', exc)
    _AI_DENOISE_RESULT_INDEX_READY = True


def _load_ai_denoise_persisted_result(task_id, module_id, row_key, data_id=''):
    task_id_text = str(task_id or '').strip()
    module_id_text = str(module_id or '').strip()
    row_key_text = str(row_key or '').strip()
    data_id_text = str(data_id or '').strip()
    if not task_id_text or not module_id_text:
        return None

    query = {
        'task_id': task_id_text,
        'module_id': module_id_text,
    }
    if row_key_text:
        query['row_key'] = row_key_text
    elif data_id_text:
        query['data_id'] = data_id_text
    else:
        return None

    result = utils.conn_db(AI_DENOISE_RESULT_COLLECTION).find_one(query)
    if isinstance(result, dict):
        return result

    if row_key_text and data_id_text:
        return utils.conn_db(AI_DENOISE_RESULT_COLLECTION).find_one(
            {
                'task_id': task_id_text,
                'module_id': module_id_text,
                'data_id': data_id_text,
            }
        )
    return None


def _build_ai_denoise_result_from_persisted(result_doc, row_key, module_id, prompt_id, prompt_name):
    source_text = str(result_doc.get('source') or 'disabled').strip().lower()
    if source_text not in ('ai', 'rule', 'disabled'):
        source_text = 'disabled'

    result_level = _normalize_ai_denoise_result_level(result_doc.get('result_level'), 'disabled')
    raw_risk_level = str(result_doc.get('risk_level') or '').strip()
    risk_level = '-' if not raw_risk_level or raw_risk_level == '-' else _normalize_risk_level_text(raw_risk_level)
    trust_value = result_doc.get('trust')
    if module_id in ('vuln', 'nuclei_result'):
        trust_raw = str(trust_value or '').strip()
        trust_text = '-' if not trust_raw or trust_raw == '-' else _normalize_trust_level_text(trust_raw)
    else:
        trust_text = _normalize_item_text(trust_value or '-', 32) or '-'
    cert_expire_days = result_doc.get('cert_expire_days')

    display_text = _normalize_item_text(
        result_doc.get('display_text')
        or _build_ai_denoise_display_text(
            module_id,
            result_level,
            risk_level=risk_level,
            trust=trust_text,
            cert_expire_days=cert_expire_days,
        ),
        64,
    ) or '未分析'

    return {
        'row_key': str(row_key or '').strip(),
        'module_id': module_id,
        'module_label': AI_DENOISE_MODULE_LABEL_MAP.get(module_id) or module_id,
        'result_level': result_level,
        'risk_level': risk_level,
        'trust': trust_text,
        'display_text': display_text,
        'summary': _normalize_item_text(result_doc.get('summary'), 900),
        'evidence': _normalize_string_list_value(result_doc.get('evidence'), max_items=8, max_item_len=280),
        'suggestions': _normalize_string_list_value(result_doc.get('suggestions'), max_items=8, max_item_len=280),
        'source': source_text,
        'prompt_id': _normalize_item_text(result_doc.get('prompt_id') or prompt_id, 80),
        'prompt_name': _normalize_item_text(result_doc.get('prompt_name') or prompt_name, 120),
        'note': _normalize_item_text(result_doc.get('note') or '当前结果来自扫描阶段已落库数据。', 260),
        'cert_expire_at': _normalize_item_text(result_doc.get('cert_expire_at'), 80),
        'cert_expire_days': cert_expire_days,
        'analyzed_at': _normalize_item_text(result_doc.get('analyzed_at'), 64),
        'finger_result': _normalize_string_list_value(result_doc.get('finger_result'), max_items=12, max_item_len=80),
        'dialogue_records': _normalize_dialogue_records(result_doc.get('dialogue_records') if isinstance(result_doc.get('dialogue_records'), list) else []),
    }


def _resolve_task_ai_denoise_runtime_status(task_id, cache_dict):
    task_id_text = str(task_id or '').strip()
    if not task_id_text:
        return {'task_status': '', 'ai_status': ''}
    if task_id_text in cache_dict:
        return cache_dict[task_id_text]

    query_id = task_id_text
    if ObjectId.is_valid(task_id_text):
        query_id = ObjectId(task_id_text)
    task_doc = utils.conn_db('task').find_one(
        {'_id': query_id},
        {'_id': 1, 'status': 1, 'ai_denoise_status.status': 1}
    )
    task_status = ''
    ai_status = ''
    if isinstance(task_doc, dict):
        task_status = str(task_doc.get('status') or '').strip().lower()
        ai_status_obj = task_doc.get('ai_denoise_status') if isinstance(task_doc.get('ai_denoise_status'), dict) else {}
        ai_status = str(ai_status_obj.get('status') or '').strip().lower()

    info = {'task_status': task_status, 'ai_status': ai_status}
    cache_dict[task_id_text] = info
    return info


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
    if text in ('danger', 'high', 'critical', '严重', '危险', '高危', '危急', 'high_value', '高价值'):
        return 'danger'
    if text in ('suspicious', 'medium', 'manual_review', '可疑', '中危', '待复核', 'medium_value', '中价值'):
        return 'suspicious'
    if text in ('safe', 'normal', 'low', 'pass', '安全', '正常', '低危', '可信', 'no_value', '无价值'):
        return 'safe'
    return default_value


def _merge_ai_denoise_result_level(current_level, next_level):
    current = _normalize_ai_denoise_result_level(current_level, 'safe')
    candidate = _normalize_ai_denoise_result_level(next_level, 'safe')
    if AI_DENOISE_RESULT_LEVEL_WEIGHT.get(candidate, 0) > AI_DENOISE_RESULT_LEVEL_WEIGHT.get(current, 0):
        return candidate
    return current


def _cap_ai_denoise_result_level(current_level, max_level):
    current = _normalize_ai_denoise_result_level(current_level, 'safe')
    cap_level = _normalize_ai_denoise_result_level(max_level, 'safe')
    if AI_DENOISE_RESULT_LEVEL_WEIGHT.get(current, 0) > AI_DENOISE_RESULT_LEVEL_WEIGHT.get(cap_level, 0):
        return cap_level
    return current


def _normalize_risk_level_text(value):
    text = str(value or '').strip().lower()
    if text in ('无', 'none', 'no_value') or '无价值' in text or 'no value' in text:
        return '无'
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
    if '高价值' in text or 'high_value' in text or 'high value' in text:
        return '高价值'
    if '中价值' in text or 'medium_value' in text or 'medium value' in text:
        return '中价值'
    if '无价值' in text or 'no_value' in text or 'no value' in text:
        return '无价值'
    if any(word in text for word in ('fp', '误报', 'suspected', '疑似')):
        return '疑似误报'
    return '可信'


def _build_wih_endpoint_value_label(result_level):
    mapping = {
        'danger': '高价值',
        'suspicious': '中价值',
        'safe': '无价值',
        'disabled': '已关闭',
    }
    return mapping.get(_normalize_ai_denoise_result_level(result_level, 'safe'), '无价值')


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
    if module_id == 'wih_endpoint':
        return _build_wih_endpoint_value_label(result_level)
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


def _normalize_site_origin(value):
    text = str(value or '').strip()
    if not text:
        return ''
    try:
        parsed = urlparse(text)
        if parsed.scheme and parsed.netloc:
            return '{}://{}'.format(parsed.scheme, parsed.netloc)
    except Exception:
        return text.rstrip('/')
    return text.rstrip('/')


@lru_cache(maxsize=2048)
def _lookup_ai_denoise_site_summary(task_id_text, site_origin):
    task_id_value = str(task_id_text or '').strip()
    site_text = str(site_origin or '').strip()
    if not task_id_value or not site_text:
        return {}

    try:
        query_value = task_id_value
        if ObjectId.is_valid(task_id_value):
            query_value = {'$in': [task_id_value, ObjectId(task_id_value)]}
        doc = utils.conn_db('site').find_one(
            {'task_id': query_value, 'site': site_text},
            {'site': 1, 'title': 1, 'finger': 1},
        )
    except Exception:
        return {}

    if not isinstance(doc, dict):
        return {}

    return {
        'site': str(doc.get('site') or site_text).strip(),
        'title': _normalize_item_text(doc.get('title'), 320),
        'finger': _extract_site_finger_names(doc.get('finger')),
    }


def _safe_wih_request_header_names(headers):
    if not isinstance(headers, dict):
        return []

    result = []
    seen = set()
    for key in headers.keys():
        name_text = str(key or '').strip()
        if not name_text:
            continue
        normalized = name_text.lower()
        if normalized in seen:
            continue
        if normalized in {'authorization', 'cookie', 'proxy-authorization', 'x-auth-token', 'x-access-token'}:
            continue
        seen.add(normalized)
        result.append(name_text[:80])
        if len(result) >= 16:
            break
    return result


def _extract_wih_endpoint_request_summary(item):
    request_template = item.get('request_template') if isinstance(item.get('request_template'), dict) else {}
    query_obj = request_template.get('query') if isinstance(request_template.get('query'), dict) else {}
    body_obj = request_template.get('body') if isinstance(request_template.get('body'), dict) else {}
    path_obj = request_template.get('path') if isinstance(request_template.get('path'), dict) else {}
    query_string = str(request_template.get('query_string') or '').strip().lstrip('?')
    ai_fill_params = item.get('ai_fill_params') if isinstance(item.get('ai_fill_params'), list) else []

    query_params = []
    body_params = []
    path_params = []
    filled_params = []
    param_names = []
    seen = set()

    def append_param(container, raw_key):
        key_text = str(raw_key or '').strip()
        if not key_text:
            return
        container.append(key_text[:80])
        lowered = key_text.lower()
        if lowered in seen:
            return
        seen.add(lowered)
        param_names.append(key_text[:80])

    for key in query_obj.keys():
        append_param(query_params, key)
    for key in body_obj.keys():
        append_param(body_params, key)
    for key in path_obj.keys():
        append_param(path_params, key)

    if query_string:
        try:
            for key_text, _ in parse_qsl(query_string, keep_blank_values=True):
                append_param(query_params, key_text)
        except Exception:
            pass

    for entry in ai_fill_params:
        if not isinstance(entry, dict):
            continue
        location = str(entry.get('location') or '').strip().lower()
        key_text = str(entry.get('name') or '').strip()
        if not key_text:
            continue
        if location == 'query':
            append_param(query_params, key_text)
        elif location == 'body':
            append_param(body_params, key_text)
        elif location == 'path':
            append_param(path_params, key_text)
        filled_params.append(key_text[:80])

    return {
        'query_params': query_params[:16],
        'body_params': body_params[:16],
        'path_params': path_params[:16],
        'param_names': param_names[:20],
        'filled_params': filled_params[:20],
        'header_names': _safe_wih_request_header_names(request_template.get('headers')),
    }


def _extract_response_packet_status_line(packet_text):
    text = str(packet_text or '').strip()
    if not text:
        return ''
    first_line = text.splitlines()[0] if text.splitlines() else ''
    return _normalize_item_text(first_line, 180)


def _extract_response_packet_body(packet_text):
    text = str(packet_text or '').strip()
    if not text:
        return ''
    parts = re.split(r'\r?\n\r?\n', text, maxsplit=1)
    if len(parts) == 2:
        return str(parts[1] or '').strip()
    return ''


def _extract_response_json_keys(value, limit=20):
    result = []
    seen = set()

    def append_key(raw_key):
        key_text = str(raw_key or '').strip()
        if not key_text:
            return
        normalized = key_text.lower()
        if normalized in seen:
            return
        seen.add(normalized)
        result.append(key_text[:80])

    def walk(node):
        if len(result) >= limit:
            return
        if isinstance(node, dict):
            for key, nested in node.items():
                append_key(key)
                if len(result) >= limit:
                    return
                if isinstance(nested, (dict, list)):
                    walk(nested)
                    if len(result) >= limit:
                        return
        elif isinstance(node, list):
            for nested in node[:5]:
                if isinstance(nested, (dict, list)):
                    walk(nested)
                    if len(result) >= limit:
                        return

    walk(value)
    return result[:limit]


def _parse_response_json_payload(body_text):
    text = str(body_text or '').strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        parsed_obj = _extract_json_object_from_text(text)
        if isinstance(parsed_obj, dict):
            return parsed_obj
    return None


def _build_wih_endpoint_response_insights(item):
    source = ''
    packet_text = ''
    for field_name, source_name in (
        ('ai_fill_response_packet', 'ai_fill'),
        ('verification_response_packet', 'verification'),
        ('response_packet', 'stored'),
    ):
        candidate = str(item.get(field_name) or '').strip()
        if candidate:
            source = source_name
            packet_text = candidate
            break

    summary_text = _normalize_item_text(item.get('ai_fill_response_summary'), 600)
    status_line = _extract_response_packet_status_line(packet_text)
    body_text = _extract_response_packet_body(packet_text)
    body_excerpt = _normalize_item_text(body_text, 800)
    packet_excerpt = _normalize_item_text(packet_text, 1200)
    parsed_json = _parse_response_json_payload(body_text)
    json_keys = _extract_response_json_keys(parsed_json, limit=24) if parsed_json is not None else []
    status_code = _safe_int_any(item.get('status_code') or item.get('response_status'), 0)

    combined_text = ' '.join(
        [
            summary_text,
            status_line,
            body_excerpt,
            ' '.join(json_keys),
        ]
    ).lower()
    json_keys_lower = [str(key or '').strip().lower() for key in json_keys if str(key or '').strip()]

    permission_denied_keywords = (
        '没有该资源访问权限', '没有访问权限', '访问权限', '权限不足', '无权访问',
        'permission denied', 'access denied', 'forbidden', 'forbidden request',
        'not authorized', 'no permission',
    )
    auth_required_keywords = (
        '未登录', '请先登录', '请登录', '登录后', '登录超时',
        'unauthorized', 'authentication failed', 'login required',
        'token invalid', 'token expired', 'invalid token',
    )
    resource_not_found_keywords = (
        'resource not found', 'not found', '不存在', '未找到',
        '没有该资源', '资源不存在',
    )
    validation_error_keywords = (
        '参数错误', '参数缺失', '参数不能为空', '缺少参数', 'invalid parameter',
        'missing parameter', 'validation failed', 'bad request', 'illegal argument',
    )
    success_keywords = (
        '操作成功', '保存成功', '创建成功', '更新成功', '复制成功', '导出成功',
        'success', '"success":true', '"ok":true',
    )
    sensitive_response_keywords = (
        'token', 'access_token', 'refresh_token', 'userid', 'user_id', 'username',
        'tenantid', 'tenant_id', 'roleid', 'role_id', 'permission', 'permissions',
        'exporturl', 'export_url', 'downloadurl', 'download_url', 'filepath',
        'file_url', 'oss', 'ak', 'sk',
    )

    semantics = []

    def append_semantic(value):
        if value not in semantics:
            semantics.append(value)

    if any(keyword in combined_text for keyword in permission_denied_keywords):
        append_semantic('permission_denied')
    if any(keyword in combined_text for keyword in auth_required_keywords):
        append_semantic('auth_required')
    if (
        'permission_denied' not in semantics
        and any(keyword in combined_text for keyword in resource_not_found_keywords)
    ):
        append_semantic('resource_not_found')
    if any(keyword in combined_text for keyword in validation_error_keywords):
        append_semantic('validation_error')

    has_sensitive_response = (
        any(keyword in combined_text for keyword in sensitive_response_keywords)
        or any(
            any(keyword in key for keyword in sensitive_response_keywords)
            for key in json_keys_lower
        )
    )
    if has_sensitive_response:
        append_semantic('sensitive_response')

    success_like = False
    if any(keyword in combined_text for keyword in success_keywords):
        success_like = True
    if isinstance(parsed_json, dict):
        if parsed_json.get('success') is True or parsed_json.get('ok') is True:
            success_like = True
        code_text = str(parsed_json.get('code') or '').strip().lower()
        if code_text in ('0', '200', '20000', 'ok', 'success'):
            success_like = True
    if (
        status_code in (200, 201, 202, 204)
        and has_sensitive_response
        and 'permission_denied' not in semantics
        and 'auth_required' not in semantics
        and 'resource_not_found' not in semantics
    ):
        success_like = True
    if success_like and 'permission_denied' not in semantics and 'auth_required' not in semantics:
        append_semantic('operation_success')

    semantic_label_map = {
        'permission_denied': '权限拒绝',
        'auth_required': '鉴权失败/需要登录',
        'resource_not_found': '资源不存在',
        'validation_error': '参数校验失败',
        'operation_success': '业务成功响应',
        'sensitive_response': '返回敏感业务字段',
    }
    semantic_labels = [semantic_label_map.get(item, item) for item in semantics]

    return {
        'source': source,
        'status_line': status_line,
        'summary': summary_text,
        'body_excerpt': body_excerpt,
        'packet_excerpt': packet_excerpt,
        'json_keys': json_keys[:12],
        'semantics': semantics,
        'semantic_labels': semantic_labels,
    }


def _build_wih_endpoint_site_summary(item):
    task_id_text = str(item.get('task_id') or '').strip()
    candidates = [
        _normalize_site_origin(item.get('target')),
        _normalize_site_origin(item.get('page_url')),
        _normalize_site_origin(item.get('url')),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        summary = _lookup_ai_denoise_site_summary(task_id_text, candidate)
        if summary:
            return summary
    return {
        'site': next((item for item in candidates if item), ''),
        'title': '',
        'finger': [],
    }


def _contains_any_keyword(text, keywords):
    lowered = str(text or '').strip().lower()
    if not lowered:
        return False
    return any(str(keyword or '').strip().lower() in lowered for keyword in list(keywords or []) if str(keyword or '').strip())


def _normalize_url_path_text(url_text):
    text = str(url_text or '').strip()
    if not text:
        return ''
    try:
        return str(urlparse(text).path or '').strip()
    except Exception:
        return ''


def _build_surface_signal_summary(url_text='', title_text='', headers_text=''):
    lower_url = str(url_text or '').strip().lower()
    lower_title = str(title_text or '').strip().lower()
    lower_headers = str(headers_text or '').strip().lower()
    merged_text = ' '.join(item for item in (lower_url, lower_title, lower_headers) if item)

    login_keywords = (
        '登录', 'login', 'signin', 'sign in', 'sso', '单点登录', '统一认证',
        '统一身份认证', '认证中心', 'captcha', '验证码', 'password', '密码登录',
    )
    auth_keywords = (
        '未登录', '请先登录', 'login required', 'authentication', 'unauthorized',
        'forbidden', '权限不足', '访问被拒绝', 'access denied',
    )
    error_keywords = (
        '404', '403', '401', 'not found', 'forbidden', 'unauthorized',
        'error', '错误', '访问出错', '出错了', '请求失败',
    )
    api_doc_keywords = (
        'swagger', 'swagger-ui', 'api-doc', 'api docs', 'openapi',
        'v2/api-docs', 'v3/api-docs', 'knife4j', 'redoc', 'rapi',
    )
    debug_keywords = (
        'phpinfo', 'actuator', 'heapdump', 'prometheus', 'mappings',
        'beans', 'env', 'jolokia', 'trace', 'debug',
    )
    admin_keywords = (
        'admin', 'manage', '后台', '管理', 'console', 'dashboard',
    )
    directory_keywords = (
        'index of', 'directory listing',
    )
    waf_keywords = (
        'cloudflare', 'safedog', 'waf', 'f5 big-ip', 'akamai', 'aliyun',
        'yundun', '安全狗', 'cdn',
    )

    return {
        'login_shell': _contains_any_keyword(merged_text, login_keywords),
        'auth_related': _contains_any_keyword(merged_text, auth_keywords),
        'error_page': _contains_any_keyword(lower_title, error_keywords),
        'api_doc': _contains_any_keyword('{} {}'.format(lower_url, lower_title), api_doc_keywords),
        'debug_surface': _contains_any_keyword('{} {}'.format(lower_url, lower_title), debug_keywords),
        'admin_surface': _contains_any_keyword('{} {}'.format(lower_url, lower_title), admin_keywords),
        'directory_listing': _contains_any_keyword(lower_title, directory_keywords),
        'waf_or_cdn': _contains_any_keyword('{} {}'.format(lower_title, lower_headers), waf_keywords),
    }


def _build_url_path_signal_summary(url_text):
    path_text = _normalize_url_path_text(url_text)
    normalized_path = str(path_text or '').strip()
    basename = os.path.basename(normalized_path.rstrip('/')) if normalized_path else ''
    basename_lower = basename.lower()
    _, ext = os.path.splitext(basename_lower)

    sensitive_exts = {
        '.sql', '.zip', '.tar', '.gz', '.7z', '.rar', '.bak', '.old', '.db', '.sqlite',
        '.env', '.pem', '.key', '.p12', '.pfx', '.crt', '.log', '.conf', '.ini', '.cfg',
        '.properties', '.yaml', '.yml', '.war', '.jar',
    }
    static_exts = {
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2',
        '.ttf', '.ico', '.map', '.mp4', '.mp3', '.avi', '.webp',
    }
    sensitive_names = {
        '.env', 'web.config', 'application.yml', 'application.yaml', 'application.properties',
        'config.php', 'id_rsa', 'known_hosts', 'passwd', 'shadow',
    }

    lower_path = normalized_path.lower()
    sensitive_file = (
        ext in sensitive_exts
        or basename_lower in sensitive_names
        or '/.git/' in lower_path
        or '/.svn/' in lower_path
        or lower_path.endswith('/.git')
        or lower_path.endswith('/.svn')
    )
    static_asset = ext in static_exts

    return {
        'path': normalized_path,
        'basename': basename[:120],
        'extension': ext,
        'sensitive_file': sensitive_file,
        'static_asset': static_asset,
    }


def _build_verify_signal_summary(verify_text, plg_type_text=''):
    excerpt = _normalize_item_text(verify_text, 1200)
    lower_text = excerpt.lower()
    strong_signals = []
    weak_signals = []

    def append_unique(container, value):
        if value and value not in container:
            container.append(value)

    if not lower_text:
        return {
            'excerpt': '',
            'strong_signals': [],
            'weak_signals': [],
        }

    strong_keyword_map = (
        ('sensitive_disclosure', ('root:x:0:0:', '/etc/passwd', 'for 16-bit app support', 'c:\\windows\\win.ini')),
        ('credential_material', ('-----begin', 'access_token', 'refresh_token', 'authorization:', 'set-cookie:', 'jsessionid=', 'phpsessid=')),
        ('sql_error_evidence', ('sql syntax', 'syntax error', 'sqlstate', 'mysql', 'postgresql', 'unterminated quoted string', 'ora-')),
        ('command_output', ('uid=', 'gid=', 'www-data', 'bin/bash', 'cmd.exe')),
        ('api_doc_or_schema', ('"openapi"', '"swagger"', 'swagger-ui', 'openapi: 3', 'graphql schema')),
    )
    weak_keyword_map = (
        ('auth_blocked', ('未登录', '请先登录', 'login required', 'forbidden', 'unauthorized', '权限不足', '访问被拒绝')),
        ('not_found', ('not found', '404', '不存在', '资源不存在')),
        ('validation_blocked', ('参数错误', '参数缺失', 'missing parameter', 'validation failed', 'bad request')),
        ('network_error', ('timeout', 'connection refused', 'connection reset', 'proxyerror', 'readtimeout', 'connecttimeout', 'dns', 'sslerror')),
        ('weak_hint_only', ('疑似', '可能存在', '待复核', '未验证', '规则命中', '无有效证据', '响应差异', '建议人工复测')),
    )

    for signal_name, keywords in strong_keyword_map:
        if _contains_any_keyword(lower_text, keywords):
            append_unique(strong_signals, signal_name)
    for signal_name, keywords in weak_keyword_map:
        if _contains_any_keyword(lower_text, keywords):
            append_unique(weak_signals, signal_name)

    if '敏感信息' in str(plg_type_text or '') and excerpt:
        append_unique(strong_signals, 'sensitive_leak')

    return {
        'excerpt': excerpt,
        'strong_signals': strong_signals,
        'weak_signals': weak_signals,
    }


def _apply_wih_endpoint_response_adjustment(item, result_item):
    if not isinstance(result_item, dict):
        return {}

    adjusted = dict(result_item)
    response_insights = _build_wih_endpoint_response_insights(item)
    semantics = set(response_insights.get('semantics') or [])
    changed = False

    if not semantics:
        return adjusted

    evidence = _normalize_string_list_value(adjusted.get('evidence'), max_items=8, max_item_len=260)
    suggestions = _normalize_string_list_value(adjusted.get('suggestions'), max_items=8, max_item_len=260)

    has_success = 'operation_success' in semantics or 'sensitive_response' in semantics
    if ('permission_denied' in semantics or 'auth_required' in semantics) and not has_success:
        capped_level = _cap_ai_denoise_result_level(adjusted.get('result_level'), 'suspicious')
        if capped_level != adjusted.get('result_level'):
            adjusted['result_level'] = capped_level
            adjusted['risk_level'] = '中'
            adjusted['trust'] = '中价值'
            changed = True
        evidence.insert(0, '响应明确表现为权限/鉴权拒绝，当前仅证明接口位于受保护边界，不等于已成功触达敏感业务。')
        suggestions.insert(0, '优先在不同认证态、不同角色和不同租户上下文下复测，再决定是否提级为高价值。')

    if 'resource_not_found' in semantics and not has_success:
        capped_level = _cap_ai_denoise_result_level(adjusted.get('result_level'), 'safe')
        if capped_level != adjusted.get('result_level'):
            adjusted['result_level'] = capped_level
            adjusted['risk_level'] = '无'
            adjusted['trust'] = '无价值'
            changed = True
        evidence.insert(0, '响应更像资源不存在或路径失效，当前不支持直接判定为高价值接口。')

    if 'validation_error' in semantics and not has_success:
        capped_level = _cap_ai_denoise_result_level(adjusted.get('result_level'), 'suspicious')
        if capped_level != adjusted.get('result_level'):
            adjusted['result_level'] = capped_level
            adjusted['risk_level'] = '中'
            adjusted['trust'] = '中价值'
            changed = True
        evidence.insert(0, '响应主要体现为参数校验失败，建议先补齐业务参数与认证上下文再复测。')

    if 'operation_success' in semantics and 'sensitive_response' in semantics:
        merged_level = _merge_ai_denoise_result_level(adjusted.get('result_level'), 'danger')
        if merged_level != adjusted.get('result_level'):
            adjusted['result_level'] = merged_level
            adjusted['risk_level'] = '高'
            adjusted['trust'] = '高价值'
            changed = True
        evidence.insert(0, '响应已出现成功业务信号，并伴随敏感字段或业务数据线索。')
    elif 'operation_success' in semantics:
        merged_level = _merge_ai_denoise_result_level(adjusted.get('result_level'), 'suspicious')
        if merged_level != adjusted.get('result_level'):
            adjusted['result_level'] = merged_level
            adjusted['risk_level'] = '中'
            adjusted['trust'] = '中价值'
            changed = True

    adjusted['evidence'] = evidence[:8]
    adjusted['suggestions'] = suggestions[:6]
    adjusted['display_text'] = _build_ai_denoise_display_text('wih_endpoint', adjusted.get('result_level'))
    if changed:
        method_text = _normalize_item_text(item.get('method'), 20).upper() or 'GET'
        url_text = _normalize_item_text(item.get('url'), 900)
        adjusted['summary'] = 'WIH接口价值分析结果：{}。接口：{} {}。已结合回复报文语义校正。'.format(
            adjusted.get('display_text') or '-',
            method_text,
            url_text or '-',
        )
    return adjusted


def _rule_analyze_site_item(item):
    site_url = _normalize_item_text(item.get('site') or item.get('url') or item.get('host'), 900)
    title_text = _normalize_item_text(item.get('title'), 320)
    header_text = _normalize_header_text(item.get('headers'))
    finger_names = _extract_site_finger_names(item.get('finger'))
    status_code = _safe_int_any(item.get('status_code') or item.get('status'), 0)
    body_length = _safe_int_any(item.get('body_length'), 0)

    lower_headers = header_text.lower()
    lower_fingers = [name.lower() for name in finger_names]
    surface_signals = _build_surface_signal_summary(site_url, title_text, header_text)

    high_value_header_keywords = (
        'x-powered-by', 'server:', 'set-cookie', 'x-aspnet-version', 'x-generator'
    )
    management_finger_keywords = (
        'jenkins', 'grafana', 'kibana', 'phpmyadmin', 'weblogic',
        'nacos', 'harbor', 'gitlab', 'jira', 'confluence',
    )

    result_level = 'safe'
    evidence = []
    ai_finger_result = list(finger_names)

    if status_code in (401, 403):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('站点返回鉴权状态码 {}，当前更像认证/权限边界，不能仅据此判定为高价值暴露。'.format(status_code))

    if status_code in (200, 201, 206):
        if surface_signals.get('api_doc') or surface_signals.get('debug_surface') or surface_signals.get('directory_listing'):
            result_level = _merge_ai_denoise_result_level(result_level, 'danger')
            evidence.append('站点已成功暴露接口文档、调试面或目录索引，这类入口应优先人工复核。')
        elif surface_signals.get('admin_surface'):
            result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
            evidence.append('站点更像后台或管理入口，但当前只有入口语义，仍需结合鉴权与实际功能确认。')

    if any(keyword in lower_headers for keyword in high_value_header_keywords):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('响应头暴露技术栈特征，可用于后续攻击面研判。')

    if any(any(keyword in finger for keyword in management_finger_keywords) for finger in lower_fingers):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('指纹命中管理类组件或常见后台系统，应结合版本与暴露面继续确认。')

    if surface_signals.get('login_shell'):
        result_level = _cap_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('页面更像登录壳或统一认证入口，不能仅因标题出现后台/管理词就直接提级为危险。')
    if surface_signals.get('error_page'):
        result_level = _cap_ai_denoise_result_level(result_level, 'safe')
        evidence.append('标题更像通用错误页或占位页，当前缺少真实暴露证据。')
    if surface_signals.get('waf_or_cdn'):
        evidence.append('站点存在 WAF/CDN 类边界特征，后续验证时需区分真实业务响应与网关拦截页。')

    if not finger_names:
        evidence.append('未识别到稳定指纹，建议结合截图与源码二次确认。')
    else:
        evidence.append('识别到指纹 {} 个。'.format(len(finger_names)))
    if body_length > 0:
        evidence.append('首页响应体长度约 {} 字节。'.format(body_length))

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
    surface_signals = _build_surface_signal_summary(url_text, title_text, '')
    path_signals = _build_url_path_signal_summary(url_text)

    strong_surface_keywords = (
        'swagger', 'v2/api-docs', 'v3/api-docs', 'openapi', 'knife4j',
        'actuator', 'phpinfo', 'heapdump', 'jolokia',
    )
    sensitive_keywords = (
        'backup', 'bak', 'config', 'secret', 'token', 'password',
        'passwd', 'credential', '.git', '.svn',
    )
    success_status = status_code in (200, 201, 206)
    blocked_status = status_code in (401, 403)
    missing_status = status_code in (404, 410)

    result_level = 'safe'
    evidence = []
    if success_status and (surface_signals.get('directory_listing') or surface_signals.get('api_doc') or surface_signals.get('debug_surface')):
        result_level = _merge_ai_denoise_result_level(result_level, 'danger')
        evidence.append('目录扫描目标已成功返回目录索引、接口文档或调试面。')
    elif success_status and path_signals.get('sensitive_file'):
        result_level = _merge_ai_denoise_result_level(result_level, 'danger')
        evidence.append('路径更像真实敏感文件或备份文件，且已成功访问。')
    elif success_status and any(keyword in lower_url for keyword in sensitive_keywords):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('URL 命中敏感目录/文件语义，但当前缺少明确文件内容证据。')
    elif blocked_status and (
        path_signals.get('sensitive_file')
        or any(keyword in lower_url for keyword in strong_surface_keywords)
        or any(keyword in lower_url for keyword in sensitive_keywords)
    ):
        result_level = 'suspicious'
        evidence.append('目录命中敏感路径但被鉴权拦截（{}），当前只能视为待复核入口。'.format(status_code))
    elif missing_status and (
        path_signals.get('sensitive_file')
        or any(keyword in lower_url for keyword in sensitive_keywords)
    ):
        evidence.append('目标路径已返回 {}，当前更像失效路径或常规字典噪声。'.format(status_code))

    if content_length >= 2 * 1024 * 1024 and success_status:
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('响应体积较大（{} 字节），可能存在打包文件暴露。'.format(content_length))
    if surface_signals.get('login_shell'):
        result_level = _cap_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('页面更像登录或认证入口，不支持仅按路径字典命中判定为危险目录暴露。')
    if surface_signals.get('error_page'):
        result_level = _cap_ai_denoise_result_level(result_level, 'safe')
        evidence.append('页面标题更像错误页/占位页，当前缺少真实敏感内容证据。')
    if path_signals.get('static_asset'):
        result_level = _cap_ai_denoise_result_level(result_level, 'safe')
        evidence.append('目标更像静态资源，不宜继续按目录泄露高风险处理。')

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
    surface_signals = _build_surface_signal_summary(url_text, title_text, '')
    path_signals = _build_url_path_signal_summary(url_text)
    parsed_url = urlparse(url_text)
    query_items = []
    try:
        query_items = list(parse_qsl(parsed_url.query, keep_blank_values=True))
    except Exception:
        query_items = []

    dangerous_paths = (
        '/.git', '/swagger', '/v2/api-docs', '/v3/api-docs', '/openapi',
        '/actuator', '/phpinfo', '/heapdump', '/jolokia',
    )
    suspicious_paths = (
        '/login', '/manage', '/console', '/upload', '/download', '/backup', '/test', '/admin'
    )
    credential_param_keys = (
        'token', 'access_token', 'refresh_token', 'apikey', 'api_key',
        'secret', 'signature', 'authorization', 'password', 'passwd',
    )

    result_level = 'safe'
    evidence = []
    success_status = status_code in (200, 201, 206)
    blocked_status = status_code in (401, 403)
    missing_status = status_code in (404, 410)

    credential_param_hit = False
    for key_text, value_text in query_items:
        key_lower = str(key_text or '').strip().lower()
        value_lower = str(value_text or '').strip().lower()
        if key_lower not in credential_param_keys:
            continue
        if len(str(value_text or '').strip()) >= 16 or value_lower.count('.') == 2:
            credential_param_hit = True
            break

    if success_status and (surface_signals.get('api_doc') or surface_signals.get('debug_surface') or any(pattern in lower_url for pattern in dangerous_paths)):
        result_level = _merge_ai_denoise_result_level(result_level, 'danger')
        evidence.append('URL 已成功暴露接口文档、调试面或敏感框架路径。')
    elif success_status and credential_param_hit:
        result_level = _merge_ai_denoise_result_level(result_level, 'danger')
        evidence.append('URL 查询参数中已出现疑似真实凭据或令牌值，应优先确认是否存在泄漏。')
    elif (success_status or blocked_status) and (
        surface_signals.get('admin_surface')
        or surface_signals.get('login_shell')
        or any(pattern in lower_url for pattern in suspicious_paths)
    ):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('URL 更像登录、后台、上传下载或测试入口，建议继续结合认证态与功能实测确认。')

    if surface_signals.get('directory_listing') and success_status:
        result_level = _merge_ai_denoise_result_level(result_level, 'danger')
        evidence.append('页面标题命中目录索引特征，需优先排查目录遍历与文件暴露。')
    if surface_signals.get('login_shell'):
        result_level = _cap_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('页面更像登录壳或认证入口，不能仅凭 admin/debug 等路径语义直接判为危险。')
    if surface_signals.get('error_page') or missing_status:
        result_level = _cap_ai_denoise_result_level(result_level, 'safe')
        evidence.append('URL 当前返回错误页或 {}，缺少可利用暴露证据。'.format(status_code or 404))
    if path_signals.get('static_asset'):
        result_level = _cap_ai_denoise_result_level(result_level, 'safe')
        evidence.append('URL 更像静态资源，默认不纳入高风险 URL 攻击面。')

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


def _rule_analyze_wih_endpoint_item(item):
    target_text = _normalize_item_text(item.get('target') or item.get('site'), 320)
    page_url_text = _normalize_item_text(item.get('page_url'), 900)
    url_text = _normalize_item_text(item.get('url'), 900)
    method_text = str(item.get('method') or 'GET').strip().upper() or 'GET'
    status_code = _safe_int_any(item.get('status_code') or item.get('response_status'), 0)
    response_size = _safe_int_any(item.get('response_size'), 0)
    body_kind = _normalize_item_text(item.get('body_kind'), 80).lower()
    ai_fill_status = _normalize_item_text(item.get('ai_fill_status'), 40).lower()
    ai_fill_source = _normalize_item_text(item.get('ai_fill_source'), 40).lower()
    ai_fill_note = _normalize_item_text(item.get('ai_fill_note'), 240)
    ai_fill_response_summary = _normalize_item_text(item.get('ai_fill_response_summary'), 600)
    ai_fill_hint_only = _safe_bool(item.get('ai_fill_hint_only'), False)
    source_types = _normalize_string_list_value(item.get('source_types'), max_items=8, max_item_len=40)
    request_summary = _extract_wih_endpoint_request_summary(item)
    site_summary = _build_wih_endpoint_site_summary(item)
    response_insights = _build_wih_endpoint_response_insights(item)
    response_semantics = set(response_insights.get('semantics') or [])

    combined_text = ' '.join(
        [
            target_text,
            page_url_text,
            url_text,
            str(site_summary.get('title') or ''),
            ' '.join(site_summary.get('finger') or []),
            ' '.join(request_summary.get('param_names') or []),
            ai_fill_response_summary,
            ai_fill_note,
            response_insights.get('body_excerpt') or '',
            ' '.join(response_insights.get('json_keys') or []),
            ' '.join(response_insights.get('semantic_labels') or []),
        ]
    ).lower()
    param_names_lower = [
        str(name or '').strip().lower()
        for name in list(request_summary.get('param_names') or [])
        if str(name or '').strip()
    ]

    high_path_keywords = (
        'admin', 'manage', 'console', 'config', 'setting', 'tenant', 'role', 'permission',
        'user', 'account', 'profile', 'member', 'staff', 'employee', 'customer',
        'login', 'auth', 'token', 'session', 'sso', 'oauth', 'passwd', 'password',
        'order', 'refund', 'payment', 'pay', 'invoice', 'wallet', 'recharge',
        'upload', 'import', 'export', 'download', 'attachment', 'file',
        'debug', 'actuator', 'swagger', 'api-doc', 'graphql',
    )
    high_param_keywords = (
        'token', 'ticket', 'code', 'password', 'passwd', 'oldpassword', 'newpassword',
        'userid', 'uid', 'roleid', 'tenantid', 'orgid', 'deptid', 'amount', 'price',
        'orderid', 'file', 'filename', 'filepath', 'path', 'redirect', 'callback',
        'mobile', 'phone', 'idcard',
    )
    low_value_keywords = (
        'news', 'notice', 'article', 'content', 'public', 'help', 'doc', 'docs',
        'faq', 'banner', 'captcha', 'health', 'ping', 'static', 'asset', 'menu',
    )

    result_level = 'safe'
    evidence = []

    if method_text in ('POST', 'PUT', 'PATCH', 'DELETE'):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('接口方法为 {}，具备状态修改或提交语义。'.format(method_text))

    if status_code in (401, 403):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('接口返回鉴权状态码 {}，可能位于受保护业务边界。'.format(status_code))

    if any(keyword in combined_text for keyword in high_path_keywords):
        result_level = _merge_ai_denoise_result_level(result_level, 'danger')
        evidence.append('URL、页面或站点上下文命中后台、账号、订单、支付或配置类关键字。')

    if any(keyword in name for name in param_names_lower for keyword in high_param_keywords):
        result_level = _merge_ai_denoise_result_level(result_level, 'danger')
        evidence.append('参数名命中认证、身份、金额、文件或重定向类高价值字段。')

    if body_kind in ('json', 'graphql'):
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
        evidence.append('请求体形态为 {}，更接近真实业务接口。'.format(body_kind))

    if body_kind == 'multipart':
        result_level = _merge_ai_denoise_result_level(result_level, 'danger')
        evidence.append('请求体为 multipart，优先关注上传、导入和解析链路。')

    if ai_fill_status in ('tested', 'filled') and request_summary.get('filled_params'):
        evidence.append(
            'AI填充补齐参数 {} 个：{}。'.format(
                len(request_summary.get('filled_params') or []),
                ', '.join(list(request_summary.get('filled_params') or [])[:8]),
            )
        )
    if ai_fill_response_summary:
        evidence.append('AI填充测试响应摘要：{}。'.format(ai_fill_response_summary))
        if any(keyword in ai_fill_response_summary.lower() for keyword in ('token', 'role', 'user', 'tenant', 'order', 'invoice', 'config', 'upload', 'export')):
            result_level = _merge_ai_denoise_result_level(result_level, 'danger')
    if response_insights.get('status_line'):
        evidence.append('响应状态行：{}。'.format(response_insights.get('status_line')))
    if response_insights.get('semantic_labels'):
        evidence.append('响应语义：{}。'.format('、'.join(response_insights.get('semantic_labels')[:4])))
    if response_insights.get('json_keys'):
        evidence.append('响应字段：{}。'.format(', '.join(list(response_insights.get('json_keys') or [])[:8])))
    if ai_fill_hint_only:
        evidence.append('AI填充判定该接口副作用较高，仅给出提示未主动实测。')
        if method_text in ('DELETE', 'PUT', 'PATCH'):
            result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
    if ai_fill_note and ai_fill_status in ('tested', 'filled', 'hint_only'):
        evidence.append('AI填充说明：{}。'.format(ai_fill_note))
    if ai_fill_source == 'ai':
        evidence.append('该接口参数补全由 AI 结合请求报文与参数语义生成。')

    if site_summary.get('title'):
        evidence.append('关联站点标题：{}。'.format(site_summary.get('title')))
    if site_summary.get('finger'):
        evidence.append('关联站点指纹：{}。'.format('、'.join(list(site_summary.get('finger') or [])[:4])))
    if request_summary.get('param_names'):
        evidence.append(
            '识别到参数 {} 个：{}。'.format(
                len(request_summary.get('param_names') or []),
                ', '.join(list(request_summary.get('param_names') or [])[:8]),
            )
        )
    if response_size > 0:
        evidence.append('接口已有响应指标：状态 {}，大小 {} 字节。'.format(status_code or '-', response_size))
    elif status_code > 0:
        evidence.append('接口已有响应状态：{}。'.format(status_code))
    if 'operation_success' in response_semantics:
        result_level = _merge_ai_denoise_result_level(result_level, 'suspicious')
    if 'sensitive_response' in response_semantics:
        result_level = _merge_ai_denoise_result_level(result_level, 'danger')
    if ('permission_denied' in response_semantics or 'auth_required' in response_semantics) and 'operation_success' not in response_semantics and 'sensitive_response' not in response_semantics:
        result_level = _cap_ai_denoise_result_level(result_level, 'suspicious')
    if 'resource_not_found' in response_semantics and 'operation_success' not in response_semantics and 'sensitive_response' not in response_semantics:
        result_level = _cap_ai_denoise_result_level(result_level, 'safe')
    if 'validation_error' in response_semantics and 'operation_success' not in response_semantics and 'sensitive_response' not in response_semantics:
        result_level = _cap_ai_denoise_result_level(result_level, 'suspicious')
    if source_types:
        evidence.append('来源类型：{}。'.format('、'.join(source_types[:4])))
    if result_level == 'safe' and any(keyword in combined_text for keyword in low_value_keywords):
        evidence.append('更接近内容展示、帮助或健康检查类接口，利用价值较低。')

    if not evidence:
        evidence.append('未发现明显的高价值接口特征。')

    directions = []
    if any(keyword in combined_text for keyword in ('auth', 'login', 'token', 'session', 'user', 'account', 'role', 'permission')):
        directions.append('鉴权/越权')
    if any(keyword in combined_text for keyword in ('order', 'refund', 'payment', 'pay', 'invoice', 'wallet', 'amount', 'price')):
        directions.append('业务逻辑')
    if any(keyword in combined_text for keyword in ('upload', 'import', 'file', 'attachment', 'multipart')):
        directions.append('上传与文件处理')
    if any(keyword in combined_text for keyword in ('export', 'download', 'report')):
        directions.append('敏感数据导出')
    if any(keyword in combined_text for keyword in ('config', 'setting', 'tenant', 'admin', 'manage')):
        directions.append('后台配置变更')
    if any(keyword in combined_text for keyword in ('debug', 'swagger', 'graphql', 'actuator')):
        directions.append('调试面与接口文档')

    dedup_directions = []
    seen_directions = set()
    for direction in directions:
        if direction in seen_directions:
            continue
        seen_directions.add(direction)
        dedup_directions.append(direction)

    suggestions = []
    if result_level == 'danger':
        suggestions.append('建议优先人工复核，先做 {} 方向验证。'.format(' / '.join(dedup_directions[:3]) or '鉴权与业务逻辑'))
        suggestions.append('结合认证态、角色差异和参数变化，验证越权、业务流程绕过或敏感数据读写。')
    elif result_level == 'suspicious':
        suggestions.append('建议纳入下一轮接口优先清单，补充认证态与不同角色访问对比。')
        suggestions.append('优先确认接口是否真实落到业务写操作、导入导出或后台配置链路。')
    else:
        suggestions.append('当前更像通用展示或低敏查询接口，可放入常规巡检队列。')
        suggestions.append('若后续补充到敏感参数、认证上下文或后台指纹，再重新提级。')

    risk_level = '高' if result_level == 'danger' else ('中' if result_level == 'suspicious' else '无')
    display_text = _build_ai_denoise_display_text('wih_endpoint', result_level)
    summary = 'WIH接口价值分析结果：{}。接口：{} {}'.format(display_text, method_text, url_text or '-')
    return {
        'result_level': result_level,
        'risk_level': risk_level,
        'trust': display_text,
        'summary': summary,
        'evidence': evidence[:8],
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

    plg_type_text = _normalize_item_text(item.get('plg_type') or item.get('type'), 120)
    has_verify = bool(verify_text and verify_text != '-')
    verify_signals = _build_verify_signal_summary(verify_text, plg_type_text=plg_type_text)
    strong_verify_signals = list(verify_signals.get('strong_signals') or [])
    weak_verify_signals = list(verify_signals.get('weak_signals') or [])

    # 风险模块规则仅做兜底，不在规则层硬编码“可信”细分逻辑。
    trust = '-'
    if not has_verify:
        trust = '疑似误报'
        result_level = _cap_ai_denoise_result_level(result_level, 'suspicious')
    if target_text in ('', '-'):
        trust = '疑似误报'
        result_level = _cap_ai_denoise_result_level(result_level, 'suspicious')
    if strong_verify_signals:
        trust = '可信'
        if result_level == 'safe':
            result_level = 'suspicious'
    if weak_verify_signals and not strong_verify_signals:
        trust = '疑似误报'
        if 'not_found' in weak_verify_signals or 'network_error' in weak_verify_signals:
            result_level = _cap_ai_denoise_result_level(result_level, 'safe')
        else:
            result_level = _cap_ai_denoise_result_level(result_level, 'suspicious')

    evidence = [
        '风险名称：{}。'.format(vul_name or '-'),
        '风险等级：{}。'.format(risk_level),
    ]
    if plg_type_text and plg_type_text != '-':
        evidence.append('风险类型：{}。'.format(plg_type_text))
    if has_verify:
        evidence.append('存在验证信息，长度 {}。'.format(len(verify_text)))
        if strong_verify_signals:
            evidence.append('验证证据命中强信号：{}。'.format('、'.join(strong_verify_signals[:4])))
        if weak_verify_signals:
            evidence.append('验证证据同时出现弱信号：{}。'.format('、'.join(weak_verify_signals[:4])))
        if verify_signals.get('excerpt'):
            evidence.append('验证证据摘要：{}。'.format(verify_signals.get('excerpt')))
    else:
        evidence.append('缺少明确验证信息（verify_data/credential 为空），已降权为疑似误报。')

    suggestions = []
    if trust == '疑似误报':
        suggestions.extend([
            '建议使用原始插件或手工 PoC 二次复测，确认是否真实可利用。',
            '结合业务鉴权与返回差异补充证据后再定级。',
        ])
    elif strong_verify_signals:
        suggestions.extend([
            '建议优先围绕已命中的验证证据复现，确认影响范围与利用前置条件。',
            '保留原始请求/响应和关键截图，避免后续只剩模板名无法复盘。',
        ])
    else:
        suggestions.extend([
            '建议以扫描阶段 AI 去噪结论作为主判断，规则结果仅作占位参考。',
            '建议补充请求/响应证据后再复测，避免误报影响优先级。',
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
    if module_id == 'wih_endpoint':
        return _rule_analyze_wih_endpoint_item(item)
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


def _format_ai_structured_dialogue_text(parsed_obj):
    if not isinstance(parsed_obj, dict):
        return ''

    result_level_raw = str(parsed_obj.get('result_level') or parsed_obj.get('level') or parsed_obj.get('status') or '').strip().lower()
    result_level_map = {
        'safe': '正常',
        'suspicious': '可疑',
        'danger': '危险',
    }
    result_level_text = result_level_map.get(result_level_raw) or _normalize_item_text(result_level_raw, 24) or '-'
    risk_level_text = _normalize_risk_level_text(parsed_obj.get('risk_level') or parsed_obj.get('severity')) or '-'
    trust_text = _normalize_trust_level_text(parsed_obj.get('trust') or parsed_obj.get('review_status')) or '-'
    summary_text = _normalize_item_text(parsed_obj.get('summary') or parsed_obj.get('analysis'), 600)
    evidence_list = _normalize_string_list_value(
        parsed_obj.get('evidence') if parsed_obj.get('evidence') is not None else parsed_obj.get('basis'),
        max_items=8,
        max_item_len=240
    )
    suggestion_list = _normalize_string_list_value(
        parsed_obj.get('suggestions') if parsed_obj.get('suggestions') is not None else parsed_obj.get('advice'),
        max_items=8,
        max_item_len=240
    )
    finger_result_list = _normalize_string_list_value(
        parsed_obj.get('finger_result') if parsed_obj.get('finger_result') is not None else parsed_obj.get('finger'),
        max_items=10,
        max_item_len=100
    )

    lines = [
        '结论：{}'.format(result_level_text),
        '风险等级：{}'.format(risk_level_text),
        '可信度：{}'.format(trust_text),
    ]
    if summary_text:
        lines.append('摘要：{}'.format(summary_text))

    if evidence_list:
        lines.append('分析依据：')
        for index, item in enumerate(evidence_list):
            lines.append('{}. {}'.format(index + 1, item))

    if suggestion_list:
        lines.append('处置建议：')
        for index, item in enumerate(suggestion_list):
            lines.append('{}. {}'.format(index + 1, item))

    if finger_result_list:
        lines.append('AI修正指纹：')
        for index, item in enumerate(finger_result_list):
            lines.append('{}. {}'.format(index + 1, item))

    return '\n'.join(lines).strip()


def _build_ai_denoise_context(module_id, item):
    if module_id == 'site':
        headers_text = _normalize_header_text(item.get('headers'))
        surface_signals = _build_surface_signal_summary(
            item.get('site') or item.get('url') or item.get('host'),
            item.get('title'),
            headers_text,
        )
        return {
            'site': _normalize_item_text(item.get('site') or item.get('url') or item.get('host'), 1200),
            'title': _normalize_item_text(item.get('title'), 420),
            'status_code': _safe_int_any(item.get('status_code') or item.get('status'), 0),
            'headers': headers_text,
            'body_length': _safe_int_any(item.get('body_length'), 0),
            'http_server': _normalize_item_text(item.get('http_server'), 160),
            'finger': _extract_site_finger_names(item.get('finger')),
            'surface_signals': [key for key, value in dict(surface_signals or {}).items() if value],
        }
    if module_id == 'fileleak':
        surface_signals = _build_surface_signal_summary(item.get('url'), item.get('title'), '')
        path_signals = _build_url_path_signal_summary(item.get('url'))
        return {
            'url': _normalize_item_text(item.get('url'), 1200),
            'title': _normalize_item_text(item.get('title'), 400),
            'status_code': _safe_int_any(item.get('status_code'), 0),
            'content_length': _safe_int_any(item.get('content_length'), 0),
            'source': _normalize_item_text(item.get('source'), 200),
            'file_extension': _normalize_item_text(path_signals.get('extension'), 24),
            'basename': _normalize_item_text(path_signals.get('basename'), 160),
            'surface_signals': [key for key, value in dict(surface_signals or {}).items() if value],
            'path_signals': [
                key for key, value in {
                    'sensitive_file': path_signals.get('sensitive_file'),
                    'static_asset': path_signals.get('static_asset'),
                }.items() if value
            ],
        }
    if module_id == 'url':
        surface_signals = _build_surface_signal_summary(item.get('url'), item.get('title'), '')
        path_signals = _build_url_path_signal_summary(item.get('url'))
        query_params = []
        try:
            parsed = urlparse(str(item.get('url') or '').strip())
            for key_text, _ in parse_qsl(parsed.query, keep_blank_values=True):
                normalized_key = str(key_text or '').strip()
                if normalized_key and normalized_key not in query_params:
                    query_params.append(normalized_key[:80])
                if len(query_params) >= 12:
                    break
        except Exception:
            query_params = []
        return {
            'url': _normalize_item_text(item.get('url'), 1200),
            'title': _normalize_item_text(item.get('title'), 400),
            'status_code': _safe_int_any(item.get('status_code'), 0),
            'content_length': _safe_int_any(item.get('content_length'), 0),
            'source': _normalize_item_text(item.get('source'), 200),
            'file_extension': _normalize_item_text(path_signals.get('extension'), 24),
            'basename': _normalize_item_text(path_signals.get('basename'), 160),
            'query_params': query_params,
            'surface_signals': [key for key, value in dict(surface_signals or {}).items() if value],
            'path_signals': [
                key for key, value in {
                    'sensitive_file': path_signals.get('sensitive_file'),
                    'static_asset': path_signals.get('static_asset'),
                }.items() if value
            ],
        }
    if module_id == 'wih_endpoint':
        request_summary = _extract_wih_endpoint_request_summary(item)
        site_summary = _build_wih_endpoint_site_summary(item)
        response_insights = _build_wih_endpoint_response_insights(item)
        return {
            'target': _normalize_item_text(item.get('target') or item.get('site'), 320),
            'page_url': _normalize_item_text(item.get('page_url'), 900),
            'url': _normalize_item_text(item.get('url'), 900),
            'method': _normalize_item_text(item.get('method'), 20).upper(),
            'status_code': _safe_int_any(item.get('status_code') or item.get('response_status'), 0),
            'response_size': _safe_int_any(item.get('response_size'), 0),
            'content_type': _normalize_item_text(item.get('content_type'), 120),
            'body_kind': _normalize_item_text(item.get('body_kind'), 80),
            'source_types': _normalize_string_list_value(item.get('source_types'), max_items=8, max_item_len=40),
            'param_names': request_summary.get('param_names') or [],
            'query_params': request_summary.get('query_params') or [],
            'body_params': request_summary.get('body_params') or [],
            'path_params': request_summary.get('path_params') or [],
            'filled_params': request_summary.get('filled_params') or [],
            'request_header_names': request_summary.get('header_names') or [],
            'site_title': _normalize_item_text(site_summary.get('title'), 320),
            'site_finger': _normalize_string_list_value(site_summary.get('finger'), max_items=8, max_item_len=80),
            'ai_fill_status': _normalize_item_text(item.get('ai_fill_status'), 40),
            'ai_fill_source': _normalize_item_text(item.get('ai_fill_source'), 40),
            'ai_fill_hint_only': _safe_bool(item.get('ai_fill_hint_only'), False),
            'ai_fill_params': item.get('ai_fill_params') if isinstance(item.get('ai_fill_params'), list) else [],
            'ai_fill_note': _normalize_item_text(item.get('ai_fill_note'), 240),
            'ai_fill_response_summary': _normalize_item_text(item.get('ai_fill_response_summary'), 600),
            'response_source': _normalize_item_text(response_insights.get('source'), 40),
            'response_status_line': _normalize_item_text(response_insights.get('status_line'), 160),
            'response_semantics': _normalize_string_list_value(response_insights.get('semantic_labels'), max_items=8, max_item_len=80),
            'response_json_keys': _normalize_string_list_value(response_insights.get('json_keys'), max_items=12, max_item_len=80),
            'response_body_excerpt': _normalize_item_text(response_insights.get('body_excerpt'), 800),
            'response_packet_excerpt': _normalize_item_text(response_insights.get('packet_excerpt'), 1200),
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
        verify_text = _normalize_item_text(item.get('verify_data') or item.get('credential') or item.get('verify_obj'), 800)
        verify_signals = _build_verify_signal_summary(verify_text, plg_type_text=item.get('plg_type') or item.get('type'))
        return {
            'vul_name': _normalize_item_text(item.get('vul_name'), 260),
            'plg_type': _normalize_item_text(item.get('plg_type'), 120),
            'target': _normalize_item_text(item.get('target'), 420),
            'credential': verify_text,
            'description': _normalize_item_text(item.get('description') or item.get('detail'), 800),
            'proof_type': _normalize_item_text(item.get('proof_type'), 120),
            'proof_strength': _normalize_item_text(item.get('proof_strength'), 80),
            'proof_summary': _normalize_item_text(item.get('proof_summary'), 600),
            'verify_signals': list(verify_signals.get('strong_signals') or [])[:6] + list(verify_signals.get('weak_signals') or [])[:6],
            'save_date': _normalize_item_text(item.get('save_date'), 60),
        }
    if module_id == 'nuclei_result':
        verify_text = _normalize_item_text(item.get('verify_data'), 1200)
        verify_signals = _build_verify_signal_summary(verify_text, plg_type_text=item.get('vuln_name') or item.get('rule_id'))
        return {
            'scanner_type': _normalize_item_text(item.get('scanner_type'), 80),
            'rule_id': _normalize_item_text(item.get('rule_id'), 200),
            'target': _normalize_item_text(item.get('target'), 420),
            'vuln_url': _normalize_item_text(item.get('vuln_url'), 420),
            'vuln_name': _normalize_item_text(item.get('vuln_name'), 260),
            'vuln_severity': _normalize_item_text(item.get('vuln_severity'), 60),
            'verify_data': verify_text,
            'description': _normalize_item_text(item.get('description') or item.get('detail'), 800),
            'proof_type': _normalize_item_text(item.get('proof_type'), 120),
            'proof_strength': _normalize_item_text(item.get('proof_strength'), 80),
            'proof_summary': _normalize_item_text(item.get('proof_summary'), 600),
            'verify_signals': list(verify_signals.get('strong_signals') or [])[:6] + list(verify_signals.get('weak_signals') or [])[:6],
        }
    return {'raw': _normalize_item_text(item, 1800)}


def _try_run_ai_denoise(module_id, item, ai_prompt, active_profile, rule_result, request_delay_ms=0):
    provider_id = _normalize_ai_provider_id(active_profile.get('provider') or 'openai')
    base_url = str(active_profile.get('base_url') or '').strip()
    api_key = str(active_profile.get('api_key') or '').strip()
    proxy_url = str(active_profile.get('proxy') or '').strip()
    request_proxies = _build_ai_proxy_dict(proxy_url)
    model_name = _normalize_ai_model_name(provider_id, active_profile.get('model'))
    profile_name = str(active_profile.get('name') or active_profile.get('id') or '').strip()
    usage_scene = AI_DENOISE_MODULE_SCENE_MAP.get(module_id) or 'ai_denoise'
    timeout_sec = _safe_int(active_profile.get('timeout_sec'), 40, min_value=8)
    request_delay_ms = _safe_int(request_delay_ms, 0, min_value=0)
    if request_delay_ms > 30000:
        request_delay_ms = 30000
    dialogue_records = []
    user_content = ''
    if not base_url or not api_key or not model_name:
        dialogue_records = _normalize_dialogue_records(
            [
                {'role': 'system', 'content': 'AI 去噪详情分析请求被拒绝。'},
                {'role': 'assistant', 'content': '模型配置不完整，无法调用 AI。'},
            ]
        )
        _write_ai_usage_log(
            scene=usage_scene,
            provider=provider_id,
            model=model_name,
            profile=profile_name,
            status='skipped',
            request_text='AI 去噪分析（模型配置不完整）',
            reply_text='',
            error_message='模型配置不完整',
            usage={},
            meta={
                'module_id': module_id,
                'source': 'ai_denoise_detail',
            },
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
    if module_id == 'wih_endpoint':
        user_payload['output_requirement']['format'] = {
            'result_level': 'safe|suspicious|danger',
            'risk_level': '无|中|高',
            'trust': '无价值|中价值|高价值',
            'summary': '一句话价值结论',
            'evidence': ['证据1', '证据2'],
            'suggestions': ['建议1', '建议2'],
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
        def _request_chat_completion(target_model):
            request_payload = dict(request_body)
            request_payload['model'] = str(target_model or '').strip()
            call_started_at = time.perf_counter()
            request_kwargs = {
                'headers': headers,
                'json': request_payload,
                'timeout': (8, timeout_sec),
            }
            if request_proxies:
                request_kwargs['proxies'] = request_proxies
            if request_delay_ms > 0:
                time.sleep(float(request_delay_ms) / 1000.0)
            conn = utils.http_req(request_url, 'post', **request_kwargs)
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
                return (
                    False,
                    '',
                    message,
                    _normalize_ai_usage_dict(payload.get('usage') if isinstance(payload, dict) else {}),
                    _normalize_ai_elapsed_ms(int((time.perf_counter() - call_started_at) * 1000.0)),
                )

            choices = payload.get('choices', []) if isinstance(payload, dict) else []
            message_obj = choices[0].get('message') if isinstance(choices, list) and choices else {}
            content_text = ''
            if isinstance(message_obj, dict):
                content_obj = message_obj.get('content')
                if isinstance(content_obj, str):
                    content_text = content_obj.strip()
                elif isinstance(content_obj, list):
                    text_parts = []
                    for fragment in content_obj:
                        if isinstance(fragment, dict) and str(fragment.get('type') or '').strip() == 'text':
                            text_value = str(fragment.get('text') or '').strip()
                            if text_value:
                                text_parts.append(text_value)
                    content_text = '\n'.join(text_parts).strip()
            usage = _normalize_ai_usage_dict(payload.get('usage') if isinstance(payload, dict) else {})
            return (
                True,
                content_text,
                '',
                usage,
                _normalize_ai_elapsed_ms(int((time.perf_counter() - call_started_at) * 1000.0)),
            )

        call_ok, content_text, call_message, usage, elapsed_ms = _request_chat_completion(model_name)
        if not call_ok and _is_ai_model_unavailable_error(call_message):
            retry_model = _pick_ai_retry_model(provider_id, model_name)
            if retry_model:
                dialogue_records.extend(
                    _normalize_dialogue_records(
                        [
                            {
                                'role': 'system',
                                'content': '模型 {} 不可用，已自动切换为 {} 重试。'.format(model_name, retry_model),
                            }
                        ],
                        max_items=2,
                    )
                )
                retry_ok, retry_content_text, retry_message, retry_usage, retry_elapsed_ms = _request_chat_completion(retry_model)
                if retry_ok:
                    model_name = retry_model
                    call_ok = True
                    content_text = retry_content_text
                    call_message = ''
                    usage = retry_usage
                    elapsed_ms = retry_elapsed_ms
                else:
                    call_ok = False
                    call_message = retry_message
                    usage = retry_usage
                    elapsed_ms = retry_elapsed_ms

        if not call_ok:
            dialogue_records.extend(
                _normalize_dialogue_records(
                    [{'role': 'assistant', 'content': 'AI接口调用失败：{}'.format(call_message)}],
                    max_items=2,
                )
            )
            _write_ai_usage_log(
                scene=usage_scene,
                provider=provider_id,
                model=model_name,
                profile=profile_name,
                status='error',
                request_text=user_content,
                reply_text='',
                error_message=call_message,
                elapsed_ms=elapsed_ms,
                usage=usage,
                meta={
                    'module_id': module_id,
                    'source': 'ai_denoise_detail',
                },
            )
            return None, call_message, dialogue_records

        parsed = _extract_json_object_from_text(content_text)
        if isinstance(parsed, dict):
            parsed_dialogue = _format_ai_structured_dialogue_text(parsed)
            if parsed_dialogue:
                dialogue_records.extend(
                    _normalize_dialogue_records(
                        [{'role': 'assistant', 'content': parsed_dialogue}],
                        max_items=2,
                        max_len=3200,
                    )
                )
            _write_ai_usage_log(
                scene=usage_scene,
                provider=provider_id,
                model=model_name,
                profile=profile_name,
                status='ok',
                request_text=user_content,
                reply_text=content_text,
                error_message='',
                elapsed_ms=elapsed_ms,
                usage=usage,
                meta={
                    'module_id': module_id,
                    'source': 'ai_denoise_detail',
                },
            )
            return parsed, '', dialogue_records

        if content_text:
            dialogue_records.extend(
                _normalize_dialogue_records(
                    [{'role': 'assistant', 'content': content_text}],
                    max_items=2,
                    max_len=3200,
                )
            )

        if not isinstance(parsed, dict):
            format_error = 'AI 返回格式不可解析'
            dialogue_records.extend(
                _normalize_dialogue_records(
                    [{'role': 'assistant', 'content': '{}，回退规则分析。'.format(format_error)}],
                    max_items=2,
                )
            )
            _write_ai_usage_log(
                scene=usage_scene,
                provider=provider_id,
                model=model_name,
                profile=profile_name,
                status='error',
                request_text=user_content,
                reply_text=content_text,
                error_message=format_error,
                elapsed_ms=elapsed_ms,
                usage=usage,
                meta={
                    'module_id': module_id,
                    'source': 'ai_denoise_detail',
                },
            )
            return None, format_error, dialogue_records
        return None, 'AI 返回格式不可解析', dialogue_records
    except Exception as exc:
        message = str(exc)
        dialogue_records.extend(
            _normalize_dialogue_records(
                [{'role': 'assistant', 'content': 'AI请求异常：{}'.format(_truncate_text(message, 240))}],
                max_items=2,
            )
        )
        _write_ai_usage_log(
            scene=usage_scene,
            provider=provider_id,
            model=model_name,
            profile=profile_name,
            status='error',
            request_text=user_content,
            reply_text='',
            error_message=message,
            usage={},
            meta={
                'module_id': module_id,
                'source': 'ai_denoise_detail',
            },
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
    elif module_id == 'wih_endpoint':
        merged['trust'] = _normalize_trust_level_text(ai_output.get('trust') or rule_result.get('trust'))
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


def _analyze_ai_denoise_batch(ai_config, module_id, items, prefer_ai=False, persisted_only=False):
    module_id = str(module_id or '').strip()
    normalized_items = _normalize_ai_denoise_items(items)

    ai_denoise_enable = _safe_bool(ai_config.get('ai_denoise_enable'), True)
    module_flags = _normalize_ai_denoise_modules(ai_config.get('ai_denoise_modules'))
    module_enabled = bool(module_flags.get(module_id, True))
    prompt_templates = _normalize_ai_prompt_templates(ai_config.get('prompt_templates'))
    prompt_ids = _normalize_ai_denoise_prompt_ids(ai_config.get('ai_denoise_prompt_ids'), prompt_templates)
    prompt_id = str(prompt_ids.get(module_id) or '').strip()
    prompt_content = _resolve_ai_prompt_content(prompt_templates, prompt_id, module_id)
    prompt_name = ''
    if prompt_id:
        for template_item in prompt_templates:
            if not isinstance(template_item, dict):
                continue
            if str(template_item.get('id') or '').strip() == prompt_id:
                prompt_name = str(template_item.get('name') or '').strip()
                break
    if not prompt_name:
        prompt_name = '模块默认提示词'

    model_profiles = _normalize_ai_model_profiles(ai_config.get('model_profiles'), legacy_ai_conf=ai_config)
    active_model_profile_id = str(ai_config.get('active_model_profile_id') or '').strip()
    active_profile = _pick_active_ai_model_profile(model_profiles, active_model_profile_id)
    ai_model_ready = bool(
        _safe_bool(ai_config.get('enable'), True)
        and str(active_profile.get('base_url') or '').strip()
        and str(active_profile.get('api_key') or '').strip()
        and str(active_profile.get('model') or '').strip()
    )
    request_delay_ms = _safe_int(ai_config.get('request_delay_ms'), 0, min_value=0)

    # 列表批量分析默认走规则，详情场景（单条）按需尝试模型，避免列表页被外部接口阻塞。
    try_use_ai = bool(
        (not persisted_only)
        and prefer_ai
        and ai_model_ready
        and ai_denoise_enable
        and module_enabled
        and len(normalized_items) <= 3
    )
    now_text = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    task_flag_cache = {}
    task_runtime_status_cache = {}

    if persisted_only:
        _ensure_ai_denoise_result_indexes()

    results = []
    for index, item in enumerate(normalized_items):
        row_key = _extract_row_key(item, index)
        rule_result = _build_ai_denoise_rule_result(module_id, item)
        if module_id == 'wih_endpoint':
            rule_result = _apply_wih_endpoint_response_adjustment(item, rule_result)
        source = 'rule'
        analysis_note = ''
        dialogue_records = _build_rule_dialogue_records(module_id, item, rule_result, note='当前为规则分析模式。')
        task_id = _extract_task_id_from_item(item)
        task_ai_denoise_flag = _resolve_task_ai_denoise_flag(task_id, task_flag_cache)

        if not ai_denoise_enable or not module_enabled:
            disabled_summary = 'AI 去噪功能已关闭，可在 AI 管理中开启后重试。'
            analysis_note = '当前模块或全局 AI 去噪开关关闭，未进入 AI 研判。'
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
                    'prompt_name': prompt_name,
                    'note': analysis_note,
                    'analyzed_at': now_text,
                    'finger_result': _normalize_string_list_value(rule_result.get('finger_result'), max_items=12, max_item_len=80),
                    'dialogue_records': dialogue_records,
                }
            )
            continue

        if task_ai_denoise_flag is None:
            summary_text = '当前资产来自旧任务（未启用 AI 去噪），统一标记为未分析。'
            analysis_note = '当前资产属于历史任务，任务配置中不存在 AI 去噪上下文。'
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
                    'prompt_name': prompt_name,
                    'note': analysis_note,
                    'analyzed_at': now_text,
                    'finger_result': _normalize_string_list_value(rule_result.get('finger_result'), max_items=12, max_item_len=80),
                    'dialogue_records': dialogue_records,
                }
            )
            continue

        if task_ai_denoise_flag is False:
            summary_text = '该任务未开启 AI 去噪，当前资产标记为未分析。'
            analysis_note = '任务创建时未开启 ai_denoise 选项。'
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
                    'prompt_name': prompt_name,
                    'note': analysis_note,
                    'analyzed_at': now_text,
                    'finger_result': _normalize_string_list_value(rule_result.get('finger_result'), max_items=12, max_item_len=80),
                    'dialogue_records': dialogue_records,
                }
            )
            continue

        if persisted_only:
            data_id = _extract_data_id_from_item(item)
            persisted_result = _load_ai_denoise_persisted_result(
                task_id=task_id,
                module_id=module_id,
                row_key=row_key,
                data_id=data_id,
            )
            if isinstance(persisted_result, dict):
                results.append(
                    _build_ai_denoise_result_from_persisted(
                        result_doc=persisted_result,
                        row_key=row_key,
                        module_id=module_id,
                        prompt_id=prompt_id,
                        prompt_name=prompt_name,
                    )
                )
                continue

            runtime_status = _resolve_task_ai_denoise_runtime_status(task_id, task_runtime_status_cache)
            ai_status = str(runtime_status.get('ai_status') or '').strip().lower()
            in_progress = ai_status in ('queued', 'running')
            summary_text = '扫描阶段 AI 去噪结果暂未落库，请稍后刷新。' if in_progress else '当前资产尚未完成 AI 去噪分析。'
            display_text = '分析中' if in_progress else '未分析'
            note_text = (
                '此处仅展示扫描阶段已落库的分析结果，未落库记录不会触发实时 AI 调用。'
                if not in_progress else
                'AI 去噪后台任务正在运行，此处仅展示已落库结果。'
            )
            dialogue_records = _normalize_dialogue_records(
                [
                    {'role': 'system', 'content': '当前为落库结果只读模式。'},
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
                    'display_text': display_text,
                    'summary': summary_text,
                    'evidence': ['未检索到对应 row_key 的 AI 去噪落库记录。'],
                    'suggestions': ['可等待后台 AI 去噪任务完成后刷新查看。'],
                    'source': 'disabled',
                    'prompt_id': prompt_id,
                    'prompt_name': prompt_name,
                    'note': note_text,
                    'analyzed_at': '',
                    'finger_result': [],
                    'dialogue_records': dialogue_records,
                }
            )
            continue

        if not ai_model_ready:
            summary_text = 'AI 模型配置不完整（未配置可用 API Key/Model/BaseURL），当前标记为未分析。'
            analysis_note = 'AI 管理中缺少可用的 API Key / 模型 / 地址配置。'
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
                    'prompt_name': prompt_name,
                    'note': analysis_note,
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
                request_delay_ms=request_delay_ms,
            )
            if ai_output:
                final_result = _normalize_ai_denoise_output(module_id, ai_output, rule_result)
                source = 'ai'
                analysis_note = '当前结果来自扫描阶段 AI 分析并已落库。'
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
                analysis_note = fallback_note or 'AI 未返回有效结构化内容，已回退规则分析。'
                dialogue_records = _build_rule_dialogue_records(module_id, item, final_result, note=fallback_note or 'AI 未返回有效结构化内容，已回退规则分析。')
                if ai_dialogue_records:
                    dialogue_records = _normalize_dialogue_records(
                        (ai_dialogue_records or []) + [
                            {
                                'role': 'system',
                                'content': '已回退为规则结论：{}'.format(final_result.get('display_text') or final_result.get('summary') or '-'),
                            },
                        ]
                    )
        else:
            fallback_note = ''
            if prefer_ai and not ai_model_ready:
                fallback_note = 'AI 模型配置不可用，已回退规则分析。'
            elif not prefer_ai:
                fallback_note = '当前为列表批量分析，默认使用规则模式避免阻塞页面。'
            analysis_note = fallback_note or '当前结果来自规则分析。'
            dialogue_records = _build_rule_dialogue_records(module_id, item, final_result, note=fallback_note)

        if module_id == 'wih_endpoint':
            final_result = _apply_wih_endpoint_response_adjustment(item, final_result)

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
                'prompt_name': prompt_name,
                'note': _normalize_item_text(analysis_note, 260),
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
        'prompt_name': prompt_name,
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


def _build_poc_update_proxy_env(proxy_url: str):
    proxy_text = str(proxy_url or '').strip()
    if not proxy_text:
        return {}

    env_patch = {
        'http_proxy': proxy_text,
        'https_proxy': proxy_text,
        'all_proxy': proxy_text,
        'HTTP_PROXY': proxy_text,
        'HTTPS_PROXY': proxy_text,
        'ALL_PROXY': proxy_text,
    }
    return env_patch


def _run_git_command(git_bin: str, args: list, cwd: Path = None, timeout: int = POC_REPO_UPDATE_TIMEOUT_SEC, env_extra=None):
    """
    执行 git 命令并返回 (rc, stdout, stderr)。
    """
    command = [git_bin] + list(args or [])
    runtime_env = None
    if isinstance(env_extra, dict) and env_extra:
        runtime_env = os.environ.copy()
        runtime_env.update({str(key): str(value) for key, value in env_extra.items() if value is not None})
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=runtime_env,
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


def _sync_poc_repo(repo_type: str, repo_url: str, proxy_url: str = ''):
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
    git_env = _build_poc_update_proxy_env(proxy_url)

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
            env_extra=git_env,
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
            env_extra=git_env,
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
                    env_extra=git_env,
                )
                operations.append('set-origin-url')
            else:
                rc, stdout, stderr = _run_git_command(
                    git_bin,
                    ['remote', 'add', 'origin', repo_url],
                    cwd=repo_dir,
                    timeout=30,
                    env_extra=git_env,
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
            env_extra=git_env,
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
            env_extra=git_env,
        )
        current_branch = str(current_branch or '').strip() if rc == 0 else ''
        if (not current_branch) or current_branch == 'HEAD':
            rc, stdout, stderr = _run_git_command(
                git_bin,
                ['checkout', branch],
                cwd=repo_dir,
                timeout=60,
                env_extra=git_env,
            )
            if rc != 0:
                rc, stdout, stderr = _run_git_command(
                    git_bin,
                    ['checkout', '-b', branch, '--track', 'origin/{}'.format(branch)],
                    cwd=repo_dir,
                    timeout=60,
                    env_extra=git_env,
                )
            operations.append('checkout')
            if rc != 0:
                raise RuntimeError('切换分支失败: {}'.format(stderr or stdout or 'unknown error'))

        rc, stdout, stderr = _run_git_command(
            git_bin,
            ['pull', '--ff-only', 'origin', branch],
            cwd=repo_dir,
            timeout=POC_REPO_UPDATE_TIMEOUT_SEC,
            env_extra=git_env,
        )
        operations.append('pull')
        if rc != 0:
            raise RuntimeError('git pull 失败: {}'.format(stderr or stdout or 'unknown error'))

    head = _collect_repo_head(git_bin, repo_dir)
    if not current_remote:
        rc, stdout, _ = _run_git_command(git_bin, ['remote', 'get-url', 'origin'], cwd=repo_dir, timeout=30, env_extra=git_env)
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
        'proxy': str(proxy_url or '').strip(),
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


def _normalize_service_api_provider(provider: str) -> str:
    return SERVICE_API_PROVIDER_TEST_SERVICE.normalize_provider(provider)


def _normalize_test_target_domain(test_target: str) -> str:
    return SERVICE_API_PROVIDER_TEST_SERVICE.normalize_target(test_target)


def _get_service_api_test_provider_specs():
    return SERVICE_API_PROVIDER_TEST_SERVICE.provider_specs()


def _collect_configured_service_api_providers(service_api: dict):
    return SERVICE_API_PROVIDER_TEST_SERVICE.configured_providers(service_api)


def _build_runtime_service_api_config_for_test(service_api: dict) -> dict:
    return SERVICE_API_PROVIDER_TEST_SERVICE._build_runtime_config(service_api)


def _run_service_api_provider_test(provider: str, service_api: dict, test_target: str):
    return SERVICE_API_PROVIDER_TEST_SERVICE.test_provider(provider, service_api, test_target)


SERVICE_API_PROVIDER_TEST_SERVICE = ServiceApiProviderTestService(
    config=Config,
    service_api_config_service=SERVICE_API_CONFIG_SERVICE,
    utils_module=utils,
    logger=logger,
)


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

        try:
            _, persist_result = CONFIG_DOMAIN_SERVICE.save(
                config_obj,
                validator=_ensure_json_like_config,
            )
            backup_path = persist_result['backup_path']
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
            raw_service_api = SERVICE_API_CONFIG_SERVICE.extract(config_obj)
            service_api, sensitive_configured = SERVICE_API_CONFIG_SERVICE.sanitize(raw_service_api)
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

        try:
            _, config_obj, persist_result = CONFIG_DOMAIN_SERVICE.update(
                service_api,
                merger=lambda current_config, payload: SERVICE_API_CONFIG_SERVICE.merge(
                    current_config,
                    SERVICE_API_CONFIG_SERVICE.fill_missing_sensitive(payload, current_config),
                ),
                validator=_ensure_json_like_config,
            )
            backup_path = persist_result['backup_path']
            raw_saved_service_api = SERVICE_API_CONFIG_SERVICE.extract(config_obj)
            saved_service_api, sensitive_configured = SERVICE_API_CONFIG_SERVICE.sanitize(raw_saved_service_api)
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
            service_api = SERVICE_API_CONFIG_SERVICE.extract(config_obj)
            sensitive_configured = SERVICE_API_CONFIG_SERVICE.sensitive_configured(service_api)
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
            merged_service_api = SERVICE_API_CONFIG_SERVICE.fill_missing_sensitive(service_api, config_obj)
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
            merged_service_api = SERVICE_API_CONFIG_SERVICE.fill_missing_sensitive(service_api, config_obj)
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
            ai_config_raw = AI_CONFIG_SERVICE.extract(config_obj)
            ai_config, sensitive_configured = AI_CONFIG_SERVICE.sanitize(ai_config_raw)
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

        try:
            _, config_obj, persist_result = CONFIG_DOMAIN_SERVICE.update(
                ai_config,
                merger=lambda current_config, payload: AI_CONFIG_SERVICE.merge(
                    current_config,
                    AI_CONFIG_SERVICE.fill_missing_sensitive(payload, current_config),
                ),
                validator=_ensure_json_like_config,
            )
            backup_path = persist_result['backup_path']
            runtime_refreshed = persist_result['runtime_refreshed']
            saved_ai_config_raw = AI_CONFIG_SERVICE.extract(config_obj)
            saved_ai_config, sensitive_configured = AI_CONFIG_SERVICE.sanitize(saved_ai_config_raw)
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
            ai_config_raw = AI_CONFIG_SERVICE.extract(config_obj)
            ai_config, sensitive_configured = AI_CONFIG_SERVICE.sanitize(ai_config_raw)
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
                'message': '已进入 Key 编辑模式。为安全起见，系统不会回传历史明文 Key。',
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
            merged_ai_config = AI_CONFIG_SERVICE.fill_missing_sensitive(ai_config, config_obj)
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


@ns.route('/ai_config/sop/upload/')
class ApiConsoleAiConfigSopUpload(ARLResource):
    """
    AI SOP 上传接口（仅支持 YAML）。
    """

    @auth
    def post(self):
        module_id = str(request.form.get('module_id') or '').strip()
        if module_id not in AI_SOP_MODULE_SCENE_MAP:
            return utils.build_ret(
                ErrorMsg.Error,
                {
                    'error': '不支持的 module_id: {}'.format(module_id),
                }
            )

        upload_file = request.files.get('file')
        if upload_file is None:
            return utils.build_ret(ErrorMsg.Error, {'error': '请上传 SOP 文件（file）'})

        filename = secure_filename(upload_file.filename or '')
        if not filename:
            return utils.build_ret(ErrorMsg.Error, {'error': 'SOP 文件名不能为空'})
        lower_name = filename.lower()
        if not (lower_name.endswith('.yaml') or lower_name.endswith('.yml')):
            return utils.build_ret(ErrorMsg.Error, {'error': '仅支持 .yaml 或 .yml 的 SOP 文件'})

        try:
            sop_payload = _parse_uploaded_ai_sop_yaml(upload_file.read())
        except Exception as exc:
            return utils.build_ret(ErrorMsg.Error, {'error': str(exc)})

        config_path = _resolve_config_path()
        prompt_id = str(AI_SOP_MODULE_PROMPT_ID_MAP.get(module_id) or '').strip()
        scene = str(AI_SOP_MODULE_SCENE_MAP.get(module_id) or '').strip()
        module_label = str(AI_SOP_MODULE_LABEL_MAP.get(module_id) or module_id)
        if not prompt_id:
            return utils.build_ret(ErrorMsg.Error, {'error': '当前模块未配置内置 SOP 模板映射'})
        sop_file = _resolve_ai_prompt_template_file(prompt_id, '')
        now_text = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        def merge_uploaded_sop(current_config, _payload):
            ai_config = AI_CONFIG_SERVICE.extract(current_config)
            prompt_templates = _normalize_ai_prompt_templates(ai_config.get('prompt_templates'))
            ai_denoise_prompt_ids = _normalize_ai_denoise_prompt_ids(
                ai_config.get('ai_denoise_prompt_ids'),
                prompt_templates,
            )

            target_index = None
            for index, item in enumerate(prompt_templates):
                if str(item.get('id') or '').strip() == prompt_id:
                    target_index = index
                    break
            if target_index is None:
                for index, item in enumerate(prompt_templates):
                    if str(item.get('scene') or '').strip() == scene:
                        target_index = index
                        break

            fallback_name = '默认AI-{}'.format(module_label)
            target_item = {
                'id': prompt_id,
                'name': str(sop_payload.get('name') or fallback_name).strip() or fallback_name,
                'scene': scene,
                'content': str(sop_payload.get('content') or '').strip(),
                'updated_at': str(sop_payload.get('updated_at') or now_text).strip() or now_text,
                'file': sop_file,
            }

            if target_index is None:
                prompt_templates.append(target_item)
            else:
                existing_item = prompt_templates[target_index] if isinstance(prompt_templates[target_index], dict) else {}
                prompt_templates[target_index] = {
                    **existing_item,
                    **target_item,
                }

            ai_config['prompt_templates'] = prompt_templates
            if module_id in AI_DENOISE_MODULE_SCENE_MAP:
                ai_denoise_prompt_ids[module_id] = prompt_id
                ai_config['ai_denoise_prompt_ids'] = ai_denoise_prompt_ids

            return AI_CONFIG_SERVICE.merge(current_config, ai_config)

        try:
            _, config_obj, persist_result = CONFIG_DOMAIN_SERVICE.update(
                sop_payload,
                merger=merge_uploaded_sop,
                validator=_ensure_json_like_config,
            )
            backup_path = persist_result['backup_path']
            runtime_refreshed = persist_result['runtime_refreshed']
            saved_ai_config_raw = AI_CONFIG_SERVICE.extract(config_obj)
            saved_ai_config, sensitive_configured = AI_CONFIG_SERVICE.sanitize(saved_ai_config_raw)
        except Exception as exc:
            logger.exception('upload ai sop failed module:%s err:%s', module_id, exc)
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
                'uploaded': True,
                'module_id': module_id,
                'module_label': module_label,
                'prompt_id': prompt_id,
                'sop_file': sop_file,
                'saved_at': now_text,
                'backup_path': backup_path,
                'runtime_refreshed': runtime_refreshed,
                'ai_config': saved_ai_config,
                'sensitive_configured': sensitive_configured,
                'provider_presets': AI_PROVIDER_PRESETS,
                'config_path': str(config_path),
            }
        )


@ns.route('/ai_usage/stats/')
class ApiConsoleAiUsageStats(ARLResource):
    """
    AI Token 用量统计接口。
    """

    @auth
    def get(self):
        now = datetime.now()
        window_days = _safe_int_any(request.args.get('days'), 7)
        if window_days <= 0:
            window_days = 7
        if window_days > 90:
            window_days = 90

        day_1_query = {'created_at': {'$gte': now - timedelta(days=1)}}
        day_7_query = {'created_at': {'$gte': now - timedelta(days=7)}}
        window_query = {'created_at': {'$gte': now - timedelta(days=window_days)}}

        all_time = _aggregate_ai_usage_stats()
        last_24h = _aggregate_ai_usage_stats(day_1_query)
        last_7d = _aggregate_ai_usage_stats(day_7_query)

        by_model = []
        by_scene = []
        avg_elapsed_ms = 0
        avg_elapsed_sample_count = 0
        top_error_reasons = []
        try:
            by_model_pipeline = [
                {'$match': window_query},
                {
                    '$group': {
                        '_id': {
                            'provider': {'$ifNull': ['$provider', '']},
                            'model': {'$ifNull': ['$model', '']},
                        },
                        'request_count': {'$sum': 1},
                        'success_count': {'$sum': {'$cond': [{'$eq': ['$status', 'ok']}, 1, 0]}},
                        'error_count': {'$sum': {'$cond': [{'$eq': ['$status', 'error']}, 1, 0]}},
                        'skip_count': {'$sum': {'$cond': [{'$eq': ['$status', 'skipped']}, 1, 0]}},
                        'prompt_tokens': {'$sum': {'$ifNull': ['$usage.prompt_tokens', 0]}},
                        'completion_tokens': {'$sum': {'$ifNull': ['$usage.completion_tokens', 0]}},
                        'total_tokens': {'$sum': {'$ifNull': ['$usage.total_tokens', 0]}},
                    }
                },
                {'$sort': {'total_tokens': -1, 'request_count': -1}},
                {'$limit': 12},
            ]
            by_model_items = list(utils.conn_db(AI_USAGE_LOG_COLLECTION).aggregate(by_model_pipeline))
            for item in by_model_items:
                identity = item.get('_id') if isinstance(item, dict) else {}
                stats_value = _normalize_ai_usage_stats_value(item)
                by_model.append(
                    {
                        'provider': str((identity or {}).get('provider') or '-'),
                        'model': str((identity or {}).get('model') or '-'),
                        **stats_value,
                    }
                )
        except Exception as exc:
            logger.warning('aggregate ai usage by_model failed: %s', exc)

        try:
            by_scene_pipeline = [
                {'$match': window_query},
                {
                    '$group': {
                        '_id': {'$ifNull': ['$scene', '']},
                        'request_count': {'$sum': 1},
                        'success_count': {'$sum': {'$cond': [{'$eq': ['$status', 'ok']}, 1, 0]}},
                        'error_count': {'$sum': {'$cond': [{'$eq': ['$status', 'error']}, 1, 0]}},
                        'skip_count': {'$sum': {'$cond': [{'$eq': ['$status', 'skipped']}, 1, 0]}},
                        'prompt_tokens': {'$sum': {'$ifNull': ['$usage.prompt_tokens', 0]}},
                        'completion_tokens': {'$sum': {'$ifNull': ['$usage.completion_tokens', 0]}},
                        'total_tokens': {'$sum': {'$ifNull': ['$usage.total_tokens', 0]}},
                    }
                },
                {'$sort': {'total_tokens': -1, 'request_count': -1}},
                {'$limit': 20},
            ]
            by_scene_items = list(utils.conn_db(AI_USAGE_LOG_COLLECTION).aggregate(by_scene_pipeline))
            for item in by_scene_items:
                scene = str(item.get('_id') or '').strip()
                stats_value = _normalize_ai_usage_stats_value(item)
                by_scene.append(
                    {
                        'scene': scene,
                        'scene_label': _normalize_ai_usage_scene_label(scene),
                        **stats_value,
                    }
                )
        except Exception as exc:
            logger.warning('aggregate ai usage by_scene failed: %s', exc)

        try:
            elapsed_pipeline = [
                {'$match': {'created_at': {'$gte': now - timedelta(days=window_days)}, 'status': {'$in': ['ok', 'error']}, 'elapsed_ms': {'$gt': 0}}},
                {
                    '$group': {
                        '_id': None,
                        'avg_elapsed_ms': {'$avg': '$elapsed_ms'},
                        'sample_count': {'$sum': 1},
                    }
                },
            ]
            elapsed_items = list(utils.conn_db(AI_USAGE_LOG_COLLECTION).aggregate(elapsed_pipeline))
            if elapsed_items:
                elapsed_item = elapsed_items[0] if isinstance(elapsed_items[0], dict) else {}
                avg_elapsed_ms = _normalize_ai_elapsed_ms(round(float(elapsed_item.get('avg_elapsed_ms') or 0)))
                avg_elapsed_sample_count = _normalize_ai_usage_value(elapsed_item.get('sample_count'))
        except Exception as exc:
            logger.warning('aggregate ai usage elapsed failed: %s', exc)

        try:
            reason_counter = Counter()
            error_query = {'created_at': {'$gte': now - timedelta(days=window_days)}, 'status': 'error'}
            error_cursor = utils.conn_db(AI_USAGE_LOG_COLLECTION).find(
                error_query,
                {'error_reason': 1, 'error_message': 1},
            ).limit(5000)
            for item in error_cursor:
                if not isinstance(item, dict):
                    continue
                reason = _normalize_ai_error_reason(item.get('error_reason') or item.get('error_message')) or '未知错误'
                reason_counter[reason] += 1
            top_error_reasons = [
                {'reason': reason, 'count': count}
                for reason, count in reason_counter.most_common(3)
            ]
        except Exception as exc:
            logger.warning('aggregate ai usage top_error_reasons failed: %s', exc)

        return utils.build_ret(
            ErrorMsg.Success,
            {
                'all_time': all_time,
                'last_24h': last_24h,
                'last_7d': last_7d,
                'by_model': by_model,
                'by_scene': by_scene,
                'avg_elapsed_ms': avg_elapsed_ms,
                'avg_elapsed_sample_count': avg_elapsed_sample_count,
                'top_error_reasons': top_error_reasons,
                'window_days': window_days,
                'updated_at': now.strftime('%Y-%m-%d %H:%M:%S'),
            },
        )


@ns.route('/ai_usage/logs/')
class ApiConsoleAiUsageLogs(ARLResource):
    """
    AI 对话日志查询接口。
    """

    @auth
    def get(self):
        limit = _safe_int_any(request.args.get('limit'), 80)
        if limit <= 0:
            limit = 80
        if limit > AI_USAGE_LOG_MAX_LIMIT:
            limit = AI_USAGE_LOG_MAX_LIMIT

        status = str(request.args.get('status') or '').strip().lower()
        scene = str(request.args.get('scene') or '').strip()
        provider = str(request.args.get('provider') or '').strip()
        model = str(request.args.get('model') or '').strip()

        query = {}
        if status in ('ok', 'error', 'skipped'):
            query['status'] = status
        if scene:
            query['scene'] = scene
        if provider:
            query['provider'] = provider
        if model:
            query['model'] = model

        items = []
        total = 0
        try:
            cursor = utils.conn_db(AI_USAGE_LOG_COLLECTION).find(query).sort([('_id', -1)]).limit(limit)
            items = [_serialize_ai_usage_log_record(item) for item in cursor]
            total = utils.conn_db(AI_USAGE_LOG_COLLECTION).count_documents(query)
        except Exception as exc:
            logger.warning('load ai usage logs failed: %s', exc)

        scene_candidates = list(AI_USAGE_SCENE_LABEL_MAP.keys())
        try:
            scene_values = utils.conn_db(AI_USAGE_LOG_COLLECTION).distinct('scene') or []
            for raw_scene in scene_values:
                scene_text = str(raw_scene or '').strip()
                if not scene_text:
                    continue
                if scene_text not in scene_candidates:
                    scene_candidates.append(scene_text)
        except Exception as exc:
            logger.warning('load ai usage scene candidates failed: %s', exc)

        available_scenes = [
            {
                'scene': scene_item,
                'scene_label': _normalize_ai_usage_scene_label(scene_item),
            }
            for scene_item in scene_candidates
        ]

        return utils.build_ret(
            ErrorMsg.Success,
            {
                'items': items,
                'total': total,
                'limit': limit,
                'status': status,
                'scene': scene,
                'provider': provider,
                'model': model,
                'available_scenes': available_scenes,
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            },
        )


@ns.route('/ai_denoise/analyze/')
class ApiConsoleAiDenoiseAnalyze(ARLResource):
    """
    AI 去噪分析接口（详情仅展示已分析结果，不再触发实时 AI 调用）。
    """

    @auth
    @ns.expect(analyze_ai_denoise_fields)
    def post(self):
        payload = request.get_json(silent=True) or {}
        module_id = str(payload.get('module_id') or '').strip()
        raw_items = payload.get('items')
        prefer_ai_requested = _safe_bool(payload.get('prefer_ai'), False)
        # 2026-03-25 起，为避免“点击详情触发实时模型调用”，此接口统一关闭 prefer_ai。
        prefer_ai = False

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
            ai_config = AI_CONFIG_SERVICE.extract(config_obj)
            result = _analyze_ai_denoise_batch(
                ai_config=ai_config,
                module_id=module_id,
                items=raw_items,
                prefer_ai=prefer_ai,
                persisted_only=True,
            )
            result['config_path'] = str(config_path)
            result['item_count'] = len(result.get('items') or [])
            result['prefer_ai_requested'] = bool(prefer_ai_requested)
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
            scan_config = SCAN_CONFIG_SERVICE.extract(config_obj)
            active_scan_profile = str(scan_config.get('scan_profile_id', '') or '')
            domain_options = _collect_domain_dict_options(scan_config.get('domain_dict'))
            file_leak_options = _collect_file_leak_dict_options(scan_config.get('file_leak_dict'))
            return utils.build_ret(
                ErrorMsg.Success,
                {
                    'scan_config': scan_config,
                    'active_scan_profile': active_scan_profile,
                    'scan_profiles': SCAN_CONFIG_SERVICE.build_profiles_payload(active_scan_profile),
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

        try:
            _, config_obj, persist_result = CONFIG_DOMAIN_SERVICE.update(
                scan_config,
                merger=SCAN_CONFIG_SERVICE.merge,
                validator=_ensure_json_like_config,
            )
            backup_path = persist_result['backup_path']
            saved_scan_config = SCAN_CONFIG_SERVICE.extract(config_obj)
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
                'scan_profiles': SCAN_CONFIG_SERVICE.build_profiles_payload(active_scan_profile),
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
            with POC_UPDATE_LOCK:
                update_info = _sync_poc_repo(
                    'nuclei',
                    NUCLEI_TEMPLATE_REPO_URL,
                    proxy_url=str(getattr(Config, 'POC_UPDATE_PROXY', '') or '').strip(),
                )
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
            with POC_UPDATE_LOCK:
                update_info = _sync_poc_repo(
                    'afrog',
                    AFROG_POC_REPO_URL,
                    proxy_url=str(getattr(Config, 'POC_UPDATE_PROXY', '') or '').strip(),
                )
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
