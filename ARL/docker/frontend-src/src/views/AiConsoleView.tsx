import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Eye,
  Key,
  Play,
  RefreshCw,
  Settings,
  Upload,
  X,
} from 'lucide-react';
import { USERNAME_KEY, requestApi } from '../api/client';
import { SensitiveRevealVerifyModal } from '../components/domain/SensitiveRevealVerifyModal';
import { Modal } from '../components/ui/Modal';
import { DataTable } from '../components/ui/DataTable';
import type {AiDenoiseModuleId} from '../domain/types';
import {
  CONSOLE_CHECKBOX_CARD_CLASS,
  CONSOLE_INPUT_CLASS,
  CONSOLE_INPUT_MONO_CLASS,
  CONSOLE_SELECT_CLASS,
  CONSOLE_TEXTAREA_MONO_CLASS,
} from '../ui/classes';

export function ConfigAiManagementPanel({ token }: { token: string }) {
  type AiProviderPreset = {
    id: string;
    label: string;
    base_url?: string;
    default_model?: string;
    default_reasoning_model?: string;
  };

  type AiCustomCompatProvider = {
    id: string;
    name: string;
    base_url: string;
    model: string;
  };

  type AiPromptTemplate = {
    id: string;
    name: string;
    scene: string;
    content: string;
    updated_at: string;
    file?: string;
  };

  type AiModelProfile = {
    id: string;
    name: string;
    provider: string;
    base_url: string;
    api_key: string;
    model: string;
    reasoning_model: string;
    proxy: string;
    timeout_sec: number;
    temperature: number;
    max_tokens: number;
  };

  type AiDenoiseModuleId = 'site' | 'fileleak' | 'cert' | 'url' | 'wih_endpoint' | 'vuln' | 'nuclei_result';
  type AiSopModuleId = AiDenoiseModuleId | 'wih_endpoint_fill';

  type AiDenoiseModules = Record<AiDenoiseModuleId, boolean>;
  type AiDenoisePromptIds = Record<AiDenoiseModuleId, string>;

  type AiConfigForm = {
    enable: boolean;
    active_model_profile_id: string;
    model_profiles: AiModelProfile[];
    provider: string;
    custom_provider_name: string;
    base_url: string;
    api_key: string;
    model: string;
    proxy_url: string;
    timeout_sec: number;
    temperature: number;
    max_tokens: number;
    dialog_system_prompt: string;
    dialog_style: string;
    dialog_language: string;
    dialog_context_messages: number;
    request_delay_ms: number;
    wih_endpoint_ai_fill_max_targets: number;
    active_prompt_id: string;
    prompt_templates: AiPromptTemplate[];
    custom_compat_providers: AiCustomCompatProvider[];
    ai_denoise_enable: boolean;
    ai_wih_endpoint_fill_enable: boolean;
    ai_denoise_modules: AiDenoiseModules;
    ai_denoise_prompt_ids: AiDenoisePromptIds;
  };

  type AiTestResult = {
    ok: boolean;
    message: string;
    provider?: string;
    profile?: string;
    model?: string;
    request_text?: string;
    reply_text?: string;
    tested_at?: string;
    detail?: string;
  };

  type AiUsageStats = {
    request_count: number;
    success_count: number;
    error_count: number;
    skip_count: number;
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };

  type AiUsageByDimensionItem = AiUsageStats & {
    provider?: string;
    model?: string;
    scene?: string;
    scene_label?: string;
  };

  type AiUsageErrorReasonItem = {
    reason: string;
    count: number;
  };

  type AiUsageStatsPayload = {
    all_time: AiUsageStats;
    last_24h: AiUsageStats;
    last_7d: AiUsageStats;
    by_model: AiUsageByDimensionItem[];
    by_scene: AiUsageByDimensionItem[];
    avg_elapsed_ms: number;
    avg_elapsed_sample_count: number;
    top_error_reasons: AiUsageErrorReasonItem[];
    window_days: number;
    updated_at: string;
  };

  type AiUsageLogItem = {
    id: string;
    created_at: string;
    scene: string;
    scene_label: string;
    provider: string;
    model: string;
    profile: string;
    status: 'ok' | 'error' | 'skipped';
    request_text: string;
    reply_text: string;
    error_message: string;
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };

  const defaultProviderPresets: AiProviderPreset[] = [
    { id: 'qwen', label: '通义千问', base_url: 'https://dashscope.aliyuncs.com/compatible-mode/v1', default_model: 'qwen-plus', default_reasoning_model: 'qwen-plus' },
    { id: 'kimi', label: 'Kimi', base_url: 'https://api.moonshot.cn/v1', default_model: 'moonshot-v1-8k', default_reasoning_model: 'moonshot-v1-8k' },
    { id: 'openai', label: 'OpenAI-GPT', base_url: 'https://api.openai.com/v1', default_model: 'gpt-4o-mini', default_reasoning_model: 'gpt-4o-mini' },
    { id: 'glm', label: '智谱 GLM', base_url: 'https://open.bigmodel.cn/api/paas/v4', default_model: 'glm-4-flash', default_reasoning_model: 'glm-4-flash' },
    { id: 'deepseek', label: 'DeepSeek', base_url: 'https://api.deepseek.com/v1', default_model: 'deepseek-chat', default_reasoning_model: 'DeepSeek-R1' },
    { id: 'custom_compatible', label: 'OpenAI 兼容接口', base_url: '', default_model: '', default_reasoning_model: '' },
  ];

  const defaultPromptTemplates: AiPromptTemplate[] = [
    {
      id: 'default_ai_report',
      name: '默认AI报告模板',
      scene: 'ai_report_export',
      content:
        '你是互联网资产自动化收集系统的安全分析助手。请基于输入数据输出结构化研判：任务概览、关键资产、风险聚类、疑似误报、优先修复建议、复测建议。要求结论可执行、避免夸大风险、避免输出不存在的数据。',
      updated_at: '',
      file: 'ai/sop/default_ai_report.yaml',
    },
    {
      id: 'default_fp_review',
      name: '默认误报复核模板',
      scene: 'false_positive_review',
      content:
        '你是安全误报复核助手。请根据规则命中、上下文证据、影响面和可复现性进行评分，输出 pass/suspected_fp/manual_review 三档。',
      updated_at: '',
      file: 'ai/sop/default_fp_review.yaml',
    },
    {
      id: 'default_ai_denoise_site',
      name: '默认AI去噪-站点',
      scene: 'ai_denoise_site',
      content:
        '你是渗透测试前置研判助手。请基于站点URL、标题、响应头、状态码与指纹信息，判断该站点是否值得优先进入渗透测试，并输出：1) 正常/可疑/危险结论；2) 最可能真实的技术栈/指纹（过滤明显误报）；3) 可直接执行的验证建议（如目录探测、认证边界测试、WAF绕过前置检查）。不要仅因标题包含后台、管理、swagger等关键词就直接判危险；缺少实证时优先给可疑。禁止编造不存在的信息。',
      updated_at: '',
      file: 'ai/sop/default_ai_denoise_site.yaml',
    },
    {
      id: 'default_ai_denoise_fileleak',
      name: '默认AI去噪-目录扫描',
      scene: 'ai_denoise_fileleak',
      content:
        '你是目录扫描去噪与渗透准备助手。请基于URL路径、状态码、标题、响应体长度判断：正常/可疑/危险，并补充后续渗透验证优先级：1) 是否存在可利用入口（备份/配置/调试/上传）；2) 建议先做哪类验证（鉴权绕过、目录遍历、文件读取、上传执行）；3) 给出2-3条可操作的验证建议。若仅命中敏感路径但返回401/403/404、空页面或普通错误页，不要直接判危险。禁止夸大风险，证据不足时明确标注待复核。',
      updated_at: '',
      file: 'ai/sop/default_ai_denoise_fileleak.yaml',
    },
    {
      id: 'default_ai_denoise_cert',
      name: '默认AI去噪-SSL证书',
      scene: 'ai_denoise_cert',
      content:
        '你是证书与传输安全评估助手。请基于证书有效期、签发信息、协议与套件特征，输出结论并判断对渗透测试阶段的影响：1) 是否存在弱协议/弱套件可用于降级或中间人相关测试前置；2) 证书到期与配置缺陷是否影响攻击面稳定性；3) 给出优先整改建议与验证步骤。',
      updated_at: '',
      file: 'ai/sop/default_ai_denoise_cert.yaml',
    },
    {
      id: 'default_ai_denoise_url',
      name: '默认AI去噪-URL信息',
      scene: 'ai_denoise_url',
      content:
        '你是URL攻击面去噪助手。请基于URL路径、参数、状态码、标题与上下文，输出安全/可疑/危险结论，并围绕渗透测试准备给出：1) 该URL属于登录、管理、调试、接口还是静态资源；2) 是否值得进一步测试（鉴权、越权、注入、文件读取、重定向等）；3) 明确下一步验证建议与优先级。不要只因URL包含admin、debug、swagger、token等关键词就直接判危险；缺少成功访问或敏感反馈时优先给可疑。',
      updated_at: '',
      file: 'ai/sop/default_ai_denoise_url.yaml',
    },
    {
      id: 'default_ai_denoise_wih_endpoint',
      name: '默认AI去噪-WIH接口',
      scene: 'ai_denoise_wih_endpoint',
      content:
        '你是WIH结构化接口价值分析助手。请基于站点信息、页面URL、接口URL、HTTP方法、参数名、AI填充后的参数类型、请求体形态、状态码、响应大小、响应语义、响应字段和回复报文摘要，输出高价值/中价值/无价值结论，并给出关键证据与优先验证方向。必须优先使用回复报文做校正：若响应明确为未登录、权限不足、访问被拒绝、资源不存在、参数校验失败，不要仅因POST或import/admin路径就直接判高价值；只有响应体现真实业务成功、敏感字段、用户/租户/权限信息、导出地址等证据时，才可提级为高价值。',
      updated_at: '',
      file: 'ai/sop/default_ai_denoise_wih_endpoint.yaml',
    },
    {
      id: 'default_ai_fill_wih_endpoint',
      name: '默认AI填充-WIH接口',
      scene: 'ai_fill_wih_endpoint',
      content:
        '你是WIH接口参数补全助手。请基于站点信息、页面URL、接口URL、HTTP方法、请求报文、请求模板、Content-Type、参数名和已有参数值，补全尽可能可用、类型正确、低副作用的参数值，并返回是否适合自动测试。DELETE、PUT、PATCH、TRACE、CONNECT及上传/二进制等高风险请求只允许给出提示，不建议自动实测。仅输出JSON对象。',
      updated_at: '',
      file: 'ai/sop/default_ai_fill_wih_endpoint.yaml',
    },
    {
      id: 'default_ai_denoise_vuln',
      name: '默认AI去噪-风险',
      scene: 'ai_denoise_vuln',
      content:
        '你是漏洞结果复核助手。请根据风险等级、目标、验证证据与规则上下文判断：可信/疑似误报，并从渗透测试视角输出：1) 哪些漏洞应优先复测；2) 复测前置条件与利用链关键点；3) 若疑似误报，给出最小复核路径。必须优先参考验证证据和命中URL，若只有模板名称或风险等级、没有利用证据，不要直接判高可信。',
      updated_at: '',
      file: 'ai/sop/default_ai_denoise_vuln.yaml',
    },
    {
      id: 'default_ai_denoise_poc',
      name: '默认AI去噪-PoC风险',
      scene: 'ai_denoise_nuclei_result',
      content:
        '你是PoC命中结果复核助手。请结合扫描器、规则ID、风险等级、命中URL与验证信息判断可信度，并输出渗透测试可执行建议：1) 是否值得人工复现；2) 复现路径与关键请求点；3) 哪些结果应降权为疑似误报。',
      updated_at: '',
      file: 'ai/sop/default_ai_denoise_poc.yaml',
    },
  ];

  const aiDenoiseModuleConfigs: Array<{
    id: AiDenoiseModuleId;
    label: string;
    scene: string;
  }> = [
    { id: 'site', label: '站点', scene: 'ai_denoise_site' },
    { id: 'fileleak', label: '目录扫描', scene: 'ai_denoise_fileleak' },
    { id: 'cert', label: 'SSL证书', scene: 'ai_denoise_cert' },
    { id: 'url', label: 'URL信息', scene: 'ai_denoise_url' },
    { id: 'wih_endpoint', label: 'WIH接口', scene: 'ai_denoise_wih_endpoint' },
    { id: 'vuln', label: '风险', scene: 'ai_denoise_vuln' },
    { id: 'nuclei_result', label: 'PoC风险', scene: 'ai_denoise_nuclei_result' },
  ];
  const aiSopModuleConfigs: Array<{
    id: AiSopModuleId;
    label: string;
    scene: string;
  }> = [
    ...aiDenoiseModuleConfigs,
    { id: 'wih_endpoint_fill', label: 'WIH接口AI填充', scene: 'ai_fill_wih_endpoint' },
  ];

  const defaultAiDenoiseModules: AiDenoiseModules = {
    site: true,
    fileleak: true,
    cert: true,
    url: true,
    wih_endpoint: true,
    vuln: true,
    nuclei_result: true,
  };

  const normalizeProviderId = (rawProvider: any) => {
    const value = String(rawProvider || '').trim().toLowerCase();
    const aliases: Record<string, string> = {
      tongyi: 'qwen',
      qianwen: 'qwen',
      moonshot: 'kimi',
      openai_compatible: 'custom_compatible',
      compatible: 'custom_compatible',
    };
    return aliases[value] || value || 'openai';
  };

  const buildPromptId = (rawText: string, fallbackIndex: number) => {
    const normalized = String(rawText || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_]+/g, '_')
      .replace(/^_+|_+$/g, '');
    return normalized || `prompt_${fallbackIndex}`;
  };

  const buildModelProfileId = (rawText: string, fallbackIndex: number) => {
    const normalized = String(rawText || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_]+/g, '_')
      .replace(/^_+|_+$/g, '');
    return normalized || `model_${fallbackIndex}`;
  };

  const normalizeModelProfiles = (rawProfiles: any, legacyRawForm?: any): AiModelProfile[] => {
    const items: AiModelProfile[] = [];
    const seen = new Set<string>();

    if (Array.isArray(rawProfiles)) {
      rawProfiles.forEach((item: any, index: number) => {
        const id = buildModelProfileId(String(item?.id || item?.name || `model_${index + 1}`), index + 1);
        if (seen.has(id)) return;
        seen.add(id);
        const provider = normalizeProviderId(item?.provider);
        const preset = defaultProviderPresets.find((entry) => entry.id === provider);
        const timeoutSec = Number(item?.timeout_sec ?? 40);
        const maxTokens = Number(item?.max_tokens ?? 4000);
        const temperature = Number(item?.temperature ?? 0.2);
        items.push({
          id,
          name: String(item?.name || id),
          provider,
          base_url: String(item?.base_url || '').trim() || String(preset?.base_url || ''),
          api_key: String(item?.api_key || ''),
          model: String(item?.model || '').trim() || String(preset?.default_model || ''),
          reasoning_model: String(item?.reasoning_model || '').trim() || String(preset?.default_reasoning_model || item?.model || preset?.default_model || ''),
          proxy: String(item?.proxy || item?.proxy_url || '').trim(),
          timeout_sec: Number.isFinite(timeoutSec) && timeoutSec > 0 ? timeoutSec : 40,
          temperature: Number.isFinite(temperature) && temperature >= 0 ? temperature : 0.2,
          max_tokens: Number.isFinite(maxTokens) && maxTokens > 0 ? maxTokens : 4000,
        });
      });
    }

    if (items.length > 0) {
      return items;
    }

    const fallbackProvider = normalizeProviderId(legacyRawForm?.provider || 'openai');
    const fallbackPreset = defaultProviderPresets.find((entry) => entry.id === fallbackProvider);
    const timeoutSec = Number(legacyRawForm?.timeout_sec ?? 40);
    const maxTokens = Number(legacyRawForm?.max_tokens ?? 4000);
    const temperature = Number(legacyRawForm?.temperature ?? 0.2);
    return [
      {
        id: 'default_model',
        name: '默认模型',
        provider: fallbackProvider,
        base_url: String(legacyRawForm?.base_url || '').trim() || String(fallbackPreset?.base_url || ''),
        api_key: String(legacyRawForm?.api_key || ''),
        model: String(legacyRawForm?.model || '').trim() || String(fallbackPreset?.default_model || ''),
        reasoning_model: String(legacyRawForm?.reasoning_model || '').trim() || String(fallbackPreset?.default_reasoning_model || legacyRawForm?.model || fallbackPreset?.default_model || ''),
        proxy: String(legacyRawForm?.proxy_url || legacyRawForm?.proxy || '').trim(),
        timeout_sec: Number.isFinite(timeoutSec) && timeoutSec > 0 ? timeoutSec : 40,
        temperature: Number.isFinite(temperature) && temperature >= 0 ? temperature : 0.2,
        max_tokens: Number.isFinite(maxTokens) && maxTokens > 0 ? maxTokens : 4000,
      },
    ];
  };

  const normalizePromptTemplates = (rawTemplates: any): AiPromptTemplate[] => {
    if (!Array.isArray(rawTemplates) || rawTemplates.length === 0) {
      return [...defaultPromptTemplates];
    }

    const items: AiPromptTemplate[] = [];
    const seen = new Set<string>();
    rawTemplates.forEach((item: any, index: number) => {
      const fallbackId = `prompt_${index + 1}`;
      const id = buildPromptId(String(item?.id || item?.name || fallbackId), index + 1);
      if (seen.has(id)) return;
      const content = String(item?.content || '').trim();
      const file = String(item?.file || '').trim();
      if (!content && !file) return;
      seen.add(id);
      items.push({
        id,
        name: String(item?.name || id),
        scene: String(item?.scene || 'ai_report_export') || 'ai_report_export',
        content,
        updated_at: String(item?.updated_at || ''),
        file,
      });
    });

    return items.length > 0 ? items : [...defaultPromptTemplates];
  };

  const normalizeCustomCompatProviders = (rawProviders: any): AiCustomCompatProvider[] => {
    if (!Array.isArray(rawProviders)) return [];
    const items: AiCustomCompatProvider[] = [];
    const seen = new Set<string>();
    rawProviders.forEach((item: any, index: number) => {
      const id = buildPromptId(String(item?.id || item?.name || `custom_${index + 1}`), index + 1);
      if (seen.has(id)) return;
      seen.add(id);
      items.push({
        id,
        name: String(item?.name || id),
        base_url: String(item?.base_url || ''),
        model: String(item?.model || ''),
      });
    });
    return items;
  };

  const normalizeAiDenoiseModules = (rawModules: any): AiDenoiseModules => {
    const source = rawModules && typeof rawModules === 'object' ? rawModules : {};
    return {
      site: source.site !== false,
      fileleak: source.fileleak !== false,
      cert: source.cert !== false,
      url: source.url !== false,
      wih_endpoint: source.wih_endpoint !== false,
      vuln: source.vuln !== false,
      nuclei_result: source.nuclei_result !== false,
    };
  };

  const normalizeAiDenoisePromptIds = (
    rawPromptIds: any,
    promptTemplates: AiPromptTemplate[],
  ): AiDenoisePromptIds => {
    const source = rawPromptIds && typeof rawPromptIds === 'object' ? rawPromptIds : {};
    const templateIdSet = new Set(promptTemplates.map((item) => item.id));
    const scenePromptIdMap: Partial<Record<AiDenoiseModuleId, string>> = {};
    aiDenoiseModuleConfigs.forEach((configItem) => {
      const foundByScene = promptTemplates.find((item) => item.scene === configItem.scene);
      if (foundByScene?.id) {
        scenePromptIdMap[configItem.id] = foundByScene.id;
      }
    });
    const fallbackPromptId = promptTemplates[0]?.id || '';
    const normalizeOne = (moduleId: AiDenoiseModuleId) => {
      const candidate = String(source[moduleId] || '').trim();
      if (candidate && templateIdSet.has(candidate)) return candidate;
      if (scenePromptIdMap[moduleId]) return String(scenePromptIdMap[moduleId] || '');
      return fallbackPromptId;
    };
    return {
      site: normalizeOne('site'),
      fileleak: normalizeOne('fileleak'),
      cert: normalizeOne('cert'),
      url: normalizeOne('url'),
      wih_endpoint: normalizeOne('wih_endpoint'),
      vuln: normalizeOne('vuln'),
      nuclei_result: normalizeOne('nuclei_result'),
    };
  };

  const normalizeForm = (rawForm: any): AiConfigForm => {
    const promptTemplates = normalizePromptTemplates(rawForm?.prompt_templates);
    const promptIds = promptTemplates.map((item) => item.id);
    const activePromptIdRaw = String(rawForm?.active_prompt_id || '').trim();
    const activePromptId = promptIds.includes(activePromptIdRaw) ? activePromptIdRaw : promptIds[0] || '';
    const dialogContextMessages = Number(rawForm?.dialog_context_messages ?? 8);
    const requestDelayMs = Number(rawForm?.request_delay_ms ?? 0);
    const wihEndpointAiFillMaxTargets = Number(rawForm?.wih_endpoint_ai_fill_max_targets ?? 0);
    const modelProfiles = normalizeModelProfiles(rawForm?.model_profiles, rawForm);
    const activeModelProfileIdRaw = String(rawForm?.active_model_profile_id || '').trim();
    const activeProfile =
      modelProfiles.find((item) => item.id === activeModelProfileIdRaw) || modelProfiles[0];
    const activeModelProfileId = activeProfile?.id || '';
    const timeoutSec = Number(activeProfile?.timeout_sec ?? 40);
    const temperature = Number(activeProfile?.temperature ?? 0.2);
    const maxTokens = Number(activeProfile?.max_tokens ?? 4000);

    return {
      enable: rawForm?.enable !== false,
      active_model_profile_id: activeModelProfileId,
      model_profiles: modelProfiles,
      provider: normalizeProviderId(activeProfile?.provider || rawForm?.provider),
      custom_provider_name: String(rawForm?.custom_provider_name || activeProfile?.name || ''),
      base_url: String(activeProfile?.base_url || rawForm?.base_url || ''),
      api_key: String(activeProfile?.api_key || rawForm?.api_key || ''),
      model: String(activeProfile?.model || rawForm?.model || ''),
      proxy_url: String(activeProfile?.proxy || rawForm?.proxy_url || rawForm?.proxy || ''),
      timeout_sec: Number.isFinite(timeoutSec) && timeoutSec > 0 ? timeoutSec : 40,
      temperature: Number.isFinite(temperature) && temperature >= 0 ? temperature : 0.2,
      max_tokens: Number.isFinite(maxTokens) && maxTokens > 0 ? maxTokens : 4000,
      dialog_system_prompt: String(rawForm?.dialog_system_prompt || ''),
      dialog_style: String(rawForm?.dialog_style || '专业'),
      dialog_language: String(rawForm?.dialog_language || 'zh-CN'),
      dialog_context_messages:
        Number.isFinite(dialogContextMessages) && dialogContextMessages > 0 ? dialogContextMessages : 8,
      request_delay_ms: Number.isFinite(requestDelayMs) && requestDelayMs >= 0 ? Math.floor(requestDelayMs) : 0,
      wih_endpoint_ai_fill_max_targets:
        Number.isFinite(wihEndpointAiFillMaxTargets) && wihEndpointAiFillMaxTargets >= 0
          ? Math.floor(wihEndpointAiFillMaxTargets)
          : 0,
      active_prompt_id: activePromptId,
      prompt_templates: promptTemplates,
      custom_compat_providers: normalizeCustomCompatProviders(rawForm?.custom_compat_providers),
      ai_denoise_enable: rawForm?.ai_denoise_enable !== false,
      ai_wih_endpoint_fill_enable: rawForm?.ai_wih_endpoint_fill_enable !== false,
      ai_denoise_modules: normalizeAiDenoiseModules(rawForm?.ai_denoise_modules),
      ai_denoise_prompt_ids: normalizeAiDenoisePromptIds(rawForm?.ai_denoise_prompt_ids, promptTemplates),
    };
  };

  const defaultForm: AiConfigForm = normalizeForm({});
  const [form, setForm] = useState<AiConfigForm>(defaultForm);
  const [providerPresets, setProviderPresets] = useState<AiProviderPreset[]>(defaultProviderPresets);
  const [configPath, setConfigPath] = useState('');
  const [updatedAt, setUpdatedAt] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [testResult, setTestResult] = useState<AiTestResult | null>(null);
  const [compatDraft, setCompatDraft] = useState<{
    name: string;
    base_url: string;
    model: string;
  }>({
    name: '',
    base_url: '',
    model: '',
  });
  const [compatDialogOpen, setCompatDialogOpen] = useState(false);
  const [sopUploadModuleId, setSopUploadModuleId] = useState<AiSopModuleId>('site');
  const [sopUploadFile, setSopUploadFile] = useState<File | null>(null);
  const [sopUploading, setSopUploading] = useState(false);
  const sopUploadInputRef = useRef<HTMLInputElement | null>(null);
  const [dialogSystemPromptOpen, setDialogSystemPromptOpen] = useState(false);
  const [modelDraft, setModelDraft] = useState<{ name: string; provider: string }>({
    name: '',
    provider: 'openai',
  });
  const [sensitiveVisible, setSensitiveVisible] = useState(false);
  const [sensitiveVerifyDialogOpen, setSensitiveVerifyDialogOpen] = useState(false);
  const [sensitiveVerifyUsername, setSensitiveVerifyUsername] = useState(() => localStorage.getItem(USERNAME_KEY) || '');
  const [sensitiveVerifyPassword, setSensitiveVerifyPassword] = useState('');
  const [sensitiveVerifyLoading, setSensitiveVerifyLoading] = useState(false);
  const [sensitiveVerifyError, setSensitiveVerifyError] = useState('');
  const [sensitiveEditingModelProfileIds, setSensitiveEditingModelProfileIds] = useState<Set<string>>(new Set());
  const [sensitiveConfiguredMap, setSensitiveConfiguredMap] = useState<{
    api_key: boolean;
    model_profile_api_keys: Record<string, boolean>;
  }>({
    api_key: false,
    model_profile_api_keys: {},
  });
  const [showRestartModal, setShowRestartModal] = useState(false);
  const [aiTestDialogOpen, setAiTestDialogOpen] = useState(false);
  const [usageLoading, setUsageLoading] = useState(false);
  const [usageError, setUsageError] = useState('');
  const [usageStats, setUsageStats] = useState<AiUsageStatsPayload | null>(null);
  const [usageLogs, setUsageLogs] = useState<AiUsageLogItem[]>([]);
  const [usageLogsTotal, setUsageLogsTotal] = useState(0);
  const [usageLogsUpdatedAt, setUsageLogsUpdatedAt] = useState('');
  const [usageLogStatus, setUsageLogStatus] = useState('');
  const [usageLogScene, setUsageLogScene] = useState('');
  const [usageLogLimit, setUsageLogLimit] = useState('10');
  const [usageLogDetail, setUsageLogDetail] = useState<AiUsageLogItem | null>(null);
  const [usageSceneOptions, setUsageSceneOptions] = useState<Array<{ scene: string; scene_label: string }>>([]);
  const [providerConfigDialogOpen, setProviderConfigDialogOpen] = useState(false);
  const [providerConfigProviderId, setProviderConfigProviderId] = useState('deepseek');
  const [providerConfigProfileId, setProviderConfigProfileId] = useState('');
  const [providerConfigApiKeyEdited, setProviderConfigApiKeyEdited] = useState(false);
  const [providerConfigDraft, setProviderConfigDraft] = useState<{
    api_key: string;
    model: string;
    reasoning_model: string;
    base_url: string;
    proxy: string;
  }>({
    api_key: '',
    model: '',
    reasoning_model: '',
    base_url: '',
    proxy: '',
  });
  const closeProviderConfigDialog = useCallback(() => {
    setProviderConfigDialogOpen(false);
    setProviderConfigApiKeyEdited(false);
    setProviderConfigDraft((prev) => ({
      ...prev,
      api_key: '',
    }));
  }, []);

  const providerPresetMap = useMemo(() => {
    const map: Record<string, AiProviderPreset> = {};
    providerPresets.forEach((item) => {
      map[item.id] = item;
    });
    return map;
  }, [providerPresets]);

  const providerUiMetaMap = useMemo(
    () =>
      ({
        qwen: {
          logo: 'QW',
          logoClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-400/40',
          apiKeyUrl: 'https://bailian.console.aliyun.com/?apiKey=1',
        },
        kimi: {
          logo: 'KM',
          logoClass: 'bg-sky-500/20 text-sky-300 border-sky-400/40',
          apiKeyUrl: 'https://platform.moonshot.cn/console/api-keys',
        },
        openai: {
          logo: 'OA',
          logoClass: 'bg-accent/20 text-accent border-accent/40',
          apiKeyUrl: 'https://platform.openai.com/api-keys',
        },
        glm: {
          logo: 'GL',
          logoClass: 'bg-violet-500/20 text-violet-300 border-violet-400/40',
          apiKeyUrl: 'https://open.bigmodel.cn/usercenter/apikeys',
        },
        deepseek: {
          logo: 'DS',
          logoClass: 'bg-cyan-500/20 text-cyan-300 border-cyan-400/40',
          apiKeyUrl: 'https://platform.deepseek.com/api_keys',
        },
        custom_compatible: {
          logo: 'API',
          logoClass: 'bg-amber-500/20 text-amber-300 border-amber-400/40',
          apiKeyUrl: 'https://platform.openai.com/api-keys',
        },
      }) as Record<
        string,
        {
          logo: string;
          logoClass: string;
          apiKeyUrl: string;
        }
      >,
    []
  );

  const providerDisplayOrder = ['qwen', 'kimi', 'openai', 'glm', 'deepseek', 'custom_compatible'];

  const providerCardList = useMemo(() => {
    const seen = new Set<string>();
    const ordered: AiProviderPreset[] = [];
    providerDisplayOrder.forEach((providerId) => {
      const preset = providerPresetMap[providerId] || defaultProviderPresets.find((item) => item.id === providerId);
      if (!preset) return;
      ordered.push(preset);
      seen.add(providerId);
    });
    providerPresets.forEach((item) => {
      if (!item?.id || seen.has(item.id)) return;
      ordered.push(item);
      seen.add(item.id);
    });
    return ordered;
  }, [providerPresetMap, providerPresets]);

  const providerProfileMap = useMemo(() => {
    const map: Record<string, AiModelProfile> = {};
    form.model_profiles.forEach((item) => {
      const providerId = normalizeProviderId(item.provider);
      if (!providerId) return;
      if (!map[providerId]) {
        map[providerId] = item;
        return;
      }
      if (item.id === form.active_model_profile_id) {
        map[providerId] = item;
      }
    });
    return map;
  }, [form.active_model_profile_id, form.model_profiles]);

  const sopTemplateMap = useMemo(() => {
    const promptById = new Map<string, AiPromptTemplate>();
    form.prompt_templates.forEach((item) => {
      promptById.set(String(item.id || '').trim(), item);
    });

    const result: Record<AiSopModuleId, AiPromptTemplate | null> = {
      site: null,
      fileleak: null,
      cert: null,
      url: null,
      wih_endpoint: null,
      vuln: null,
      nuclei_result: null,
      wih_endpoint_fill: null,
    };

    aiSopModuleConfigs.forEach((configItem) => {
      const configuredPromptId = (configItem.id === 'wih_endpoint_fill')
        ? ''
        : String(form.ai_denoise_prompt_ids[configItem.id] || '').trim();
      const byId = configuredPromptId ? promptById.get(configuredPromptId) || null : null;
      if (byId) {
        result[configItem.id] = byId;
        return;
      }
      const byScene = form.prompt_templates.find((item) => item.scene === configItem.scene) || null;
      result[configItem.id] = byScene;
    });

    return result;
  }, [aiSopModuleConfigs, form.ai_denoise_prompt_ids, form.prompt_templates]);

  const isActionBusy = loading || saving || testing;
  const aiInputClass = CONSOLE_INPUT_CLASS;
  const aiInputMonoClass = CONSOLE_INPUT_MONO_CLASS;
  const aiSelectWrapClass = 'relative w-full';
  const aiUploadFilenameClass =
    'flex-1 h-10 rounded-xl border border-base-300 bg-base-100 px-3 text-sm text-content-muted flex items-center truncate';

  const clearSopUploadSelection = useCallback(() => {
    setSopUploadFile(null);
    if (sopUploadInputRef.current) {
      sopUploadInputRef.current.value = '';
    }
  }, []);

  const handleSopFileChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] || null;
    if (!file) {
      setSopUploadFile(null);
      return;
    }
    const lowerName = file.name.toLowerCase();
    if (!lowerName.endsWith('.yaml') && !lowerName.endsWith('.yml')) {
      setError('SOP 文件仅支持 .yaml/.yml');
      setSopUploadFile(null);
      event.currentTarget.value = '';
      return;
    }
    setSopUploadFile(file);
    setError('');
  }, []);

  const resetSensitiveState = useCallback(() => {
    setSensitiveVisible(false);
    setSensitiveVerifyDialogOpen(false);
    setSensitiveVerifyPassword('');
    setSensitiveVerifyError('');
    setSensitiveVerifyLoading(false);
    setSensitiveEditingModelProfileIds(new Set());
  }, []);

  const normalizeSensitiveConfigured = useCallback((rawValue: any, currentForm?: AiConfigForm) => {
    const raw = rawValue && typeof rawValue === 'object' ? rawValue : {};
    const rawProfileMap = raw?.model_profile_api_keys && typeof raw.model_profile_api_keys === 'object'
      ? raw.model_profile_api_keys
      : {};
    const profileMap: Record<string, boolean> = {};
    Object.entries(rawProfileMap).forEach(([profileId, configured]) => {
      const normalizedId = String(profileId || '').trim();
      if (!normalizedId) return;
      profileMap[normalizedId] = Boolean(configured);
    });
    const activeProfileId = String(currentForm?.active_model_profile_id || '').trim();
    const activeConfiguredByProfile = activeProfileId ? Boolean(profileMap[activeProfileId]) : false;
    const activeConfigured = raw?.api_key !== undefined
      ? Boolean(raw.api_key)
      : activeConfiguredByProfile;
    return {
      api_key: activeConfigured,
      model_profile_api_keys: profileMap,
    };
  }, []);

  const findActiveModelProfile = useCallback(
    (currentForm: AiConfigForm) =>
      currentForm.model_profiles.find((item) => item.id === currentForm.active_model_profile_id) ||
      currentForm.model_profiles[0],
    []
  );

  const syncFormWithActiveModel = useCallback(
    (currentForm: AiConfigForm, profile: AiModelProfile): AiConfigForm => ({
      ...currentForm,
      active_model_profile_id: profile.id,
      provider: profile.provider,
      base_url: profile.base_url,
      api_key: profile.api_key,
      model: profile.model,
      proxy_url: profile.proxy,
      timeout_sec: profile.timeout_sec,
      temperature: profile.temperature,
      max_tokens: profile.max_tokens,
      custom_provider_name: profile.name || currentForm.custom_provider_name,
    }),
    []
  );

  const updateActiveModelProfile = useCallback(
    (updater: (current: AiModelProfile) => AiModelProfile) => {
      setForm((prev) => {
        const activeProfile = findActiveModelProfile(prev);
        if (!activeProfile) return prev;
        const nextProfile = updater(activeProfile);
        const nextProfiles = prev.model_profiles.map((item) => (item.id === nextProfile.id ? nextProfile : item));
        return syncFormWithActiveModel(
          {
            ...prev,
            model_profiles: nextProfiles,
          },
          nextProfile
        );
      });
    },
    [findActiveModelProfile, syncFormWithActiveModel]
  );

  const buildAiPayload = useCallback((currentForm: AiConfigForm): Record<string, any> => {
    const timeoutSec = Number(currentForm.timeout_sec);
    const maxTokens = Number(currentForm.max_tokens);
    const dialogContextMessages = Number(currentForm.dialog_context_messages);
    const requestDelayMs = Number(currentForm.request_delay_ms);
    const wihEndpointAiFillMaxTargets = Number(currentForm.wih_endpoint_ai_fill_max_targets);
    const temperature = Number(currentForm.temperature);
    const promptTemplates = normalizePromptTemplates(currentForm.prompt_templates);
    const promptIds = promptTemplates.map((item) => item.id);
    const activePromptId = promptIds.includes(currentForm.active_prompt_id)
      ? currentForm.active_prompt_id
      : promptIds[0] || '';
    const profiles = normalizeModelProfiles(currentForm.model_profiles, currentForm);
    const activeModelProfileId = String(currentForm.active_model_profile_id || '').trim() || profiles[0]?.id || '';
    const activeProvider = normalizeProviderId(currentForm.provider);
    const normalizedActiveProfile: AiModelProfile = {
      id: activeModelProfileId || buildModelProfileId('default_model', 1),
      name: String(
        profiles.find((item) => item.id === activeModelProfileId)?.name ||
          currentForm.custom_provider_name ||
          '默认模型'
      ).trim(),
      provider: activeProvider,
      base_url: String(currentForm.base_url || '').trim(),
      api_key: String(currentForm.api_key || '').trim(),
      model: String(currentForm.model || '').trim(),
      reasoning_model: String(
        profiles.find((item) => item.id === activeModelProfileId)?.reasoning_model || ''
      ).trim(),
      proxy: String(currentForm.proxy_url || '').trim(),
      timeout_sec: Number.isFinite(timeoutSec) && timeoutSec > 0 ? Math.floor(timeoutSec) : 40,
      temperature: Number.isFinite(temperature) && temperature >= 0 ? Number(temperature.toFixed(2)) : 0.2,
      max_tokens: Number.isFinite(maxTokens) && maxTokens > 0 ? Math.floor(maxTokens) : 4000,
    };
    let activeExists = false;
    const modelProfiles = profiles.map((item) => {
      if (item.id !== normalizedActiveProfile.id) return item;
      activeExists = true;
      return { ...item, ...normalizedActiveProfile };
    });
    if (!activeExists) {
      modelProfiles.unshift(normalizedActiveProfile);
    }
    const sanitizedModelProfiles = modelProfiles.map((item) => {
      const normalizedItem = {
        ...item,
        api_key: String(item.api_key || '').trim(),
      };
      if (sensitiveEditingModelProfileIds.has(item.id)) {
        return normalizedItem;
      }
      const { api_key, ...rest } = normalizedItem;
      return rest;
    });

    const payload: Record<string, any> = {
      enable: Boolean(currentForm.enable),
      active_model_profile_id: normalizedActiveProfile.id,
      model_profiles: sanitizedModelProfiles,
      provider: activeProvider,
      custom_provider_name: String(currentForm.custom_provider_name || '').trim(),
      base_url: normalizedActiveProfile.base_url,
      api_key: normalizedActiveProfile.api_key,
      model: normalizedActiveProfile.model,
      reasoning_model: normalizedActiveProfile.reasoning_model,
      proxy_url: normalizedActiveProfile.proxy,
      timeout_sec: normalizedActiveProfile.timeout_sec,
      temperature: normalizedActiveProfile.temperature,
      max_tokens: normalizedActiveProfile.max_tokens,
      dialog_system_prompt: String(currentForm.dialog_system_prompt || '').trim(),
      dialog_style: String(currentForm.dialog_style || '专业').trim() || '专业',
      dialog_language: String(currentForm.dialog_language || 'zh-CN').trim() || 'zh-CN',
      dialog_context_messages:
        Number.isFinite(dialogContextMessages) && dialogContextMessages > 0 ? Math.floor(dialogContextMessages) : 8,
      request_delay_ms: Number.isFinite(requestDelayMs) && requestDelayMs >= 0 ? Math.floor(requestDelayMs) : 0,
      wih_endpoint_ai_fill_max_targets:
        Number.isFinite(wihEndpointAiFillMaxTargets) && wihEndpointAiFillMaxTargets >= 0
          ? Math.min(5000, Math.floor(wihEndpointAiFillMaxTargets))
          : 0,
      active_prompt_id: activePromptId,
      prompt_templates: promptTemplates,
      custom_compat_providers: normalizeCustomCompatProviders(currentForm.custom_compat_providers),
      ai_denoise_enable: Boolean(currentForm.ai_denoise_enable),
      ai_wih_endpoint_fill_enable: Boolean(currentForm.ai_wih_endpoint_fill_enable),
      ai_denoise_modules: normalizeAiDenoiseModules(currentForm.ai_denoise_modules),
      ai_denoise_prompt_ids: normalizeAiDenoisePromptIds(currentForm.ai_denoise_prompt_ids, promptTemplates),
    };
    if (!sensitiveEditingModelProfileIds.has(normalizedActiveProfile.id)) {
      delete payload.api_key;
    }
    return payload;
  }, [findActiveModelProfile, sensitiveEditingModelProfileIds]);

  const normalizeAiUsageStatsValue = useCallback((rawValue: any): AiUsageStats => {
    const toInt = (value: any) => {
      const numeric = Number(value);
      return Number.isFinite(numeric) && numeric > 0 ? Math.floor(numeric) : 0;
    };
    return {
      request_count: toInt(rawValue?.request_count),
      success_count: toInt(rawValue?.success_count),
      error_count: toInt(rawValue?.error_count),
      skip_count: toInt(rawValue?.skip_count),
      prompt_tokens: toInt(rawValue?.prompt_tokens),
      completion_tokens: toInt(rawValue?.completion_tokens),
      total_tokens: toInt(rawValue?.total_tokens),
    };
  }, []);

  const getUsageLogPreviewText = useCallback((rawText: string, maxLength = 70) => {
    const normalized = String(rawText || '')
      .replace(/\s+/g, ' ')
      .trim();
    if (!normalized) return '-';
    if (normalized.length <= maxLength) return normalized;
    return `${normalized.slice(0, maxLength)}...`;
  }, []);

  const loadAiUsageDashboard = useCallback(async () => {
    setUsageLoading(true);
    setUsageError('');
    try {
      const parsedLimit = Number(usageLogLimit);
      const logLimit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? Math.floor(parsedLimit) : 10;
      const logsQuery: Record<string, any> = { limit: logLimit };
      if (usageLogStatus) logsQuery.status = usageLogStatus;
      if (usageLogScene) logsQuery.scene = usageLogScene;
      const [statsResult, logsResult] = await Promise.all([
        requestApi(token, '/api_console/ai_usage/stats/', { method: 'GET' }),
        requestApi(token, '/api_console/ai_usage/logs/', { method: 'GET', query: logsQuery }),
      ]);
      const statsData = statsResult?.data || {};
      const logsData = logsResult?.data || {};
      const normalizedStats: AiUsageStatsPayload = {
        all_time: normalizeAiUsageStatsValue(statsData?.all_time),
        last_24h: normalizeAiUsageStatsValue(statsData?.last_24h),
        last_7d: normalizeAiUsageStatsValue(statsData?.last_7d),
        by_model: Array.isArray(statsData?.by_model)
          ? statsData.by_model.map((item: any) => ({
              ...normalizeAiUsageStatsValue(item),
              provider: String(item?.provider || ''),
              model: String(item?.model || ''),
            }))
          : [],
        by_scene: Array.isArray(statsData?.by_scene)
          ? statsData.by_scene.map((item: any) => ({
              ...normalizeAiUsageStatsValue(item),
              scene: String(item?.scene || ''),
              scene_label: String(item?.scene_label || item?.scene || ''),
            }))
          : [],
        avg_elapsed_ms: Number.isFinite(Number(statsData?.avg_elapsed_ms))
          ? Math.max(0, Math.round(Number(statsData?.avg_elapsed_ms)))
          : 0,
        avg_elapsed_sample_count: Number.isFinite(Number(statsData?.avg_elapsed_sample_count))
          ? Math.max(0, Math.floor(Number(statsData?.avg_elapsed_sample_count)))
          : 0,
        top_error_reasons: Array.isArray(statsData?.top_error_reasons)
          ? statsData.top_error_reasons
              .map((item: any) => ({
                reason: String(item?.reason || '').trim(),
                count: Number.isFinite(Number(item?.count)) ? Math.max(0, Math.floor(Number(item.count))) : 0,
              }))
              .filter((item: { reason: string; count: number }) => Boolean(item.reason) && item.count > 0)
          : [],
        window_days: Number(statsData?.window_days || 7) || 7,
        updated_at: String(statsData?.updated_at || ''),
      };
      setUsageStats(normalizedStats);

      const sceneItems = Array.isArray(logsData?.available_scenes) ? logsData.available_scenes : [];
      setUsageSceneOptions(
        sceneItems
          .map((item: any) => ({
            scene: String(item?.scene || ''),
            scene_label: String(item?.scene_label || item?.scene || ''),
          }))
          .filter((item: { scene: string }) => Boolean(item.scene))
      );

      const logItems = Array.isArray(logsData?.items) ? logsData.items : [];
      const normalizedLogs: AiUsageLogItem[] = logItems.map((item: any) => {
        const statusRaw = String(item?.status || '').toLowerCase();
        const status = statusRaw === 'error' ? 'error' : statusRaw === 'skipped' ? 'skipped' : 'ok';
        return {
          id: String(item?.id || ''),
          created_at: String(item?.created_at || ''),
          scene: String(item?.scene || ''),
          scene_label: String(item?.scene_label || item?.scene || ''),
          provider: String(item?.provider || ''),
          model: String(item?.model || ''),
          profile: String(item?.profile || ''),
          status,
          request_text: String(item?.request_text || ''),
          reply_text: String(item?.reply_text || ''),
          error_message: String(item?.error_message || ''),
          prompt_tokens: normalizeAiUsageStatsValue({ prompt_tokens: item?.prompt_tokens }).prompt_tokens,
          completion_tokens: normalizeAiUsageStatsValue({ completion_tokens: item?.completion_tokens }).completion_tokens,
          total_tokens: normalizeAiUsageStatsValue({ total_tokens: item?.total_tokens }).total_tokens,
        };
      });
      setUsageLogs(normalizedLogs);
      setUsageLogsTotal(Number(logsData?.total || 0) || 0);
      setUsageLogsUpdatedAt(String(logsData?.updated_at || statsData?.updated_at || ''));
    } catch (err: any) {
      setUsageError(err?.message || '加载 AI 用量统计失败');
    } finally {
      setUsageLoading(false);
    }
  }, [normalizeAiUsageStatsValue, token, usageLogLimit, usageLogScene, usageLogStatus]);

  const loadAiConfig = useCallback(async () => {
    resetSensitiveState();
    setLoading(true);
    setError('');
    setSuccess('');
    setTestResult(null);
    setAiTestDialogOpen(false);
    setShowRestartModal(false);
    try {
      const result = await requestApi(token, '/api_console/ai_config/', { method: 'GET' });
      const data = result?.data || {};
      const remotePresets = Array.isArray(data?.provider_presets) ? data.provider_presets : [];
      const normalizedPresets = remotePresets
        .map((item: any) => {
          const id = String(item?.id || '').trim();
          if (!id) return null;
          return {
            id,
            label: String(item?.label || id),
            base_url: String(item?.base_url || ''),
            default_model: String(item?.default_model || ''),
          };
        })
        .filter((item: AiProviderPreset | null): item is AiProviderPreset => Boolean(item));

      setProviderPresets(normalizedPresets.length > 0 ? normalizedPresets : defaultProviderPresets);
      const normalizedForm = normalizeForm(data?.ai_config || {});
      setForm(normalizedForm);
      setSensitiveConfiguredMap(normalizeSensitiveConfigured(data?.sensitive_configured, normalizedForm));
      setModelDraft((prev) => ({ ...prev, provider: normalizedForm.provider || 'openai' }));
      setSensitiveVerifyUsername(localStorage.getItem(USERNAME_KEY) || '');
      setConfigPath(String(data?.config_path || ''));
      setUpdatedAt(String(data?.updated_at || ''));
    } catch (err: any) {
      setError(err?.message || '加载 AI 管理配置失败');
    } finally {
      setLoading(false);
    }
  }, [token, normalizeSensitiveConfigured, resetSensitiveState]);

  useEffect(() => {
    void loadAiConfig();
  }, [loadAiConfig]);

  useEffect(() => {
    void loadAiUsageDashboard();
  }, [loadAiUsageDashboard]);

  useEffect(() => {
    if (!compatDialogOpen && !providerConfigDialogOpen && !showRestartModal && !aiTestDialogOpen && !usageLogDetail) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      if (usageLogDetail) {
        setUsageLogDetail(null);
        return;
      }
      if (aiTestDialogOpen) {
        setAiTestDialogOpen(false);
        return;
      }
      if (showRestartModal) {
        setShowRestartModal(false);
        return;
      }
      if (providerConfigDialogOpen) {
        closeProviderConfigDialog();
        return;
      }
      if (compatDialogOpen) {
        setCompatDialogOpen(false);
      }
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [aiTestDialogOpen, closeProviderConfigDialog, compatDialogOpen, providerConfigDialogOpen, showRestartModal, usageLogDetail]);

  useEffect(() => {
    clearSopUploadSelection();
  }, [clearSopUploadSelection, sopUploadModuleId]);

  const createProviderProfileForForm = useCallback(
    (currentForm: AiConfigForm, providerIdRaw: string): AiModelProfile => {
      const providerId = normalizeProviderId(providerIdRaw);
      const preset = providerPresetMap[providerId] || defaultProviderPresets.find((item) => item.id === providerId);
      const profileName = String(preset?.label || providerId || '模型').trim();
      let fallbackIndex = currentForm.model_profiles.length + 1;
      let candidateId = buildModelProfileId(`provider_${providerId}`, fallbackIndex);
      while (currentForm.model_profiles.some((item) => item.id === candidateId)) {
        fallbackIndex += 1;
        candidateId = buildModelProfileId(`provider_${providerId}_${fallbackIndex}`, fallbackIndex);
      }
      return {
        id: candidateId,
        name: profileName,
        provider: providerId,
        base_url: String(preset?.base_url || ''),
        api_key: '',
        model: String(preset?.default_model || ''),
        reasoning_model: String(preset?.default_reasoning_model || preset?.default_model || ''),
        proxy: '',
        timeout_sec: 40,
        temperature: 0.2,
        max_tokens: 4000,
      };
    },
    [providerPresetMap]
  );

  const setDefaultAiProvider = useCallback(
    (providerIdRaw: string) => {
      const providerId = normalizeProviderId(providerIdRaw);
      setForm((prev) => {
        const existedProfile = prev.model_profiles.find((item) => normalizeProviderId(item.provider) === providerId);
        if (existedProfile) {
          return syncFormWithActiveModel(prev, existedProfile);
        }
        const nextProfile = createProviderProfileForForm(prev, providerId);
        return syncFormWithActiveModel(
          {
            ...prev,
            model_profiles: [...prev.model_profiles, nextProfile],
          },
          nextProfile
        );
      });
      setError('');
      setSuccess('');
    },
    [createProviderProfileForForm, syncFormWithActiveModel]
  );

  const openProviderConfigDialog = useCallback(
    (providerIdRaw: string) => {
      const providerId = normalizeProviderId(providerIdRaw);
      const existingProfile = providerProfileMap[providerId];
      const nextProfile = existingProfile || createProviderProfileForForm(form, providerId);
      if (!existingProfile) {
        setForm((prev) => ({
          ...prev,
          model_profiles: [...prev.model_profiles, nextProfile],
        }));
      }
      setProviderConfigProviderId(providerId);
      setProviderConfigProfileId(nextProfile.id);
      setProviderConfigApiKeyEdited(false);
      setProviderConfigDraft({
        api_key: String(nextProfile.api_key || ''),
        model: String(nextProfile.model || ''),
        reasoning_model: String(nextProfile.reasoning_model || ''),
        base_url: String(nextProfile.base_url || ''),
        proxy: String(nextProfile.proxy || ''),
      });
      setProviderConfigDialogOpen(true);
      setError('');
    },
    [createProviderProfileForForm, form, providerProfileMap]
  );

  const saveProviderConfigDraft = useCallback(() => {
    const providerId = normalizeProviderId(providerConfigProviderId);
    const profileId = String(providerConfigProfileId || '').trim();
    const providerLabel = providerPresetMap[providerId]?.label || providerId;
    const fallbackPreset = providerPresetMap[providerId] || defaultProviderPresets.find((item) => item.id === providerId);
    setForm((prev) => {
      let targetProfile =
        prev.model_profiles.find((item) => item.id === profileId) ||
        prev.model_profiles.find((item) => normalizeProviderId(item.provider) === providerId) ||
        null;

      let nextProfiles = [...prev.model_profiles];
      if (!targetProfile) {
        targetProfile = createProviderProfileForForm(prev, providerId);
        nextProfiles.push(targetProfile);
      }

      const nextProfile: AiModelProfile = {
        ...targetProfile,
        name: String(targetProfile.name || providerLabel || providerId).trim(),
        provider: providerId,
        base_url: String(providerConfigDraft.base_url || '').trim() || String(fallbackPreset?.base_url || ''),
        model: String(providerConfigDraft.model || '').trim() || String(fallbackPreset?.default_model || ''),
        reasoning_model: String(providerConfigDraft.reasoning_model || '').trim(),
        proxy: String(providerConfigDraft.proxy || '').trim(),
        api_key: providerConfigApiKeyEdited ? String(providerConfigDraft.api_key || '') : String(targetProfile.api_key || ''),
      };

      nextProfiles = nextProfiles.map((item) => (item.id === targetProfile?.id ? nextProfile : item));
      if (
        targetProfile.id === prev.active_model_profile_id ||
        normalizeProviderId(prev.provider) === providerId
      ) {
        return syncFormWithActiveModel(
          {
            ...prev,
            model_profiles: nextProfiles,
          },
          nextProfile
        );
      }
      return {
        ...prev,
        model_profiles: nextProfiles,
      };
    });

    if (providerConfigApiKeyEdited && profileId) {
      setSensitiveEditingModelProfileIds((prev) => {
        const next = new Set(prev);
        next.add(profileId);
        return next;
      });
    }
    closeProviderConfigDialog();
    setSuccess(`${providerLabel} 配置已更新，点击“保存配置”后生效`);
    setError('');
  }, [
    closeProviderConfigDialog,
    createProviderProfileForForm,
    providerConfigApiKeyEdited,
    providerConfigDraft.api_key,
    providerConfigDraft.base_url,
    providerConfigDraft.model,
    providerConfigDraft.reasoning_model,
    providerConfigDraft.proxy,
    providerConfigProfileId,
    providerConfigProviderId,
    providerPresetMap,
    syncFormWithActiveModel,
  ]);

  const handleProviderChange = (nextProvider: string) => {
    const providerId = normalizeProviderId(nextProvider);
    setForm((prev) => {
      const matchedProfile = prev.model_profiles.find((item) => item.provider === providerId);
      if (matchedProfile) {
        return syncFormWithActiveModel(prev, matchedProfile);
      }
      const activeProfile = findActiveModelProfile(prev);
      if (!activeProfile) return prev;
      const preset = providerPresetMap[providerId];
      const nextBaseUrl = String(preset?.base_url || '').trim() || activeProfile.base_url;
      const nextModel = String(preset?.default_model || '').trim() || activeProfile.model;
      const nextProfile: AiModelProfile = {
        ...activeProfile,
        provider: providerId,
        base_url: providerId === 'custom_compatible' ? activeProfile.base_url : nextBaseUrl,
        model: providerId === 'custom_compatible' ? activeProfile.model : nextModel,
      };
      const nextProfiles = prev.model_profiles.map((item) => (item.id === nextProfile.id ? nextProfile : item));
      return syncFormWithActiveModel(
        {
          ...prev,
          model_profiles: nextProfiles,
        },
        nextProfile
      );
    });
    setError('');
    setSuccess('');
  };

  const selectActiveModelProfile = (profileId: string) => {
    setForm((prev) => {
      const profile = prev.model_profiles.find((item) => item.id === profileId);
      if (!profile) return prev;
      return syncFormWithActiveModel(prev, profile);
    });
    setError('');
    setSuccess('');
  };

  const addModelProfile = () => {
    const providerId = normalizeProviderId(modelDraft.provider || 'openai');
    const preset = providerPresetMap[providerId];
    const profileName = modelDraft.name.trim() || `模型${form.model_profiles.length + 1}`;
    let fallbackIndex = form.model_profiles.length + 1;
    let candidateId = buildModelProfileId(profileName, fallbackIndex);
    while (form.model_profiles.some((item) => item.id === candidateId)) {
      fallbackIndex += 1;
      candidateId = buildModelProfileId(`${profileName}_${fallbackIndex}`, fallbackIndex);
    }

    const nextProfile: AiModelProfile = {
      id: candidateId,
      name: profileName,
      provider: providerId,
      base_url: String(preset?.base_url || ''),
      api_key: '',
      model: String(preset?.default_model || ''),
      reasoning_model: String(preset?.default_reasoning_model || preset?.default_model || ''),
      proxy: '',
      timeout_sec: 40,
      temperature: 0.2,
      max_tokens: 4000,
    };

    setForm((prev) => {
      const merged = {
        ...prev,
        model_profiles: [...prev.model_profiles, nextProfile],
      };
      return syncFormWithActiveModel(merged, nextProfile);
    });
    setModelDraft({ name: '', provider: providerId });
    setError('');
    setSuccess(`模型配置已新增：${profileName}`);
  };

  const removeModelProfile = (profileId: string) => {
    if (form.model_profiles.length <= 1) {
      setError('至少保留一个模型配置');
      return;
    }
    setForm((prev) => {
      const remaining = prev.model_profiles.filter((item) => item.id !== profileId);
      if (remaining.length === prev.model_profiles.length) return prev;
      const fallbackProfile = remaining[0];
      const baseForm = {
        ...prev,
        model_profiles: remaining,
      };
      return syncFormWithActiveModel(baseForm, fallbackProfile);
    });
    setSuccess('');
  };

  const updateActiveModelName = (nextName: string) => {
    updateActiveModelProfile((active) => ({
      ...active,
      name: nextName,
    }));
  };

  const applyCompatProvider = (providerId: string) => {
    const provider = form.custom_compat_providers.find((item) => item.id === providerId);
    if (!provider) return;
    updateActiveModelProfile((active) => ({
      ...active,
      name: provider.name || active.name,
      provider: 'custom_compatible',
      base_url: provider.base_url,
      model: provider.model || active.model,
    }));
    setForm((prev) => ({
      ...prev,
      custom_provider_name: provider.name,
    }));
    setError('');
    setSuccess(`已套用兼容接口：${provider.name}`);
  };

  const addCompatProvider = () => {
    const name = compatDraft.name.trim();
    const baseUrl = compatDraft.base_url.trim();
    if (!name) {
      setError('请填写兼容接口名称');
      return false;
    }
    if (!baseUrl) {
      setError('请填写兼容接口 Base URL');
      return false;
    }

    if (form.custom_compat_providers.some((item) => item.name.trim().toLowerCase() === name.toLowerCase())) {
      setError(`兼容接口名称重复：${name}`);
      return false;
    }

    let fallbackIndex = form.custom_compat_providers.length + 1;
    let candidateId = buildPromptId(name, fallbackIndex);
    while (form.custom_compat_providers.some((item) => item.id === candidateId)) {
      fallbackIndex += 1;
      candidateId = buildPromptId(`${name}_${fallbackIndex}`, fallbackIndex);
    }

    setForm((prev) => ({
      ...prev,
      custom_compat_providers: [
        ...prev.custom_compat_providers,
        {
          id: candidateId,
          name,
          base_url: baseUrl,
          model: compatDraft.model.trim(),
        },
      ],
    }));
    setCompatDraft({ name: '', base_url: '', model: '' });
    setError('');
    setSuccess(`兼容接口已新增：${name}`);
    return true;
  };

  const removeCompatProvider = (providerId: string) => {
    setForm((prev) => ({
      ...prev,
      custom_compat_providers: prev.custom_compat_providers.filter((item) => item.id !== providerId),
    }));
    setError('');
  };

  const updateAiDenoiseModuleEnabled = (moduleId: AiDenoiseModuleId, enabled: boolean) => {
    setForm((prev) => ({
      ...prev,
      ai_denoise_modules: {
        ...prev.ai_denoise_modules,
        [moduleId]: enabled,
      },
    }));
    setError('');
  };

  const uploadAiSop = async () => {
    if (!sopUploadFile) {
      setError('请先选择要上传的 SOP 文件');
      return;
    }

    setSopUploading(true);
    setError('');
    setSuccess('');
    try {
      const formData = new FormData();
      formData.append('module_id', sopUploadModuleId);
      formData.append('file', sopUploadFile);
      const result = await requestApi(token, '/api_console/ai_config/sop/upload/', {
        method: 'POST',
        body: formData,
      });
      const data = result?.data || {};
      const normalizedSavedForm = normalizeForm(data?.ai_config || {});
      setForm(normalizedSavedForm);
      setSensitiveConfiguredMap(normalizeSensitiveConfigured(data?.sensitive_configured, normalizedSavedForm));
      setConfigPath(String(data?.config_path || configPath));
      setUpdatedAt(String(data?.saved_at || updatedAt));
      const moduleLabel = String(data?.module_label || aiSopModuleConfigs.find((item) => item.id === sopUploadModuleId)?.label || sopUploadModuleId);
      const sopFilePath = String(data?.sop_file || '');
      setSuccess(`SOP 上传成功：${moduleLabel}${sopFilePath ? `（${sopFilePath}）` : ''}`);
      setShowRestartModal(data?.runtime_refreshed === false);

      clearSopUploadSelection();
    } catch (err: any) {
      setError(err?.message || 'SOP 上传失败');
    } finally {
      setSopUploading(false);
    }
  };

  const toggleSensitiveDisplay = () => {
    if (sensitiveVisible) {
      setSensitiveVisible(false);
      setSensitiveVerifyPassword('');
      setSensitiveVerifyError('');
      setSensitiveEditingModelProfileIds(new Set());
      void loadAiConfig();
      return;
    }
    setSensitiveVerifyUsername(localStorage.getItem(USERNAME_KEY) || sensitiveVerifyUsername);
    setSensitiveVerifyPassword('');
    setSensitiveVerifyError('');
    setSensitiveVerifyDialogOpen(true);
  };

  const verifySensitiveDisplay = async () => {
    if (!sensitiveVerifyUsername.trim() || !sensitiveVerifyPassword) {
      setSensitiveVerifyError('请输入登录账号和密码');
      return;
    }
    setSensitiveVerifyLoading(true);
    setSensitiveVerifyError('');
    try {
      const result = await requestApi(token, '/api_console/ai_config/reveal/', {
        method: 'POST',
        body: {
          username: sensitiveVerifyUsername.trim(),
          password: sensitiveVerifyPassword,
        },
      });
      const data = result?.data || {};
      const normalizedForm = normalizeForm(data?.ai_config || {});
      setForm(normalizedForm);
      setSensitiveConfiguredMap(normalizeSensitiveConfigured(data?.sensitive_configured, normalizedForm));
      setSensitiveEditingModelProfileIds(new Set());
      setSensitiveVisible(true);
      setSensitiveVerifyDialogOpen(false);
      setSensitiveVerifyPassword('');
      setSuccess('身份验证通过，已进入 Key 编辑模式（历史 Key 不回显）');
    } catch (err: any) {
      setSensitiveVerifyError(err?.message || '验证失败');
    } finally {
      setSensitiveVerifyLoading(false);
    }
  };

  const saveAiConfig = async () => {
    const payload = buildAiPayload(form);
    if (payload.prompt_templates.length === 0) {
      setError('请至少保留一条 SOP 模板');
      return;
    }

    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/api_console/ai_config/', {
        method: 'POST',
        body: {
          ai_config: payload,
        },
      });
      const data = result?.data || {};
      const remotePresets = Array.isArray(data?.provider_presets) ? data.provider_presets : [];
      const normalizedPresets = remotePresets
        .map((item: any) => {
          const id = String(item?.id || '').trim();
          if (!id) return null;
          return {
            id,
            label: String(item?.label || id),
            base_url: String(item?.base_url || ''),
            default_model: String(item?.default_model || ''),
          };
        })
        .filter((item: AiProviderPreset | null): item is AiProviderPreset => Boolean(item));
      if (normalizedPresets.length > 0) {
        setProviderPresets(normalizedPresets);
      }
      const normalizedSavedForm = normalizeForm(data?.ai_config || payload);
      setForm(normalizedSavedForm);
      setSensitiveConfiguredMap(normalizeSensitiveConfigured(data?.sensitive_configured, normalizedSavedForm));
      setModelDraft((prev) => ({ ...prev, provider: normalizedSavedForm.provider || 'openai' }));
      setConfigPath(String(data?.config_path || configPath));
      setUpdatedAt(String(data?.saved_at || updatedAt));
      const backupText = data?.backup_path ? `，备份: ${data.backup_path}` : '';
      const runtimeRefreshed = data?.runtime_refreshed !== false;
      setSuccess(runtimeRefreshed ? `AI 管理配置已保存${backupText}` : `AI 管理配置已保存${backupText}，需重启容器生效`);
      setShowRestartModal(!runtimeRefreshed);
      setSensitiveVisible(false);
      setSensitiveVerifyPassword('');
      setSensitiveVerifyError('');
      setSensitiveEditingModelProfileIds(new Set());
    } catch (err: any) {
      setError(err?.message || '保存 AI 管理配置失败');
    } finally {
      setSaving(false);
    }
  };

  const runAiConnectivityTest = async () => {
    const payload = buildAiPayload(form);
    setTesting(true);
    setError('');
    setSuccess('');
    setTestResult(null);
    setAiTestDialogOpen(false);
    try {
      const result = await requestApi(token, '/api_console/ai_config/test/', {
        method: 'POST',
        body: {
          ai_config: payload,
        },
      });
      const data = result?.data || {};
      const detailRaw = data?.detail && typeof data.detail === 'object' ? data.detail : {};
      const detailText = Object.keys(detailRaw).length > 0 ? JSON.stringify(detailRaw, null, 2) : '';
      const normalized: AiTestResult = {
        ok: Boolean(data?.ok),
        message: String(data?.message || ''),
        provider: String(data?.provider || ''),
        profile: String(detailRaw?.profile || ''),
        model: String(detailRaw?.model || ''),
        request_text: String(detailRaw?.request_text || '你好呀～'),
        reply_text: String(detailRaw?.reply_text || ''),
        tested_at: String(data?.tested_at || ''),
        detail: detailText,
      };
      setTestResult(normalized);
      setAiTestDialogOpen(true);
      const skippedWithoutConfig = !normalized.ok && normalized.message.includes('已跳过');
      if (normalized.ok) {
        setSuccess('AI 连通性测试成功');
      } else if (skippedWithoutConfig) {
        setSuccess(normalized.message || '当前模型尚未完整配置，已跳过测试');
      } else {
        setError(normalized.message || 'AI 连通性测试失败');
      }
    } catch (err: any) {
      setError(err?.message || 'AI 连通性测试失败');
    } finally {
      setTesting(false);
      void loadAiUsageDashboard();
    }
  };

  const providerConfigLabel = providerPresetMap[providerConfigProviderId]?.label || providerConfigProviderId || 'AI';
  const providerConfigMeta = providerUiMetaMap[providerConfigProviderId] || {
    logo: 'AI',
    logoClass: 'bg-base-100 text-base-content border-base-300',
    apiKeyUrl: '',
  };
  const providerConfigApiKeyConfigured = providerConfigProfileId
    ? Boolean(sensitiveConfiguredMap.model_profile_api_keys[providerConfigProfileId])
    : false;
  const showProviderConfigApiKeyRaw = sensitiveVisible || providerConfigApiKeyEdited;
  const usageRequestCount = usageStats?.all_time?.request_count || 0;
  const usageSuccessCount = usageStats?.all_time?.success_count || 0;
  const usageErrorCount = usageStats?.all_time?.error_count || 0;
  const usageSkipCount = usageStats?.all_time?.skip_count || 0;
  const usageSuccessRate = usageRequestCount > 0 ? ((usageSuccessCount / usageRequestCount) * 100).toFixed(1) : '0.0';
  const usageAvgTokens = usageRequestCount > 0 ? Math.round((usageStats?.all_time?.total_tokens || 0) / usageRequestCount) : 0;
  const usageAvgElapsedMs = usageStats?.avg_elapsed_ms || 0;
  const usageAvgElapsedSampleCount = usageStats?.avg_elapsed_sample_count || 0;
  const usageTopModelListText = usageStats?.by_model?.slice(0, 5)
    .map((item) => `${item.provider || '-'} / ${item.model || '-'} (${item.total_tokens})`)
    .join('；') || '';
  const usageTopSceneListText = usageStats?.by_scene?.slice(0, 5)
    .map((item) => `${item.scene_label || item.scene || '-'} (${item.total_tokens})`)
    .join('；') || '';
  const usageTopErrorReasonText = usageStats?.top_error_reasons?.map((item) => `${item.reason} (${item.count})`).join('；') || '';

  return (
    <div className="bg-base-200/35 border border-base-300 rounded-2xl p-5 space-y-5">
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3">
        <div>
          <div className="text-sm font-bold tracking-wide">AI管理</div>
          <div className="text-xs text-content-muted mt-1">
            统一管理 AI 提供方、默认模型选择、对话参数与 SOP。每家 AI 独立配置，运行期每次仅使用一个默认模型。
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void loadAiConfig()}
            className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2 disabled:opacity-60"
            disabled={isActionBusy}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            重新加载
          </button>
          <button
            type="button"
            onClick={() => void runAiConnectivityTest()}
            className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2 disabled:opacity-60"
            disabled={isActionBusy}
          >
            <Play className={`w-4 h-4 ${testing ? 'animate-spin' : ''}`} />
            {testing ? '测试中...' : 'AI测试'}
          </button>
          <button
            type="button"
            onClick={toggleSensitiveDisplay}
            className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2 disabled:opacity-60"
            disabled={isActionBusy}
          >
            <Eye className="w-4 h-4" />
            {sensitiveVisible ? '退出Key编辑' : '编辑Key'}
          </button>
          <button
            type="button"
            onClick={() => void saveAiConfig()}
            className="px-4 py-2 rounded-xl bg-brand-accent text-white text-sm font-black hover:opacity-90 transition flex items-center gap-2 disabled:opacity-60"
            disabled={isActionBusy}
          >
            <Settings className={`w-4 h-4 ${saving ? 'animate-spin' : ''}`} />
            {saving ? '保存中...' : '保存配置'}
          </button>
        </div>
      </div>

      {error ? (
        <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">
          {error}
        </div>
      ) : null}
      {success ? (
        <div className="text-xs text-emerald-400 bg-emerald-400/10 border border-emerald-400/30 rounded-lg px-3 py-2">
          {success}
        </div>
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
        <div className="bg-base-100/60 border border-base-300 rounded-xl px-3 py-2">
          <span className="text-content-muted">配置文件:</span>
          <span className="font-mono ml-2">{configPath || '-'}</span>
        </div>
        <div className="bg-base-100/60 border border-base-300 rounded-xl px-3 py-2">
          <span className="text-content-muted">最近更新时间:</span>
          <span className="font-mono ml-2">{updatedAt || '-'}</span>
        </div>
      </div>

      <div className="text-xs text-amber-300 bg-amber-300/10 border border-amber-300/30 rounded-xl px-3 py-2">
        提示：AI 去噪分析支持按模块独立开关与 SOP 绑定。详情页仅展示扫描阶段已落库的分析结果，不会因点击详情而再次触发 AI 调用。
      </div>

      <div className="space-y-4 rounded-xl border border-base-300/80 bg-base-100/25 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-black tracking-wide text-base-content">AI提供方独立配置</div>
          <label className={CONSOLE_CHECKBOX_CARD_CLASS}>
            <input
              type="checkbox"
              checked={form.enable}
              onChange={(event) => setForm((prev) => ({ ...prev, enable: event.target.checked }))}
              className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
            />
            <span className="font-medium">启用 AI 能力</span>
          </label>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-[260px_minmax(0,1fr)] gap-3 items-end">
          <div className="space-y-2">
            <label htmlFor="ai-default-provider" className="text-xs font-bold text-content-muted block">
              默认 AI
            </label>
            <div className={aiSelectWrapClass}>
              <select
                id="ai-default-provider"
                value={normalizeProviderId(form.provider)}
                onChange={(event) => setDefaultAiProvider(event.target.value)}
                className={CONSOLE_SELECT_CLASS}
              >
                {providerCardList.map((provider) => (
                  <option key={provider.id} value={provider.id}>
                    {provider.label}
                  </option>
                ))}
              </select>
              <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
            </div>
          </div>
          <div className="text-[11px] text-content-muted">
            每家 AI 单独配置。点击下方卡片可弹窗设置 `API Key / 分析模型 / API Base URL / 网络代理`。卡片右上角绿色标记表示该提供方已配置 Key。
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {providerCardList.map((provider) => {
            const providerId = normalizeProviderId(provider.id);
            const profile = providerProfileMap[providerId];
            const profileId = String(profile?.id || '').trim();
            const configuredByMap = profileId ? Boolean(sensitiveConfiguredMap.model_profile_api_keys[profileId]) : false;
            const configuredByValue = Boolean(String(profile?.api_key || '').trim());
            const configured = configuredByMap || configuredByValue;
            const isDefault = normalizeProviderId(form.provider) === providerId;
            const providerMeta = providerUiMetaMap[providerId] || {
              logo: 'AI',
              logoClass: 'bg-base-100 text-base-content border-base-300',
              apiKeyUrl: '',
            };
            return (
              <div key={provider.id} className="rounded-xl border border-base-300 bg-base-100/35 p-3 space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <div className={`h-10 w-10 rounded-xl border flex items-center justify-center text-[11px] font-black tracking-wide ${providerMeta.logoClass}`}>
                      {providerMeta.logo}
                    </div>
                    <div className="min-w-0">
                      <div className="text-sm font-black truncate">{provider.label}</div>
                      <div className="text-[11px] text-content-muted truncate">
                        {isDefault ? '当前默认 AI' : '可设为默认 AI'}
                      </div>
                    </div>
                  </div>
                  <div className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-lg border text-[11px] ${
                    configured
                      ? 'text-emerald-300 border-emerald-300/40 bg-emerald-300/10'
                      : 'text-content-muted border-base-300 bg-base-100/60'
                  }`}>
                    {configured ? <CheckCircle2 className="w-3.5 h-3.5" /> : null}
                    {configured ? '已配置' : '未配置'}
                  </div>
                </div>
                <div className="text-[11px] text-content-muted space-y-1">
                  <div className="truncate">分析模型：{profile?.model || provider.default_model || '-'}</div>
                  <div className="truncate">思考模型：{profile?.reasoning_model || provider.default_reasoning_model || '-'}</div>
                  <div className="font-mono truncate">API Base URL：{profile?.base_url || provider.base_url || '-'}</div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setDefaultAiProvider(providerId)}
                    className="px-3 py-1.5 rounded-lg border border-base-300 text-xs font-semibold hover:bg-base-100/70 transition"
                  >
                    设为默认
                  </button>
                  <button
                    type="button"
                    onClick={() => openProviderConfigDialog(providerId)}
                    className="px-3 py-1.5 rounded-lg border border-base-300 text-xs font-semibold hover:bg-base-100/70 transition"
                  >
                    配置
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="space-y-4 rounded-xl border border-base-300/80 bg-base-100/25 p-4">
        <div className="text-xs font-black tracking-wide text-base-content">AI对话高级参数（可选）</div>
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 items-start">
          <div className="space-y-2">
            <label htmlFor="ai-timeout" className="text-xs font-bold text-content-muted block">
              超时时间（秒）
            </label>
            <input
              id="ai-timeout"
              type="number"
              min={1}
              value={String(form.timeout_sec)}
              onChange={(event) =>
                updateActiveModelProfile((active) => ({
                  ...active,
                  timeout_sec: Number(event.target.value || 0),
                }))
              }
              className={aiInputClass}
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="ai-temperature" className="text-xs font-bold text-content-muted block">
              温度（Temperature）
            </label>
            <input
              id="ai-temperature"
              type="number"
              min={0}
              step={0.1}
              value={String(form.temperature)}
              onChange={(event) =>
                updateActiveModelProfile((active) => ({
                  ...active,
                  temperature: Number(event.target.value || 0),
                }))
              }
              className={aiInputClass}
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="ai-max-tokens" className="text-xs font-bold text-content-muted block">
              最大 Tokens
            </label>
            <input
              id="ai-max-tokens"
              type="number"
              min={1}
              value={String(form.max_tokens)}
              onChange={(event) =>
                updateActiveModelProfile((active) => ({
                  ...active,
                  max_tokens: Number(event.target.value || 0),
                }))
              }
              className={aiInputClass}
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="ai-request-delay" className="text-xs font-bold text-content-muted block">
              请求延迟（毫秒）
            </label>
            <input
              id="ai-request-delay"
              type="number"
              min={0}
              value={String(form.request_delay_ms)}
              onChange={(event) =>
                setForm((prev) => ({ ...prev, request_delay_ms: Number(event.target.value || 0) }))
              }
              className={aiInputClass}
              placeholder="默认 0（不延迟）"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="ai-dialog-language" className="text-xs font-bold text-content-muted block">
              输出语言
            </label>
            <div className={aiSelectWrapClass}>
              <select
                id="ai-dialog-language"
                value={form.dialog_language}
                onChange={(event) => setForm((prev) => ({ ...prev, dialog_language: event.target.value }))}
                className={CONSOLE_SELECT_CLASS}
              >
                <option value="zh-CN">中文</option>
                <option value="en-US">英文</option>
              </select>
              <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
            </div>
          </div>
          <div className="space-y-2">
            <label htmlFor="ai-dialog-context" className="text-xs font-bold text-content-muted block">
              上下文消息数
            </label>
            <input
              id="ai-dialog-context"
              type="number"
              min={1}
              value={String(form.dialog_context_messages)}
              onChange={(event) =>
                setForm((prev) => ({ ...prev, dialog_context_messages: Number(event.target.value || 0) }))
              }
              className={aiInputClass}
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="ai-wih-endpoint-max-targets" className="text-xs font-bold text-content-muted block">
              WIH接口AI填充上限
            </label>
            <input
              id="ai-wih-endpoint-max-targets"
              type="number"
              min={0}
              max={5000}
              value={String(form.wih_endpoint_ai_fill_max_targets)}
              onChange={(event) =>
                setForm((prev) => ({
                  ...prev,
                  wih_endpoint_ai_fill_max_targets: Number(event.target.value || 0),
                }))
              }
              className={aiInputClass}
              placeholder="默认 0"
            />
            <div className="text-[11px] text-content-muted">
              单次任务里允许进入 AI 填充的 `WIH` 接口数量上限，`0` 表示不限制。
            </div>
          </div>
          <div className="space-y-2 xl:col-span-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <label htmlFor="ai-dialog-system-prompt" className="text-xs font-bold text-content-muted block">
                更多可选参数（默认可不填）
              </label>
              <button
                type="button"
                onClick={() => setDialogSystemPromptOpen((prev) => !prev)}
                className="px-3 py-1.5 rounded-lg border border-base-300 text-xs font-semibold hover:bg-base-100/70 transition"
              >
                {dialogSystemPromptOpen ? '收起可选参数' : '展开可选参数'}
              </button>
            </div>
            {dialogSystemPromptOpen ? (
              <div className="space-y-3">
                <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
                  <div className="space-y-2">
                    <label htmlFor="ai-dialog-style" className="text-xs font-bold text-content-muted block">
                      回复风格
                    </label>
                    <input
                      id="ai-dialog-style"
                      value={form.dialog_style}
                      onChange={(event) => setForm((prev) => ({ ...prev, dialog_style: event.target.value }))}
                      className={aiInputClass}
                      placeholder="默认：专业"
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <label htmlFor="ai-dialog-system-prompt" className="text-xs font-bold text-content-muted block">
                    系统提示词
                  </label>
                  <textarea
                    id="ai-dialog-system-prompt"
                    value={form.dialog_system_prompt}
                    onChange={(event) => setForm((prev) => ({ ...prev, dialog_system_prompt: event.target.value }))}
                    className={`${CONSOLE_TEXTAREA_MONO_CLASS} min-h-[100px]`}
                    placeholder="用于统一约束 AI 输出风格与格式（可选）"
                  />
                </div>
              </div>
            ) : (
              <div className="text-[11px] text-content-muted">默认使用“专业”回复风格，只有需要细调时再展开设置。</div>
            )}
          </div>
        </div>
      </div>

      <div className="space-y-4 rounded-xl border border-base-300/80 bg-base-100/25 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-black tracking-wide text-base-content">AI功能开关配置</div>
          <div className="flex flex-wrap items-center gap-2">
            <label className={`${CONSOLE_CHECKBOX_CARD_CLASS} h-9 px-2.5`}>
              <input
                type="checkbox"
                checked={form.ai_denoise_enable}
                onChange={(event) => setForm((prev) => ({ ...prev, ai_denoise_enable: event.target.checked }))}
                className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
              />
              <span className="text-xs font-semibold">启用AI去噪</span>
            </label>
            <label className={`${CONSOLE_CHECKBOX_CARD_CLASS} h-9 px-2.5`}>
              <input
                type="checkbox"
                checked={form.ai_wih_endpoint_fill_enable}
                onChange={(event) => setForm((prev) => ({ ...prev, ai_wih_endpoint_fill_enable: event.target.checked }))}
                className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
              />
              <span className="text-xs font-semibold">启用WIH接口AI填充</span>
            </label>
          </div>
        </div>
        <div className="text-xs text-content-muted">
          WIH接口AI填充会优先根据请求报文、参数名和请求体形态补齐低副作用测试值，再把测试摘要交给后续 AI 去噪使用。AI去噪支持站点、目录扫描、SSL证书、URL信息、WIH接口、风险、PoC风险独立开关。对应 SOP 在下方「SOP管理」中上传维护。
        </div>
        <div className="rounded-xl border border-base-300 bg-base-100/35 p-3 grid grid-cols-1 xl:grid-cols-[180px_auto_1fr] gap-3 items-center">
          <div className="text-sm font-semibold">WIH接口AI填充</div>
          <label className={`${CONSOLE_CHECKBOX_CARD_CLASS} h-9 px-2.5`}>
            <input
              type="checkbox"
              checked={Boolean(form.ai_wih_endpoint_fill_enable)}
              onChange={(event) => setForm((prev) => ({ ...prev, ai_wih_endpoint_fill_enable: event.target.checked }))}
              className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
            />
            <span className="text-xs font-semibold">{form.ai_wih_endpoint_fill_enable ? '已开启' : '已关闭'}</span>
          </label>
          <div className="text-xs text-content-muted break-all">
            <div>
              SOP：{sopTemplateMap.wih_endpoint_fill?.name || '-'}{sopTemplateMap.wih_endpoint_fill?.scene ? ` (${sopTemplateMap.wih_endpoint_fill?.scene})` : ''}
            </div>
            <div className="font-mono mt-1">{sopTemplateMap.wih_endpoint_fill?.file || '-'}</div>
          </div>
        </div>
        <div className="space-y-2">
          {aiDenoiseModuleConfigs.map((moduleConfig) => {
            const moduleEnabled = Boolean(form.ai_denoise_modules[moduleConfig.id]);
            const sopTemplate = sopTemplateMap[moduleConfig.id];
            return (
              <div
                key={moduleConfig.id}
                className="rounded-xl border border-base-300 bg-base-100/35 p-3 grid grid-cols-1 xl:grid-cols-[180px_auto_1fr] gap-3 items-center"
              >
                <div className="text-sm font-semibold">{moduleConfig.label}</div>
                <label className={`${CONSOLE_CHECKBOX_CARD_CLASS} h-9 px-2.5`}>
                  <input
                    type="checkbox"
                    checked={moduleEnabled}
                    onChange={(event) => updateAiDenoiseModuleEnabled(moduleConfig.id, event.target.checked)}
                    className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
                    disabled={!form.ai_denoise_enable}
                  />
                  <span className="text-xs font-semibold">{moduleEnabled ? '已开启' : '已关闭'}</span>
                </label>
                <div className="text-xs text-content-muted break-all">
                  <div>
                    SOP：{sopTemplate?.name || '-'}{sopTemplate?.scene ? ` (${sopTemplate.scene})` : ''}
                  </div>
                  <div className="font-mono mt-1">{sopTemplate?.file || '-'}</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="space-y-4 rounded-xl border border-base-300/80 bg-base-100/25 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-black tracking-wide text-base-content">SOP管理</div>
        </div>
        <div className="text-xs text-content-muted">
          提示词管理已改为 SOP 管理。仅支持上传 `.yaml/.yml` SOP 文件，不支持页面内在线编辑。内置模块包括：站点、目录扫描、SSL证书、URL信息、WIH接口AI填充、WIH接口价值去噪、风险、PoC风险。
        </div>
        <div className="grid grid-cols-1 xl:grid-cols-[220px_minmax(0,1fr)_auto] gap-3 items-end">
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">目标模块</label>
            <div className="relative">
              <select
                value={sopUploadModuleId}
                onChange={(event) => setSopUploadModuleId(event.target.value as AiSopModuleId)}
                className={CONSOLE_SELECT_CLASS}
                disabled={sopUploading}
              >
                {aiSopModuleConfigs.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.label}
                  </option>
                ))}
              </select>
              <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
            </div>
          </div>
          <div className="space-y-2">
            <label htmlFor="ai-sop-upload-input" className="text-xs font-bold text-content-muted block">
              选择SOP文件（.yaml/.yml）
            </label>
            <input
              id="ai-sop-upload-input"
              ref={sopUploadInputRef}
              type="file"
              accept=".yaml,.yml"
              className="hidden"
              onClick={(event) => {
                event.currentTarget.value = '';
              }}
              onChange={handleSopFileChange}
              disabled={sopUploading}
            />
            <div className="flex flex-col lg:flex-row gap-2">
              <button
                type="button"
                onClick={() => sopUploadInputRef.current?.click()}
                className="px-4 py-2 h-10 rounded-xl border border-base-300 text-sm font-semibold whitespace-nowrap hover:bg-base-100/70 transition flex items-center justify-center disabled:opacity-60"
                disabled={sopUploading}
              >
                选择文件
              </button>
              <div className={aiUploadFilenameClass}>{sopUploadFile?.name || '未选择文件'}</div>
              <button
                type="button"
                onClick={clearSopUploadSelection}
                className="px-3 py-2 h-10 rounded-xl border border-base-300 text-xs font-semibold whitespace-nowrap hover:bg-base-100/70 transition disabled:opacity-60"
                disabled={sopUploading || !sopUploadFile}
              >
                清空
              </button>
            </div>
          </div>
          <button
            type="button"
            onClick={() => void uploadAiSop()}
            className="px-4 py-2 h-10 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition disabled:opacity-60 flex items-center gap-2"
            disabled={sopUploading}
          >
            <Upload className={`w-4 h-4 ${sopUploading ? 'animate-pulse' : ''}`} />
            {sopUploading ? '上传中...' : '上传SOP'}
          </button>
        </div>

        <div className="space-y-2">
          {aiSopModuleConfigs.map((moduleConfig) => {
            const template = sopTemplateMap[moduleConfig.id];
            return (
              <div key={moduleConfig.id} className="rounded-xl border border-base-300 bg-base-100/35 p-3">
                <div className="grid grid-cols-1 xl:grid-cols-[140px_220px_1fr_160px] gap-3 text-xs">
                  <div>
                    <div className="text-content-muted">模块</div>
                    <div className="text-sm font-semibold text-base-content">{moduleConfig.label}</div>
                  </div>
                  <div>
                    <div className="text-content-muted">SOP模板</div>
                    <div className="text-base-content">{template?.name || '-'}</div>
                    <div className="text-content-muted">{template?.scene || moduleConfig.scene}</div>
                  </div>
                  <div className="min-w-0">
                    <div className="text-content-muted">文件</div>
                    <div className="font-mono break-all">{template?.file || '-'}</div>
                  </div>
                  <div>
                    <div className="text-content-muted">更新时间</div>
                    <div className="font-mono">{template?.updated_at || '-'}</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="space-y-4 rounded-xl border border-base-300/80 bg-base-100/25 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-black tracking-wide text-base-content">Token用量统计与AI对话日志</div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-[120px]">
              <select
                value={usageLogStatus}
                onChange={(event) => setUsageLogStatus(event.target.value)}
                className={CONSOLE_SELECT_CLASS}
                disabled={usageLoading}
              >
                <option value="">全部状态</option>
                <option value="ok">成功</option>
                <option value="error">失败</option>
                <option value="skipped">跳过</option>
              </select>
              <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
            </div>
            <div className="relative min-w-[180px]">
              <select
                value={usageLogScene}
                onChange={(event) => setUsageLogScene(event.target.value)}
                className={CONSOLE_SELECT_CLASS}
                disabled={usageLoading}
              >
                <option value="">全部场景</option>
                {usageSceneOptions.map((item) => (
                  <option key={item.scene} value={item.scene}>
                    {item.scene_label}
                  </option>
                ))}
              </select>
              <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
            </div>
            <div className="relative min-w-[120px]">
              <select
                value={usageLogLimit}
                onChange={(event) => setUsageLogLimit(event.target.value)}
                className={CONSOLE_SELECT_CLASS}
                disabled={usageLoading}
              >
                <option value="10">最近10条</option>
                <option value="20">最近20条</option>
                <option value="40">最近40条</option>
              </select>
              <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
            </div>
            <button
              type="button"
              onClick={() => void loadAiUsageDashboard()}
              className="px-3 py-1.5 rounded-lg border border-base-300 text-xs font-semibold hover:bg-base-100/70 transition flex items-center gap-2 disabled:opacity-60"
              disabled={usageLoading}
            >
              <RefreshCw className={`w-4 h-4 ${usageLoading ? 'animate-spin' : ''}`} />
              刷新统计
            </button>
          </div>
        </div>

        {usageStats ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="rounded-xl border border-base-300 bg-base-100/40 p-3 space-y-1">
              <div className="text-xs text-content-muted">累计总量</div>
              <div className="text-sm font-black">Total {usageStats.all_time.total_tokens}</div>
              <div className="text-[11px] text-content-muted">
                Prompt {usageStats.all_time.prompt_tokens} / Completion {usageStats.all_time.completion_tokens}
              </div>
              <div className="text-[11px] text-content-muted">
                请求 {usageStats.all_time.request_count} | 成功 {usageStats.all_time.success_count} | 失败 {usageStats.all_time.error_count}
              </div>
            </div>
            <div className="rounded-xl border border-base-300 bg-base-100/40 p-3 space-y-1">
              <div className="text-xs text-content-muted">总体成功率</div>
              <div className="text-sm font-black">{usageSuccessRate}%</div>
              <div className="text-[11px] text-content-muted">
                成功 {usageSuccessCount} / 请求 {usageRequestCount}
              </div>
              <div className="text-[11px] text-content-muted">
                失败 {usageErrorCount} | 跳过 {usageSkipCount}
              </div>
            </div>
            <div className="rounded-xl border border-base-300 bg-base-100/40 p-3 space-y-1">
              <div className="text-xs text-content-muted">平均响应耗时</div>
              <div className="text-sm font-black">{usageAvgElapsedMs} ms</div>
              <div className="text-[11px] text-content-muted">
                统计样本：{usageAvgElapsedSampleCount}
              </div>
              <div className="text-[11px] text-content-muted">
                单次平均Token：{usageAvgTokens}
              </div>
            </div>
          </div>
        ) : (
          <div className="text-xs text-content-muted">暂无 Token 统计数据。</div>
        )}

        {usageTopModelListText ? (
          <div className="text-[11px] text-content-muted">
            最近{usageStats?.window_days || 7}天高频模型Top5：{usageTopModelListText}
          </div>
        ) : null}

        {usageTopSceneListText ? (
          <div className="text-[11px] text-content-muted">
            最近{usageStats?.window_days || 7}天高消耗场景Top5：{usageTopSceneListText}
          </div>
        ) : null}

        {usageTopErrorReasonText ? (
          <div className="text-[11px] text-content-muted">
            最近{usageStats?.window_days || 7}天失败原因Top3：{usageTopErrorReasonText}
          </div>
        ) : null}

        <div className="rounded-xl border border-base-300 bg-base-100/35 overflow-hidden">
          <div className="px-3 py-2 text-xs text-content-muted border-b border-base-300 flex items-center justify-between gap-2">
            <span>最近对话日志（显示最新 {usageLogs.length} / 总计 {usageLogsTotal}）</span>
            <span>{usageLogsUpdatedAt ? `更新时间：${usageLogsUpdatedAt}` : ''}</span>
          </div>
          <DataTable
            dense
            tableClass="text-xs"
            emptyText="暂无日志记录"
            rows={usageLogs}
            rowKey={(item, index) => item.id || `${item.created_at}-${item.scene}-${item.model}-${index}`}
            columns={[
              { key: 'created_at', header: '时间', headerClass: 'text-content-muted text-left', cellClass: 'text-left whitespace-nowrap', render: (item: any) => item.created_at || '-' },
              { key: 'scene', header: '场景', headerClass: 'text-content-muted text-left', cellClass: 'text-left whitespace-nowrap', render: (item: any) => item.scene_label || item.scene || '-' },
              {
                key: 'status',
                header: '状态',
                headerClass: 'text-content-muted text-left',
                cellClass: 'text-left whitespace-nowrap',
                render: (item: any) => (
                  <span
                    className={`inline-flex items-center px-2 py-0.5 rounded border ${
                      item.status === 'ok'
                        ? 'text-emerald-300 border-emerald-300/40 bg-emerald-300/10'
                        : item.status === 'skipped'
                          ? 'text-amber-300 border-amber-300/40 bg-amber-300/10'
                          : 'text-error border-error/40 bg-error/10'
                    }`}
                  >
                    {item.status === 'ok' ? '成功' : item.status === 'skipped' ? '跳过' : '失败'}
                  </span>
                ),
              },
              {
                key: 'model',
                header: '模型',
                headerClass: 'text-content-muted text-left',
                cellClass: 'text-left whitespace-nowrap',
                render: (item: any) => (
                  <>
                    <div>{item.provider || '-'}</div>
                    <div className="text-[11px] text-content-muted">{item.model || '-'}</div>
                  </>
                ),
              },
              {
                key: 'tokens',
                header: 'Tokens',
                headerClass: 'text-content-muted text-left',
                cellClass: 'text-left whitespace-nowrap',
                render: (item: any) => (
                  <>
                    <div>Total {item.total_tokens}</div>
                    <div className="text-[11px] text-content-muted">
                      P {item.prompt_tokens} / C {item.completion_tokens}
                    </div>
                  </>
                ),
              },
              { key: 'request_text', header: '用户输入摘要', headerClass: 'text-content-muted text-left', cellClass: 'text-left max-w-[260px] whitespace-normal break-all text-[11px] leading-5', render: (item: any) => getUsageLogPreviewText(item.request_text, 88) },
              { key: 'reply_text', header: 'AI回复摘要', headerClass: 'text-content-muted text-left', cellClass: 'text-left max-w-[300px] whitespace-normal break-all text-[11px] leading-5', render: (item: any) => getUsageLogPreviewText(item.reply_text || item.error_message, 96) },
              {
                key: 'action',
                header: '操作',
                headerClass: 'text-content-muted text-left',
                cellClass: 'text-left whitespace-nowrap',
                render: (item: any) => (
                  <button
                    type="button"
                    onClick={() => setUsageLogDetail(item)}
                    className="px-2 py-1 rounded-lg border border-base-300 text-[11px] font-semibold hover:bg-base-100/70 transition"
                  >
                    查看详情
                  </button>
                ),
              },
            ]}
          />
        </div>
        {usageError ? (
          <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">
            {usageError}
          </div>
        ) : null}
      </div>

      {providerConfigDialogOpen ? (
        <Modal open onClose={closeProviderConfigDialog} boxClass="w-full max-w-2xl!">
            <div className="px-5 py-4 border-b border-base-300 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 min-w-0">
                <div className={`h-8 w-8 rounded-lg border flex items-center justify-center text-[10px] font-black tracking-wide ${providerConfigMeta.logoClass}`}>
                  {providerConfigMeta.logo}
                </div>
                <div className="text-sm font-black tracking-wide truncate">配置 {providerConfigLabel}</div>
              </div>
              <button
                type="button"
                onClick={closeProviderConfigDialog}
                className="p-1.5 rounded-lg border border-base-300 hover:bg-base-100/70 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-3">
              <div className="space-y-2">
                <label htmlFor="provider-config-api-key" className="text-xs font-bold text-content-muted block">
                  API Key
                </label>
                <input
                  id="provider-config-api-key"
                  type={showProviderConfigApiKeyRaw ? 'text' : 'password'}
                  value={providerConfigDraft.api_key}
                  onChange={(event) => {
                    setProviderConfigApiKeyEdited(true);
                    setProviderConfigDraft((prev) => ({ ...prev, api_key: event.target.value }));
                  }}
                  className={aiInputMonoClass}
                  placeholder={
                    providerConfigApiKeyConfigured && !showProviderConfigApiKeyRaw
                      ? '已配置（留空保持不变，输入新值将覆盖）'
                      : '请输入 API Key'
                  }
                  autoComplete="off"
                />
                {providerConfigMeta.apiKeyUrl ? (
                  <a
                    href={providerConfigMeta.apiKeyUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-accent hover:underline inline-flex items-center gap-1"
                  >
                    从{providerConfigLabel}获取 API Key
                  </a>
                ) : null}
              </div>

              <div className="space-y-2">
                <label htmlFor="provider-config-model" className="text-xs font-bold text-content-muted block">
                  分析模型
                </label>
                <input
                  id="provider-config-model"
                  value={providerConfigDraft.model}
                  onChange={(event) => setProviderConfigDraft((prev) => ({ ...prev, model: event.target.value }))}
                  className={aiInputMonoClass}
                  placeholder="例如 deepseek-chat / qwen-plus / gpt-4o-mini"
                />
              </div>

              <div className="space-y-2">
                <label htmlFor="provider-config-reasoning-model" className="text-xs font-bold text-content-muted block">
                  思考模型
                </label>
                <input
                  id="provider-config-reasoning-model"
                  value={providerConfigDraft.reasoning_model}
                  onChange={(event) => setProviderConfigDraft((prev) => ({ ...prev, reasoning_model: event.target.value }))}
                  className={aiInputMonoClass}
                  placeholder="留空时默认跟随分析模型；也可单独填写专用思考模型"
                />
              </div>

              <div className="space-y-2">
                <label htmlFor="provider-config-base-url" className="text-xs font-bold text-content-muted block">
                  API Base URL
                </label>
                <input
                  id="provider-config-base-url"
                  value={providerConfigDraft.base_url}
                  onChange={(event) => setProviderConfigDraft((prev) => ({ ...prev, base_url: event.target.value }))}
                  className={aiInputMonoClass}
                  placeholder="https://api.deepseek.com/v1"
                />
              </div>

              <div className="space-y-2">
                <label htmlFor="provider-config-proxy" className="text-xs font-bold text-content-muted block">
                  网络代理
                </label>
                <input
                  id="provider-config-proxy"
                  value={providerConfigDraft.proxy}
                  onChange={(event) => setProviderConfigDraft((prev) => ({ ...prev, proxy: event.target.value }))}
                  className={aiInputMonoClass}
                  placeholder="支持 http:// / https:// / socks5://"
                />
              </div>
            </div>

            <div className="px-5 py-4 border-t border-base-300 flex justify-end gap-2 bg-base-100/25">
              <button
                type="button"
                onClick={closeProviderConfigDialog}
                className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition"
              >
                取消
              </button>
              <button
                type="button"
                onClick={saveProviderConfigDraft}
                className="px-4 py-2 rounded-xl bg-brand-accent text-white text-sm font-black hover:opacity-90 transition"
              >
                保存
              </button>
            </div>
        </Modal>
      ) : null}

      {compatDialogOpen ? (
        <Modal open onClose={() => setCompatDialogOpen(false)} boxClass="w-full max-w-2xl!">
            <div className="px-5 py-4 border-b border-base-300 flex items-center justify-between gap-3">
              <div className="text-sm font-black tracking-wide">添加 OpenAI 兼容接口</div>
              <button
                type="button"
                onClick={() => setCompatDialogOpen(false)}
                className="p-1.5 rounded-lg border border-base-300 hover:bg-base-100/70 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5 space-y-3">
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
                <input
                  value={compatDraft.name}
                  onChange={(event) => setCompatDraft((prev) => ({ ...prev, name: event.target.value }))}
                  className={CONSOLE_INPUT_CLASS}
                  placeholder="接口名称（必填）"
                />
                <input
                  value={compatDraft.base_url}
                  onChange={(event) => setCompatDraft((prev) => ({ ...prev, base_url: event.target.value }))}
                  className={`${CONSOLE_INPUT_MONO_CLASS} xl:col-span-2`}
                  placeholder="Base URL（必填）"
                />
                <input
                  value={compatDraft.model}
                  onChange={(event) => setCompatDraft((prev) => ({ ...prev, model: event.target.value }))}
                  className={CONSOLE_INPUT_CLASS}
                  placeholder="默认模型（可选）"
                />
              </div>
              <div className="text-xs text-content-muted">
                保存配置后，该接口会出现在「模型提供方 = OpenAI 兼容接口」的可套用列表中。
              </div>
            </div>
            <div className="px-5 py-4 border-t border-base-300 flex justify-end gap-2 bg-base-100/25">
              <button
                type="button"
                onClick={() => setCompatDialogOpen(false)}
                className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition"
              >
                取消
              </button>
              <button
                type="button"
                onClick={() => {
                  const ok = addCompatProvider();
                  if (ok) setCompatDialogOpen(false);
                }}
                className="px-4 py-2 rounded-xl bg-brand-accent text-white text-sm font-black hover:opacity-90 transition"
              >
                确认添加
              </button>
            </div>
        </Modal>
      ) : null}

      {showRestartModal ? (
        <Modal open onClose={() => setShowRestartModal(false)} boxClass="w-full max-w-md!">
            <div className="px-6 py-4 border-b border-base-300 flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              <h4 className="text-lg font-black tracking-wide">需要重启容器</h4>
            </div>
            <div className="px-6 py-5 space-y-4">
              <p className="text-sm font-semibold">AI 配置保存成功！</p>
              <p className="text-sm text-content-muted leading-relaxed">
                当前运行环境未完成热加载，请在服务器执行重启命令使配置生效：
              </p>
              <div className="bg-base-100/50 border border-base-300 rounded-lg p-3">
                <code className="text-xs text-accent font-mono block select-all">
                  docker-compose restart
                </code>
              </div>
              <p className="text-xs text-content-muted">(或使用 ./restart.sh 脚本)</p>
            </div>
            <div className="px-6 py-4 border-t border-base-300 flex justify-end bg-base-100/30">
              <button
                type="button"
                onClick={() => setShowRestartModal(false)}
                className="px-5 py-2.5 rounded-xl bg-brand-accent hover:opacity-90 transition text-sm font-black tracking-wider shadow-lg shadow-accent/20"
              >
                我知道了
              </button>
            </div>
        </Modal>
      ) : null}

      {usageLogDetail ? (
        <Modal open onClose={() => setUsageLogDetail(null)} boxClass="w-full max-w-4xl!">
            <div className="px-5 py-4 border-b border-base-300 flex items-center justify-between gap-3">
              <div className="text-sm font-black tracking-wide min-w-0 break-all">AI对话日志详情</div>
              <button
                type="button"
                onClick={() => setUsageLogDetail(null)}
                className="p-1.5 rounded-lg border border-base-300 hover:bg-base-100/70 transition shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5 space-y-3 overflow-y-auto min-h-0">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-content-muted">
                <div className="break-all">时间：{usageLogDetail.created_at || '-'}</div>
                <div className="break-all">场景：{usageLogDetail.scene_label || usageLogDetail.scene || '-'}</div>
                <div className="break-all">状态：{usageLogDetail.status === 'ok' ? '成功' : usageLogDetail.status === 'skipped' ? '跳过' : '失败'}</div>
                <div className="break-all">模型：{usageLogDetail.provider || '-'} / {usageLogDetail.model || '-'}</div>
                <div className="break-all">配置：{usageLogDetail.profile || '-'}</div>
                <div className="break-all">Tokens：Total {usageLogDetail.total_tokens}（P {usageLogDetail.prompt_tokens} / C {usageLogDetail.completion_tokens}）</div>
              </div>
              <div className="space-y-2 rounded-xl border border-base-300 bg-base-100/35 p-3">
                <div className="text-xs font-semibold">用户输入</div>
                <pre className="max-h-[220px] overflow-auto text-xs rounded-lg border border-base-300/70 bg-base-100 px-3 py-2 whitespace-pre-wrap break-all">
                  {usageLogDetail.request_text || '-'}
                </pre>
                <div className="text-xs font-semibold pt-1">AI回复</div>
                <pre className="max-h-[260px] overflow-auto text-xs rounded-lg border border-base-300/70 bg-base-100 px-3 py-2 whitespace-pre-wrap break-all">
                  {usageLogDetail.reply_text || usageLogDetail.error_message || '-'}
                </pre>
              </div>
            </div>
            <div className="px-5 py-4 border-t border-base-300 flex justify-end gap-2 bg-base-100/25">
              <button
                type="button"
                onClick={() => setUsageLogDetail(null)}
                className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition"
              >
                关闭
              </button>
            </div>
        </Modal>
      ) : null}

      {aiTestDialogOpen && testResult ? (
        <Modal open onClose={() => setAiTestDialogOpen(false)} boxClass="w-full max-w-2xl!">
            <div className="px-5 py-4 border-b border-base-300 flex items-center justify-between gap-3">
              <div className="text-sm font-black tracking-wide">AI测试结果</div>
              <button
                type="button"
                onClick={() => setAiTestDialogOpen(false)}
                className="p-1.5 rounded-lg border border-base-300 hover:bg-base-100/70 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5 space-y-3 overflow-y-auto min-h-0">
              <div
                className={`text-xs rounded-lg px-3 py-2 border ${
                  testResult.ok
                    ? 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30'
                    : testResult.message.includes('已跳过')
                      ? 'text-amber-300 bg-amber-300/10 border-amber-300/30'
                      : 'text-error bg-error/10 border-error/30'
                }`}
              >
                {testResult.message || '-'}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-content-muted">
                <div>提供方：{testResult.provider || '-'}</div>
                <div>模型：{testResult.model || '-'}</div>
                <div>配置：{testResult.profile || '-'}</div>
                <div>测试时间：{testResult.tested_at || '-'}</div>
              </div>
              <div className="space-y-2 rounded-xl border border-base-300 bg-base-100/35 p-3">
                <div className="text-xs font-semibold">用户发送</div>
                <div className="text-sm rounded-lg border border-base-300/70 bg-base-100 px-3 py-2 whitespace-pre-wrap break-all">
                  {testResult.request_text || '你好呀～'}
                </div>
                <div className="text-xs font-semibold pt-1">AI回复</div>
                <div className="text-sm rounded-lg border border-base-300/70 bg-base-100 px-3 py-2 whitespace-pre-wrap break-all min-h-[44px]">
                  {testResult.reply_text || '-'}
                </div>
              </div>
              {testResult.detail ? (
                <details className="text-xs text-content-muted">
                  <summary className="cursor-pointer select-none">调试详情</summary>
                  <pre className="mt-2 max-h-[300px] overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] bg-base-100/45 border border-base-300 rounded-lg p-3">
                    {testResult.detail}
                  </pre>
                </details>
              ) : null}
            </div>
            <div className="px-5 py-4 border-t border-base-300 flex justify-end gap-2 bg-base-100/25">
              <button
                type="button"
                onClick={() => setAiTestDialogOpen(false)}
                className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition"
              >
                关闭
              </button>
            </div>
        </Modal>
      ) : null}
      <SensitiveRevealVerifyModal
        open={sensitiveVerifyDialogOpen}
        title="进入 AI Key 编辑模式需要身份验证"
        username={sensitiveVerifyUsername}
        password={sensitiveVerifyPassword}
        loading={sensitiveVerifyLoading}
        error={sensitiveVerifyError}
        onClose={() => {
          setSensitiveVerifyDialogOpen(false);
          setSensitiveVerifyPassword('');
          setSensitiveVerifyError('');
        }}
        onConfirm={() => void verifySensitiveDisplay()}
        onUsernameChange={setSensitiveVerifyUsername}
        onPasswordChange={setSensitiveVerifyPassword}
      />
    </div>
  );
}
