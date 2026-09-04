import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';
import {
  CheckCircle2,
  Eye,
  Key,
  Play,
  RefreshCw,
  Settings,
  X,
} from 'lucide-react';
import { USERNAME_KEY, requestApi } from '../api/client';
import { SensitiveRevealVerifyModal } from '../components/domain/SensitiveRevealVerifyModal';
import { Modal } from '../components/ui/Modal';
import { PageHeader } from '../layout/PageHeader';
import { CONSOLE_INPUT_MONO_CLASS } from '../ui/classes';

export function ApiConsoleView({ token }: { token: string }) {
  type ServiceApiForm = {
    fofa_url: string;
    fofa_email: string;
    fofa_key: string;
    fofa_enable: boolean;
    hunter_api_key: string;
    hunter_enable: boolean;
    hunter_request_interval: string;
    hunter_rate_limit_retry: string;
    hunter_rate_limit_backoff: string;
    hunter_rate_limit_max_sleep: string;
    hunter_how_api_key: string;
    hunter_how_enable: boolean;
    hunter_how_page_size: string;
    hunter_how_max_page: string;
    hunter_how_request_interval: string;
    hunter_how_rate_limit_retry: string;
    hunter_how_rate_limit_backoff: string;
    hunter_how_rate_limit_max_sleep: string;
    shodan_api_key: string;
    shodan_enable: boolean;
    shodan_max_page: string;
    shodan_request_interval: string;
    shodan_rate_limit_retry: string;
    shodan_rate_limit_backoff: string;
    shodan_rate_limit_max_sleep: string;
    quake_token: string;
    quake_enable: boolean;
    quake_rate_limit_retry: string;
    quake_rate_limit_backoff: string;
    quake_rate_limit_max_sleep: string;
    zoomeye_api_key: string;
    zoomeye_enable: boolean;
    zoomeye_max_page: string;
    zoomeye_request_interval: string;
    zoomeye_rate_limit_retry: string;
    zoomeye_rate_limit_backoff: string;
    zoomeye_rate_limit_max_sleep: string;
    securitytrails_api_key: string;
    securitytrails_enable: boolean;
    virustotal_api_key: string;
    virustotal_enable: boolean;
    chaos_api_key: string;
    chaos_enable: boolean;
    passivetotal_email: string;
    passivetotal_key: string;
    passivetotal_enable: boolean;
    github_token: string;
  };

  type ServiceApiProviderTestResult = {
    ok: boolean;
    message: string;
    detail: string;
    testedAt: string;
  };

  type ServiceApiBatchTestItem = ServiceApiProviderTestResult & {
    providerId: string;
    label: string;
  };

  type ServiceApiBatchTestSummary = {
    total: number;
    successCount: number;
    failCount: number;
    testedAt: string;
    message: string;
  };

  type ServiceApiBoolKey =
    | 'fofa_enable'
    | 'hunter_enable'
    | 'hunter_how_enable'
    | 'shodan_enable'
    | 'quake_enable'
    | 'zoomeye_enable'
    | 'securitytrails_enable'
    | 'virustotal_enable'
    | 'chaos_enable'
    | 'passivetotal_enable';

  type ServiceApiStringKey = Exclude<keyof ServiceApiForm, ServiceApiBoolKey>;

  const defaultForm: ServiceApiForm = {
    fofa_url: 'https://fofa.info',
    fofa_email: '',
    fofa_key: '',
    fofa_enable: true,
    hunter_api_key: '',
    hunter_enable: true,
    hunter_request_interval: '1.0',
    hunter_rate_limit_retry: '4',
    hunter_rate_limit_backoff: '2',
    hunter_rate_limit_max_sleep: '60',
    hunter_how_api_key: '',
    hunter_how_enable: false,
    hunter_how_page_size: '100',
    hunter_how_max_page: '5',
    hunter_how_request_interval: '1.0',
    hunter_how_rate_limit_retry: '4',
    hunter_how_rate_limit_backoff: '2',
    hunter_how_rate_limit_max_sleep: '60',
    shodan_api_key: '',
    shodan_enable: false,
    shodan_max_page: '20',
    shodan_request_interval: '1.0',
    shodan_rate_limit_retry: '4',
    shodan_rate_limit_backoff: '2',
    shodan_rate_limit_max_sleep: '60',
    quake_token: '',
    quake_enable: true,
    quake_rate_limit_retry: '4',
    quake_rate_limit_backoff: '3',
    quake_rate_limit_max_sleep: '90',
    zoomeye_api_key: '',
    zoomeye_enable: true,
    zoomeye_max_page: '20',
    zoomeye_request_interval: '1.0',
    zoomeye_rate_limit_retry: '4',
    zoomeye_rate_limit_backoff: '2',
    zoomeye_rate_limit_max_sleep: '60',
    securitytrails_api_key: '',
    securitytrails_enable: false,
    virustotal_api_key: '',
    virustotal_enable: true,
    chaos_api_key: '',
    chaos_enable: false,
    passivetotal_email: '',
    passivetotal_key: '',
    passivetotal_enable: false,
    github_token: '',
  };

  const [configPath, setConfigPath] = useState('');
  const [updatedAt, setUpdatedAt] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [form, setForm] = useState<ServiceApiForm>(defaultForm);
  const [testingProviderId, setTestingProviderId] = useState('');
  const [providerTestResultMap, setProviderTestResultMap] = useState<Record<string, ServiceApiProviderTestResult>>({});
  const [batchTestDialogOpen, setBatchTestDialogOpen] = useState(false);
  const [batchTesting, setBatchTesting] = useState(false);
  const [batchTestError, setBatchTestError] = useState('');
  const [batchTestResults, setBatchTestResults] = useState<ServiceApiBatchTestItem[]>([]);
  const [batchTestSummary, setBatchTestSummary] = useState<ServiceApiBatchTestSummary>({
    total: 0,
    successCount: 0,
    failCount: 0,
    testedAt: '',
    message: '',
  });
  const [sensitiveVisible, setSensitiveVisible] = useState(false);
  const [sensitiveVerifyDialogOpen, setSensitiveVerifyDialogOpen] = useState(false);
  const [sensitiveVerifyUsername, setSensitiveVerifyUsername] = useState(() => localStorage.getItem(USERNAME_KEY) || '');
  const [sensitiveVerifyPassword, setSensitiveVerifyPassword] = useState('');
  const [sensitiveVerifyLoading, setSensitiveVerifyLoading] = useState(false);
  const [sensitiveVerifyError, setSensitiveVerifyError] = useState('');
  const [sensitiveEditingFieldSet, setSensitiveEditingFieldSet] = useState<Set<ServiceApiStringKey>>(new Set());
  const [sensitiveConfiguredMap, setSensitiveConfiguredMap] = useState<Partial<Record<ServiceApiStringKey, boolean>>>({});

  const sensitiveFieldSet = useMemo(
    () =>
      new Set<ServiceApiStringKey>([
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
      ]),
    []
  );

  const resetSensitiveState = useCallback(() => {
    setSensitiveVisible(false);
    setSensitiveVerifyDialogOpen(false);
    setSensitiveVerifyPassword('');
    setSensitiveVerifyError('');
    setSensitiveVerifyLoading(false);
    setSensitiveEditingFieldSet(new Set());
  }, []);

  const normalizeForm = useCallback((rawValue: any): ServiceApiForm => {
    const raw = rawValue || {};
    return {
      fofa_url: String(raw.fofa_url || defaultForm.fofa_url),
      fofa_email: String(raw.fofa_email || ''),
      fofa_key: String(raw.fofa_key || ''),
      fofa_enable: raw.fofa_enable === undefined ? true : Boolean(raw.fofa_enable),
      hunter_api_key: String(raw.hunter_api_key || ''),
      hunter_enable: raw.hunter_enable === undefined ? true : Boolean(raw.hunter_enable),
      hunter_request_interval: String(raw.hunter_request_interval ?? defaultForm.hunter_request_interval),
      hunter_rate_limit_retry: String(raw.hunter_rate_limit_retry ?? defaultForm.hunter_rate_limit_retry),
      hunter_rate_limit_backoff: String(raw.hunter_rate_limit_backoff ?? defaultForm.hunter_rate_limit_backoff),
      hunter_rate_limit_max_sleep: String(raw.hunter_rate_limit_max_sleep ?? defaultForm.hunter_rate_limit_max_sleep),
      hunter_how_api_key: String(raw.hunter_how_api_key || ''),
      hunter_how_enable: raw.hunter_how_enable === undefined ? false : Boolean(raw.hunter_how_enable),
      hunter_how_page_size: String(raw.hunter_how_page_size ?? defaultForm.hunter_how_page_size),
      hunter_how_max_page: String(raw.hunter_how_max_page ?? defaultForm.hunter_how_max_page),
      hunter_how_request_interval: String(raw.hunter_how_request_interval ?? defaultForm.hunter_how_request_interval),
      hunter_how_rate_limit_retry: String(raw.hunter_how_rate_limit_retry ?? defaultForm.hunter_how_rate_limit_retry),
      hunter_how_rate_limit_backoff: String(raw.hunter_how_rate_limit_backoff ?? defaultForm.hunter_how_rate_limit_backoff),
      hunter_how_rate_limit_max_sleep: String(raw.hunter_how_rate_limit_max_sleep ?? defaultForm.hunter_how_rate_limit_max_sleep),
      shodan_api_key: String(raw.shodan_api_key || ''),
      shodan_enable: raw.shodan_enable === undefined ? false : Boolean(raw.shodan_enable),
      shodan_max_page: String(raw.shodan_max_page ?? defaultForm.shodan_max_page),
      shodan_request_interval: String(raw.shodan_request_interval ?? defaultForm.shodan_request_interval),
      shodan_rate_limit_retry: String(raw.shodan_rate_limit_retry ?? defaultForm.shodan_rate_limit_retry),
      shodan_rate_limit_backoff: String(raw.shodan_rate_limit_backoff ?? defaultForm.shodan_rate_limit_backoff),
      shodan_rate_limit_max_sleep: String(raw.shodan_rate_limit_max_sleep ?? defaultForm.shodan_rate_limit_max_sleep),
      quake_token: String(raw.quake_token || ''),
      quake_enable: raw.quake_enable === undefined ? true : Boolean(raw.quake_enable),
      quake_rate_limit_retry: String(raw.quake_rate_limit_retry ?? defaultForm.quake_rate_limit_retry),
      quake_rate_limit_backoff: String(raw.quake_rate_limit_backoff ?? defaultForm.quake_rate_limit_backoff),
      quake_rate_limit_max_sleep: String(raw.quake_rate_limit_max_sleep ?? defaultForm.quake_rate_limit_max_sleep),
      zoomeye_api_key: String(raw.zoomeye_api_key || ''),
      zoomeye_enable: raw.zoomeye_enable === undefined ? true : Boolean(raw.zoomeye_enable),
      zoomeye_max_page: String(raw.zoomeye_max_page ?? defaultForm.zoomeye_max_page),
      zoomeye_request_interval: String(raw.zoomeye_request_interval ?? defaultForm.zoomeye_request_interval),
      zoomeye_rate_limit_retry: String(raw.zoomeye_rate_limit_retry ?? defaultForm.zoomeye_rate_limit_retry),
      zoomeye_rate_limit_backoff: String(raw.zoomeye_rate_limit_backoff ?? defaultForm.zoomeye_rate_limit_backoff),
      zoomeye_rate_limit_max_sleep: String(raw.zoomeye_rate_limit_max_sleep ?? defaultForm.zoomeye_rate_limit_max_sleep),
      securitytrails_api_key: String(raw.securitytrails_api_key || ''),
      securitytrails_enable: raw.securitytrails_enable === undefined ? false : Boolean(raw.securitytrails_enable),
      virustotal_api_key: String(raw.virustotal_api_key || ''),
      virustotal_enable: raw.virustotal_enable === undefined ? true : Boolean(raw.virustotal_enable),
      chaos_api_key: String(raw.chaos_api_key || ''),
      chaos_enable: raw.chaos_enable === undefined ? false : Boolean(raw.chaos_enable),
      passivetotal_email: String(raw.passivetotal_email || ''),
      passivetotal_key: String(raw.passivetotal_key || ''),
      passivetotal_enable: raw.passivetotal_enable === undefined ? false : Boolean(raw.passivetotal_enable),
      github_token: String(raw.github_token || ''),
    };
  }, []);

  const normalizeSensitiveConfigured = useCallback((rawValue: any) => {
    const raw = rawValue && typeof rawValue === 'object' ? rawValue : {};
    const normalized: Partial<Record<ServiceApiStringKey, boolean>> = {};
    sensitiveFieldSet.forEach((fieldKey) => {
      normalized[fieldKey] = Boolean((raw as Record<string, any>)?.[fieldKey]);
    });
    return normalized;
  }, [sensitiveFieldSet]);

  const updateTextField = (key: ServiceApiStringKey, value: string) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const updateBoolField = (key: ServiceApiBoolKey, value: boolean) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const loadServiceApiConfig = useCallback(async () => {
    resetSensitiveState();
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/api_console/service_api/', { method: 'GET' });
      const data = result?.data || {};
      setForm(normalizeForm(data?.service_api));
      setSensitiveConfiguredMap(normalizeSensitiveConfigured(data?.sensitive_configured));
      setConfigPath(String(data.config_path || ''));
      setUpdatedAt(String(data.updated_at || ''));
      setSensitiveVerifyUsername(localStorage.getItem(USERNAME_KEY) || '');
    } catch (err: any) {
      setError(err?.message || '加载 API 配置失败');
    } finally {
      setLoading(false);
    }
  }, [token, normalizeForm, normalizeSensitiveConfigured, resetSensitiveState]);

  useEffect(() => {
    void loadServiceApiConfig();
  }, [loadServiceApiConfig]);

  /**
   * 构造保存/测试共用的 service_api payload，避免两处字段处理不一致。
   */
  const buildServiceApiPayload = useCallback((currentForm: ServiceApiForm) => {
    const normalizedUrl = currentForm.fofa_url.trim();
    const payload: Record<string, any> = {
      ...currentForm,
      fofa_url: normalizedUrl,
      fofa_email: currentForm.fofa_email.trim(),
      hunter_request_interval: currentForm.hunter_request_interval.trim(),
      hunter_rate_limit_retry: currentForm.hunter_rate_limit_retry.trim(),
      hunter_rate_limit_backoff: currentForm.hunter_rate_limit_backoff.trim(),
      hunter_rate_limit_max_sleep: currentForm.hunter_rate_limit_max_sleep.trim(),
      hunter_how_page_size: currentForm.hunter_how_page_size.trim(),
      hunter_how_max_page: currentForm.hunter_how_max_page.trim(),
      hunter_how_request_interval: currentForm.hunter_how_request_interval.trim(),
      hunter_how_rate_limit_retry: currentForm.hunter_how_rate_limit_retry.trim(),
      hunter_how_rate_limit_backoff: currentForm.hunter_how_rate_limit_backoff.trim(),
      hunter_how_rate_limit_max_sleep: currentForm.hunter_how_rate_limit_max_sleep.trim(),
      shodan_max_page: currentForm.shodan_max_page.trim(),
      shodan_request_interval: currentForm.shodan_request_interval.trim(),
      shodan_rate_limit_retry: currentForm.shodan_rate_limit_retry.trim(),
      shodan_rate_limit_backoff: currentForm.shodan_rate_limit_backoff.trim(),
      shodan_rate_limit_max_sleep: currentForm.shodan_rate_limit_max_sleep.trim(),
      quake_rate_limit_retry: currentForm.quake_rate_limit_retry.trim(),
      quake_rate_limit_backoff: currentForm.quake_rate_limit_backoff.trim(),
      quake_rate_limit_max_sleep: currentForm.quake_rate_limit_max_sleep.trim(),
      zoomeye_max_page: currentForm.zoomeye_max_page.trim(),
      zoomeye_request_interval: currentForm.zoomeye_request_interval.trim(),
      zoomeye_rate_limit_retry: currentForm.zoomeye_rate_limit_retry.trim(),
      zoomeye_rate_limit_backoff: currentForm.zoomeye_rate_limit_backoff.trim(),
      zoomeye_rate_limit_max_sleep: currentForm.zoomeye_rate_limit_max_sleep.trim(),
      passivetotal_email: currentForm.passivetotal_email.trim(),
    };
    sensitiveFieldSet.forEach((fieldKey) => {
      if (sensitiveEditingFieldSet.has(fieldKey)) {
        payload[fieldKey] = String(currentForm[fieldKey] || '').trim();
        return;
      }
      delete payload[fieldKey];
    });
    return payload;
  }, [sensitiveEditingFieldSet, sensitiveFieldSet]);

  const toggleSensitiveDisplay = () => {
    if (sensitiveVisible) {
      setForm((prev) => {
        const next = { ...prev };
        sensitiveFieldSet.forEach((fieldKey) => {
          next[fieldKey] = '';
        });
        return next;
      });
      setSensitiveVisible(false);
      setSensitiveEditingFieldSet(new Set());
      void loadServiceApiConfig();
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
    setError('');
    try {
      const result = await requestApi(token, '/api_console/service_api/reveal/', {
        method: 'POST',
        body: {
          username: sensitiveVerifyUsername.trim(),
          password: sensitiveVerifyPassword,
        },
      });
      const data = result?.data || {};
      setForm(normalizeForm(data?.service_api));
      setSensitiveConfiguredMap(normalizeSensitiveConfigured(data?.sensitive_configured));
      setSensitiveEditingFieldSet(new Set());
      setSensitiveVisible(true);
      setSensitiveVerifyDialogOpen(false);
      setSensitiveVerifyPassword('');
      setSuccess('身份验证通过，已按需拉取敏感 key');
    } catch (err: any) {
      setSensitiveVerifyError(err?.message || '验证失败');
    } finally {
      setSensitiveVerifyLoading(false);
    }
  };

  const saveServiceApiConfig = async () => {
    const serviceApiPayload = buildServiceApiPayload(form);
    const normalizedUrl = serviceApiPayload.fofa_url;
    if (!normalizedUrl) {
      setError('FOFA URL 不能为空');
      return;
    }

    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/api_console/service_api/', {
        method: 'POST',
        body: {
          service_api: serviceApiPayload,
        },
      });

      const data = result?.data || {};
      setForm(normalizeForm(data?.service_api));
      setSensitiveConfiguredMap(normalizeSensitiveConfigured(data?.sensitive_configured));
      setConfigPath(String(data.config_path || configPath));
      setUpdatedAt(String(data.saved_at || updatedAt));
      const backupPath = data?.backup_path ? `，备份: ${data.backup_path}` : '';
      setSuccess(`API 配置已保存${backupPath}`);
      setSensitiveVisible(false);
      setSensitiveVerifyPassword('');
      setSensitiveVerifyError('');
      setSensitiveEditingFieldSet(new Set());
    } catch (err: any) {
      setError(err?.message || '保存 API 配置失败');
    } finally {
      setSaving(false);
    }
  };

  const formatProviderTestDetail = (detailRaw: any): string => {
    if (!detailRaw || typeof detailRaw !== 'object') return '';
    const detailPairs = Object.entries(detailRaw)
      .filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== '')
      .slice(0, 6)
      .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(',') : String(value)}`);
    return detailPairs.join(' | ');
  };

  const buildProviderTestResult = (detailRaw: any, fallbackMessage: string): ServiceApiProviderTestResult => {
    const ok = Boolean(detailRaw?.ok);
    return {
      ok,
      message: String(detailRaw?.message || (ok ? '测试成功' : fallbackMessage)),
      detail: formatProviderTestDetail(detailRaw?.detail || {}),
      testedAt: String(detailRaw?.tested_at || detailRaw?.testedAt || ''),
    };
  };

  const testServiceApiProvider = async (providerId: string, providerTitle: string) => {
    setTestingProviderId(providerId);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/api_console/service_api/test/', {
        method: 'POST',
        body: {
          provider: providerId,
          service_api: buildServiceApiPayload(form),
        },
      });
      const data = result?.data || {};
      const providerResult = buildProviderTestResult(data, `${providerTitle} 测试失败`);
      setProviderTestResultMap((prev) => ({
        ...prev,
        [providerId]: providerResult,
      }));
      setSuccess(`${providerTitle} 测试已完成`);
    } catch (err: any) {
      const message = err?.message || `${providerTitle} 测试失败`;
      setProviderTestResultMap((prev) => ({
        ...prev,
        [providerId]: {
          ok: false,
          message,
          detail: '',
          testedAt: '',
        },
      }));
      setError(message);
    } finally {
      setTestingProviderId('');
    }
  };

  const providers: Array<{
    id: string;
    title: string;
    alias?: string;
    website?: string;
    enableKey?: ServiceApiBoolKey;
    enableLabel?: string;
    fields: Array<{
      key: ServiceApiStringKey;
      label: string;
      placeholder: string;
      hint?: string;
      inputType?: 'text' | 'number';
      step?: string;
      min?: string;
    }>;
  }> = [
    {
      id: 'fofa',
      title: 'FOFA',
      website: 'https://fofa.info/',
      enableKey: 'fofa_enable',
      enableLabel: '启用 FOFA 插件',
      fields: [
        { key: 'fofa_url', label: 'URL', placeholder: 'https://fofa.info', hint: 'FOFA.URL' },
        { key: 'fofa_email', label: '邮箱', placeholder: '请输入 FOFA 邮箱', hint: 'FOFA.EMAIL' },
        { key: 'fofa_key', label: 'KEY', placeholder: '请输入 FOFA KEY', hint: 'FOFA.KEY' },
      ],
    },
    {
      id: 'hunter',
      title: 'hunter_qax',
      alias: 'Hunter',
      website: 'https://hunter.qianxin.com/',
      enableKey: 'hunter_enable',
      enableLabel: '启用 Hunter 插件',
      fields: [
        { key: 'hunter_api_key', label: 'API KEY', placeholder: '请输入 Hunter API KEY', hint: 'QUERY_PLUGIN.hunter_qax.api_key' },
        {
          key: 'hunter_request_interval',
          label: '请求间隔(秒)',
          placeholder: '1.0',
          hint: 'QUERY_PLUGIN.hunter_qax.request_interval',
          inputType: 'number',
          step: '0.1',
          min: '0',
        },
        {
          key: 'hunter_rate_limit_retry',
          label: '限频重试次数',
          placeholder: '4',
          hint: 'QUERY_PLUGIN.hunter_qax.rate_limit_retry',
          inputType: 'number',
          step: '1',
          min: '0',
        },
        {
          key: 'hunter_rate_limit_backoff',
          label: '退避基数(秒)',
          placeholder: '2',
          hint: 'QUERY_PLUGIN.hunter_qax.rate_limit_backoff',
          inputType: 'number',
          step: '1',
          min: '1',
        },
        {
          key: 'hunter_rate_limit_max_sleep',
          label: '最大等待(秒)',
          placeholder: '60',
          hint: 'QUERY_PLUGIN.hunter_qax.rate_limit_max_sleep',
          inputType: 'number',
          step: '1',
          min: '1',
        },
      ],
    },
    {
      id: 'hunter_how',
      title: 'hunter.how',
      website: 'https://hunter.how/',
      enableKey: 'hunter_how_enable',
      enableLabel: '启用 hunter.how 插件',
      fields: [
        { key: 'hunter_how_api_key', label: 'API KEY', placeholder: '请输入 hunter.how API KEY', hint: 'QUERY_PLUGIN.hunter_how.api_key' },
        {
          key: 'hunter_how_page_size',
          label: '每页数量',
          placeholder: '100',
          hint: 'QUERY_PLUGIN.hunter_how.page_size',
          inputType: 'number',
          step: '1',
          min: '1',
        },
        {
          key: 'hunter_how_max_page',
          label: '最大页数',
          placeholder: '5',
          hint: 'QUERY_PLUGIN.hunter_how.max_page',
          inputType: 'number',
          step: '1',
          min: '1',
        },
        {
          key: 'hunter_how_request_interval',
          label: '请求间隔(秒)',
          placeholder: '1.0',
          hint: 'QUERY_PLUGIN.hunter_how.request_interval',
          inputType: 'number',
          step: '0.1',
          min: '0',
        },
        {
          key: 'hunter_how_rate_limit_retry',
          label: '限频重试次数',
          placeholder: '4',
          hint: 'QUERY_PLUGIN.hunter_how.rate_limit_retry',
          inputType: 'number',
          step: '1',
          min: '0',
        },
        {
          key: 'hunter_how_rate_limit_backoff',
          label: '退避基数(秒)',
          placeholder: '2',
          hint: 'QUERY_PLUGIN.hunter_how.rate_limit_backoff',
          inputType: 'number',
          step: '1',
          min: '1',
        },
        {
          key: 'hunter_how_rate_limit_max_sleep',
          label: '最大等待(秒)',
          placeholder: '60',
          hint: 'QUERY_PLUGIN.hunter_how.rate_limit_max_sleep',
          inputType: 'number',
          step: '1',
          min: '1',
        },
      ],
    },
    {
      id: 'shodan',
      title: 'Shodan',
      website: 'https://www.shodan.io/',
      enableKey: 'shodan_enable',
      enableLabel: '启用 Shodan 插件',
      fields: [
        { key: 'shodan_api_key', label: 'API KEY', placeholder: '请输入 Shodan API KEY', hint: 'QUERY_PLUGIN.shodan.api_key' },
        {
          key: 'shodan_max_page',
          label: '最大页数',
          placeholder: '20',
          hint: 'QUERY_PLUGIN.shodan.max_page',
          inputType: 'number',
          step: '1',
          min: '1',
        },
        {
          key: 'shodan_request_interval',
          label: '请求间隔(秒)',
          placeholder: '1.0',
          hint: 'QUERY_PLUGIN.shodan.request_interval',
          inputType: 'number',
          step: '0.1',
          min: '0',
        },
        {
          key: 'shodan_rate_limit_retry',
          label: '限频重试次数',
          placeholder: '4',
          hint: 'QUERY_PLUGIN.shodan.rate_limit_retry',
          inputType: 'number',
          step: '1',
          min: '0',
        },
        {
          key: 'shodan_rate_limit_backoff',
          label: '退避基数(秒)',
          placeholder: '2',
          hint: 'QUERY_PLUGIN.shodan.rate_limit_backoff',
          inputType: 'number',
          step: '1',
          min: '1',
        },
        {
          key: 'shodan_rate_limit_max_sleep',
          label: '最大等待(秒)',
          placeholder: '60',
          hint: 'QUERY_PLUGIN.shodan.rate_limit_max_sleep',
          inputType: 'number',
          step: '1',
          min: '1',
        },
      ],
    },
    {
      id: 'quake',
      title: 'quake_360',
      alias: 'Quake360',
      website: 'https://quake.360.cn/',
      enableKey: 'quake_enable',
      enableLabel: '启用 Quake 插件',
      fields: [
        { key: 'quake_token', label: 'Token', placeholder: '请输入 Quake Token', hint: 'QUERY_PLUGIN.quake_360.quake_token' },
        {
          key: 'quake_rate_limit_retry',
          label: '限频重试次数',
          placeholder: '4',
          hint: 'QUERY_PLUGIN.quake_360.rate_limit_retry',
          inputType: 'number',
          step: '1',
          min: '0',
        },
        {
          key: 'quake_rate_limit_backoff',
          label: '退避基数(秒)',
          placeholder: '3',
          hint: 'QUERY_PLUGIN.quake_360.rate_limit_backoff',
          inputType: 'number',
          step: '1',
          min: '1',
        },
        {
          key: 'quake_rate_limit_max_sleep',
          label: '最大等待(秒)',
          placeholder: '90',
          hint: 'QUERY_PLUGIN.quake_360.rate_limit_max_sleep',
          inputType: 'number',
          step: '1',
          min: '1',
        },
      ],
    },
    {
      id: 'zoomeye',
      title: 'Zoomeye',
      website: 'https://www.zoomeye.org/',
      enableKey: 'zoomeye_enable',
      enableLabel: '启用 Zoomeye 插件',
      fields: [
        { key: 'zoomeye_api_key', label: 'API KEY', placeholder: '请输入 Zoomeye API KEY', hint: 'QUERY_PLUGIN.zoomeye.api_key' },
        {
          key: 'zoomeye_max_page',
          label: '最大页数',
          placeholder: '20',
          hint: 'QUERY_PLUGIN.zoomeye.max_page',
          inputType: 'number',
          step: '1',
          min: '1',
        },
        {
          key: 'zoomeye_request_interval',
          label: '请求间隔(秒)',
          placeholder: '1.0',
          hint: 'QUERY_PLUGIN.zoomeye.request_interval',
          inputType: 'number',
          step: '0.1',
          min: '0',
        },
        {
          key: 'zoomeye_rate_limit_retry',
          label: '限频重试次数',
          placeholder: '4',
          hint: 'QUERY_PLUGIN.zoomeye.rate_limit_retry',
          inputType: 'number',
          step: '1',
          min: '0',
        },
        {
          key: 'zoomeye_rate_limit_backoff',
          label: '退避基数(秒)',
          placeholder: '2',
          hint: 'QUERY_PLUGIN.zoomeye.rate_limit_backoff',
          inputType: 'number',
          step: '1',
          min: '1',
        },
        {
          key: 'zoomeye_rate_limit_max_sleep',
          label: '最大等待(秒)',
          placeholder: '60',
          hint: 'QUERY_PLUGIN.zoomeye.rate_limit_max_sleep',
          inputType: 'number',
          step: '1',
          min: '1',
        },
      ],
    },
    {
      id: 'securitytrails',
      title: 'SecurityTrails',
      website: 'https://securitytrails.com/',
      enableKey: 'securitytrails_enable',
      enableLabel: '启用 SecurityTrails 插件',
      fields: [
        {
          key: 'securitytrails_api_key',
          label: 'API KEY',
          placeholder: '请输入 SecurityTrails API KEY',
          hint: 'QUERY_PLUGIN.securitytrails.api_key',
        },
      ],
    },
    {
      id: 'virustotal',
      title: 'virustotal',
      alias: 'VirusTotal',
      website: 'https://www.virustotal.com/gui/',
      enableKey: 'virustotal_enable',
      enableLabel: '启用 VirusTotal 插件',
      fields: [
        { key: 'virustotal_api_key', label: 'API KEY', placeholder: '请输入 VirusTotal API KEY', hint: 'QUERY_PLUGIN.virustotal.api_key' },
      ],
    },
    {
      id: 'chaos',
      title: 'Chaos',
      website: 'https://chaos.projectdiscovery.io/',
      enableKey: 'chaos_enable',
      enableLabel: '启用 Chaos 插件',
      fields: [
        { key: 'chaos_api_key', label: 'API KEY', placeholder: '请输入 Chaos API KEY', hint: 'QUERY_PLUGIN.chaos.api_key' },
      ],
    },
    {
      id: 'github',
      title: 'GitHub',
      website: 'https://github.com/settings/tokens',
      fields: [
        { key: 'github_token', label: 'TOKEN', placeholder: '请输入 GitHub Personal Access Token', hint: 'GITHUB.TOKEN' },
      ],
    },
  ];

  const getProviderDisplayName = (providerId: string, fallbackLabel = '') => {
    const provider = providers.find((item) => item.id === providerId);
    return fallbackLabel || provider?.alias || provider?.title || providerId;
  };

  const testConfiguredServiceApis = async () => {
    setBatchTestDialogOpen(true);
    setBatchTesting(true);
    setBatchTestError('');
    setBatchTestResults([]);
    setBatchTestSummary({
      total: 0,
      successCount: 0,
      failCount: 0,
      testedAt: '',
      message: '',
    });
    setError('');
    setSuccess('');

    try {
      const result = await requestApi(token, '/api_console/service_api/test_batch/', {
        method: 'POST',
        body: {
          service_api: buildServiceApiPayload(form),
        },
      });
      const data = result?.data || {};
      const rawItems = Array.isArray(data?.items) ? data.items : [];
      const normalizedItems: ServiceApiBatchTestItem[] = rawItems.map((item: any) => {
        const providerId = String(item?.provider || '');
        const label = getProviderDisplayName(providerId, String(item?.label || ''));
        const providerResult = buildProviderTestResult(item, `${label} 测试失败`);
        return {
          providerId,
          label,
          ...providerResult,
        };
      });

      const successCount = Number(data?.success_count ?? normalizedItems.filter((item) => item.ok).length);
      const failCount = Number(data?.fail_count ?? normalizedItems.filter((item) => !item.ok).length);
      const summaryMessage = String(
        data?.message || (normalizedItems.length ? '批量验证完成' : '未检测到已配置的 API，无需验证')
      );

      setBatchTestResults(normalizedItems);
      setBatchTestSummary({
        total: Number(data?.total ?? normalizedItems.length),
        successCount,
        failCount,
        testedAt: String(data?.tested_at || ''),
        message: summaryMessage,
      });

      if (normalizedItems.length > 0) {
        setProviderTestResultMap((prev) => {
          const next = { ...prev };
          normalizedItems.forEach((item) => {
            next[item.providerId] = {
              ok: item.ok,
              message: item.message,
              detail: item.detail,
              testedAt: item.testedAt,
            };
          });
          return next;
        });
      }

      setSuccess(
        normalizedItems.length > 0
          ? `一键验证完成，成功 ${successCount} 项，失败 ${failCount} 项`
          : summaryMessage
      );
    } catch (err: any) {
      const message = err?.message || '一键验证失败';
      setBatchTestError(message);
      setBatchTestSummary({
        total: 0,
        successCount: 0,
        failCount: 0,
        testedAt: '',
        message,
      });
      setError(message);
    } finally {
      setBatchTesting(false);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <PageHeader title="API 管理" description="统一维护 FOFA、Hunter、hunter.how、Shodan、Quake、Zoomeye 等第三方 API 配置并同步保存。" />

      <div className="bg-base-200/35 border border-base-300 rounded-2xl p-5 space-y-4">
        <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3">
          <div className="text-sm font-bold tracking-wide">API 凭据配置</div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void loadServiceApiConfig()}
              className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
              disabled={loading || batchTesting || Boolean(testingProviderId)}
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              重新加载
            </button>
            <button
              onClick={() => void testConfiguredServiceApis()}
              className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2 disabled:opacity-60"
              disabled={batchTesting || Boolean(testingProviderId) || loading || saving}
            >
              <CheckCircle2 className={`w-4 h-4 ${batchTesting ? 'animate-pulse' : ''}`} />
              {batchTesting ? '验证中...' : '一键验证'}
            </button>
            <button
              type="button"
              onClick={toggleSensitiveDisplay}
              className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2 disabled:opacity-60"
              disabled={batchTesting || Boolean(testingProviderId) || loading || saving}
            >
              <Eye className="w-4 h-4" />
              {sensitiveVisible ? '隐藏Key' : '显示Key'}
            </button>
            <button
              onClick={() => void saveServiceApiConfig()}
              className="px-4 py-2 rounded-xl bg-brand-accent text-white text-sm font-black hover:opacity-90 transition flex items-center gap-2 disabled:opacity-60"
              disabled={saving || loading || batchTesting || Boolean(testingProviderId)}
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

        <div className="text-xs text-content-muted bg-base-100/50 border border-base-300 rounded-xl px-3 py-2">
          提示：保存后会写入配置文件，建议重启 `web` 与 `worker` 容器让 API 插件配置立即生效。
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {providers.map((provider) => (
          <div key={provider.id} className="bg-base-200/35 border border-base-300 rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <h3 className="text-sm font-black tracking-wide break-all">
                  {provider.title}
                  {provider.alias ? <span className="ml-2 text-content-muted font-semibold">({provider.alias})</span> : null}
                </h3>
                {provider.website ? (
                  <a
                    href={provider.website}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-accent hover:underline break-all font-mono"
                    title={provider.website}
                  >
                    {provider.website}
                  </a>
                ) : null}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {['github', 'chaos'].includes(provider.id) ? null : (
                  <button
                    type="button"
                    onClick={() => void testServiceApiProvider(provider.id, provider.alias || provider.title)}
                    className="px-3 py-1.5 rounded-lg border border-base-300 text-xs font-semibold hover:bg-base-100/70 transition flex items-center gap-1 disabled:opacity-60"
                    disabled={batchTesting || Boolean(testingProviderId) || loading || saving}
                  >
                    <Play className={`w-3.5 h-3.5 ${testingProviderId === provider.id ? 'animate-spin' : ''}`} />
                    {testingProviderId === provider.id ? '测试中...' : '测试'}
                  </button>
                )}
                {provider.enableKey ? (
                  <label className="flex items-center gap-2 text-xs text-content-muted shrink-0">
                    <input
                      type="checkbox"
                      checked={Boolean(form[provider.enableKey])}
                      onChange={(event) => updateBoolField(provider.enableKey, event.target.checked)}
                      className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
                    />
                    <span>{provider.enableLabel}</span>
                  </label>
                ) : null}
              </div>
            </div>

            <div className="space-y-3">
              {provider.fields.map((field) => {
                const rawValue = String(form[field.key] || '');
                const isSensitiveField = sensitiveFieldSet.has(field.key);
                const isSensitiveEditing = sensitiveEditingFieldSet.has(field.key);
                const sensitiveConfigured = isSensitiveField && Boolean(sensitiveConfiguredMap[field.key]);
                const showRaw = !isSensitiveField || sensitiveVisible || isSensitiveEditing;
                const inputType = isSensitiveField ? (showRaw ? 'text' : 'password') : field.inputType || 'text';
                const placeholderText =
                  isSensitiveField && sensitiveConfigured && !showRaw
                    ? '已配置（留空保持不变，输入新值将覆盖）'
                    : field.placeholder;
                return (
                  <div key={field.key} className="space-y-1">
                    <label className="text-xs font-bold text-content-muted block">
                      {field.label}
                      {field.hint ? <span className="ml-2 font-mono opacity-70">{field.hint}</span> : null}
                    </label>
                    <input
                      type={inputType}
                      step={field.step}
                      min={field.min}
                      value={rawValue}
                      onChange={(event) => {
                        if (isSensitiveField && !isSensitiveEditing) {
                          setSensitiveEditingFieldSet((prev) => {
                            const next = new Set(prev);
                            next.add(field.key);
                            return next;
                          });
                        }
                        updateTextField(field.key, event.target.value);
                      }}
                      className={CONSOLE_INPUT_MONO_CLASS}
                      placeholder={placeholderText}
                      autoComplete="off"
                    />
                    {isSensitiveField && sensitiveConfigured && !showRaw ? (
                      <div className="text-[11px] text-content-muted">当前已配置，后端默认不回传明文。</div>
                    ) : null}
                  </div>
                );
              })}
            </div>

            {providerTestResultMap[provider.id] ? (
              <div
                className={`text-xs rounded-lg px-3 py-2 border ${
                  providerTestResultMap[provider.id].ok
                    ? 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30'
                    : 'text-error bg-error/10 border-error/30'
                }`}
              >
                <div>{providerTestResultMap[provider.id].message}</div>
                {providerTestResultMap[provider.id].detail ? <div className="mt-1 font-mono opacity-80 break-all whitespace-pre-wrap">{providerTestResultMap[provider.id].detail}</div> : null}
                {providerTestResultMap[provider.id].testedAt ? <div className="mt-1 opacity-70">{providerTestResultMap[provider.id].testedAt}</div> : null}
              </div>
            ) : null}
          </div>
        ))}
      </div>

      {batchTestDialogOpen ? (
        <Modal open onClose={() => setBatchTestDialogOpen(false)} boxClass="w-full max-w-4xl!">
            <div className="px-6 py-4 border-b border-base-300 flex items-center justify-between gap-3">
              <div>
                <h4 className="text-lg font-black">API 一键验证</h4>
                <p className="text-xs text-content-muted mt-1">仅验证已填写凭据的 API，未配置项会自动跳过。</p>
              </div>
              <button
                type="button"
                onClick={() => setBatchTestDialogOpen(false)}
                className="p-2 rounded-lg hover:bg-base-100/70 transition"
                title="关闭"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 text-xs">
                <div className="bg-base-100/60 border border-base-300 rounded-xl px-3 py-3">
                  <div className="text-content-muted">已验证</div>
                  <div className="mt-1 text-2xl font-black">{batchTestSummary.total}</div>
                </div>
                <div className="bg-emerald-400/10 border border-emerald-400/30 rounded-xl px-3 py-3">
                  <div className="text-emerald-300">成功</div>
                  <div className="mt-1 text-2xl font-black text-emerald-300">{batchTestSummary.successCount}</div>
                </div>
                <div className="bg-error/10 border border-error/30 rounded-xl px-3 py-3">
                  <div className="text-error">失败</div>
                  <div className="mt-1 text-2xl font-black text-error">{batchTestSummary.failCount}</div>
                </div>
                <div className="bg-base-100/60 border border-base-300 rounded-xl px-3 py-3">
                  <div className="text-content-muted">完成时间</div>
                  <div className="mt-1 font-mono break-all">{batchTestSummary.testedAt || '-'}</div>
                </div>
              </div>

              {batchTestSummary.message ? (
                <div className="text-xs text-content-muted bg-base-100/50 border border-base-300 rounded-xl px-3 py-2">
                  {batchTestSummary.message}
                </div>
              ) : null}

              {batchTestError ? (
                <div className="text-sm text-error bg-error/10 border border-error/30 rounded-xl px-3 py-2">
                  {batchTestError}
                </div>
              ) : null}

              {batchTesting ? (
                <div className="flex items-center gap-3 rounded-xl border border-base-300 bg-base-100/40 px-4 py-4 text-sm">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>正在验证已配置的 API，请稍候...</span>
                </div>
              ) : null}

              {!batchTesting && batchTestResults.length === 0 ? (
                <div className="rounded-xl border border-base-300 bg-base-100/40 px-4 py-8 text-sm text-content-muted text-center">
                  暂无需要验证的已配置 API。
                </div>
              ) : null}

              {batchTestResults.length > 0 ? (
                <div className="max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar space-y-3 pr-1">
                  {batchTestResults.map((item) => (
                    <div
                      key={`${item.providerId}-${item.testedAt || item.message}`}
                      className="rounded-xl border border-base-300 bg-base-100/40 px-4 py-4"
                    >
                      <div className="flex items-start gap-3">
                        <div
                          className={`mt-0.5 flex h-9 w-9 items-center justify-center rounded-full shrink-0 ${
                            item.ok
                              ? 'bg-emerald-400/10 text-emerald-300 border border-emerald-400/30'
                              : 'bg-error/10 text-error border border-error/30'
                          }`}
                        >
                          {item.ok ? <CheckCircle2 className="w-4 h-4" /> : <X className="w-4 h-4" />}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                            <div className="text-sm font-black">{item.label}</div>
                            <div className={`text-xs font-semibold ${item.ok ? 'text-emerald-300' : 'text-error'}`}>
                              {item.ok ? '验证成功' : '验证失败'}
                            </div>
                          </div>
                          <div className="mt-1 text-sm break-all">{item.message}</div>
                          {item.detail ? (
                            <div className="mt-2 text-xs font-mono text-content-muted break-all whitespace-pre-wrap">
                              {item.detail}
                            </div>
                          ) : null}
                          {item.testedAt ? (
                            <div className="mt-2 text-xs text-content-muted">{item.testedAt}</div>
                          ) : null}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : null}

              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={() => setBatchTestDialogOpen(false)}
                  className="px-5 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition"
                >
                  关闭
                </button>
              </div>
            </div>
        </Modal>
      ) : null}
      <SensitiveRevealVerifyModal
        open={sensitiveVerifyDialogOpen}
        title="显示 API Key 需要身份验证"
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
