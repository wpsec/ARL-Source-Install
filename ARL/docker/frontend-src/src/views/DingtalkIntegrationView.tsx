import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';
import {
  Database,
  Eye,
  Globe,
  Play,
  RefreshCw,
  Settings,
} from 'lucide-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { USERNAME_KEY, requestApi } from '../api/client';
import { SensitiveRevealVerifyModal } from '../components/domain/SensitiveRevealVerifyModal';
import { PageHeader } from '../layout/PageHeader';
import {
  CONSOLE_ALERT_ERROR_CLASS,
  CONSOLE_ALERT_SUCCESS_CLASS,
  CONSOLE_CHECKBOX_CARD_CLASS,
  CONSOLE_INPUT_CLASS,
  CONSOLE_INPUT_MONO_CLASS,
  CONSOLE_PAGE_CLASS,
  CONSOLE_PANEL_CLASS,
  CONSOLE_PRIMARY_BUTTON_CLASS,
  CONSOLE_SECONDARY_BUTTON_CLASS,
  CONSOLE_TEXTAREA_MONO_CLASS,
} from '../ui/classes';

function formatRuntimeFieldList(value: unknown): string {
  if (!Array.isArray(value)) return '无';
  const fields = value.map((item) => String(item ?? '').trim()).filter(Boolean);
  return fields.length > 0 ? fields.join('\n') : '无';
}

export function DingtalkIntegrationView({ token }: { token: string }) {
  type DingtalkConfigForm = {
    dingding_access_token: string;
    dingding_secret: string;
    kb_enable: boolean;
    ssl_cert_notify_enable: boolean;
    ssl_cert_notify_days: number;
    base_url: string;
    corp_id: string;
    app_key: string;
    app_secret: string;
    operator_id: string;
    workspace_id: string;
    parent_node_id: string;
    create_node_path: string;
    kb_timeout: number;
    title_prefix: string;
    report_base_url: string;
  };

  type DingtalkBoolKey = 'kb_enable' | 'ssl_cert_notify_enable';
  type DingtalkStringKey = Exclude<keyof DingtalkConfigForm, DingtalkBoolKey | 'kb_timeout' | 'ssl_cert_notify_days'>;
  type DingtalkSensitiveStringKey =
    | 'dingding_access_token'
    | 'dingding_secret'
    | 'corp_id'
    | 'app_key'
    | 'app_secret'
    | 'operator_id'
    | 'workspace_id'
    | 'parent_node_id';

  const defaultForm: DingtalkConfigForm = {
    dingding_access_token: '',
    dingding_secret: '',
    kb_enable: false,
    ssl_cert_notify_enable: false,
    ssl_cert_notify_days: 30,
    base_url: 'https://api.dingtalk.com',
    corp_id: '',
    app_key: '',
    app_secret: '',
    operator_id: '',
    workspace_id: '',
    parent_node_id: '',
    create_node_path: '/v1.0/doc/workspaces/{workspace_id}/docs',
    kb_timeout: 20,
    title_prefix: '互联网资产自动化收集',
    report_base_url: '',
  };

  const [form, setForm] = useState<DingtalkConfigForm>(defaultForm);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [debugResult, setDebugResult] = useState('');
  const [sensitiveVisible, setSensitiveVisible] = useState(false);
  const [sensitiveVerifyDialogOpen, setSensitiveVerifyDialogOpen] = useState(false);
  const [sensitiveVerifyUsername, setSensitiveVerifyUsername] = useState(() => localStorage.getItem(USERNAME_KEY) || '');
  const [sensitiveVerifyPassword, setSensitiveVerifyPassword] = useState('');
  const [sensitiveVerifyLoading, setSensitiveVerifyLoading] = useState(false);
  const [sensitiveVerifyError, setSensitiveVerifyError] = useState('');
  const [sensitiveEditingFieldSet, setSensitiveEditingFieldSet] = useState<Set<DingtalkSensitiveStringKey>>(new Set());
  const [sensitiveConfiguredMap, setSensitiveConfiguredMap] = useState<Partial<Record<DingtalkSensitiveStringKey, boolean>>>({});

  const sensitiveFieldSet = useMemo(
    () =>
      new Set<DingtalkSensitiveStringKey>([
        'dingding_access_token',
        'dingding_secret',
        'corp_id',
        'app_key',
        'app_secret',
        'operator_id',
        'workspace_id',
        'parent_node_id',
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

  const normalizeForm = useCallback((rawValue: any): DingtalkConfigForm => {
    const raw = rawValue || {};
    const parsedNotifyDays = Number(raw.ssl_cert_notify_days || 30);
    const safeNotifyDays = Number.isFinite(parsedNotifyDays) && parsedNotifyDays > 0 ? parsedNotifyDays : 30;
    return {
      dingding_access_token: String(raw.dingding_access_token || ''),
      dingding_secret: String(raw.dingding_secret || ''),
      kb_enable: Boolean(raw.kb_enable),
      ssl_cert_notify_enable: Boolean(raw.ssl_cert_notify_enable),
      ssl_cert_notify_days: safeNotifyDays,
      base_url: String(raw.base_url || 'https://api.dingtalk.com'),
      corp_id: String(raw.corp_id || ''),
      app_key: String(raw.app_key || ''),
      app_secret: String(raw.app_secret || ''),
      operator_id: String(raw.operator_id || ''),
      workspace_id: String(raw.workspace_id || ''),
      parent_node_id: String(raw.parent_node_id || ''),
      create_node_path: String(raw.create_node_path || '/v1.0/doc/workspaces/{workspace_id}/docs'),
      kb_timeout: Number(raw.kb_timeout || 20),
      title_prefix: String(raw.title_prefix || '互联网资产自动化收集'),
      report_base_url: String(raw.report_base_url || ''),
    };
  }, []);

  const normalizeSensitiveConfigured = useCallback((rawValue: any) => {
    const raw = rawValue && typeof rawValue === 'object' ? rawValue : {};
    const normalized: Partial<Record<DingtalkSensitiveStringKey, boolean>> = {};
    sensitiveFieldSet.forEach((fieldKey) => {
      normalized[fieldKey] = Boolean((raw as Record<string, any>)?.[fieldKey]);
    });
    return normalized;
  }, [sensitiveFieldSet]);

  // 数据层迁移（计划 4 控制台批次）：初始化读取 = useQuery 快照 + 水合。
  // 运行状态和文件元数据只从快照派生；保存先合并服务端响应再失效重取。
  // reveal/workspaces/nodes 为按需操作读，保持自身响应回写、不触碰配置缓存。
  const queryClient = useQueryClient();
  const dingtalkConfigQueryKey = ['dingtalk-integration-config', token] as const;
  const dingtalkConfigQuery = useQuery({
    queryKey: dingtalkConfigQueryKey,
    queryFn: () => requestApi(token, '/dingtalk_api/config/', { method: 'GET' }),
    retry: 0,
  });
  const workspacesMutation = useMutation({
    mutationFn: (operatorId: string) => requestApi(token, '/dingtalk_api/workspaces/', {
      method: 'POST',
      body: { operator_id: operatorId },
    }),
  });
  const nodesMutation = useMutation({
    mutationFn: ({ operatorId, parentNodeId }: { operatorId: string; parentNodeId: string }) => requestApi(token, '/dingtalk_api/nodes/', {
      method: 'POST',
      body: {
        operator_id: operatorId,
        parent_node_id: parentNodeId,
      },
    }),
  });
  const loading = dingtalkConfigQuery.isPending;
  const dingtalkConfigData = dingtalkConfigQuery.data?.data || {};
  const runtimeStatus = dingtalkConfigData.runtime_status || {};
  const configPath = String(dingtalkConfigData.config_path || '');
  const updatedAt = String(dingtalkConfigData.updated_at || '');
  const mergeDingtalkConfigQueryData = useCallback((nextData: any) => {
    if (!nextData || typeof nextData !== 'object') return;
    const normalizedData = {
      ...nextData,
      ...(nextData.updated_at || !nextData.saved_at ? {} : { updated_at: nextData.saved_at }),
    };
    queryClient.setQueryData(dingtalkConfigQueryKey, (current: any) => {
      if (!current || typeof current !== 'object') return current;
      return {
        ...current,
        data: {
          ...(current.data || {}),
          ...normalizedData,
        },
      };
    });
  }, [dingtalkConfigQueryKey, queryClient]);
  const loadingWorkspaces = workspacesMutation.isPending;
  const loadingNodes = nodesMutation.isPending;

  useEffect(() => {
    if (dingtalkConfigQuery.isPending) {
      setError('');
      setSuccess('');
      return;
    }
    if (dingtalkConfigQuery.isError) {
      setError((dingtalkConfigQuery.error as Error)?.message || '加载钉钉集成配置失败');
      return;
    }
    resetSensitiveState();
    const data = dingtalkConfigQuery.data?.data || {};
    setForm(normalizeForm(data?.config));
    setSensitiveConfiguredMap(normalizeSensitiveConfigured(data?.sensitive_configured));
    setSensitiveVerifyUsername(localStorage.getItem(USERNAME_KEY) || '');
  }, [
    dingtalkConfigQuery.isPending,
    dingtalkConfigQuery.isError,
    dingtalkConfigQuery.data,
    normalizeForm,
    normalizeSensitiveConfigured,
    resetSensitiveState,
  ]);

  const updateStringField = (key: DingtalkStringKey, value: string) => {
    if (sensitiveFieldSet.has(key as DingtalkSensitiveStringKey)) {
      setSensitiveEditingFieldSet((prev) => {
        if (prev.has(key as DingtalkSensitiveStringKey)) return prev;
        const next = new Set(prev);
        next.add(key as DingtalkSensitiveStringKey);
        return next;
      });
    }
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const updateBoolField = (key: DingtalkBoolKey, value: boolean) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const updateTimeout = (value: string) => {
    setForm((prev) => ({ ...prev, kb_timeout: Number(value || 0) }));
  };

  const updateSslNotifyDays = (value: string) => {
    setForm((prev) => ({ ...prev, ssl_cert_notify_days: Number(value || 0) }));
  };

  const buildDingtalkPayload = useCallback((currentForm: DingtalkConfigForm) => {
    const payload: Record<string, any> = {
      ...currentForm,
      base_url: currentForm.base_url.trim(),
      create_node_path: currentForm.create_node_path.trim(),
      kb_timeout: Math.floor(currentForm.kb_timeout),
      ssl_cert_notify_days: Math.floor(currentForm.ssl_cert_notify_days),
      title_prefix: currentForm.title_prefix.trim(),
      report_base_url: currentForm.report_base_url.trim(),
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

  const getSensitiveInputMeta = useCallback(
    (fieldKey: DingtalkSensitiveStringKey, fallbackPlaceholder: string) => {
      const isEditing = sensitiveEditingFieldSet.has(fieldKey);
      const configured = Boolean(sensitiveConfiguredMap[fieldKey]);
      const showRaw = sensitiveVisible || isEditing;
      return {
        type: showRaw ? 'text' : 'password',
        placeholder: configured && !showRaw ? '已配置（留空保持不变，输入新值将覆盖）' : fallbackPlaceholder,
        configuredHidden: configured && !showRaw,
      };
    },
    [sensitiveConfiguredMap, sensitiveEditingFieldSet, sensitiveVisible]
  );

  const toggleSensitiveDisplay = () => {
    if (sensitiveVisible) {
      // 先本地收敛明文态（原 loadDingtalkConfig 开头同款 reset），再重取脱敏快照。
      resetSensitiveState();
      void dingtalkConfigQuery.refetch();
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
      const result = await requestApi(token, '/dingtalk_api/reveal/', {
        method: 'POST',
        body: {
          username: sensitiveVerifyUsername.trim(),
          password: sensitiveVerifyPassword,
        },
      });
      const data = result?.data || {};
      setForm(normalizeForm(data?.config));
      setSensitiveConfiguredMap(normalizeSensitiveConfigured(data?.sensitive_configured));
      setSensitiveEditingFieldSet(new Set());
      setSensitiveVisible(true);
      setSensitiveVerifyDialogOpen(false);
      setSensitiveVerifyPassword('');
      setSuccess('身份验证通过，已显示敏感配置');
    } catch (err: any) {
      setSensitiveVerifyError(err?.message || '验证失败');
    } finally {
      setSensitiveVerifyLoading(false);
    }
  };

  const saveDingtalkConfig = async () => {
    if (!form.base_url.trim()) {
      setError('钉钉 OpenAPI 地址不能为空');
      return;
    }
    if (!Number.isFinite(form.kb_timeout) || form.kb_timeout <= 0) {
      setError('知识库超时时间必须大于 0');
      return;
    }
    if (!Number.isFinite(form.ssl_cert_notify_days) || form.ssl_cert_notify_days <= 0) {
      setError('SSL证书提醒天数必须大于 0');
      return;
    }

    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/dingtalk_api/config/', {
        method: 'POST',
        body: {
          dingtalk_config: buildDingtalkPayload(form),
        },
      });
      const data = result?.data || {};
      setForm(normalizeForm(data?.config));
      setSensitiveConfiguredMap(normalizeSensitiveConfigured(data?.sensitive_configured));
      const backupPath = data?.backup_path ? `，备份: ${data.backup_path}` : '';
      setSuccess(`钉钉集成配置已保存${backupPath}`);
      setSensitiveVisible(false);
      setSensitiveVerifyPassword('');
      setSensitiveVerifyError('');
      setSensitiveEditingFieldSet(new Set());
      mergeDingtalkConfigQueryData(data);
      void queryClient.invalidateQueries({ queryKey: dingtalkConfigQueryKey });
    } catch (err: any) {
      setError(err?.message || '保存钉钉集成配置失败');
    } finally {
      setSaving(false);
    }
  };

  const runDingtalkTest = async () => {
    setTesting(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/dingtalk_api/test/', {
        method: 'POST',
        body: { force_refresh_token: true },
      });
      setDebugResult(JSON.stringify(result?.data || {}, null, 2));
      setSuccess('钉钉连通性测试完成');
      void queryClient.invalidateQueries({ queryKey: dingtalkConfigQueryKey });
    } catch (err: any) {
      setError(err?.message || '钉钉连通性测试失败');
    } finally {
      setTesting(false);
    }
  };

  const loadWorkspaces = async () => {
    setError('');
    setSuccess('');
    try {
      const result = await workspacesMutation.mutateAsync(form.operator_id.trim());
      setDebugResult(JSON.stringify(result?.data || {}, null, 2));
      setSuccess('空间列表获取成功');
    } catch (err: any) {
      setError(err?.message || '获取空间列表失败');
    }
  };

  const loadNodes = async () => {
    setError('');
    setSuccess('');
    try {
      const result = await nodesMutation.mutateAsync({
        operatorId: form.operator_id.trim(),
        parentNodeId: form.parent_node_id.trim(),
      });
      setDebugResult(JSON.stringify(result?.data || {}, null, 2));
      setSuccess('节点列表获取成功');
    } catch (err: any) {
      setError(err?.message || '获取节点列表失败');
    }
  };

  return (
    <div className={CONSOLE_PAGE_CLASS}>
      <PageHeader title="钉钉集成" description="在浏览器中维护钉钉机器人与知识库配置，保存后写入运行配置（容器内 /code/app/config.yaml，对应宿主机 config-runtime.yaml），支持资产报告链接等参数统一管理。" />

      <div className={`${CONSOLE_PANEL_CLASS} p-5 space-y-4`}>
        <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3">
          <div className="text-sm font-bold tracking-wide">配置状态</div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => {
                setError('');
                setSuccess('');
                void dingtalkConfigQuery.refetch();
              }}
              className={`${CONSOLE_SECONDARY_BUTTON_CLASS} gap-2`}
              disabled={loading}
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              重新加载
            </button>
            <button
              type="button"
              onClick={toggleSensitiveDisplay}
              className={`${CONSOLE_SECONDARY_BUTTON_CLASS} gap-2 disabled:opacity-60`}
              disabled={saving || loading}
            >
              <Eye className="w-4 h-4" />
              {sensitiveVisible ? '隐藏敏感配置' : '显示敏感配置'}
            </button>
            <button
              onClick={() => void saveDingtalkConfig()}
              className={`${CONSOLE_PRIMARY_BUTTON_CLASS} gap-2 disabled:opacity-60`}
              disabled={saving || loading}
            >
              <Settings className={`w-4 h-4 ${saving ? 'animate-spin' : ''}`} />
              {saving ? '保存中...' : '保存配置'}
            </button>
          </div>
        </div>

        {error ? (
          <div role="alert" className={CONSOLE_ALERT_ERROR_CLASS}>
            {error}
          </div>
        ) : null}
        {success ? (
          <div role="status" className={CONSOLE_ALERT_SUCCESS_CLASS}>
            {success}
          </div>
        ) : null}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
          <div className="bg-base-100 border border-base-300 rounded-box px-3 py-2">
            <span className="text-content-muted">配置文件:</span>
            <span className="font-mono ml-2">{configPath || '-'}</span>
          </div>
          <div className="bg-base-100 border border-base-300 rounded-box px-3 py-2">
            <span className="text-content-muted">最近更新时间:</span>
            <span className="font-mono ml-2">{updatedAt || '-'}</span>
          </div>
        </div>

        <div className="text-xs text-content-muted bg-base-100 border border-base-300 rounded-box px-3 py-2">
          提示：保存后 `web` 端调试会立即生效；扫描任务通知建议重启 `worker` 容器后完全生效。
        </div>
      </div>

      <div className={`${CONSOLE_PANEL_CLASS} p-5 space-y-5`}>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              钉钉机器人 Token
              <span className="ml-2 font-mono opacity-70">DINGDING.ACCESS_TOKEN</span>
            </label>
            {(() => {
              const meta = getSensitiveInputMeta('dingding_access_token', '用于群机器人通知');
              return (
                <>
            <input
                  type={meta.type}
              value={form.dingding_access_token}
              onChange={(event) => updateStringField('dingding_access_token', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
                  placeholder={meta.placeholder}
            />
                  {meta.configuredHidden ? (
                    <div className="text-[11px] text-content-muted">当前已配置，后端默认不回传明文。</div>
                  ) : null}
                </>
              );
            })()}
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              钉钉机器人 Secret
              <span className="ml-2 font-mono opacity-70">DINGDING.SECRET</span>
            </label>
            {(() => {
              const meta = getSensitiveInputMeta('dingding_secret', '机器人加签密钥（可选）');
              return (
                <>
            <input
                  type={meta.type}
              value={form.dingding_secret}
              onChange={(event) => updateStringField('dingding_secret', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
                  placeholder={meta.placeholder}
            />
                  {meta.configuredHidden ? (
                    <div className="text-[11px] text-content-muted">当前已配置，后端默认不回传明文。</div>
                  ) : null}
                </>
              );
            })()}
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <label className={CONSOLE_CHECKBOX_CARD_CLASS}>
            <input
              type="checkbox"
              checked={form.kb_enable}
              onChange={(event) => updateBoolField('kb_enable', event.target.checked)}
              className="checkbox checkbox-primary checkbox-sm"
            />
            <span className="font-medium">启用知识库推送</span>
          </label>
          <label className={CONSOLE_CHECKBOX_CARD_CLASS}>
            <input
              type="checkbox"
              checked={form.ssl_cert_notify_enable}
              onChange={(event) => updateBoolField('ssl_cert_notify_enable', event.target.checked)}
              className="checkbox checkbox-primary checkbox-sm"
            />
            <span className="font-medium">SSL证书过期通知</span>
          </label>
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              SSL提醒天数
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.SSL_CERT_NOTIFY_DAYS</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(form.ssl_cert_notify_days)}
              onChange={(event) => updateSslNotifyDays(event.target.value)}
              className={CONSOLE_INPUT_CLASS}
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              API 超时时间(秒)
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.KB_TIMEOUT</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(form.kb_timeout)}
              onChange={(event) => updateTimeout(event.target.value)}
              className={CONSOLE_INPUT_CLASS}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              OpenAPI 地址
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.BASE_URL</span>
            </label>
            <input
              value={form.base_url}
              onChange={(event) => updateStringField('base_url', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
              placeholder="https://api.dingtalk.com"
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              资产结果访问地址
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.REPORT_BASE_URL</span>
            </label>
            <input
              value={form.report_base_url}
              onChange={(event) => updateStringField('report_base_url', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
              placeholder="如: https://arl.example.com"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              CorpID
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.CORP_ID</span>
            </label>
            {(() => {
              const meta = getSensitiveInputMeta('corp_id', '请输入 CorpID');
              return (
                <>
            <input
                  type={meta.type}
              value={form.corp_id}
              onChange={(event) => updateStringField('corp_id', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
            />
                  {meta.configuredHidden ? (
                    <div className="text-[11px] text-content-muted">当前已配置，后端默认不回传明文。</div>
                  ) : null}
                </>
              );
            })()}
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              AppKey
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.APP_KEY</span>
            </label>
            {(() => {
              const meta = getSensitiveInputMeta('app_key', '请输入 AppKey');
              return (
                <>
            <input
                  type={meta.type}
              value={form.app_key}
              onChange={(event) => updateStringField('app_key', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
            />
                  {meta.configuredHidden ? (
                    <div className="text-[11px] text-content-muted">当前已配置，后端默认不回传明文。</div>
                  ) : null}
                </>
              );
            })()}
          </div>
          <div className="space-y-2 xl:col-span-2">
            <label className="text-xs font-bold text-content-muted block">
              AppSecret
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.APP_SECRET</span>
            </label>
            {(() => {
              const meta = getSensitiveInputMeta('app_secret', '请输入 AppSecret');
              return (
                <>
            <input
                  type={meta.type}
              value={form.app_secret}
              onChange={(event) => updateStringField('app_secret', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
            />
                  {meta.configuredHidden ? (
                    <div className="text-[11px] text-content-muted">当前已配置，后端默认不回传明文。</div>
                  ) : null}
                </>
              );
            })()}
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              操作者ID
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.OPERATOR_ID</span>
            </label>
            {(() => {
              const meta = getSensitiveInputMeta('operator_id', '请输入操作者ID');
              return (
                <>
            <input
                  type={meta.type}
              value={form.operator_id}
              onChange={(event) => updateStringField('operator_id', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
            />
                  {meta.configuredHidden ? (
                    <div className="text-[11px] text-content-muted">当前已配置，后端默认不回传明文。</div>
                  ) : null}
                </>
              );
            })()}
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              工作空间ID
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.WORKSPACE_ID</span>
            </label>
            {(() => {
              const meta = getSensitiveInputMeta('workspace_id', '请输入工作空间ID');
              return (
                <>
            <input
                  type={meta.type}
              value={form.workspace_id}
              onChange={(event) => updateStringField('workspace_id', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
            />
                  {meta.configuredHidden ? (
                    <div className="text-[11px] text-content-muted">当前已配置，后端默认不回传明文。</div>
                  ) : null}
                </>
              );
            })()}
          </div>
          <div className="space-y-2 xl:col-span-2">
            <label className="text-xs font-bold text-content-muted block">
              父节点ID
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.PARENT_NODE_ID</span>
            </label>
            {(() => {
              const meta = getSensitiveInputMeta('parent_node_id', '请输入父节点ID');
              return (
                <>
            <input
                  type={meta.type}
              value={form.parent_node_id}
              onChange={(event) => updateStringField('parent_node_id', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
            />
                  {meta.configuredHidden ? (
                    <div className="text-[11px] text-content-muted">当前已配置，后端默认不回传明文。</div>
                  ) : null}
                </>
              );
            })()}
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              创建文档接口路径
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.CREATE_NODE_PATH</span>
            </label>
            <input
              value={form.create_node_path}
              onChange={(event) => updateStringField('create_node_path', event.target.value)}
              className={CONSOLE_INPUT_MONO_CLASS}
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-content-muted block">
              报告标题前缀
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.TITLE_PREFIX</span>
            </label>
            <input
              value={form.title_prefix}
              onChange={(event) => updateStringField('title_prefix', event.target.value)}
              className={CONSOLE_INPUT_CLASS}
            />
          </div>
        </div>
      </div>

      <div className={`${CONSOLE_PANEL_CLASS} p-5 space-y-4`}>
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => void runDingtalkTest()}
            className={`${CONSOLE_SECONDARY_BUTTON_CLASS} gap-2 disabled:opacity-60`}
            disabled={testing || loading}
          >
            <Play className={`w-4 h-4 ${testing ? 'animate-spin' : ''}`} />
            {testing ? '测试中...' : '测试连通性'}
          </button>
          <button
            onClick={() => void loadWorkspaces()}
            className={`${CONSOLE_SECONDARY_BUTTON_CLASS} gap-2 disabled:opacity-60`}
            disabled={loadingWorkspaces || loading}
          >
            <Globe className={`w-4 h-4 ${loadingWorkspaces ? 'animate-spin' : ''}`} />
            获取空间列表
          </button>
          <button
            onClick={() => void loadNodes()}
            className={`${CONSOLE_SECONDARY_BUTTON_CLASS} gap-2 disabled:opacity-60`}
            disabled={loadingNodes || loading}
          >
            <Database className={`w-4 h-4 ${loadingNodes ? 'animate-spin' : ''}`} />
            获取节点列表
          </button>
        </div>

        <div className="text-xs text-content-muted bg-base-100 border border-base-300 rounded-box px-3 py-2 whitespace-pre-line break-words">
          <div>运行状态</div>
          <div className="mt-1">缺失基础字段：{formatRuntimeFieldList(runtimeStatus?.missing_basic_fields)}</div>
          <div className="mt-1">缺失发布字段：{formatRuntimeFieldList(runtimeStatus?.missing_publish_fields)}</div>
        </div>

        <div className="space-y-2">
          <label className="text-xs font-bold text-content-muted block">调试输出</label>
          <textarea
            value={debugResult}
            readOnly
            className={`${CONSOLE_TEXTAREA_MONO_CLASS} min-h-[220px]`}
            placeholder="点击测试按钮后显示返回结果"
          />
        </div>
      </div>
      <SensitiveRevealVerifyModal
        open={sensitiveVerifyDialogOpen}
        title="显示钉钉敏感配置需要身份验证"
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
