import { useEffect, useMemo, useState } from 'react';
import { ChevronDown, Play, X } from 'lucide-react';
import { normalizeListData, requestApi } from '../api/client';
import { Modal } from '../components/ui/Modal';
import {
  deepClone,
  fromDatetimeLocalValue,
  humanizeField,
  toDatetimeLocalValue,
} from '../domain/format';
import { flattenPayloadFields, getPayloadValue, updatePayloadValue } from '../domain/payload';
import type {JsonValue, ModuleAction} from '../domain/types';
import { UNIFIED_SELECT_CLASS } from '../ui/classes';

export function ActionDialog({
  token,
  action,
  initialPayload,
  onClose,
  onSubmit,
}: {
  token: string;
  action: ModuleAction;
  initialPayload: JsonValue;
  onClose: () => void;
  onSubmit: (payload: JsonValue, file?: File | null) => Promise<void>;
}) {
  type TaskDomainDictOption = {
    label: string;
    path: string;
    source: string;
    exists: boolean;
    size: number;
    selected?: boolean;
  };

  const [formPayload, setFormPayload] = useState<JsonValue>(deepClone(initialPayload));
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [file, setFile] = useState<File | null>(null);

  const editable = action.allowPayloadEdit !== false;
  const isTaskCreate = action.id === 'create_task';
  const isAssetScopeCreate = action.id === 'asset_scope_add';
  const isAssetScopeAddScope = action.id === 'asset_scope_add_scope';
  const isAssetScopeUpdate = action.id === 'asset_scope_update';
  const isAssetScopeAddScheduler = action.id === 'asset_scope_add_scheduler';
  const isAssetScopeAddSiteMonitor = action.id === 'asset_scope_add_site_monitor';
  const isAssetScopeAddWihMonitor = action.id === 'asset_scope_add_wih_monitor';
  const isTaskScheduleCreate = action.id === 'task_schedule_add';
  const isFofaSubmitAction = action.id === 'fofa_submit' || action.id === 'fofa_submit_center';
  const isFofaTestAction = action.id === 'fofa_test';
  const isFofaAction = isFofaSubmitAction || isFofaTestAction;
  const shouldLoadPolicyOptions = isTaskScheduleCreate || isAssetScopeAddScheduler || isFofaSubmitAction;
  const isPolicySelectionRequired = isTaskScheduleCreate || isAssetScopeAddScheduler;
  const isGithubSchedulerAction = action.id === 'github_scheduler_add' || action.id === 'github_scheduler_update';
  const isPolicyAction = action.id === 'policy_add' || action.id === 'policy_edit';
  const shouldLoadDictOptions = isTaskCreate || isPolicyAction;
  const fields = useMemo(() => flattenPayloadFields(formPayload), [formPayload]);
  const displayFields = useMemo(
    () =>
      fields.filter((field) => {
        if (!action.selectedField) return true;
        if ((action.selectionMode || 'none') === 'none') return true;
        return field.path !== action.selectedField;
      }),
    [fields, action.selectedField, action.selectionMode]
  );
  const policyRootPath = action.id === 'policy_edit' ? 'policy_data.policy' : 'policy';
  const policyNamePath = action.id === 'policy_edit' ? 'policy_data.name' : 'name';
  const policyDescPath = action.id === 'policy_edit' ? 'policy_data.desc' : 'desc';
  const taskFeatureSections = useMemo(() => {
    if (!isTaskCreate) return [];
    const isBooleanField = (key: string) => typeof formPayload?.[key] === 'boolean';
    const sections = [
      {
        title: '域名探测',
        // “域名爆破”在任务级固定开启，这里隐藏开关，避免与字典配置形成重复认知。
        keys: ['alt_dns', 'dns_query_plugin', 'arl_search'],
      },
      {
        title: '网络探测',
        keys: ['port_scan', 'service_detection', 'os_detection', 'ssl_cert', 'skip_scan_cdn_ip'],
      },
      {
        title: 'Web与风险',
        keys: ['site_identify', 'search_engines', 'site_spider', 'site_capture', 'file_leak', 'nuclei_scan', 'afrog_scan', 'findvhost', 'web_info_hunter', 'smart_skip_waf', 'ai_denoise', 'dingding_notify'],
      },
    ];
    return sections
      .map((section) => ({
        title: section.title,
        keys: section.keys.filter(isBooleanField),
      }))
      .filter((section) => section.keys.length > 0);
  }, [formPayload, isTaskCreate]);
  const taskFeatureKeys = useMemo(
    () => taskFeatureSections.flatMap((section) => section.keys),
    [taskFeatureSections]
  );
  const allTaskFeaturesEnabled =
    taskFeatureKeys.length > 0 && taskFeatureKeys.every((key) => Boolean(formPayload?.[key]));
  const setAllTaskFeatures = (enabled: boolean) => {
    setFormPayload((prev) => {
      const next = deepClone(prev || {});
      taskFeatureKeys.forEach((key) => {
        next[key] = enabled;
      });
      return next;
    });
  };
  const taskName = String(formPayload?.name ?? '');
  const taskTarget = String(formPayload?.target ?? '');
  const taskDomainDict = String(formPayload?.domain_dict ?? '');
  const taskFileLeakDict = String(formPayload?.file_leak_dict ?? '');
  const taskPortScanType = String(formPayload?.port_scan_type ?? 'test');
  const taskPortCustom = String(formPayload?.port_custom ?? '80,443');
  const taskScheduleName = String(formPayload?.name ?? '');
  const taskScheduleTarget = String(formPayload?.target ?? '');
  const taskScheduleType = String(formPayload?.schedule_type ?? 'future_scan') === 'recurrent_scan' ? 'recurrent_scan' : 'future_scan';
  const taskSchedulePolicyId = String(formPayload?.policy_id ?? '');
  const fofaTaskName = String(formPayload?.name ?? '');
  const fofaProvider = String(formPayload?.provider ?? 'fofa').trim() || 'fofa';
  const fofaQueryText = String(formPayload?.query ?? '');
  const fofaPolicyId = String(formPayload?.policy_id ?? '');
  const taskScheduleCron = String(formPayload?.cron ?? '');
  const taskScheduleStartDate = toDatetimeLocalValue(formPayload?.start_date);
  const taskScheduleTag = String(formPayload?.task_tag ?? 'task') === 'risk_cruising' ? 'risk_cruising' : 'task';
  const taskScheduleNotifyEnable = Boolean(formPayload?.notify_enable);
  const taskScheduleNotifyKbEnable = Boolean(formPayload?.notify_kb_enable);
  const githubSchedulerName = String(formPayload?.name ?? '');
  const githubSchedulerKeyword = String(formPayload?.keyword ?? '');
  const githubSchedulerCron = String(formPayload?.cron ?? '');
  const githubSchedulerDingdingNotify = Boolean(formPayload?.dingding_notify);
  const githubSchedulerKbNotifyEnable = Boolean(formPayload?.kb_notify_enable);
  const scopeGroupName = String(formPayload?.name ?? '');
  const scopeType = String(formPayload?.scope_type ?? 'domain') === 'ip' ? 'ip' : 'domain';
  const scopeText = String(formPayload?.scope ?? '');
  const scopeAddTargetText = String(formPayload?.scope ?? '');
  const scopeBlackText = String(formPayload?.black_scope ?? '');
  const scopeMonitorRangeText = String(formPayload?.domain ?? '');
  const scopeMonitorIntervalHours = Math.max(1, Math.round((Number(formPayload?.interval || 86400) || 86400) / 3600));
  const policyName = String(getPayloadValue(formPayload, policyNamePath) ?? '');
  const policyDesc = String(getPayloadValue(formPayload, policyDescPath) ?? '');
  const policyDomainDict = String(getPayloadValue(formPayload, `${policyRootPath}.domain_dict`) ?? '');
  const policyFileLeakDict = String(getPayloadValue(formPayload, `${policyRootPath}.file_leak_dict`) ?? '');
  const policyPortScanType = String(getPayloadValue(formPayload, `${policyRootPath}.ip_config.port_scan_type`) ?? 'test');
  const policyPortCustom = String(getPayloadValue(formPayload, `${policyRootPath}.ip_config.port_custom`) ?? '80,443');
  const [policySearchKeyword, setPolicySearchKeyword] = useState('');
  const [policyPocKeyword, setPolicyPocKeyword] = useState('');
  const [policyBruteKeyword, setPolicyBruteKeyword] = useState('');
  const [policyPluginLoading, setPolicyPluginLoading] = useState(false);
  const [policyPluginError, setPolicyPluginError] = useState('');
  const [policyPocOptions, setPolicyPocOptions] = useState<Array<{ plugin_name: string; vul_name: string }>>([]);
  const [policyBruteOptions, setPolicyBruteOptions] = useState<Array<{ plugin_name: string; vul_name: string }>>([]);
  const [taskSchedulePolicyOptions, setTaskSchedulePolicyOptions] = useState<Array<{ label: string; value: string }>>([]);
  const [taskSchedulePolicyLoading, setTaskSchedulePolicyLoading] = useState(false);
  const [taskSchedulePolicyError, setTaskSchedulePolicyError] = useState('');
  const [fofaTesting, setFofaTesting] = useState(false);
  const [fofaResultSize, setFofaResultSize] = useState<number | null>(null);
  const [taskDomainDictOptions, setTaskDomainDictOptions] = useState<TaskDomainDictOption[]>([]);
  const [taskDomainDictLoading, setTaskDomainDictLoading] = useState(false);
  const [taskDomainDictError, setTaskDomainDictError] = useState('');
  const [taskDefaultDomainDictPath, setTaskDefaultDomainDictPath] = useState('');
  const [taskFileLeakDictOptions, setTaskFileLeakDictOptions] = useState<TaskDomainDictOption[]>([]);
  const [taskFileLeakDictError, setTaskFileLeakDictError] = useState('');
  const [taskDefaultFileLeakDictPath, setTaskDefaultFileLeakDictPath] = useState('');
  const measureProviderOptions = [
    { label: 'FOFA', value: 'fofa' },
    { label: 'Hunter', value: 'hunter_qax' },
    { label: 'Shodan', value: 'shodan' },
    { label: 'Zoomeye', value: 'zoomeye' },
    { label: 'Quake360', value: 'quake_360' },
  ];
  const measureProviderLabelMap: Record<string, string> = {
    fofa: 'FOFA',
    hunter_qax: 'Hunter',
    shodan: 'Shodan',
    zoomeye: 'Zoomeye',
    quake_360: 'Quake360',
  };
  const measureProviderExamples: Record<string, string> = {
    fofa: 'app="Nginx"\ncountry="CN" && port="443"',
    hunter_qax: 'web.title="后台"\nip="203.0.113.10"',
    shodan: 'hostname:"example.com"\nproduct:nginx country:CN',
    zoomeye: 'domain="example.com"\napp="Nginx"',
    quake_360: 'service:"nginx"\nport:443 AND country:"China"',
  };
  const currentMeasureProviderLabel = measureProviderLabelMap[fofaProvider] || 'FOFA';

  const getPolicyPath = (suffix: string) => `${policyRootPath}.${suffix}`;
  const updatePolicyValue = (suffix: string, value: any) => {
    setFormPayload((prev) => updatePayloadValue(prev, getPolicyPath(suffix), value));
  };

  const extractPluginNames = (value: any): string[] => {
    if (!Array.isArray(value)) return [];
    return value
      .map((item) => String(item?.plugin_name || '').trim())
      .filter((item) => item);
  };

  const selectedPolicyPocNames = extractPluginNames(getPayloadValue(formPayload, getPolicyPath('poc_config')));
  const selectedPolicyBruteNames = extractPluginNames(getPayloadValue(formPayload, getPolicyPath('brute_config')));
  const policyOptionDefs = [
    { key: 'domain_config.alt_dns', label: 'DNS字典智能生成' },
    { key: 'domain_config.dns_query_plugin', label: '测绘引擎查询' },
    { key: 'domain_config.arl_search', label: 'ARL 历史查询' },
    { key: 'ip_config.port_scan', label: '端口扫描' },
    { key: 'ip_config.service_detection', label: '服务识别' },
    { key: 'ip_config.os_detection', label: '操作系统识别' },
    { key: 'ip_config.ssl_cert', label: 'SSL 证书获取' },
    { key: 'ip_config.skip_scan_cdn_ip', label: '跳过CDN' },
    { key: 'site_config.site_identify', label: '站点识别' },
    { key: 'site_config.search_engines', label: '搜索引擎调用' },
    { key: 'site_config.site_spider', label: '站点爬虫' },
    { key: 'site_config.site_capture', label: '站点截图' },
    { key: 'file_leak', label: '目录扫描' },
    { key: 'site_config.nuclei_scan', label: 'nuclei 调用' },
    { key: 'site_config.afrog_scan', label: 'afrog 调用' },
    { key: 'site_config.web_info_hunter', label: 'WIH 调用' },
    { key: 'site_config.smart_skip_waf', label: '跳过WAF' },
    { key: 'site_config.ai_denoise', label: 'AI去噪分析' },
  ];
  const filteredPolicyOptions = policyOptionDefs.filter((item) => {
    const keyword = policySearchKeyword.trim().toLowerCase();
    if (!keyword) return true;
    return item.label.toLowerCase().includes(keyword);
  });
  const policyOptionAllEnabled =
    policyOptionDefs.length > 0 &&
    policyOptionDefs.every((item) => Boolean(getPayloadValue(formPayload, getPolicyPath(item.key))));
  const setPolicyOptionAll = (enabled: boolean) => {
    setFormPayload((prev) => {
      let next = deepClone(prev || {});
      policyOptionDefs.forEach((item) => {
        next = updatePayloadValue(next, getPolicyPath(item.key), enabled);
      });
      return next;
    });
  };
  const filteredPolicyPocOptions = policyPocOptions.filter((item) => {
    const keyword = policyPocKeyword.trim().toLowerCase();
    if (!keyword) return true;
    return item.plugin_name.toLowerCase().includes(keyword) || item.vul_name.toLowerCase().includes(keyword);
  });
  const filteredPolicyBruteOptions = policyBruteOptions.filter((item) => {
    const keyword = policyBruteKeyword.trim().toLowerCase();
    if (!keyword) return true;
    return item.plugin_name.toLowerCase().includes(keyword) || item.vul_name.toLowerCase().includes(keyword);
  });
  const policyPocAllSelected =
    policyPocOptions.length > 0 && policyPocOptions.every((item) => selectedPolicyPocNames.includes(item.plugin_name));
  const policyBruteAllSelected =
    policyBruteOptions.length > 0 && policyBruteOptions.every((item) => selectedPolicyBruteNames.includes(item.plugin_name));
  const taskDomainDictSelectOptions = useMemo(() => {
    const next = [...taskDomainDictOptions];
    const exists = next.some((item) => item.path === taskDomainDict);
    if (taskDomainDict && !exists) {
      next.push({
        label: taskDomainDict,
        path: taskDomainDict,
        source: 'custom',
        exists: true,
        size: 0,
      });
    }
    return next;
  }, [taskDomainDictOptions, taskDomainDict]);
  const taskFileLeakDictSelectOptions = useMemo(() => {
    const next = [...taskFileLeakDictOptions];
    const exists = next.some((item) => item.path === taskFileLeakDict);
    if (taskFileLeakDict && !exists) {
      next.push({
        label: taskFileLeakDict,
        path: taskFileLeakDict,
        source: 'custom',
        exists: true,
        size: 0,
      });
    }
    return next;
  }, [taskFileLeakDictOptions, taskFileLeakDict]);
  const policyDomainDictSelectOptions = useMemo(() => {
    const next = [...taskDomainDictOptions];
    const exists = next.some((item) => item.path === policyDomainDict);
    if (policyDomainDict && !exists) {
      next.push({
        label: policyDomainDict,
        path: policyDomainDict,
        source: 'custom',
        exists: true,
        size: 0,
      });
    }
    return next;
  }, [taskDomainDictOptions, policyDomainDict]);
  const policyFileLeakDictSelectOptions = useMemo(() => {
    const next = [...taskFileLeakDictOptions];
    const exists = next.some((item) => item.path === policyFileLeakDict);
    if (policyFileLeakDict && !exists) {
      next.push({
        label: policyFileLeakDict,
        path: policyFileLeakDict,
        source: 'custom',
        exists: true,
        size: 0,
      });
    }
    return next;
  }, [taskFileLeakDictOptions, policyFileLeakDict]);

  const setPolicyPluginConfig = (field: 'poc_config' | 'brute_config', pluginNames: string[]) => {
    const payloadList = pluginNames.map((pluginName) => ({
      plugin_name: pluginName,
      enable: true,
    }));
    updatePolicyValue(field, payloadList);
  };

  const togglePolicyPluginSelection = (field: 'poc_config' | 'brute_config', pluginName: string, enabled: boolean) => {
    const currentList = field === 'poc_config' ? selectedPolicyPocNames : selectedPolicyBruteNames;
    const nextSet = new Set(currentList);
    if (enabled) {
      nextSet.add(pluginName);
    } else {
      nextSet.delete(pluginName);
    }
    setPolicyPluginConfig(field, Array.from(nextSet));
  };

  useEffect(() => {
    const nextPayload = deepClone(initialPayload);
    setFormPayload(nextPayload);
    setError('');
    setPolicySearchKeyword('');
    setPolicyPocKeyword('');
    setPolicyBruteKeyword('');
    setFofaTesting(false);
    setFofaResultSize(null);
  }, [initialPayload]);

  const normalizeFofaQueries = (rawQuery: string): string[] => {
    const lines = String(rawQuery || '')
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line);
    const seen = new Set<string>();
    const normalized: string[] = [];
    lines.forEach((line) => {
      if (seen.has(line)) return;
      seen.add(line);
      normalized.push(line);
    });
    return normalized;
  };

  const runFofaQueryTest = async () => {
    try {
      setError('');
      setFofaTesting(true);
      const queryItems = normalizeFofaQueries(fofaQueryText);
      if (queryItems.length === 0) {
        throw new Error('请填写查询语句（支持多行输入）');
      }

      const normalizedQuery = queryItems.join('\n');
      setFormPayload((prev) => updatePayloadValue(prev, 'query', normalizedQuery));

      const result = await requestApi(token, '/task_fofa/test', {
        method: 'POST',
        body: { provider: fofaProvider, query: normalizedQuery },
      });
      const totalSize = Number(result?.data?.size ?? 0);
      setFofaResultSize(Number.isFinite(totalSize) ? totalSize : 0);
    } catch (err: any) {
      setFofaResultSize(null);
      setError(err?.message || '测绘语法测试失败');
    } finally {
      setFofaTesting(false);
    }
  };

  useEffect(() => {
    if (!shouldLoadDictOptions) {
      setTaskDomainDictOptions([]);
      setTaskDomainDictLoading(false);
      setTaskDomainDictError('');
      setTaskDefaultDomainDictPath('');
      setTaskFileLeakDictOptions([]);
      setTaskFileLeakDictError('');
      setTaskDefaultFileLeakDictPath('');
      return;
    }

    let cancelled = false;
    const loadTaskDomainDictOptions = async () => {
      setTaskDomainDictLoading(true);
      setTaskDomainDictError('');
      setTaskFileLeakDictError('');
      try {
        const response = await requestApi(token, '/api_console/scan_config/', { method: 'GET' });
        const data = response?.data || {};
        const options = Array.isArray(data?.available_domain_dicts) ? data.available_domain_dicts : [];
        const fileLeakOptions = Array.isArray(data?.available_file_leak_dicts) ? data.available_file_leak_dicts : [];
        const defaultPath = String(data?.scan_config?.domain_dict || '').trim();
        const defaultFileLeakPath = String(data?.scan_config?.file_leak_dict || '').trim();
        if (cancelled) return;

        const normalizedOptions = options
          .map((item: any) => ({
            label: String(item?.label || item?.path || '').trim(),
            path: String(item?.path || '').trim(),
            source: String(item?.source || 'custom').trim() || 'custom',
            exists: Boolean(item?.exists),
            size: Number(item?.size || 0),
            selected: Boolean(item?.selected),
          }))
          .filter((item: TaskDomainDictOption) => item.path);
        const normalizedFileLeakOptions = fileLeakOptions
          .map((item: any) => ({
            label: String(item?.label || item?.path || '').trim(),
            path: String(item?.path || '').trim(),
            source: String(item?.source || 'custom').trim() || 'custom',
            exists: Boolean(item?.exists),
            size: Number(item?.size || 0),
            selected: Boolean(item?.selected),
          }))
          .filter((item: TaskDomainDictOption) => item.path);

        // 新建任务默认优先选择 domain_2w.txt，找不到时回退到扫描配置默认字典。
        const preferredBigDictPath =
          normalizedOptions.find((item) => /domain_2w\.txt$/i.test(item.path) || /domain_2w\.txt/i.test(item.label))?.path || '';
        const effectiveDefaultPath = preferredBigDictPath || defaultPath;

        setTaskDomainDictOptions(normalizedOptions);
        setTaskFileLeakDictOptions(normalizedFileLeakOptions);
        setTaskDefaultDomainDictPath(effectiveDefaultPath);
        setTaskDefaultFileLeakDictPath(defaultFileLeakPath);

        setFormPayload((prev) => {
          let next = prev;
          if (isTaskCreate) {
            const currentDict = String(prev?.domain_dict || '').trim();
            const currentFileLeakDict = String(prev?.file_leak_dict || '').trim();
            if (!currentDict && effectiveDefaultPath) {
              next = updatePayloadValue(next, 'domain_dict', effectiveDefaultPath);
            }
            if (!currentFileLeakDict && defaultFileLeakPath) {
              next = updatePayloadValue(next, 'file_leak_dict', defaultFileLeakPath);
            }
            return next;
          }

          if (isPolicyAction) {
            const domainDictPath = `${policyRootPath}.domain_dict`;
            const fileLeakDictPath = `${policyRootPath}.file_leak_dict`;
            const currentDict = getPayloadValue(prev, domainDictPath);
            const currentFileLeakDict = getPayloadValue(prev, fileLeakDictPath);
            // 策略字典支持“跟随配置管理默认值”，因此只补齐空串字段，不强制写入默认路径。
            if (currentDict === undefined) {
              next = updatePayloadValue(next, domainDictPath, '');
            }
            if (currentFileLeakDict === undefined) {
              next = updatePayloadValue(next, fileLeakDictPath, '');
            }
          }
          return next;
        });
      } catch (err: any) {
        if (cancelled) return;
        setTaskDomainDictOptions([]);
        setTaskDefaultDomainDictPath('');
        setTaskFileLeakDictOptions([]);
        setTaskDefaultFileLeakDictPath('');
        setTaskDomainDictError(err?.message || '加载字典列表失败');
        setTaskFileLeakDictError(err?.message || '加载字典列表失败');
      } finally {
        if (!cancelled) setTaskDomainDictLoading(false);
      }
    };

    void loadTaskDomainDictOptions();
    return () => {
      cancelled = true;
    };
  }, [isPolicyAction, isTaskCreate, policyRootPath, shouldLoadDictOptions, token]);

  useEffect(() => {
    if (!shouldLoadPolicyOptions) {
      setTaskSchedulePolicyOptions([]);
      setTaskSchedulePolicyLoading(false);
      setTaskSchedulePolicyError('');
      return;
    }
    let cancelled = false;

    const loadTaskSchedulePolicies = async () => {
      setTaskSchedulePolicyLoading(true);
      setTaskSchedulePolicyError('');
      try {
        const response = await requestApi(token, '/policy/', {
          method: 'GET',
          query: { page: 1, size: 1000, order: 'name' },
        });
        const items = normalizeListData(response).items || [];
        const options = items
          .map((item: any) => {
            const policyId = String(item?._id || item?.policy_id || '').trim();
            const policyName = String(item?.name || '').trim() || '未命名策略';
            if (!policyId) return null;
            return { label: policyName, value: policyId };
          })
          .filter((item): item is { label: string; value: string } => Boolean(item));
        if (cancelled) return;

        setTaskSchedulePolicyOptions(options);
        if (options.length === 0) {
          if (isPolicySelectionRequired) {
            setTaskSchedulePolicyError('未找到可用策略，请先在策略配置中创建策略');
          } else {
            setTaskSchedulePolicyError('');
          }
        } else {
          setTaskSchedulePolicyError('');
          if (!isPolicySelectionRequired) return;
          setFormPayload((prev) => {
            const currentPolicyId = String(prev?.policy_id || '').trim();
            if (currentPolicyId) return prev;
            return updatePayloadValue(prev, 'policy_id', options[0].value);
          });
        }
      } catch (err: any) {
        if (cancelled) return;
        setTaskSchedulePolicyOptions([]);
        if (isPolicySelectionRequired) {
          setTaskSchedulePolicyError(err?.message || '加载策略列表失败');
        } else {
          setTaskSchedulePolicyError('');
        }
      } finally {
        if (!cancelled) {
          setTaskSchedulePolicyLoading(false);
        }
      }
    };

    void loadTaskSchedulePolicies();
    return () => {
      cancelled = true;
    };
  }, [isPolicySelectionRequired, shouldLoadPolicyOptions, token]);

  useEffect(() => {
    if (!isPolicyAction) return;
    let cancelled = false;

    const loadPolicyPlugins = async () => {
      setPolicyPluginLoading(true);
      setPolicyPluginError('');
      try {
        const response = await requestApi(token, '/poc/', {
          method: 'GET',
          query: { page: 1, size: 5000 },
        });
        const items = normalizeListData(response).items || [];
        const normalized = items
          .map((item: any) => ({
            plugin_name: String(item?.plugin_name || '').trim(),
            vul_name: String(item?.vul_name || '').trim(),
            plugin_type: String(item?.plugin_type || '').trim().toLowerCase(),
          }))
          .filter((item: any) => item.plugin_name);
        if (cancelled) return;
        setPolicyPocOptions(
          normalized
            .filter((item: any) => item.plugin_type === 'poc')
            .map((item: any) => ({ plugin_name: item.plugin_name, vul_name: item.vul_name }))
        );
        setPolicyBruteOptions(
          normalized
            .filter((item: any) => item.plugin_type === 'brute')
            .map((item: any) => ({ plugin_name: item.plugin_name, vul_name: item.vul_name }))
        );
      } catch (err: any) {
        if (cancelled) return;
        setPolicyPluginError(err?.message || '加载 PoC 列表失败');
      } finally {
        if (!cancelled) {
          setPolicyPluginLoading(false);
        }
      }
    };

    void loadPolicyPlugins();
    return () => {
      cancelled = true;
    };
  }, [isPolicyAction, token]);

  useEffect(() => {
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      onClose();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  return (
    <Modal
      open
      onClose={onClose}
      boxClass={`w-full ${isTaskCreate || isPolicyAction || isTaskScheduleCreate ? 'max-w-5xl!' : 'max-w-3xl!'}`}
    >
        <div className="px-6 py-4 border-b border-base-300 flex items-center justify-between">
          <div>
            <h4 className="text-lg font-black">{action.label}</h4>
            <p className="text-xs text-content-muted font-mono mt-1">
              {action.method} {action.path}
            </p>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-base-100/70 transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          {action.description ? <p className="text-sm text-content-muted">{action.description}</p> : null}

          {action.fileFieldName ? (
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wider font-bold text-content-muted">上传文件</label>
              <input
                type="file"
                accept={action.fileAccept}
                onChange={(event) => {
                  const nextFile = event.target.files?.[0] || null;
                  setFile(nextFile);
                }}
                className="w-full text-sm file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border file:border-base-300 file:bg-base-100 file:text-white"
              />
            </div>
          ) : null}

          {isTaskCreate ? (
            <div className="space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">任务名称</label>
                <input
                  value={taskName}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                  className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                  placeholder="例如：生产资产扫描-03"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">域名爆破字典</label>
                <div className="relative">
                  <select
                    value={taskDomainDict}
                    disabled={!editable || taskDomainDictLoading}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'domain_dict', event.target.value))}
                    className={UNIFIED_SELECT_CLASS}
                  >
                    {taskDomainDictSelectOptions.length === 0 ? <option value="">暂无可用字典</option> : null}
                    {taskDomainDictSelectOptions.map((item) => (
                      <option key={item.path} value={item.path}>
                        {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
                <p className="text-[11px] text-content-muted">
                  默认自动选择 `domain_2w.txt`；你可以按任务改选其它字典。当前默认：
                  {taskDefaultDomainDictPath ? ` ${taskDefaultDomainDictPath}` : '（未找到，需手动选择）'}
                </p>
              </div>

              {taskDomainDictError ? (
                <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">
                  {taskDomainDictError}
                </div>
              ) : null}

              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">目录扫描字典</label>
                <div className="relative">
                  <select
                    value={taskFileLeakDict}
                    disabled={!editable || taskDomainDictLoading}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'file_leak_dict', event.target.value))}
                    className={UNIFIED_SELECT_CLASS}
                  >
                    {taskFileLeakDictSelectOptions.length === 0 ? <option value="">暂无可用字典</option> : null}
                    {taskFileLeakDictSelectOptions.map((item) => (
                      <option key={item.path} value={item.path}>
                        {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
                <p className="text-[11px] text-content-muted">
                  默认使用配置管理中的目录扫描字典；你可以按任务改选其它字典。当前默认：
                  {taskDefaultFileLeakDictPath ? ` ${taskDefaultFileLeakDictPath}` : '（未找到，需手动选择）'}
                </p>
              </div>

              {taskFileLeakDictError ? (
                <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">
                  {taskFileLeakDictError}
                </div>
              ) : null}

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">目标（支持一行一个）</label>
                  <textarea
                    value={taskTarget}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'target', event.target.value))}
                    className="w-full min-h-[132px] rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                    placeholder={'example.com\napi.example.com\n1.2.3.4'}
                  />
                  <p className="text-[11px] text-content-muted">可输入多个目标，支持换行、空格或逗号分隔，提交时会自动归一化。</p>
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">端口扫描范围</label>
                  <div className="relative">
                    <select
                      value={taskPortScanType}
                      disabled={!editable}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'port_scan_type', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="test">test（常见端口）</option>
                      <option value="top100">top100</option>
                      <option value="top1000">top1000</option>
                      <option value="all">all（全端口）</option>
                      <option value="custom">custom（自定义）</option>
                    </select>
                    <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                  {taskPortScanType === 'custom' ? (
                    <input
                      value={taskPortCustom}
                      disabled={!editable}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'port_custom', event.target.value))}
                      className="mt-2 w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                      placeholder="例如：80,443,8080,10000-10100"
                    />
                  ) : null}
                  <div className="mt-3 p-3 rounded-xl border border-base-300 bg-base-100/40 text-[11px] text-content-muted leading-relaxed">
                    建议仅勾选需要的扫描项。目标多时优先开启核心能力（端口扫描、服务识别、站点识别），可提升效率。
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <label className="text-xs font-bold text-content-muted">扫描功能</label>
                  <button
                    type="button"
                    onClick={() => setAllTaskFeatures(!allTaskFeaturesEnabled)}
                    className="text-xs font-bold text-accent hover:underline"
                    disabled={!editable || taskFeatureKeys.length === 0}
                  >
                    {allTaskFeaturesEnabled ? '取消全选' : '全选'}
                  </button>
                </div>
                <div className="space-y-3">
                  {taskFeatureSections.map((section) => (
                    <div key={section.title} className="space-y-2">
                      <p className="text-[11px] font-bold text-content-muted tracking-wide">{section.title}</p>
                      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
                        {section.keys.map((fieldKey) => (
                          <label
                            key={fieldKey}
                            className="flex items-center gap-2 rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm hover:border-accent/50 transition"
                          >
                            <input
                              type="checkbox"
                              checked={Boolean(formPayload?.[fieldKey])}
                              disabled={!editable}
                              className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
                              onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, fieldKey, event.target.checked))}
                            />
                            <span className="font-medium truncate">{humanizeField(fieldKey)}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : isFofaAction ? (
            <div className="space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar pr-1">
              {isFofaSubmitAction ? (
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">任务名称</label>
                  <input
                    value={fofaTaskName}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                    className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                    placeholder="请输入任务名称"
                  />
                </div>
              ) : null}

              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">测绘引擎</label>
                <div className="relative">
                  <select
                    value={fofaProvider}
                    disabled={!editable}
                    onChange={(event) => {
                      const nextProvider = event.target.value;
                      setFormPayload((prev) => updatePayloadValue(prev, 'provider', nextProvider));
                      setFofaResultSize(null);
                    }}
                    className={UNIFIED_SELECT_CLASS}
                  >
                    {measureProviderOptions.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">查询语句</label>
                <textarea
                  value={fofaQueryText}
                  disabled={!editable}
                  onChange={(event) => {
                    setFormPayload((prev) => updatePayloadValue(prev, 'query', event.target.value));
                    setFofaResultSize(null);
                  }}
                  className="w-full min-h-[160px] rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                  placeholder={`请输入 ${currentMeasureProviderLabel} 原生语法（支持多行输入）\n${measureProviderExamples[fofaProvider] || measureProviderExamples.fofa}`}
                />
                <p className="text-[11px] text-content-muted">
                  一行一条 {currentMeasureProviderLabel} 语句，测试和提交时会自动去除空行并去重。
                </p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">结果数</label>
                  <div className="w-full rounded-xl border border-base-300 bg-base-100/60 px-3 py-2 text-sm font-mono">
                    {fofaResultSize === null ? '-' : String(fofaResultSize)}
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">测试</label>
                  <button
                    type="button"
                    onClick={() => void runFofaQueryTest()}
                    disabled={!editable || fofaTesting}
                    className="w-full px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition disabled:opacity-60 flex items-center justify-center gap-2"
                  >
                    <Play className={`w-4 h-4 ${fofaTesting ? 'animate-spin' : ''}`} />
                    {fofaTesting ? '测试中...' : `测试${currentMeasureProviderLabel}`}
                  </button>
                </div>
              </div>

              {isFofaSubmitAction ? (
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">关联策略</label>
                  <div className="relative">
                    <select
                      value={fofaPolicyId}
                      disabled={!editable || taskSchedulePolicyLoading}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'policy_id', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="">
                        {taskSchedulePolicyLoading ? '策略加载中...' : '不关联策略（使用默认扫描配置）'}
                      </option>
                      {taskSchedulePolicyOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
              ) : null}
            </div>
          ) : isTaskScheduleCreate ? (
            <div className="space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar pr-1">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-content-muted">名称</label>
                  <input
                    value={taskScheduleName}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                    className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                    placeholder="请输入计划任务名称"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-content-muted">策略</label>
                  <div className="relative">
                    <select
                      value={taskSchedulePolicyId}
                      disabled={!editable || taskSchedulePolicyLoading}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'policy_id', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="">{taskSchedulePolicyLoading ? '策略加载中...' : '请选择策略'}</option>
                      {taskSchedulePolicyOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-content-muted">计划类型</label>
                  <div className="relative">
                    <select
                      value={taskScheduleType}
                      disabled={!editable}
                      onChange={(event) => {
                        const nextType = event.target.value === 'recurrent_scan' ? 'recurrent_scan' : 'future_scan';
                        setFormPayload((prev) => {
                          let next = updatePayloadValue(prev, 'schedule_type', nextType);
                          if (nextType === 'recurrent_scan' && !String(getPayloadValue(next, 'cron') || '').trim()) {
                            next = updatePayloadValue(next, 'cron', '0 2 * * *');
                          }
                          return next;
                        });
                      }}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="future_scan">定时任务</option>
                      <option value="recurrent_scan">周期任务</option>
                    </select>
                    <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-content-muted">任务类别</label>
                  <div className="relative">
                    <select
                      value={taskScheduleTag}
                      disabled={!editable}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'task_tag', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="task">资产发现任务</option>
                      <option value="risk_cruising">风险巡航任务</option>
                    </select>
                    <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
              </div>

              {taskScheduleType === 'future_scan' ? (
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-content-muted">开始时间</label>
                  <input
                    type="datetime-local"
                    value={taskScheduleStartDate}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'start_date', fromDatetimeLocalValue(event.target.value)))}
                    className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                  />
                </div>
              ) : (
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-content-muted">CRON</label>
                  <input
                    value={taskScheduleCron}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'cron', event.target.value))}
                    className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                    placeholder="例如：0 */6 * * *"
                  />
                </div>
              )}

              <div className="space-y-1">
                <label className="text-sm font-semibold text-content-muted">目标（支持多行，一行一个目标资产）</label>
                <textarea
                  value={taskScheduleTarget}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'target', event.target.value))}
                  className="w-full min-h-[148px] rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                  placeholder={
                    taskScheduleTag === 'risk_cruising'
                      ? 'http://10.0.1.1:8081/\n10.0.1.1:2222'
                      : 'example.com\n10.0.0.1\n10.0.0.0/24'
                  }
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <label className="flex items-center gap-2 rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm hover:border-accent/50 transition">
                  <input
                    type="checkbox"
                    checked={taskScheduleNotifyEnable}
                    disabled={!editable}
                    className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'notify_enable', event.target.checked))}
                  />
                  <span className="font-medium">钉钉通知</span>
                </label>
                <label className="flex items-center gap-2 rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm hover:border-accent/50 transition">
                  <input
                    type="checkbox"
                    checked={taskScheduleNotifyKbEnable}
                    disabled={!editable}
                    className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'notify_kb_enable', event.target.checked))}
                  />
                  <span className="font-medium">推送钉钉知识库</span>
                </label>
              </div>

              {taskSchedulePolicyError ? (
                <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">
                  {taskSchedulePolicyError}
                </div>
              ) : null}
            </div>
          ) : isGithubSchedulerAction ? (
            <div className="space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-sm font-semibold text-content-muted">任务名</label>
                <input
                  value={githubSchedulerName}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                  className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                  placeholder="请输入任务名"
                />
              </div>

              <div className="space-y-1">
                <label className="text-sm font-semibold text-content-muted">关键字</label>
                <input
                  value={githubSchedulerKeyword}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'keyword', event.target.value))}
                  className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                  placeholder="例如：AKIA"
                />
              </div>

              <div className="space-y-1">
                <label className="text-sm font-semibold text-content-muted">cron表达式</label>
                <input
                  value={githubSchedulerCron}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'cron', event.target.value))}
                  className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                  placeholder="例如：0 */6 * * *"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <label className="flex items-center gap-2 rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm hover:border-accent/50 transition">
                  <input
                    type="checkbox"
                    checked={githubSchedulerDingdingNotify}
                    disabled={!editable}
                    className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'dingding_notify', event.target.checked))}
                  />
                  <span className="font-medium">钉钉通知</span>
                </label>
                <label className="flex items-center gap-2 rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm hover:border-accent/50 transition">
                  <input
                    type="checkbox"
                    checked={githubSchedulerKbNotifyEnable}
                    disabled={!editable}
                    className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'kb_notify_enable', event.target.checked))}
                  />
                  <span className="font-medium">推送钉钉知识库</span>
                </label>
              </div>
            </div>
          ) : isAssetScopeCreate ? (
            <div className="space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">资产类别</label>
                <div className="relative">
                  <select
                    value={scopeType}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'scope_type', event.target.value))}
                    className={UNIFIED_SELECT_CLASS}
                  >
                    <option value="domain">域名资产</option>
                    <option value="ip">IP资产</option>
                  </select>
                  <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">资产组名称</label>
                <input
                  value={scopeGroupName}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                  className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                  placeholder="例如：生产外网资产"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">资产范围（支持一行一个）</label>
                <textarea
                  value={scopeText}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'scope', event.target.value))}
                  className="w-full min-h-[168px] rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                  placeholder={
                    scopeType === 'ip'
                      ? '1.1.1.1\n1.1.1.0/24\n1.1.1.1-1.1.1.100'
                      : 'example.com\napi.example.com'
                  }
                />
                <p className="text-[11px] text-content-muted">
                  支持换行、空格或逗号分隔，提交时会自动归一化为多条资产范围。
                </p>
              </div>
            </div>
          ) : isAssetScopeAddScope || isAssetScopeUpdate ? (
            <div className="space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">资产组名称</label>
                <input
                  value={scopeGroupName}
                  disabled={!isAssetScopeUpdate || !editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                  className="w-full rounded-xl border border-base-300 bg-base-100/60 px-3 py-2 text-sm"
                  placeholder="取资产组名称"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">
                  {isAssetScopeUpdate ? '资产范围（保存后覆盖当前列表）' : '资产范围'}
                </label>
                <textarea
                  value={scopeAddTargetText}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'scope', event.target.value))}
                  className="w-full min-h-[168px] rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                  placeholder={'example.com\napi.example.com'}
                />
                <p className="text-[11px] text-content-muted">支持多行或逗号分割。</p>
              </div>
              {isAssetScopeUpdate ? (
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">黑名单</label>
                  <textarea
                    value={scopeBlackText}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'black_scope', event.target.value))}
                    className="w-full min-h-[96px] rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                    placeholder={'test.example.com'}
                  />
                  <p className="text-[11px] text-content-muted">可留空，支持多行或逗号分割。</p>
                </div>
              ) : null}
            </div>
          ) : isAssetScopeAddScheduler ? (
            <div className="space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">范围</label>
                <textarea
                  value={scopeMonitorRangeText}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'domain', event.target.value))}
                  className="w-full min-h-[148px] rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                  placeholder={'example.com\napi.example.com'}
                />
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">运行间隔</label>
                  <div className="relative">
                    <input
                      type="number"
                      min={6}
                      value={scopeMonitorIntervalHours}
                      disabled={!editable}
                      onChange={(event) => {
                        const nextHours = Number(event.target.value || '0');
                        const safeHours = Number.isFinite(nextHours) ? Math.max(1, Math.floor(nextHours)) : 1;
                        setFormPayload((prev) => updatePayloadValue(prev, 'interval', safeHours * 3600));
                      }}
                      className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 pr-10 text-sm"
                    />
                    <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-content-muted">小时</span>
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">策略</label>
                  <div className="relative">
                    <select
                      value={taskSchedulePolicyId}
                      disabled={!editable || taskSchedulePolicyLoading}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'policy_id', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="">{taskSchedulePolicyLoading ? '策略加载中...' : '请选择策略'}</option>
                      {taskSchedulePolicyOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
              </div>
              {taskSchedulePolicyError ? (
                <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">
                  {taskSchedulePolicyError}
                </div>
              ) : null}
            </div>
          ) : (isAssetScopeAddSiteMonitor || isAssetScopeAddWihMonitor) ? (
            <div className="space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">运行间隔</label>
                <div className="relative">
                  <input
                    type="number"
                    min={6}
                    value={scopeMonitorIntervalHours}
                    disabled={!editable}
                    onChange={(event) => {
                      const nextHours = Number(event.target.value || '0');
                      const safeHours = Number.isFinite(nextHours) ? Math.max(1, Math.floor(nextHours)) : 1;
                      setFormPayload((prev) => updatePayloadValue(prev, 'interval', safeHours * 3600));
                    }}
                    className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 pr-10 text-sm"
                  />
                  <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-content-muted">小时</span>
                </div>
              </div>
            </div>
          ) : isPolicyAction ? (
            <div className="space-y-5 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar pr-1">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">策略名称</label>
                  <input
                    value={policyName}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, policyNamePath, event.target.value))}
                    className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                    placeholder="请输入策略名称"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">策略描述</label>
                  <input
                    value={policyDesc}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, policyDescPath, event.target.value))}
                    className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                    placeholder="请输入策略描述"
                  />
                </div>
              </div>

              <div className="bg-base-200/35 border border-base-300 rounded-2xl p-4 space-y-4">
                <h5 className="text-sm font-black">字典配置</h5>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="text-xs font-bold text-content-muted">域名爆破字典</label>
                    <div className="relative">
                      <select
                        value={policyDomainDict}
                        disabled={!editable || taskDomainDictLoading}
                        onChange={(event) => updatePolicyValue('domain_dict', event.target.value)}
                        className={UNIFIED_SELECT_CLASS}
                      >
                        <option value="">跟随配置管理默认字典</option>
                        {policyDomainDictSelectOptions.map((item) => (
                          <option key={item.path} value={item.path}>
                            {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                          </option>
                        ))}
                      </select>
                      <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                    </div>
                    <p className="text-[11px] text-content-muted">
                      不选择时，按配置管理默认字典执行。当前默认：
                      {taskDefaultDomainDictPath ? ` ${taskDefaultDomainDictPath}` : '（未配置）'}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-bold text-content-muted">目录扫描字典</label>
                    <div className="relative">
                      <select
                        value={policyFileLeakDict}
                        disabled={!editable || taskDomainDictLoading}
                        onChange={(event) => updatePolicyValue('file_leak_dict', event.target.value)}
                        className={UNIFIED_SELECT_CLASS}
                      >
                        <option value="">跟随配置管理默认字典</option>
                        {policyFileLeakDictSelectOptions.map((item) => (
                          <option key={item.path} value={item.path}>
                            {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                          </option>
                        ))}
                      </select>
                      <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                    </div>
                    <p className="text-[11px] text-content-muted">
                      不选择时，按配置管理默认字典执行。当前默认：
                      {taskDefaultFileLeakDictPath ? ` ${taskDefaultFileLeakDictPath}` : '（未配置）'}
                    </p>
                  </div>
                </div>
              </div>

              {taskDomainDictError ? (
                <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">
                  {taskDomainDictError}
                </div>
              ) : null}
              {taskFileLeakDictError ? (
                <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">
                  {taskFileLeakDictError}
                </div>
              ) : null}

              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">端口扫描类型</label>
                <div className="relative">
                  <select
                    value={policyPortScanType}
                    disabled={!editable}
                    onChange={(event) => updatePolicyValue('ip_config.port_scan_type', event.target.value)}
                    className={UNIFIED_SELECT_CLASS}
                  >
                    <option value="test">测试</option>
                    <option value="top100">TOP100</option>
                    <option value="top1000">TOP1000</option>
                    <option value="all">全端口</option>
                    <option value="custom">自定义</option>
                  </select>
                  <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              {policyPortScanType === 'custom' ? (
                <div className="space-y-1">
                  <label className="text-xs font-bold text-content-muted">自定义端口</label>
                  <input
                    value={policyPortCustom}
                    disabled={!editable}
                    onChange={(event) => updatePolicyValue('ip_config.port_custom', event.target.value)}
                    className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                    placeholder="80,443,8080"
                  />
                </div>
              ) : null}

              <div className="bg-base-200/35 border border-base-300 rounded-2xl p-4 space-y-4">
                <div className="flex items-center justify-between gap-3">
                  <h5 className="text-sm font-black">基础扫描配置</h5>
                  <button
                    type="button"
                    className="text-xs font-bold text-accent hover:underline"
                    onClick={() => setPolicyOptionAll(!policyOptionAllEnabled)}
                    disabled={!editable}
                  >
                    {policyOptionAllEnabled ? '取消全选' : '全选'}
                  </button>
                </div>
                <input
                  value={policySearchKeyword}
                  onChange={(event) => setPolicySearchKeyword(event.target.value)}
                  className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                  placeholder="请输入关键字进行查询"
                />
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
                  {filteredPolicyOptions.map((item) => (
                    <label key={item.key} className="flex items-center gap-2 rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm">
                      <input
                        type="checkbox"
                        checked={Boolean(getPayloadValue(formPayload, getPolicyPath(item.key)))}
                        disabled={!editable}
                        onChange={(event) => updatePolicyValue(item.key, event.target.checked)}
                        className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
                      />
                      <span className="truncate">{item.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="bg-base-200/35 border border-base-300 rounded-2xl p-4 space-y-4">
                <div className="flex items-center justify-between gap-3">
                  <h5 className="text-sm font-black">PoC 配置</h5>
                  <button
                    type="button"
                    className="text-xs font-bold text-accent hover:underline"
                    onClick={() =>
                      setPolicyPluginConfig(
                        'poc_config',
                        policyPocAllSelected ? [] : policyPocOptions.map((item) => item.plugin_name)
                      )
                    }
                    disabled={!editable || policyPocOptions.length === 0}
                  >
                    {policyPocAllSelected ? '取消全选' : '全选'}
                  </button>
                </div>
                <input
                  value={policyPocKeyword}
                  onChange={(event) => setPolicyPocKeyword(event.target.value)}
                  className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                  placeholder="请输入关键字筛选 PoC"
                />
                <div className="max-h-52 overflow-y-auto custom-scrollbar grid grid-cols-1 md:grid-cols-2 gap-2 pr-1">
                  {filteredPolicyPocOptions.map((item) => (
                    <label key={item.plugin_name} className="flex items-center gap-2 rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm">
                      <input
                        type="checkbox"
                        checked={selectedPolicyPocNames.includes(item.plugin_name)}
                        disabled={!editable}
                        onChange={(event) => togglePolicyPluginSelection('poc_config', item.plugin_name, event.target.checked)}
                        className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
                      />
                      <span className="truncate">{item.vul_name || item.plugin_name}</span>
                    </label>
                  ))}
                  {!policyPluginLoading && filteredPolicyPocOptions.length === 0 ? (
                    <p className="text-xs text-content-muted">暂无匹配的 PoC 项</p>
                  ) : null}
                </div>
              </div>

              <div className="bg-base-200/35 border border-base-300 rounded-2xl p-4 space-y-4">
                <div className="flex items-center justify-between gap-3">
                  <h5 className="text-sm font-black">弱口令爆破配置</h5>
                  <button
                    type="button"
                    className="text-xs font-bold text-accent hover:underline"
                    onClick={() =>
                      setPolicyPluginConfig(
                        'brute_config',
                        policyBruteAllSelected ? [] : policyBruteOptions.map((item) => item.plugin_name)
                      )
                    }
                    disabled={!editable || policyBruteOptions.length === 0}
                  >
                    {policyBruteAllSelected ? '取消全选' : '全选'}
                  </button>
                </div>
                <input
                  value={policyBruteKeyword}
                  onChange={(event) => setPolicyBruteKeyword(event.target.value)}
                  className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                  placeholder="请输入关键字筛选弱口令插件"
                />
                <div className="max-h-52 overflow-y-auto custom-scrollbar grid grid-cols-1 md:grid-cols-2 gap-2 pr-1">
                  {filteredPolicyBruteOptions.map((item) => (
                    <label key={item.plugin_name} className="flex items-center gap-2 rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm">
                      <input
                        type="checkbox"
                        checked={selectedPolicyBruteNames.includes(item.plugin_name)}
                        disabled={!editable}
                        onChange={(event) => togglePolicyPluginSelection('brute_config', item.plugin_name, event.target.checked)}
                        className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
                      />
                      <span className="truncate">{item.vul_name || item.plugin_name}</span>
                    </label>
                  ))}
                  {!policyPluginLoading && filteredPolicyBruteOptions.length === 0 ? (
                    <p className="text-xs text-content-muted">暂无匹配的弱口令插件</p>
                  ) : null}
                </div>
              </div>

              {policyPluginLoading ? (
                <div className="text-xs text-content-muted">PoC 列表加载中...</div>
              ) : null}
              {policyPluginError ? (
                <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">
                  {policyPluginError}
                </div>
              ) : null}
            </div>
          ) : (
            <div className="space-y-3 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar pr-1">
              {displayFields.map((field) => {
                const value = field.value;
                const disabled = !editable;
                const isBoolean = typeof value === 'boolean';
                const isNumber = typeof value === 'number';
                const isComplex = Array.isArray(value) || (value && typeof value === 'object');

                return (
                  <div key={field.path} className="space-y-1">
                    <label className="text-xs font-bold text-content-muted">
                      {humanizeField(field.path)}
                      {!isTaskCreate && !isPolicyAction ? <span className="ml-2 text-[10px] font-mono opacity-70">{field.path}</span> : null}
                    </label>
                    {isBoolean ? (
                      <label className="flex items-center justify-between rounded-xl border border-base-300 bg-base-100 px-3 py-2.5 text-sm">
                        <span className="font-semibold">{value ? '启用' : '关闭'}</span>
                        <input
                          type="checkbox"
                          checked={value}
                          disabled={disabled}
                          className="h-5 w-5 cursor-pointer rounded-md border border-base-300 bg-base-100"
                          onChange={(event) => {
                            setFormPayload((prev) => updatePayloadValue(prev, field.path, event.target.checked));
                          }}
                        />
                      </label>
                    ) : isNumber ? (
                      <input
                        type="number"
                        value={value}
                        disabled={disabled}
                        onChange={(event) => {
                          const next = Number(event.target.value || '0');
                          setFormPayload((prev) => updatePayloadValue(prev, field.path, next));
                        }}
                        className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                      />
                    ) : isComplex ? (
                      <input
                        value={Array.isArray(value) ? value.join(',') : String(value ?? '')}
                        disabled={disabled}
                        onChange={(event) => {
                          const nextValues = event.target.value
                            .split(',')
                            .map((item) => item.trim())
                            .filter((item) => item);
                          setFormPayload((prev) => updatePayloadValue(prev, field.path, nextValues));
                          setError('');
                        }}
                        placeholder="多个值请用逗号分隔"
                        className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                      />
                    ) : (
                      <input
                        value={String(value ?? '')}
                        disabled={disabled}
                        onChange={(event) => {
                          setFormPayload((prev) => updatePayloadValue(prev, field.path, event.target.value));
                        }}
                        className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                      />
                    )}
                  </div>
                );
              })}

            </div>
          )}

          {!editable ? (
            <div className="text-xs text-content-muted bg-base-100/60 border border-base-300 rounded-lg px-3 py-2">
              当前动作使用固定参数，已禁用编辑。
            </div>
          ) : null}

          {error ? (
            <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">{error}</div>
          ) : null}

          <div className="flex justify-end gap-3">
            <button
              onClick={onClose}
              className="px-5 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition"
            >
              取消
            </button>
            <button
              onClick={async () => {
                try {
                  setLoading(true);
                  setError('');
                  let payload: JsonValue = deepClone(!editable ? initialPayload : formPayload);
                  if (isFofaAction && editable) {
                    const normalizedQueryList = normalizeFofaQueries(String(payload.query || ''));
                    if (normalizedQueryList.length === 0) {
                      throw new Error('请填写查询语句（支持多行输入）');
                    }

                    const normalizedQuery = normalizedQueryList.join('\n');
                    payload.query = normalizedQuery;

                    if (isFofaSubmitAction) {
                      const normalizedName = String(payload.name || '').trim();
                      const policyId = String(payload.policy_id || '').trim();

                      if (!normalizedName) {
                        throw new Error('请填写任务名称');
                      }

                      payload.name = normalizedName;
                      if (policyId) {
                        payload.policy_id = policyId;
                      } else {
                        delete payload.policy_id;
                      }
                    } else {
                      payload = { query: normalizedQuery };
                    }
                  }
                  if (isTaskCreate && editable) {
                    const normalizedName = String(payload.name || '').trim();
                    const normalizedTargets = String(payload.target || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .map((item) => item.trim())
                      .filter((item) => item);
                    const normalizedDomainDict = String(payload.domain_dict || '').trim();
                    const fallbackDomainDict = String(taskDefaultDomainDictPath || '').trim();
                    const resolvedDomainDict = normalizedDomainDict || fallbackDomainDict;
                    const normalizedFileLeakDict = String(payload.file_leak_dict || '').trim();
                    const fallbackFileLeakDict = String(taskDefaultFileLeakDictPath || '').trim();
                    const resolvedFileLeakDict = normalizedFileLeakDict || fallbackFileLeakDict;
                    const normalizedPortScanType = String(payload.port_scan_type || 'test').trim().toLowerCase();
                    const normalizedPortCustom = String(payload.port_custom || '')
                      .replace(/，/g, ',')
                      .replace(/\s+/g, ',')
                      .split(',')
                      .map((item) => item.trim())
                      .filter((item) => item)
                      .join(',');

                    if (!normalizedName) {
                      throw new Error('请填写任务名称');
                    }
                    if (normalizedTargets.length === 0) {
                      throw new Error('请填写目标，支持一行一个');
                    }
                    if (normalizedPortScanType === 'custom') {
                      if (!normalizedPortCustom) {
                        throw new Error('端口扫描范围为 custom 时，请填写自定义端口');
                      }
                      const hasInvalidPort = normalizedPortCustom
                        .split(',')
                        .some((item) => !/^\d+(?:-\d+)?$/.test(item));
                      if (hasInvalidPort) {
                        throw new Error('自定义端口格式错误，仅支持端口或端口段，如 80,443,10000-10100');
                      }
                    }

                    payload.name = normalizedName;
                    payload.target = normalizedTargets.join('\n');
                    payload.domain_brute = true;
                    payload.domain_brute_type = 'big';
                    payload.port_scan_type = normalizedPortScanType;
                    if (!resolvedDomainDict) {
                      throw new Error('未找到可用域名爆破字典，请先在配置管理中确认 domain_2w.txt 或上传字典');
                    }
                    payload.domain_dict = resolvedDomainDict;
                    if (Boolean(payload.file_leak) && !resolvedFileLeakDict) {
                      throw new Error('目录扫描已开启，但未找到可用目录扫描字典，请先在配置管理中配置或上传字典');
                    }
                    if (resolvedFileLeakDict) {
                      payload.file_leak_dict = resolvedFileLeakDict;
                    } else {
                      delete payload.file_leak_dict;
                    }
                    if (normalizedPortScanType === 'custom') {
                      payload.port_custom = normalizedPortCustom;
                    } else {
                      delete payload.port_custom;
                    }
                  }
                  if (isTaskScheduleCreate && editable) {
                    const normalizedName = String(payload.name || '').trim();
                    const normalizedTargets = String(payload.target || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .flatMap((line) => line.split(/\s+/))
                      .map((item) => item.trim())
                      .filter((item) => item);
                    const scheduleType = String(payload.schedule_type || 'future_scan').trim().toLowerCase();
                    const taskTag = String(payload.task_tag || 'task').trim().toLowerCase();
                    const policyId = String(payload.policy_id || '').trim();
                    const cron = String(payload.cron || '').trim();
                    const startDate = fromDatetimeLocalValue(String(payload.start_date || '').trim());

                    if (!normalizedName) {
                      throw new Error('请填写名称');
                    }
                    if (normalizedTargets.length === 0) {
                      throw new Error('请填写目标，支持一行一个目标资产');
                    }
                    if (!policyId) {
                      throw new Error('请选择策略');
                    }
                    if (!['future_scan', 'recurrent_scan'].includes(scheduleType)) {
                      throw new Error('计划类型无效');
                    }
                    if (!['task', 'risk_cruising'].includes(taskTag)) {
                      throw new Error('任务类别无效');
                    }
                    if (scheduleType === 'future_scan' && !startDate) {
                      throw new Error('请选择开始时间');
                    }
                    if (scheduleType === 'recurrent_scan' && !cron) {
                      throw new Error('请填写 CRON 表达式');
                    }

                    payload.name = normalizedName;
                    payload.target = normalizedTargets.join('\n');
                    payload.schedule_type = scheduleType;
                    payload.task_tag = taskTag;
                    payload.policy_id = policyId;
                    payload.notify_enable = Boolean(payload.notify_enable);
                    payload.notify_kb_enable = Boolean(payload.notify_kb_enable);
                    payload.notify_channel = 'dingding';
                    payload.notify_on = 'finished';
                    if (scheduleType === 'future_scan') {
                      payload.start_date = startDate;
                      payload.cron = '';
                    } else {
                      payload.cron = cron;
                      payload.start_date = '';
                    }
                  }
                  if (isGithubSchedulerAction && editable) {
                    const normalizedName = String(payload.name || '').trim();
                    const normalizedKeyword = String(payload.keyword || '').trim();
                    const normalizedCron = String(payload.cron || '').trim();

                    if (!normalizedName) {
                      throw new Error('请填写任务名');
                    }
                    if (!normalizedKeyword) {
                      throw new Error('请填写关键字');
                    }
                    if (!normalizedCron) {
                      throw new Error('请填写 cron 表达式');
                    }

                    payload.name = normalizedName;
                    payload.keyword = normalizedKeyword;
                    payload.cron = normalizedCron;
                    payload.dingding_notify = Boolean(payload.dingding_notify);
                    payload.kb_notify_enable = Boolean(payload.kb_notify_enable);
                  }
                  if (isAssetScopeCreate && editable) {
                    const normalizedName = String(payload.name || '').trim();
                    const normalizedScopes = String(payload.scope || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .flatMap((line) => line.split(/\s+/))
                      .map((item) => item.trim())
                      .filter((item) => item);

                    if (!normalizedName) {
                      throw new Error('请填写资产组名称');
                    }
                    if (normalizedScopes.length === 0) {
                      throw new Error('请填写资产范围，支持一行一个');
                    }

                    payload.name = normalizedName;
                    payload.scope_type = String(payload.scope_type || 'domain') === 'ip' ? 'ip' : 'domain';
                    payload.scope = normalizedScopes.join('\n');
                    payload.black_scope = '';
                  }
                  if ((isAssetScopeAddScope || isAssetScopeUpdate) && editable) {
                    const scopeId = String(payload.scope_id || '').trim();
                    const normalizedName = String(payload.name || '').trim();
                    const normalizedScopes = String(payload.scope || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .flatMap((line) => line.split(/\s+/))
                      .map((item) => item.trim())
                      .filter((item) => item);
                    const normalizedBlackScopes = String(payload.black_scope || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .flatMap((line) => line.split(/\s+/))
                      .map((item) => item.trim())
                      .filter((item) => item);

                    if (!scopeId) {
                      throw new Error('资产范围ID无效，请刷新后重试');
                    }
                    if (isAssetScopeUpdate && !normalizedName) {
                      throw new Error('请填写资产组名称');
                    }
                    if (normalizedScopes.length === 0) {
                      throw new Error('请填写资产范围，支持多行或逗号分割');
                    }

                    if (isAssetScopeUpdate) {
                      payload = {
                        scope_id: scopeId,
                        name: normalizedName,
                        scope: normalizedScopes.join(','),
                        black_scope: normalizedBlackScopes.join(','),
                      };
                    } else {
                      payload = {
                        scope_id: scopeId,
                        scope: normalizedScopes.join(','),
                      };
                    }
                  }
                  if (isAssetScopeAddScheduler && editable) {
                    const scopeId = String(payload.scope_id || '').trim();
                    const policyId = String(payload.policy_id || '').trim();
                    const normalizedName = String(payload.name || '').trim();
                    const interval = Number(payload.interval || 0);
                    const normalizedTargets = String(payload.domain || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .flatMap((line) => line.split(/\s+/))
                      .map((item) => item.trim())
                      .filter((item) => item);

                    if (!scopeId) {
                      throw new Error('资产范围ID无效，请刷新后重试');
                    }
                    if (normalizedTargets.length === 0) {
                      throw new Error('请填写范围');
                    }
                    if (!Number.isFinite(interval) || interval < 3600 * 6) {
                      throw new Error('运行间隔最小为6小时');
                    }

                    payload = {
                      scope_id: scopeId,
                      domain: normalizedTargets.join(','),
                      interval: Math.floor(interval),
                      name: normalizedName,
                      policy_id: policyId,
                    };
                  }
                  if ((isAssetScopeAddSiteMonitor || isAssetScopeAddWihMonitor) && editable) {
                    const scopeId = String(payload.scope_id || '').trim();
                    const normalizedName = String(payload.name || '').trim();
                    const interval = Number(payload.interval || 0);

                    if (!scopeId) {
                      throw new Error('资产范围ID无效，请刷新后重试');
                    }
                    if (!Number.isFinite(interval) || interval < 3600 * 6) {
                      throw new Error('运行间隔最小为6小时');
                    }

                    payload = {
                      scope_id: scopeId,
                      interval: Math.floor(interval),
                      name: normalizedName,
                    };
                  }
                  if (isPolicyAction && editable) {
                    const normalizedPolicyName = String(getPayloadValue(payload, policyNamePath) || '').trim();
                    if (!normalizedPolicyName) {
                      throw new Error('请填写策略名称');
                    }

                    const normalizedPortScanType = String(getPayloadValue(payload, getPolicyPath('ip_config.port_scan_type')) || 'test').trim().toLowerCase();
                    const normalizedPortCustom = String(getPayloadValue(payload, getPolicyPath('ip_config.port_custom')) || '')
                      .replace(/，/g, ',')
                      .replace(/\s+/g, ',')
                      .split(',')
                      .map((item) => item.trim())
                      .filter((item) => item)
                      .join(',');
                    const normalizedDomainDict = String(getPayloadValue(payload, getPolicyPath('domain_dict')) || '').trim();
                    const normalizedFileLeakDict = String(getPayloadValue(payload, getPolicyPath('file_leak_dict')) || '').trim();

                    if (normalizedPortScanType === 'custom' && !normalizedPortCustom) {
                      throw new Error('端口扫描类型为自定义时，请填写自定义端口');
                    }
                    if (normalizedPortScanType === 'custom') {
                      const hasInvalidPort = normalizedPortCustom
                        .split(',')
                        .some((item) => !/^\d+(?:-\d+)?$/.test(item));
                      if (hasInvalidPort) {
                        throw new Error('自定义端口格式错误，仅支持端口或端口段，如 80,443,10000-10100');
                      }
                    }

                    payload = updatePayloadValue(payload, policyNamePath, normalizedPolicyName);
                    // 策略层固定启用域名爆破，字典来源通过 domain_dict 指定。
                    payload = updatePayloadValue(payload, getPolicyPath('domain_config.domain_brute'), true);
                    payload = updatePayloadValue(payload, getPolicyPath('domain_config.domain_brute_type'), 'big');
                    payload = updatePayloadValue(payload, getPolicyPath('domain_dict'), normalizedDomainDict);
                    payload = updatePayloadValue(payload, getPolicyPath('file_leak_dict'), normalizedFileLeakDict);
                    if (normalizedPortScanType === 'custom') {
                      payload = updatePayloadValue(payload, getPolicyPath('ip_config.port_custom'), normalizedPortCustom);
                    }
                  }
                  await onSubmit(payload, file);
                  onClose();
                } catch (err: any) {
                  setError(err?.message || '执行失败');
                } finally {
                  setLoading(false);
                }
              }}
              className="px-5 py-2.5 rounded-xl bg-brand-accent hover:opacity-90 transition text-sm font-black tracking-wider uppercase"
              disabled={loading}
            >
              {loading ? '执行中...' : (isPolicyAction || isTaskScheduleCreate || isGithubSchedulerAction || isAssetScopeAddScope || isAssetScopeAddScheduler || isAssetScopeAddSiteMonitor || isAssetScopeAddWihMonitor) ? '确定' : '执行'}
            </button>
          </div>
        </div>
    </Modal>
  );
}
