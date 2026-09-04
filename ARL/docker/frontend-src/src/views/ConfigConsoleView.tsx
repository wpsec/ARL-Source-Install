import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  AlertTriangle,
  ChevronDown,
  GitBranch,
  RefreshCw,
  Settings,
  Upload,
} from 'lucide-react';
import { requestApi } from '../api/client';
import { Modal } from '../components/ui/Modal';
import { PageHeader } from '../layout/PageHeader';
import {
  CONSOLE_FILE_INPUT_CLASS,
  CONSOLE_INPUT_CLASS,
  CONSOLE_SELECT_CLASS,
  CONSOLE_TEXTAREA_MONO_CLASS,
} from '../ui/classes';

export function ConfigConsoleView({ token }: { token: string }) {
  type ScanProfileValueMap = Record<string, string | number | boolean>;

  type DomainDictOption = {
    label: string;
    path: string;
    source: string;
    exists: boolean;
    size: number;
    selected?: boolean;
  };

  type ScanProfile = {
    id: string;
    label: string;
    description: string;
    cpu_cores: number;
    memory_gb: number;
    bandwidth_mbps: number;
    selected?: boolean;
    values: ScanProfileValueMap;
  };

  const fallbackScanProfiles: ScanProfile[] = [
    {
      id: 'low_performance',
      label: '低性能配置',
      description: '适用于低资源主机，单次并行约 1 个目标，优先保证系统可访问性',
      cpu_cores: 2,
      memory_gb: 2,
      bandwidth_mbps: 3,
      values: {
        domain_brute_concurrent: 48,
        alt_dns_concurrent: 160,
        web_gunicorn_workers: 1,
        celery_task_worker_concurrency: 1,
        celery_github_worker_concurrency: 1,
        celery_heavy_worker_concurrency: 1,
        celery_web_worker_concurrency: 1,
        celery_prefetch_multiplier: 1,
        celery_max_tasks_per_child: 16,
        celery_max_memory_per_child: 200000,
        nuclei_single_target_timeout_sec: 3600,
        nuclei_rate_limit: 3,
        nuclei_concurrency: 1,
        nuclei_bulk_size: 2,
        afrog_concurrency: 3,
        afrog_rate_limit: 3,
        urlfinder_url_probe_enable: true,
        urlfinder_url_probe_max_targets: 150,
        urlfinder_url_probe_concurrency: 3,
        host_timeout_type: 'default',
        host_timeout: 1200,
        port_parallelism: 10,
        port_min_rate: 32,
      },
    },
    {
      id: 'medium_performance',
      label: '中性能配置',
      description: '适用于中等资源主机，单次并行约 2 个目标，兼顾扫描效率与系统可用性',
      cpu_cores: 4,
      memory_gb: 4,
      bandwidth_mbps: 5,
      values: {
        domain_brute_concurrent: 96,
        alt_dns_concurrent: 320,
        web_gunicorn_workers: 2,
        celery_task_worker_concurrency: 2,
        celery_github_worker_concurrency: 1,
        celery_heavy_worker_concurrency: 2,
        celery_web_worker_concurrency: 2,
        celery_prefetch_multiplier: 1,
        celery_max_tasks_per_child: 20,
        celery_max_memory_per_child: 280000,
        nuclei_single_target_timeout_sec: 7200,
        nuclei_rate_limit: 4,
        nuclei_concurrency: 2,
        nuclei_bulk_size: 3,
        afrog_concurrency: 8,
        afrog_rate_limit: 8,
        urlfinder_url_probe_enable: true,
        urlfinder_url_probe_max_targets: 220,
        urlfinder_url_probe_concurrency: 4,
        host_timeout_type: 'default',
        host_timeout: 1200,
        port_parallelism: 16,
        port_min_rate: 48,
      },
    },
    {
      id: 'high_performance',
      label: '高性能配置',
      description: '适用于高资源主机，单次并行约 3 个目标，兼顾准确率与扫描吞吐',
      cpu_cores: 8,
      memory_gb: 16,
      bandwidth_mbps: 10,
      values: {
        domain_brute_concurrent: 360,
        alt_dns_concurrent: 1400,
        web_gunicorn_workers: 6,
        celery_task_worker_concurrency: 3,
        celery_github_worker_concurrency: 2,
        celery_heavy_worker_concurrency: 3,
        celery_web_worker_concurrency: 3,
        celery_prefetch_multiplier: 1,
        celery_max_tasks_per_child: 32,
        celery_max_memory_per_child: 720000,
        nuclei_single_target_timeout_sec: 900,
        nuclei_rate_limit: 50,
        nuclei_concurrency: 24,
        nuclei_bulk_size: 30,
        afrog_concurrency: 30,
        afrog_rate_limit: 30,
        urlfinder_url_probe_enable: true,
        urlfinder_url_probe_max_targets: 800,
        urlfinder_url_probe_concurrency: 20,
        host_timeout_type: 'default',
        host_timeout: 1500,
        port_parallelism: 64,
        port_min_rate: 260,
      },
    },
  ];

  const [configPath, setConfigPath] = useState('');
  const [updatedAt, setUpdatedAt] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [nucleiPocUpdating, setNucleiPocUpdating] = useState(false);
  const [afrogPocUpdating, setAfrogPocUpdating] = useState(false);
  const [domainUploading, setDomainUploading] = useState(false);
  const [fileLeakUploading, setFileLeakUploading] = useState(false);
  const [showRestartModal, setShowRestartModal] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [domainDictOptions, setDomainDictOptions] = useState<DomainDictOption[]>([]);
  const [fileLeakDictOptions, setFileLeakDictOptions] = useState<DomainDictOption[]>([]);
  const [scanProfiles, setScanProfiles] = useState<ScanProfile[]>(fallbackScanProfiles);
  const [uploadDomainFile, setUploadDomainFile] = useState<File | null>(null);
  const [uploadFileLeakFile, setUploadFileLeakFile] = useState<File | null>(null);
  const domainUploadInputRef = useRef<HTMLInputElement | null>(null);
  const fileLeakUploadInputRef = useRef<HTMLInputElement | null>(null);

  const [domainDict, setDomainDict] = useState('');
  const [fileLeakDict, setFileLeakDict] = useState('');
  const [domainBruteConcurrent, setDomainBruteConcurrent] = useState(360);
  const [altDnsConcurrent, setAltDnsConcurrent] = useState(1400);
  const [webGunicornWorkers, setWebGunicornWorkers] = useState(6);
  const [celeryTaskWorkerConcurrency, setCeleryTaskWorkerConcurrency] = useState(3);
  const [celeryGithubWorkerConcurrency, setCeleryGithubWorkerConcurrency] = useState(2);
  const [celeryHeavyWorkerConcurrency, setCeleryHeavyWorkerConcurrency] = useState(3);
  const [celeryWebWorkerConcurrency, setCeleryWebWorkerConcurrency] = useState(3);
  const [celeryPrefetchMultiplier, setCeleryPrefetchMultiplier] = useState(1);
  const [celeryMaxTasksPerChild, setCeleryMaxTasksPerChild] = useState(32);
  const [celeryMaxMemoryPerChild, setCeleryMaxMemoryPerChild] = useState(720000);
  const [nucleiSingleTargetTimeoutSec, setNucleiSingleTargetTimeoutSec] = useState(900);
  const [nucleiRateLimit, setNucleiRateLimit] = useState(50);
  const [nucleiConcurrency, setNucleiConcurrency] = useState(24);
  const [nucleiBulkSize, setNucleiBulkSize] = useState(30);
  const [afrogConcurrency, setAfrogConcurrency] = useState(30);
  const [afrogRateLimit, setAfrogRateLimit] = useState(30);
  const [pocUpdateProxy, setPocUpdateProxy] = useState('');
  const [urlfinderUrlProbeEnable, setUrlfinderUrlProbeEnable] = useState(true);
  const [urlfinderUrlProbeMaxTargets, setUrlfinderUrlProbeMaxTargets] = useState(800);
  const [urlfinderUrlProbeConcurrency, setUrlfinderUrlProbeConcurrency] = useState(20);
  const [hostTimeoutType, setHostTimeoutType] = useState('default');
  const [hostTimeout, setHostTimeout] = useState(1500);
  const [portParallelism, setPortParallelism] = useState(64);
  const [portMinRate, setPortMinRate] = useState(260);
  const [blackIpsText, setBlackIpsText] = useState('');
  const [dnsResolversText, setDnsResolversText] = useState('');
  const compactFieldInputClass = `${CONSOLE_INPUT_CLASS} xl:max-w-[440px]`;
  const compactFieldFilenameClass = `${CONSOLE_FILE_INPUT_CLASS} flex-none w-full lg:w-[440px]`;

  const splitTextList = (rawText: string) =>
    rawText
      .replace(/,/g, '\n')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '');

  const normalizeScanProfiles = (rawValue: any): ScanProfile[] => {
    if (!Array.isArray(rawValue) || rawValue.length === 0) {
      return fallbackScanProfiles;
    }

    const normalizedList: ScanProfile[] = rawValue
      .map((item: any) => {
        const id = String(item?.id || '').trim();
        if (!id) {
          return null;
        }
        const values: ScanProfileValueMap = item?.values && typeof item.values === 'object' ? item.values : {};
        return {
          id,
          label: String(item?.label || id),
          description: String(item?.description || ''),
          cpu_cores: Number(item?.cpu_cores || 0),
          memory_gb: Number(item?.memory_gb || 0),
          bandwidth_mbps: Number(item?.bandwidth_mbps || 0),
          selected: Boolean(item?.selected),
          values,
        };
      })
      .filter((item: ScanProfile | null): item is ScanProfile => Boolean(item));

    return normalizedList.length > 0 ? normalizedList : fallbackScanProfiles;
  };

  const applyScanProfile = (profile: ScanProfile) => {
    const values = profile.values || {};
    const getNumber = (key: string, currentValue: number) => {
      const raw = values[key];
      const parsed = Number(raw);
      return Number.isFinite(parsed) && parsed > 0 ? parsed : currentValue;
    };
    const getBool = (key: string, currentValue: boolean) => {
      const raw = values[key];
      if (typeof raw === 'boolean') {
        return raw;
      }
      if (typeof raw === 'number') {
        return raw > 0;
      }
      if (typeof raw === 'string') {
        const normalized = raw.trim().toLowerCase();
        if (['1', 'true', 'yes', 'y', 'on'].includes(normalized)) {
          return true;
        }
        if (['0', 'false', 'no', 'n', 'off'].includes(normalized)) {
          return false;
        }
      }
      return currentValue;
    };

    setDomainBruteConcurrent(getNumber('domain_brute_concurrent', domainBruteConcurrent));
    setAltDnsConcurrent(getNumber('alt_dns_concurrent', altDnsConcurrent));
    setWebGunicornWorkers(getNumber('web_gunicorn_workers', webGunicornWorkers));
    setCeleryTaskWorkerConcurrency(getNumber('celery_task_worker_concurrency', celeryTaskWorkerConcurrency));
    setCeleryGithubWorkerConcurrency(getNumber('celery_github_worker_concurrency', celeryGithubWorkerConcurrency));
    setCeleryHeavyWorkerConcurrency(getNumber('celery_heavy_worker_concurrency', celeryHeavyWorkerConcurrency));
    setCeleryWebWorkerConcurrency(getNumber('celery_web_worker_concurrency', celeryWebWorkerConcurrency));
    setCeleryPrefetchMultiplier(getNumber('celery_prefetch_multiplier', celeryPrefetchMultiplier));
    setCeleryMaxTasksPerChild(getNumber('celery_max_tasks_per_child', celeryMaxTasksPerChild));
    setCeleryMaxMemoryPerChild(getNumber('celery_max_memory_per_child', celeryMaxMemoryPerChild));
    setNucleiSingleTargetTimeoutSec(getNumber('nuclei_single_target_timeout_sec', nucleiSingleTargetTimeoutSec));
    setNucleiRateLimit(getNumber('nuclei_rate_limit', nucleiRateLimit));
    setNucleiConcurrency(getNumber('nuclei_concurrency', nucleiConcurrency));
    setNucleiBulkSize(getNumber('nuclei_bulk_size', nucleiBulkSize));
    setAfrogConcurrency(getNumber('afrog_concurrency', afrogConcurrency));
    setAfrogRateLimit(getNumber('afrog_rate_limit', afrogRateLimit));
    setUrlfinderUrlProbeEnable(getBool('urlfinder_url_probe_enable', urlfinderUrlProbeEnable));
    setUrlfinderUrlProbeMaxTargets(getNumber('urlfinder_url_probe_max_targets', urlfinderUrlProbeMaxTargets));
    setUrlfinderUrlProbeConcurrency(getNumber('urlfinder_url_probe_concurrency', urlfinderUrlProbeConcurrency));

    const timeoutTypeRaw = String(values.host_timeout_type || '').trim().toLowerCase();
    if (timeoutTypeRaw === 'custom' || timeoutTypeRaw === 'default') {
      setHostTimeoutType(timeoutTypeRaw);
    }
    setHostTimeout(getNumber('host_timeout', hostTimeout));
    setPortParallelism(getNumber('port_parallelism', portParallelism));
    setPortMinRate(getNumber('port_min_rate', portMinRate));
    setError('');
    setSuccess(`已应用预定义配置：${profile.label}，请点击“保存配置”生效。`);
  };

  const currentProfileValues = useMemo(
    () => ({
      domain_brute_concurrent: Math.floor(domainBruteConcurrent),
      alt_dns_concurrent: Math.floor(altDnsConcurrent),
      web_gunicorn_workers: Math.floor(webGunicornWorkers),
      celery_task_worker_concurrency: Math.floor(celeryTaskWorkerConcurrency),
      celery_github_worker_concurrency: Math.floor(celeryGithubWorkerConcurrency),
      celery_heavy_worker_concurrency: Math.floor(celeryHeavyWorkerConcurrency),
      celery_web_worker_concurrency: Math.floor(celeryWebWorkerConcurrency),
      celery_prefetch_multiplier: Math.floor(celeryPrefetchMultiplier),
      celery_max_tasks_per_child: Math.floor(celeryMaxTasksPerChild),
      celery_max_memory_per_child: Math.floor(celeryMaxMemoryPerChild),
      nuclei_single_target_timeout_sec: Math.floor(nucleiSingleTargetTimeoutSec),
      nuclei_rate_limit: Math.floor(nucleiRateLimit),
      nuclei_concurrency: Math.floor(nucleiConcurrency),
      nuclei_bulk_size: Math.floor(nucleiBulkSize),
      afrog_concurrency: Math.floor(afrogConcurrency),
      afrog_rate_limit: Math.floor(afrogRateLimit),
      urlfinder_url_probe_enable: Boolean(urlfinderUrlProbeEnable),
      urlfinder_url_probe_max_targets: Math.floor(urlfinderUrlProbeMaxTargets),
      urlfinder_url_probe_concurrency: Math.floor(urlfinderUrlProbeConcurrency),
      host_timeout_type: hostTimeoutType === 'custom' ? 'custom' : 'default',
      host_timeout: Math.floor(hostTimeout),
      port_parallelism: Math.floor(portParallelism),
      port_min_rate: Math.floor(portMinRate),
    }),
    [
      domainBruteConcurrent,
      altDnsConcurrent,
      webGunicornWorkers,
      celeryTaskWorkerConcurrency,
      celeryGithubWorkerConcurrency,
      celeryHeavyWorkerConcurrency,
      celeryWebWorkerConcurrency,
      celeryPrefetchMultiplier,
      celeryMaxTasksPerChild,
      celeryMaxMemoryPerChild,
      nucleiSingleTargetTimeoutSec,
      nucleiRateLimit,
      nucleiConcurrency,
      nucleiBulkSize,
      afrogConcurrency,
      afrogRateLimit,
      urlfinderUrlProbeEnable,
      urlfinderUrlProbeMaxTargets,
      urlfinderUrlProbeConcurrency,
      hostTimeoutType,
      hostTimeout,
      portParallelism,
      portMinRate,
    ]
  );

  const matchedScanProfileId = useMemo(() => {
    for (const profile of scanProfiles) {
      const values = profile.values || {};
      const matched = Object.keys(values).every((key) => {
        return (currentProfileValues as any)[key] === values[key];
      });
      if (matched) {
        return profile.id;
      }
    }
    return '';
  }, [scanProfiles, currentProfileValues]);
  const matchedScanProfileLabel = useMemo(() => {
    if (!matchedScanProfileId) return '';
    const matchedProfile = scanProfiles.find((profile) => profile.id === matchedScanProfileId);
    return matchedProfile?.label || matchedScanProfileId;
  }, [scanProfiles, matchedScanProfileId]);
  const isCustomScanProfileMatched = !matchedScanProfileId;

  const loadScanConfig = useCallback(async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/api_console/scan_config/', { method: 'GET' });
      const data = result?.data || {};
      const scanConfig = data?.scan_config || {};
      const nextDomainOptions = Array.isArray(data?.available_domain_dicts) ? data.available_domain_dicts : [];
      const nextFileLeakOptions = Array.isArray(data?.available_file_leak_dicts) ? data.available_file_leak_dicts : [];
      const nextScanProfiles = normalizeScanProfiles(data?.scan_profiles);

      setDomainDict(String(scanConfig.domain_dict || ''));
      setFileLeakDict(String(scanConfig.file_leak_dict || ''));
      setDomainBruteConcurrent(Number(scanConfig.domain_brute_concurrent || 360));
      setAltDnsConcurrent(Number(scanConfig.alt_dns_concurrent || 1400));
      setWebGunicornWorkers(Number(scanConfig.web_gunicorn_workers || 6));
      setCeleryTaskWorkerConcurrency(Number(scanConfig.celery_task_worker_concurrency || 3));
      setCeleryGithubWorkerConcurrency(Number(scanConfig.celery_github_worker_concurrency || 2));
      setCeleryHeavyWorkerConcurrency(Number(scanConfig.celery_heavy_worker_concurrency || 3));
      setCeleryWebWorkerConcurrency(Number(scanConfig.celery_web_worker_concurrency || 3));
      setCeleryPrefetchMultiplier(Number(scanConfig.celery_prefetch_multiplier || 1));
      setCeleryMaxTasksPerChild(Number(scanConfig.celery_max_tasks_per_child || 32));
      setCeleryMaxMemoryPerChild(Number(scanConfig.celery_max_memory_per_child || 720000));
      setNucleiSingleTargetTimeoutSec(Number(scanConfig.nuclei_single_target_timeout_sec || 900));
      setNucleiRateLimit(Number(scanConfig.nuclei_rate_limit || 50));
      setNucleiConcurrency(Number(scanConfig.nuclei_concurrency || 24));
      setNucleiBulkSize(Number(scanConfig.nuclei_bulk_size || 30));
      setAfrogConcurrency(Number(scanConfig.afrog_concurrency || 30));
      setAfrogRateLimit(Number(scanConfig.afrog_rate_limit || 30));
      setPocUpdateProxy(String(scanConfig.poc_update_proxy || ''));
      setUrlfinderUrlProbeEnable(Boolean(scanConfig.urlfinder_url_probe_enable ?? true));
      setUrlfinderUrlProbeMaxTargets(Number(scanConfig.urlfinder_url_probe_max_targets || 800));
      setUrlfinderUrlProbeConcurrency(Number(scanConfig.urlfinder_url_probe_concurrency || 20));
      setHostTimeoutType(String(scanConfig.host_timeout_type || 'default').toLowerCase() === 'custom' ? 'custom' : 'default');
      setHostTimeout(Number(scanConfig.host_timeout || 1500));
      setPortParallelism(Number(scanConfig.port_parallelism || 64));
      setPortMinRate(Number(scanConfig.port_min_rate || 260));
      setBlackIpsText(Array.isArray(scanConfig.black_ips) ? scanConfig.black_ips.join('\n') : '');
      setDnsResolversText(Array.isArray(scanConfig.dns_resolvers) ? scanConfig.dns_resolvers.join('\n') : '');

      setDomainDictOptions(nextDomainOptions);
      setFileLeakDictOptions(nextFileLeakOptions);
      setScanProfiles(nextScanProfiles);
      setConfigPath(String(data.config_path || ''));
      setUpdatedAt(String(data.updated_at || ''));
    } catch (err: any) {
      setError(err?.message || '加载扫描配置失败');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void loadScanConfig();
  }, [loadScanConfig]);

  const saveScanConfig = async () => {
    const normalizedDomainDict = domainDict.trim();
    if (!normalizedDomainDict) {
      setError('请先选择域名爆破字典');
      return;
    }
    const normalizedFileLeakDict = fileLeakDict.trim();
    if (!normalizedFileLeakDict) {
      setError('请先选择目录扫描字典');
      return;
    }

    if (!Number.isFinite(domainBruteConcurrent) || domainBruteConcurrent <= 0) {
      setError('域名爆破并发数必须大于 0');
      return;
    }

    if (!Number.isFinite(altDnsConcurrent) || altDnsConcurrent <= 0) {
      setError('组合生成域名爆破并发数必须大于 0');
      return;
    }
    if (!Number.isFinite(webGunicornWorkers) || webGunicornWorkers <= 0) {
      setError('Web 进程并发必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryTaskWorkerConcurrency) || celeryTaskWorkerConcurrency <= 0) {
      setError('Celery 主队列并发必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryGithubWorkerConcurrency) || celeryGithubWorkerConcurrency <= 0) {
      setError('Celery GitHub 队列并发必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryHeavyWorkerConcurrency) || celeryHeavyWorkerConcurrency <= 0) {
      setError('Celery 重任务队列并发必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryWebWorkerConcurrency) || celeryWebWorkerConcurrency <= 0) {
      setError('Celery Web 重任务队列并发必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryPrefetchMultiplier) || celeryPrefetchMultiplier <= 0) {
      setError('Celery 预取倍率必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryMaxTasksPerChild) || celeryMaxTasksPerChild <= 0) {
      setError('Celery 子进程任务上限必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryMaxMemoryPerChild) || celeryMaxMemoryPerChild <= 0) {
      setError('Celery 子进程内存上限必须大于 0');
      return;
    }
    if (!Number.isFinite(nucleiSingleTargetTimeoutSec) || nucleiSingleTargetTimeoutSec <= 0) {
      setError('Nuclei 单目标最大扫描时间必须大于 0');
      return;
    }
    if (!Number.isFinite(nucleiRateLimit) || nucleiRateLimit <= 0) {
      setError('Nuclei 限速必须大于 0');
      return;
    }
    if (!Number.isFinite(nucleiConcurrency) || nucleiConcurrency <= 0) {
      setError('Nuclei 并发必须大于 0');
      return;
    }
    if (!Number.isFinite(nucleiBulkSize) || nucleiBulkSize <= 0) {
      setError('Nuclei bulk-size 必须大于 0');
      return;
    }
    if (!Number.isFinite(afrogConcurrency) || afrogConcurrency <= 0) {
      setError('afrog 并发必须大于 0');
      return;
    }
    if (!Number.isFinite(afrogRateLimit) || afrogRateLimit <= 0) {
      setError('afrog 每秒请求上限必须大于 0');
      return;
    }
    if (!Number.isFinite(urlfinderUrlProbeMaxTargets) || urlfinderUrlProbeMaxTargets <= 0) {
      setError('URLFinder URL 探测最大目标数必须大于 0');
      return;
    }
    if (!Number.isFinite(urlfinderUrlProbeConcurrency) || urlfinderUrlProbeConcurrency <= 0) {
      setError('URLFinder URL 探测并发必须大于 0');
      return;
    }
    if (!['default', 'custom'].includes(String(hostTimeoutType || '').toLowerCase())) {
      setError('端口扫描主机超时策略仅支持 default/custom');
      return;
    }
    if (!Number.isFinite(hostTimeout) || hostTimeout <= 0) {
      setError('端口扫描主机超时时间必须大于 0');
      return;
    }
    if (!Number.isFinite(portParallelism) || portParallelism <= 0) {
      setError('端口扫描并行度必须大于 0');
      return;
    }
    if (!Number.isFinite(portMinRate) || portMinRate <= 0) {
      setError('端口扫描最小发包速率必须大于 0');
      return;
    }

    const blackIps = splitTextList(blackIpsText);
    if (blackIps.length === 0) {
      setError('黑名单IP配置不能为空');
      return;
    }

    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/api_console/scan_config/', {
        method: 'POST',
        body: {
          scan_config: {
            domain_dict: normalizedDomainDict,
            file_leak_dict: normalizedFileLeakDict,
            domain_brute_concurrent: Math.floor(domainBruteConcurrent),
            alt_dns_concurrent: Math.floor(altDnsConcurrent),
            web_gunicorn_workers: Math.floor(webGunicornWorkers),
            celery_task_worker_concurrency: Math.floor(celeryTaskWorkerConcurrency),
            celery_github_worker_concurrency: Math.floor(celeryGithubWorkerConcurrency),
            celery_heavy_worker_concurrency: Math.floor(celeryHeavyWorkerConcurrency),
            celery_web_worker_concurrency: Math.floor(celeryWebWorkerConcurrency),
            celery_prefetch_multiplier: Math.floor(celeryPrefetchMultiplier),
            celery_max_tasks_per_child: Math.floor(celeryMaxTasksPerChild),
            celery_max_memory_per_child: Math.floor(celeryMaxMemoryPerChild),
            nuclei_single_target_timeout_sec: Math.floor(nucleiSingleTargetTimeoutSec),
            nuclei_rate_limit: Math.floor(nucleiRateLimit),
            nuclei_concurrency: Math.floor(nucleiConcurrency),
            nuclei_bulk_size: Math.floor(nucleiBulkSize),
            afrog_concurrency: Math.floor(afrogConcurrency),
            afrog_rate_limit: Math.floor(afrogRateLimit),
            poc_update_proxy: String(pocUpdateProxy || '').trim(),
            urlfinder_url_probe_enable: Boolean(urlfinderUrlProbeEnable),
            urlfinder_url_probe_max_targets: Math.floor(urlfinderUrlProbeMaxTargets),
            urlfinder_url_probe_concurrency: Math.floor(urlfinderUrlProbeConcurrency),
            host_timeout_type: String(hostTimeoutType || 'default').toLowerCase() === 'custom' ? 'custom' : 'default',
            host_timeout: Math.floor(hostTimeout),
            port_parallelism: Math.floor(portParallelism),
            port_min_rate: Math.floor(portMinRate),
            scan_profile_id: matchedScanProfileId || '',
            black_ips: blackIps,
            dns_resolvers: splitTextList(dnsResolversText),
          },
        },
      });

      const data = result?.data || {};
      const savedConfig = data?.scan_config || {};
      const nextDomainOptions = Array.isArray(data?.available_domain_dicts) ? data.available_domain_dicts : [];
      const nextFileLeakOptions = Array.isArray(data?.available_file_leak_dicts) ? data.available_file_leak_dicts : [];
      const nextScanProfiles = normalizeScanProfiles(data?.scan_profiles);
      const backupPath = data?.backup_path ? `，备份: ${data.backup_path}` : '';

      setDomainDict(String(savedConfig.domain_dict || normalizedDomainDict));
      setFileLeakDict(String(savedConfig.file_leak_dict || normalizedFileLeakDict));
      setDomainBruteConcurrent(Number(savedConfig.domain_brute_concurrent || domainBruteConcurrent));
      setAltDnsConcurrent(Number(savedConfig.alt_dns_concurrent || altDnsConcurrent));
      setWebGunicornWorkers(Number(savedConfig.web_gunicorn_workers || webGunicornWorkers));
      setCeleryTaskWorkerConcurrency(Number(savedConfig.celery_task_worker_concurrency || celeryTaskWorkerConcurrency));
      setCeleryGithubWorkerConcurrency(Number(savedConfig.celery_github_worker_concurrency || celeryGithubWorkerConcurrency));
      setCeleryHeavyWorkerConcurrency(Number(savedConfig.celery_heavy_worker_concurrency || celeryHeavyWorkerConcurrency));
      setCeleryWebWorkerConcurrency(Number(savedConfig.celery_web_worker_concurrency || celeryWebWorkerConcurrency));
      setCeleryPrefetchMultiplier(Number(savedConfig.celery_prefetch_multiplier || celeryPrefetchMultiplier));
      setCeleryMaxTasksPerChild(Number(savedConfig.celery_max_tasks_per_child || celeryMaxTasksPerChild));
      setCeleryMaxMemoryPerChild(Number(savedConfig.celery_max_memory_per_child || celeryMaxMemoryPerChild));
      setNucleiSingleTargetTimeoutSec(Number(savedConfig.nuclei_single_target_timeout_sec || nucleiSingleTargetTimeoutSec));
      setNucleiRateLimit(Number(savedConfig.nuclei_rate_limit || nucleiRateLimit));
      setNucleiConcurrency(Number(savedConfig.nuclei_concurrency || nucleiConcurrency));
      setNucleiBulkSize(Number(savedConfig.nuclei_bulk_size || nucleiBulkSize));
      setAfrogConcurrency(Number(savedConfig.afrog_concurrency || afrogConcurrency));
      setAfrogRateLimit(Number(savedConfig.afrog_rate_limit || afrogRateLimit));
      setPocUpdateProxy(String(savedConfig.poc_update_proxy || pocUpdateProxy));
      setUrlfinderUrlProbeEnable(Boolean(savedConfig.urlfinder_url_probe_enable ?? urlfinderUrlProbeEnable));
      setUrlfinderUrlProbeMaxTargets(Number(savedConfig.urlfinder_url_probe_max_targets || urlfinderUrlProbeMaxTargets));
      setUrlfinderUrlProbeConcurrency(Number(savedConfig.urlfinder_url_probe_concurrency || urlfinderUrlProbeConcurrency));
      setHostTimeoutType(String(savedConfig.host_timeout_type || hostTimeoutType || 'default').toLowerCase() === 'custom' ? 'custom' : 'default');
      setHostTimeout(Number(savedConfig.host_timeout || hostTimeout));
      setPortParallelism(Number(savedConfig.port_parallelism || portParallelism));
      setPortMinRate(Number(savedConfig.port_min_rate || portMinRate));
      setBlackIpsText(Array.isArray(savedConfig.black_ips) ? savedConfig.black_ips.join('\n') : blackIpsText);
      setDnsResolversText(Array.isArray(savedConfig.dns_resolvers) ? savedConfig.dns_resolvers.join('\n') : dnsResolversText);

      setDomainDictOptions(nextDomainOptions);
      setFileLeakDictOptions(nextFileLeakOptions);
      setScanProfiles(nextScanProfiles);
      setConfigPath(String(data.config_path || configPath));
      setUpdatedAt(String(data.saved_at || updatedAt));
      setSuccess(`扫描配置已保存${backupPath}`);
      setShowRestartModal(true);
    } catch (err: any) {
      setError(err?.message || '保存扫描配置失败');
    } finally {
      setSaving(false);
    }
  };

  const uploadDomainDict = async () => {
    if (!uploadDomainFile) {
      setError('请先选择要上传的字典文件');
      return;
    }

    setDomainUploading(true);
    setError('');
    setSuccess('');
    try {
      const formData = new FormData();
      formData.append('file', uploadDomainFile);
      const result = await requestApi(token, '/api_console/scan_config/domain_dict/upload/', {
        method: 'POST',
        body: formData,
      });
      const data = result?.data || {};
      const uploadedPath = String(data?.domain_dict_path || '');
      const nextOptions = Array.isArray(data?.available_domain_dicts) ? data.available_domain_dicts : [];

      if (uploadedPath) {
        setDomainDict(uploadedPath);
      }
      setDomainDictOptions(nextOptions);
      setUpdatedAt(String(data.saved_at || updatedAt));
      setSuccess(`字典上传成功: ${uploadDomainFile.name}`);

      setUploadDomainFile(null);
      if (domainUploadInputRef.current) {
        domainUploadInputRef.current.value = '';
      }
    } catch (err: any) {
      setError(err?.message || '字典上传失败');
    } finally {
      setDomainUploading(false);
    }
  };

  const uploadFileLeakDict = async () => {
    if (!uploadFileLeakFile) {
      setError('请先选择要上传的字典文件');
      return;
    }

    setFileLeakUploading(true);
    setError('');
    setSuccess('');
    try {
      const formData = new FormData();
      formData.append('file', uploadFileLeakFile);
      const result = await requestApi(token, '/api_console/scan_config/file_leak_dict/upload/', {
        method: 'POST',
        body: formData,
      });
      const data = result?.data || {};
      const uploadedPath = String(data?.file_leak_dict_path || '');
      const nextOptions = Array.isArray(data?.available_file_leak_dicts) ? data.available_file_leak_dicts : [];

      if (uploadedPath) {
        setFileLeakDict(uploadedPath);
      }
      setFileLeakDictOptions(nextOptions);
      setUpdatedAt(String(data.saved_at || updatedAt));
      setSuccess(`字典上传成功: ${uploadFileLeakFile.name}`);

      setUploadFileLeakFile(null);
      if (fileLeakUploadInputRef.current) {
        fileLeakUploadInputRef.current.value = '';
      }
    } catch (err: any) {
      setError(err?.message || '字典上传失败');
    } finally {
      setFileLeakUploading(false);
    }
  };

  const updatePocRepo = async (repoType: 'nuclei' | 'afrog') => {
    const isNuclei = repoType === 'nuclei';
    const endpoint = isNuclei
      ? '/api_console/scan_config/nuclei_poc/update/'
      : '/api_console/scan_config/afrog_poc/update/';

    if (isNuclei) {
      setNucleiPocUpdating(true);
    } else {
      setAfrogPocUpdating(true);
    }
    setError('');
    setSuccess('');

    try {
      const result = await requestApi(token, endpoint, { method: 'POST' });
      const data = result?.data || {};
      const repoDir = String(data?.repo_dir || '').trim();
      const branch = String(data?.branch || '').trim();
      const commit = String(data?.commit || '').trim();
      const commitSubject = String(data?.commit_subject || '').trim();
      const backupPath = String(data?.backup_path || '').trim();
      const proxy = String(data?.proxy || '').trim();
      const commitShort = commit ? commit.slice(0, 12) : '-';
      const summary = [
        branch ? `分支: ${branch}` : '',
        `commit: ${commitShort}`,
        commitSubject ? `说明: ${commitSubject}` : '',
        proxy ? `代理: ${proxy}` : '',
        repoDir ? `目录: ${repoDir}` : '',
        backupPath ? `备份: ${backupPath}` : '',
      ]
        .filter((item) => item)
        .join('，');

      setUpdatedAt(String(data?.updated_at || updatedAt));
      setSuccess(`${isNuclei ? 'Nuclei PoC' : 'afrog PoC'} 更新成功（${summary}）`);
    } catch (err: any) {
      const baseMsg = err?.message || `${isNuclei ? 'Nuclei PoC' : 'afrog PoC'} 更新失败`;
      const proxyHint = String(pocUpdateProxy || '').trim()
        ? '当前已带代理重试，如仍失败请检查代理可达性或仓库连通性。'
        : '如网络受限，可先在“PoC 更新代理”中配置 http/https/socks5 代理后重试。';
      setError(`${baseMsg}。因为是从 GitHub 拉取，${proxyHint}`);
    } finally {
      if (isNuclei) {
        setNucleiPocUpdating(false);
      } else {
        setAfrogPocUpdating(false);
      }
    }
  };
  const isConfigActionBusy =
    loading || saving || domainUploading || fileLeakUploading || nucleiPocUpdating || afrogPocUpdating;

  return (
    <div className="p-8 space-y-6">
      <PageHeader title="配置管理" description="支持配置域名爆破字典、目录扫描字典、扫描并发、端口扫描默认超时/并行度、Nuclei / afrog 参数、Web/Celery 运行并发、黑名单IP与域名解析器，并提供低/中/高性能预定义档位，保存后写入运行配置（容器内 /code/app/config.yaml，对应宿主机 config-runtime.yaml），重启后生效。" />

      <div className="bg-base-200/35 border border-base-300 rounded-2xl p-5 space-y-4">
        <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3">
          <div className="text-sm font-bold tracking-wide">扫描配置</div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => void loadScanConfig()}
              className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
              disabled={isConfigActionBusy}
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              重新加载
            </button>
            <button
              onClick={() => void updatePocRepo('nuclei')}
              className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2 disabled:opacity-60"
              disabled={isConfigActionBusy}
            >
              <GitBranch className={`w-4 h-4 ${nucleiPocUpdating ? 'animate-spin' : ''}`} />
              {nucleiPocUpdating ? '更新中...' : '更新 Nuclei PoC'}
            </button>
            <button
              onClick={() => void updatePocRepo('afrog')}
              className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2 disabled:opacity-60"
              disabled={isConfigActionBusy}
            >
              <GitBranch className={`w-4 h-4 ${afrogPocUpdating ? 'animate-spin' : ''}`} />
              {afrogPocUpdating ? '更新中...' : '更新 afrog PoC'}
            </button>
            <button
              onClick={() => void saveScanConfig()}
              className="px-4 py-2 rounded-xl bg-brand-accent text-white text-sm font-black hover:opacity-90 transition flex items-center gap-2 disabled:opacity-60"
              disabled={isConfigActionBusy}
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
          提示：保存后会写入配置文件，建议重启 `web` 与 `worker` 容器让扫描参数完全生效。
        </div>
        <div className="text-xs text-content-muted bg-base-100/50 border border-base-300 rounded-xl px-3 py-2">
          PoC 更新说明：按钮会调用 git 同步远端仓库（nuclei: projectdiscovery/nuclei-templates，afrog: zan8in/afrog-pocs）。
        </div>
        <div className="grid grid-cols-1 xl:grid-cols-[220px_minmax(0,1fr)] gap-3 items-center rounded-xl border border-base-300 bg-base-100/25 px-3 py-3">
          <div className="space-y-1">
            <div className="text-xs font-black tracking-wide text-base-content">PoC 更新代理</div>
            <div className="text-[11px] text-content-muted">仅作用于 Nuclei / afrog PoC 仓库更新时的 `git clone/pull`。</div>
          </div>
          <input
            type="text"
            value={pocUpdateProxy}
            onChange={(event) => setPocUpdateProxy(event.target.value)}
            className={compactFieldInputClass}
            placeholder="支持 http:// / https:// / socks5://"
          />
        </div>
      </div>

      <div className="bg-base-200/35 border border-base-300 rounded-2xl p-5 space-y-5">
        <div className="space-y-4 rounded-xl border border-base-300/80 bg-base-100/25 p-4">
          <div className="text-xs font-black tracking-wide text-base-content">预定义资源档位</div>
          <div className="text-xs text-content-muted">
            一键套用常见机型参数（CPU/内存/带宽），覆盖 Nuclei、afrog、域名爆破、端口扫描、URL 探测、Web/Celery 并发等关键项，降低低配主机被扫描压垮风险。
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-4 gap-3">
            {scanProfiles.map((profile) => {
              const isMatched = matchedScanProfileId === profile.id;
              return (
                <button
                  key={profile.id}
                  type="button"
                  onClick={() => applyScanProfile(profile)}
                  className={`text-left rounded-xl border p-3 transition ${
                    isMatched
                      ? 'border-accent bg-accent/10'
                      : 'border-base-300 hover:bg-base-100/70'
                  }`}
                >
                  <div className="text-sm font-bold">{profile.label}</div>
                  <div className="mt-1 text-xs text-content-muted">
                    规格：{profile.cpu_cores}核CPU · {profile.memory_gb}GB内存 · {profile.bandwidth_mbps}Mbps带宽
                  </div>
                  <div className="mt-2 text-xs text-content-muted">{profile.description || '预定义扫描参数模板'}</div>
                </button>
              );
            })}
            <div
              className={`text-left rounded-xl border p-3 transition ${
                isCustomScanProfileMatched
                  ? 'border-accent bg-accent/10'
                  : 'border-base-300 bg-base-100/30'
              }`}
            >
              <div className="text-sm font-bold">自定义配置</div>
              <div className="mt-1 text-xs text-content-muted">
                手动调整扫描参数，不套用预定义模板
              </div>
              <div className="mt-2 text-xs text-content-muted">
                {isCustomScanProfileMatched ? '当前生效' : '当前未生效'}
              </div>
            </div>
          </div>
          <div className="text-xs text-content-muted">
            当前命中档位：{matchedScanProfileLabel || '自定义配置'}
          </div>
        </div>

        <div className="space-y-4 rounded-xl border border-base-300/80 bg-base-100/25 p-4">
          <div className="text-xs font-black tracking-wide text-base-content">字典管理</div>
        <div className="space-y-2">
          <label htmlFor="config-domain-dict-select" className="text-xs font-bold text-content-muted block">
            域名爆破字典
            <span className="ml-2 font-mono opacity-70">ARL.DOMAIN_DICT</span>
          </label>
          <div className="relative xl:max-w-[440px]">
            <select
              id="config-domain-dict-select"
              value={domainDict}
              onChange={(event) => setDomainDict(event.target.value)}
              className={CONSOLE_SELECT_CLASS}
            >
              <option value="">请选择字典文件</option>
              {domainDictOptions.map((item) => (
                <option key={item.path} value={item.path}>
                  {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                </option>
              ))}
            </select>
            <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
          </div>
        </div>

        <div className="space-y-2">
          <label htmlFor="config-domain-dict-upload" className="text-xs font-bold text-content-muted block">上传域名爆破字典（.txt）</label>
          <input
            id="config-domain-dict-upload"
            ref={domainUploadInputRef}
            type="file"
            accept=".txt"
            className="hidden"
            onChange={(event) => {
              const file = event.target.files?.[0];
              setUploadDomainFile(file || null);
            }}
          />
          <div className="flex flex-col lg:flex-row gap-2">
            <button
              type="button"
              onClick={() => domainUploadInputRef.current?.click()}
              className="px-4 py-2 h-10 rounded-xl border border-base-300 text-sm font-semibold whitespace-nowrap hover:bg-base-100/70 transition flex items-center justify-center disabled:opacity-60"
              disabled={isConfigActionBusy}
            >
              选择文件
            </button>
            <div className={`${compactFieldFilenameClass} flex items-center text-content-muted truncate`}>
              {uploadDomainFile?.name || '未选择文件'}
            </div>
            <button
              type="button"
              onClick={() => void uploadDomainDict()}
              className="px-4 py-2 h-10 rounded-xl border border-base-300 text-sm font-semibold whitespace-nowrap hover:bg-base-100/70 transition flex items-center justify-center gap-2 disabled:opacity-60"
              disabled={isConfigActionBusy}
            >
              <Upload className={`w-4 h-4 ${domainUploading ? 'animate-spin' : ''}`} />
              {domainUploading ? '上传中...' : '上传域名爆破字典'}
            </button>
          </div>
        </div>

        <div className="space-y-2">
          <label htmlFor="config-fileleak-dict-select" className="text-xs font-bold text-content-muted block">
            目录扫描字典
            <span className="ml-2 font-mono opacity-70">ARL.FILE_LEAK_DICT</span>
          </label>
          <div className="relative xl:max-w-[440px]">
            <select
              id="config-fileleak-dict-select"
              value={fileLeakDict}
              onChange={(event) => setFileLeakDict(event.target.value)}
              className={CONSOLE_SELECT_CLASS}
            >
              <option value="">请选择字典文件</option>
              {fileLeakDictOptions.map((item) => (
                <option key={item.path} value={item.path}>
                  {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                </option>
              ))}
            </select>
            <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
          </div>
        </div>

        <div className="space-y-2">
          <label htmlFor="config-fileleak-dict-upload" className="text-xs font-bold text-content-muted block">上传敏感文件字典（.txt）</label>
          <input
            id="config-fileleak-dict-upload"
            ref={fileLeakUploadInputRef}
            type="file"
            accept=".txt"
            className="hidden"
            onChange={(event) => {
              const file = event.target.files?.[0];
              setUploadFileLeakFile(file || null);
            }}
          />
          <div className="flex flex-col lg:flex-row gap-2">
            <button
              type="button"
              onClick={() => fileLeakUploadInputRef.current?.click()}
              className="px-4 py-2 h-10 rounded-xl border border-base-300 text-sm font-semibold whitespace-nowrap hover:bg-base-100/70 transition flex items-center justify-center disabled:opacity-60"
              disabled={isConfigActionBusy}
            >
              选择文件
            </button>
            <div className={`${compactFieldFilenameClass} flex items-center text-content-muted truncate`}>
              {uploadFileLeakFile?.name || '未选择文件'}
            </div>
            <button
              type="button"
              onClick={() => void uploadFileLeakDict()}
              className="px-4 py-2 h-10 rounded-xl border border-base-300 text-sm font-semibold whitespace-nowrap hover:bg-base-100/70 transition flex items-center justify-center gap-2 disabled:opacity-60"
              disabled={isConfigActionBusy}
            >
              <Upload className={`w-4 h-4 ${fileLeakUploading ? 'animate-spin' : ''}`} />
              {fileLeakUploading ? '上传中...' : '上传敏感文件字典'}
            </button>
          </div>
        </div>
        </div>

        <div className="space-y-4 rounded-xl border border-base-300/80 bg-base-100/25 p-4">
          <div className="text-xs font-black tracking-wide text-base-content">并发与资源配置</div>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label htmlFor="config-domain-brute-concurrent" className="text-xs font-bold text-content-muted block">
              域名爆破并发数
              <span className="ml-2 font-mono opacity-70">ARL.DOMAIN_BRUTE_CONCURRENT</span>
            </label>
            <input
              id="config-domain-brute-concurrent"
              type="number"
              min={1}
              value={String(domainBruteConcurrent)}
              onChange={(event) => setDomainBruteConcurrent(Number(event.target.value || 0))}
              className={compactFieldInputClass}
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="config-alt-dns-concurrent" className="text-xs font-bold text-content-muted block">
              组合生成域名爆破并发数
              <span className="ml-2 font-mono opacity-70">ARL.ALT_DNS_CONCURRENT</span>
            </label>
            <input
              id="config-alt-dns-concurrent"
              type="number"
              min={1}
              value={String(altDnsConcurrent)}
              onChange={(event) => setAltDnsConcurrent(Number(event.target.value || 0))}
              className={compactFieldInputClass}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label htmlFor="config-web-gunicorn-workers" className="text-xs font-bold text-content-muted block">
              Web API 服务并发数 (界面与接口响应进程)
              <span className="ml-2 font-mono opacity-70">ARL.WEB_GUNICORN_WORKERS</span>
            </label>
            <input
              id="config-web-gunicorn-workers"
              type="number"
              min={1}
              value={String(webGunicornWorkers)}
              onChange={(event) => setWebGunicornWorkers(Number(event.target.value || 0))}
              className={compactFieldInputClass}
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="config-celery-task-worker-concurrency" className="text-xs font-bold text-content-muted block">
              后台并行扫描任务数 (同时执行的最大任务数)
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_TASK_WORKER_CONCURRENCY</span>
            </label>
            <input
              id="config-celery-task-worker-concurrency"
              type="number"
              min={1}
              value={String(celeryTaskWorkerConcurrency)}
              onChange={(event) => setCeleryTaskWorkerConcurrency(Number(event.target.value || 0))}
              className={compactFieldInputClass}
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="config-celery-heavy-worker-concurrency" className="text-xs font-bold text-content-muted block">
              后台并行重任务数 (全端口/深度识别队列)
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_HEAVY_WORKER_CONCURRENCY</span>
            </label>
            <input
              id="config-celery-heavy-worker-concurrency"
              type="number"
              min={1}
              value={String(celeryHeavyWorkerConcurrency)}
              onChange={(event) => setCeleryHeavyWorkerConcurrency(Number(event.target.value || 0))}
              className={compactFieldInputClass}
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="config-celery-web-worker-concurrency" className="text-xs font-bold text-content-muted block">
              后台并行 Web 重任务数 (目录/PoC/截图/爬虫队列)
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_WEB_WORKER_CONCURRENCY</span>
            </label>
            <input
              id="config-celery-web-worker-concurrency"
              type="number"
              min={1}
              value={String(celeryWebWorkerConcurrency)}
              onChange={(event) => setCeleryWebWorkerConcurrency(Number(event.target.value || 0))}
              className={compactFieldInputClass}
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="config-celery-github-worker-concurrency" className="text-xs font-bold text-content-muted block">
              后台并行 GitHub 任务数 (独立队列)
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_GITHUB_WORKER_CONCURRENCY</span>
            </label>
            <input
              id="config-celery-github-worker-concurrency"
              type="number"
              min={1}
              value={String(celeryGithubWorkerConcurrency)}
              onChange={(event) => setCeleryGithubWorkerConcurrency(Number(event.target.value || 0))}
              className={compactFieldInputClass}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label htmlFor="config-celery-prefetch-multiplier" className="text-xs font-bold text-content-muted block">
              任务预拉取数 (单进程一次从队列领取的排队数)
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_PREFETCH_MULTIPLIER</span>
            </label>
            <input
              id="config-celery-prefetch-multiplier"
              type="number"
              min={1}
              value={String(celeryPrefetchMultiplier)}
              onChange={(event) => setCeleryPrefetchMultiplier(Number(event.target.value || 0))}
              className={compactFieldInputClass}
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="config-celery-max-tasks-per-child" className="text-xs font-bold text-content-muted block">
              进程回收阈值：单进程执行多少任务后重启 (防内存泄漏)
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_MAX_TASKS_PER_CHILD</span>
            </label>
            <input
              id="config-celery-max-tasks-per-child"
              type="number"
              min={1}
              value={String(celeryMaxTasksPerChild)}
              onChange={(event) => setCeleryMaxTasksPerChild(Number(event.target.value || 0))}
              className={compactFieldInputClass}
            />
          </div>

          <div className="space-y-2 xl:col-span-2">
            <label htmlFor="config-celery-max-memory-per-child" className="text-xs font-bold text-content-muted block">
              进程回收阈值：单进程达多少内存后重启(KB) (防内存泄漏)
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_MAX_MEMORY_PER_CHILD</span>
            </label>
            <input
              id="config-celery-max-memory-per-child"
              type="number"
              min={1}
              value={String(celeryMaxMemoryPerChild)}
              onChange={(event) => setCeleryMaxMemoryPerChild(Number(event.target.value || 0))}
              className={compactFieldInputClass}
            />
          </div>
        </div>
        </div>

        <div className="space-y-4 rounded-xl border border-base-300/80 bg-base-100/25 p-4">
          <div className="text-xs font-black tracking-wide text-base-content">扫描超时与端口参数</div>
        <div className="space-y-3 rounded-xl border border-base-300 bg-base-100/35 p-4">
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="config-nuclei-single-target-timeout-sec" className="text-xs font-bold text-content-muted block">
                Nuclei 单个目标最多扫描时间（秒）
                <span className="ml-2 font-mono opacity-70">ARL.NUCLEI_SINGLE_TARGET_TIMEOUT_SEC</span>
              </label>
              <input
                id="config-nuclei-single-target-timeout-sec"
                type="number"
                min={60}
                value={String(nucleiSingleTargetTimeoutSec)}
                onChange={(event) => setNucleiSingleTargetTimeoutSec(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="config-nuclei-rate-limit" className="text-xs font-bold text-content-muted block">
                Nuclei 每秒请求上限
                <span className="ml-2 font-mono opacity-70">ARL.NUCLEI_RATE_LIMIT</span>
              </label>
              <input
                id="config-nuclei-rate-limit"
                type="number"
                min={1}
                value={String(nucleiRateLimit)}
                onChange={(event) => setNucleiRateLimit(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="config-nuclei-concurrency" className="text-xs font-bold text-content-muted block">
                Nuclei 模板并发
                <span className="ml-2 font-mono opacity-70">ARL.NUCLEI_CONCURRENCY</span>
              </label>
              <input
                id="config-nuclei-concurrency"
                type="number"
                min={1}
                value={String(nucleiConcurrency)}
                onChange={(event) => setNucleiConcurrency(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="config-nuclei-bulk-size" className="text-xs font-bold text-content-muted block">
                Nuclei bulk-size
                <span className="ml-2 font-mono opacity-70">ARL.NUCLEI_BULK_SIZE</span>
              </label>
              <input
                id="config-nuclei-bulk-size"
                type="number"
                min={1}
                value={String(nucleiBulkSize)}
                onChange={(event) => setNucleiBulkSize(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="config-afrog-concurrency" className="text-xs font-bold text-content-muted block">
                afrog 并发
                <span className="ml-2 font-mono opacity-70">ARL.AFROG_CONCURRENCY</span>
              </label>
              <input
                id="config-afrog-concurrency"
                type="number"
                min={1}
                value={String(afrogConcurrency)}
                onChange={(event) => setAfrogConcurrency(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="config-afrog-rate-limit" className="text-xs font-bold text-content-muted block">
                afrog 每秒请求上限
                <span className="ml-2 font-mono opacity-70">ARL.AFROG_RATE_LIMIT</span>
              </label>
              <input
                id="config-afrog-rate-limit"
                type="number"
                min={1}
                value={String(afrogRateLimit)}
                onChange={(event) => setAfrogRateLimit(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
          </div>
          <div className="text-xs text-content-muted">
            当前 Nuclei 超时约 {(nucleiSingleTargetTimeoutSec / 3600).toFixed(2)} 小时/目标，afrog 走站点级批量 PoC 扫描并会按这里的并发与限速执行。建议优先使用上方预定义资源档位统一调整。
          </div>
        </div>

        <div className="space-y-3 rounded-xl border border-base-300 bg-base-100/35 p-4">
          <div className="flex items-center gap-3">
            <input
              id="config-urlfinder-url-probe-enable"
              type="checkbox"
              checked={Boolean(urlfinderUrlProbeEnable)}
              onChange={(event) => setUrlfinderUrlProbeEnable(event.target.checked)}
              className="h-4 w-4 cursor-pointer rounded border border-base-300 bg-base-100"
            />
            <label htmlFor="config-urlfinder-url-probe-enable" className="text-xs font-bold text-content-muted">
              启用 URLFinder URL 可达性探测并入 URL 信息
              <span className="ml-2 font-mono opacity-70">ARL.URLFINDER_URL_PROBE_ENABLE</span>
            </label>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="config-urlfinder-url-probe-max-targets" className="text-xs font-bold text-content-muted block">
                URL 探测最大目标数
                <span className="ml-2 font-mono opacity-70">ARL.URLFINDER_URL_PROBE_MAX_TARGETS</span>
              </label>
              <input
                id="config-urlfinder-url-probe-max-targets"
                type="number"
                min={1}
                value={String(urlfinderUrlProbeMaxTargets)}
                onChange={(event) => setUrlfinderUrlProbeMaxTargets(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="config-urlfinder-url-probe-concurrency" className="text-xs font-bold text-content-muted block">
                URL 探测并发
                <span className="ml-2 font-mono opacity-70">ARL.URLFINDER_URL_PROBE_CONCURRENCY</span>
              </label>
              <input
                id="config-urlfinder-url-probe-concurrency"
                type="number"
                min={1}
                value={String(urlfinderUrlProbeConcurrency)}
                onChange={(event) => setUrlfinderUrlProbeConcurrency(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
          </div>
        </div>

        <div className="space-y-3 rounded-xl border border-base-300 bg-base-100/35 p-4">
          <div className="text-xs font-bold text-content-muted">端口扫描全局默认参数（策略未显式设置时生效）</div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="config-host-timeout-type" className="text-xs font-bold text-content-muted block">
                主机超时策略
                <span className="ml-2 font-mono opacity-70">ARL.HOST_TIMEOUT_TYPE</span>
              </label>
              <div className="relative xl:max-w-[440px]">
                <select
                  id="config-host-timeout-type"
                  value={hostTimeoutType}
                  onChange={(event) => setHostTimeoutType(event.target.value === 'custom' ? 'custom' : 'default')}
                  className={CONSOLE_SELECT_CLASS}
                >
                  <option value="default">default（按扫描模式自动估算）</option>
                  <option value="custom">custom（固定超时）</option>
                </select>
                <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
              </div>
            </div>
            <div className="space-y-2">
              <label htmlFor="config-host-timeout" className="text-xs font-bold text-content-muted block">
                主机超时（秒）
                <span className="ml-2 font-mono opacity-70">ARL.HOST_TIMEOUT</span>
              </label>
              <input
                id="config-host-timeout"
                type="number"
                min={1}
                value={String(hostTimeout)}
                onChange={(event) => setHostTimeout(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="config-port-parallelism" className="text-xs font-bold text-content-muted block">
                探测报文并行度
                <span className="ml-2 font-mono opacity-70">ARL.PORT_PARALLELISM</span>
              </label>
              <input
                id="config-port-parallelism"
                type="number"
                min={1}
                value={String(portParallelism)}
                onChange={(event) => setPortParallelism(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="config-port-min-rate" className="text-xs font-bold text-content-muted block">
                最少发包速率
                <span className="ml-2 font-mono opacity-70">ARL.PORT_MIN_RATE</span>
              </label>
              <input
                id="config-port-min-rate"
                type="number"
                min={1}
                value={String(portMinRate)}
                onChange={(event) => setPortMinRate(Number(event.target.value || 0))}
                className={compactFieldInputClass}
              />
            </div>
          </div>
          <div className="text-xs text-content-muted">
            说明：该组参数作为全局默认值。历史任务策略中未显式传入时，会自动使用这里的配置。
          </div>
        </div>
        </div>

        <div className="space-y-4 rounded-xl border border-base-300/80 bg-base-100/25 p-4">
          <div className="text-xs font-black tracking-wide text-base-content">安全过滤与解析器</div>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label htmlFor="config-black-ips" className="text-xs font-bold text-content-muted block">
              黑名单IP配置
              <span className="ml-2 font-mono opacity-70">ARL.BLACK_IPS</span>
            </label>
            <textarea
              id="config-black-ips"
              value={blackIpsText}
              onChange={(event) => setBlackIpsText(event.target.value)}
              className={`${CONSOLE_TEXTAREA_MONO_CLASS} min-h-[120px]`}
              placeholder="每行一个IP段，例如 127.0.0.0/8"
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="config-dns-resolvers" className="text-xs font-bold text-content-muted block">
              域名解析器配置
              <span className="ml-2 font-mono opacity-70">ARL.DNS_RESOLVERS</span>
            </label>
            <textarea
              id="config-dns-resolvers"
              value={dnsResolversText}
              onChange={(event) => setDnsResolversText(event.target.value)}
              className={`${CONSOLE_TEXTAREA_MONO_CLASS} min-h-[120px]`}
              placeholder="每行一个DNS解析器，例如 223.5.5.5 或 1.1.1.1:53"
            />
          </div>
        </div>
        </div>
      </div>

      {showRestartModal ? (
        <Modal open onClose={() => setShowRestartModal(false)} boxClass="w-full max-w-md!">
            <div className="px-6 py-4 border-b border-base-300 flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              <h4 className="text-lg font-black tracking-wide">需要重启容器</h4>
            </div>
            <div className="px-6 py-5 space-y-4">
              <p className="text-sm font-semibold">配置保存成功！</p>
              <p className="text-sm text-content-muted leading-relaxed">
                由于当前系统配置不支持热更新，请在服务器中执行容器重启以使新配置生效：
              </p>
              <div className="bg-base-100/50 border border-base-300 rounded-lg p-3">
                <code className="text-xs text-accent font-mono block select-all">
                  docker-compose restart
                </code>
              </div>
              <p className="text-xs text-content-muted">
                (或使用提供的 ./restart.sh 脚本)
              </p>
            </div>
            <div className="px-6 py-4 border-t border-base-300 flex justify-end gap-3 bg-base-100/30">
              <button
                onClick={() => setShowRestartModal(false)}
                className="px-5 py-2.5 rounded-xl bg-brand-accent hover:opacity-90 transition text-sm font-black tracking-wider shadow-lg shadow-accent/20"
              >
                我知道了
              </button>
            </div>
        </Modal>
      ) : null}
    </div>
  );
}
