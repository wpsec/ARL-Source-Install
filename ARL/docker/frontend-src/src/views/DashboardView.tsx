import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  FileCode,
  Globe,
  Monitor,
  Plus,
  RefreshCw,
  Settings,
  Terminal,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { normalizeListData, requestApi } from '../api/client';
import { StatusPill } from '../components/ui/StatusPill';
import {
  formatPercent,
  normalizeValue,
  normalizeValueNoTruncate,
  parseNumericValue,
} from '../domain/format';
import { formatCpuSummary, formatUsageSummary } from '../domain/system';
import type {OpenModuleHandler} from '../domain/types';
import { PageHeader } from '../layout/PageHeader';

export function DashboardView({
  token,
  onOpenModule,
  onQuickCreateTask,
}: {
  token: string;
  onOpenModule: OpenModuleHandler;
  onQuickCreateTask: () => void;
}) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [lastUpdatedAt, setLastUpdatedAt] = useState('');
  const [stats, setStats] = useState({
    task: 0,
    scheduler: 0,
    asset_scope: 0,
    asset_site: 0,
    domain_total: 0,
    ip_total: 0,
    service_total: 0,
    url_total: 0,
    vuln: 0,
    github_task: 0,
    running_task: 0,
    new_assets_today: 0,
  });
  const [deviceInfo, setDeviceInfo] = useState<any>({});
  const [recentTasks, setRecentTasks] = useState<any[]>([]);
  const [assetTrend, setAssetTrend] = useState<any[]>([]);
  const [riskDistribution, setRiskDistribution] = useState<any[]>([]);
  const [networkTrend, setNetworkTrend] = useState<any[]>([]);
  const [recentLogs, setRecentLogs] = useState<any[]>([]);
  const [isLogPaused, setIsLogPaused] = useState(false);

  const resolveTaskStatus = (rawStatus: any): { text: string; type: 'success' | 'error' | 'info' } => {
    const normalized = String(rawStatus ?? '').toLowerCase();
    if (normalized.includes('done') || normalized.includes('finish') || normalized.includes('success')) return { text: '已完成', type: 'success' };
    if (normalized.includes('fail') || normalized.includes('error') || normalized.includes('stop') || normalized.includes('cancel')) {
      return { text: '异常/停止', type: 'error' };
    }
    if (normalized.includes('run') || normalized.includes('start') || normalized.includes('queue') || normalized.includes('wait')) {
      return { text: '进行中', type: 'info' };
    }
    return { text: normalized || '未知', type: 'info' };
  };

  const loadAssetOverviewCounts = useCallback(async () => {
    const targets = [
      { key: 'domain_total', path: '/domain/' },
      { key: 'ip_total', path: '/ip/' },
      { key: 'service_total', path: '/service/' },
      { key: 'url_total', path: '/url/' },
    ] as const;

    const responses = await Promise.all(
      targets.map((target) => requestApi(token, target.path, { method: 'GET', query: { page: 1, size: 1 } }))
    );

    const counts: Record<string, number> = {};
    responses.forEach((response, index) => {
      counts[targets[index].key] = Number(normalizeListData(response).total || 0);
    });
    return counts as {
      domain_total: number;
      ip_total: number;
      service_total: number;
      url_total: number;
    };
  }, [token]);

  const loadFallback = useCallback(async () => {
    const targets = [
      { key: 'task', path: '/task/' },
      { key: 'scheduler_recurrent', path: '/task_schedule/', query: { status: 'scheduled', schedule_type: 'recurrent_scan' } },
      { key: 'scheduler_future_pending', path: '/task_schedule/', query: { status: 'scheduled', schedule_type: 'future_scan' } },
      { key: 'asset_scope', path: '/asset_scope/' },
      { key: 'asset_site', path: '/asset_site/' },
      { key: 'vuln', path: '/vuln/' },
      { key: 'github_task', path: '/github_task/' },
    ] as const;

    const [responses, consoleInfo, recentTaskResponse, assetOverview] = await Promise.all([
      Promise.all(targets.map((target) => {
        const extraQuery = 'query' in target ? target.query : {};
        return requestApi(token, target.path, {
          method: 'GET',
          query: { page: 1, size: 1, ...extraQuery },
        });
      })),
      requestApi(token, '/console/info', { method: 'GET' }),
      requestApi(token, '/task/', { method: 'GET', query: { page: 1, size: 6, order: '-_id' } }),
      loadAssetOverviewCounts(),
    ]);

    const nextStats: any = {};
    responses.forEach((response, index) => {
      const normalized = normalizeListData(response);
      nextStats[targets[index].key] = normalized.total;
    });
    const recentTaskItems = normalizeListData(recentTaskResponse).items.slice(0, 6);
    const activeRecentTaskCount = recentTaskItems.filter((task: any) => {
      const status = String(task?.status || '').trim().toLowerCase();
      return Boolean(status) && !['done', 'stop', 'error'].includes(status);
    }).length;

    setStats((prev) => ({
      ...prev,
      task: Number(nextStats.task || 0),
      scheduler: Number(nextStats.scheduler_recurrent || 0) + Number(nextStats.scheduler_future_pending || 0),
      asset_scope: Number(nextStats.asset_scope || 0),
      asset_site: Number(nextStats.asset_site || 0),
      domain_total: Number(assetOverview.domain_total || 0),
      ip_total: Number(assetOverview.ip_total || 0),
      service_total: Number(assetOverview.service_total || 0),
      url_total: Number(assetOverview.url_total || 0),
      vuln: Number(nextStats.vuln || 0),
      github_task: Number(nextStats.github_task || 0),
      running_task: Number(prev.running_task || 0) > 0 ? Number(prev.running_task || 0) : activeRecentTaskCount,
    }));
    setDeviceInfo(consoleInfo?.data?.device_info || {});
    setRecentTasks(recentTaskItems);
    setRecentLogs((prev) => (prev.length > 0 ? prev : [{ level: 'INFO', source: 'SCAN', msg: '当前为兼容模式，扫描日志接口不可用', time: '' }]));
    setLastUpdatedAt(new Date().toLocaleString('zh-CN', { hour12: false }));
  }, [token, loadAssetOverviewCounts]);

  const loadRecentLogs = useCallback(async (force = false) => {
    if (isLogPaused && !force) {
      return;
    }
    try {
      const response = await requestApi(token, '/console/recent_logs', { method: 'GET', query: { limit: 120 } });
      const logs = Array.isArray(response?.data?.recent_logs) ? response.data.recent_logs : [];
      if (logs.length > 0) {
        setRecentLogs(logs);
      }
    } catch {
      // 日志轮询失败时不打断仪表盘其他内容
    }
  }, [token, isLogPaused]);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const dashboardInfo = await requestApi(token, '/console/dashboard', { method: 'GET' });
      const dashboardData = dashboardInfo?.data || {};
      if (!dashboardData?.stats) {
        throw new Error('仪表盘聚合数据为空');
      }

      const nextStats = dashboardData.stats || {};
      const hasActiveTasksField = Object.prototype.hasOwnProperty.call(nextStats, 'active_tasks');
      const activeTaskCount = hasActiveTasksField
        ? Number(nextStats.active_tasks || 0)
        : Number(nextStats.running_tasks || 0) + Number(nextStats.waiting_tasks || 0);
      const hasAssetOverviewFields = ['domain_total', 'ip_total', 'service_total', 'url_total']
        .some((key) => Object.prototype.hasOwnProperty.call(nextStats, key));
      const assetOverview = hasAssetOverviewFields
        ? {
            domain_total: Number(nextStats.domain_total || 0),
            ip_total: Number(nextStats.ip_total || 0),
            service_total: Number(nextStats.service_total || 0),
            url_total: Number(nextStats.url_total || 0),
          }
        : await loadAssetOverviewCounts();
      setStats({
        task: Number(nextStats.task_total || 0),
        scheduler: Number(nextStats.task_schedule_total ?? nextStats.scheduler_total ?? 0),
        asset_scope: Number(nextStats.asset_scope_total || 0),
        asset_site: Number(nextStats.asset_site_total || 0),
        domain_total: Number(assetOverview.domain_total || 0),
        ip_total: Number(assetOverview.ip_total || 0),
        service_total: Number(assetOverview.service_total || 0),
        url_total: Number(assetOverview.url_total || 0),
        vuln: Number(nextStats.vuln_total || 0),
        github_task: Number(nextStats.github_task_total || 0),
        running_task: Number(activeTaskCount || 0),
        new_assets_today: Number(nextStats.new_assets_today || 0),
      });
      setDeviceInfo(dashboardData.device_info || {});
      setAssetTrend(Array.isArray(dashboardData.asset_trend_7d) ? dashboardData.asset_trend_7d : []);
      setRiskDistribution(Array.isArray(dashboardData.risk_distribution) ? dashboardData.risk_distribution : []);
      setNetworkTrend(Array.isArray(dashboardData.network_trend) ? dashboardData.network_trend : []);
      const dashboardRecentLogs = Array.isArray(dashboardData.recent_logs) ? dashboardData.recent_logs : [];
      if (!isLogPaused) {
        setRecentLogs(dashboardRecentLogs);
      }
      setLastUpdatedAt(dashboardData.last_updated ? normalizeValue(dashboardData.last_updated) : new Date().toLocaleString('zh-CN', { hour12: false }));

      const recentTaskResponse = await requestApi(token, '/task/', { method: 'GET', query: { page: 1, size: 6, order: '-_id' } });
      setRecentTasks(normalizeListData(recentTaskResponse).items.slice(0, 6));
    } catch (err: any) {
      try {
        await loadFallback();
      } catch (fallbackErr: any) {
        setError(fallbackErr?.message || err?.message || '加载仪表盘失败');
      }
    } finally {
      setLoading(false);
    }
  }, [token, loadFallback, isLogPaused, loadAssetOverviewCounts]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (isLogPaused) {
      return;
    }
    void loadRecentLogs();
    const timer = window.setInterval(() => {
      void loadRecentLogs();
    }, 10000);
    return () => window.clearInterval(timer);
  }, [loadRecentLogs, isLogPaused]);

  // 兼容后端不同版本的字段命名
  const memoryInfo = deviceInfo?.memory || deviceInfo?.virtual_memory;
  const diskInfo = deviceInfo?.disk || deviceInfo?.disk_usage;
  const cpuPercent = parseNumericValue(deviceInfo?.cpu?.percent) || 0;
  const memoryPercent = parseNumericValue(memoryInfo?.percent) || 0;
  const diskPercent = parseNumericValue(diskInfo?.percent) || 0;
  const highRisk = Number((riskDistribution.find((item) => item?.name === '高危') || {}).value || 0);
  const cards = [
    { title: '总资产数', value: stats.asset_site, change: `今日 +${stats.new_assets_today}`, isUp: true, icon: Globe, color: 'text-accent' },
    { title: '活跃任务', value: stats.running_task, change: `总计 ${stats.task}`, isUp: true, icon: Activity, color: 'text-secondary' },
    { title: '高危风险', value: highRisk, change: `总计 ${stats.vuln}`, isUp: highRisk === 0, icon: AlertTriangle, color: 'text-error' },
    { title: '计划任务', value: stats.scheduler, change: `资产分组 ${stats.asset_scope}`, isUp: stats.scheduler > 0, icon: Settings, color: 'text-warning' },
  ];
  const buildEmptyAssetTrend = () => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    return Array.from({ length: 7 }, (_, index) => {
      const day = new Date(today);
      day.setDate(today.getDate() - (6 - index));
      const month = String(day.getMonth() + 1).padStart(2, '0');
      const date = String(day.getDate()).padStart(2, '0');
      return {
        name: `${month}-${date}`,
        assets: 0,
        vulns: 0,
      };
    });
  };
  // 回退模式下不要把“总资产数”伪装成“7日增长趋势”。
  const trendData = assetTrend.length > 0 ? assetTrend : buildEmptyAssetTrend();
  const assetOverviewData = [
    { name: '子域名', value: Number(stats.domain_total || 0), color: '#14b8a6' },
    { name: 'IP', value: Number(stats.ip_total || 0), color: '#3b82f6' },
    { name: '服务', value: Number(stats.service_total || 0), color: '#22c55e' },
    { name: 'URL', value: Number(stats.url_total || 0), color: '#f97316' },
  ];
  const netData = networkTrend.length > 0 ? networkTrend : [{ time: '13:40', in: 120, out: 80 }];
  const logsData = recentLogs.length > 0 ? recentLogs : [{ level: 'INFO', source: 'SCAN', msg: '暂无扫描日志数据', time: '' }];
  const quickModules = [
    { id: 'task', label: '任务管理', desc: '下发、停止、导出扫描任务', icon: Activity, color: 'text-accent' },
    { id: 'policy', label: '策略配置', desc: '维护标准化扫描策略模板', icon: FileCode, color: 'text-secondary' },
    { id: 'scheduler', label: '资产监控', desc: '周期监控资产组与站点变化', icon: Monitor, color: 'text-warning' },
    { id: 'asset_scope', label: '资产分组', desc: '维护范围并执行批量导出', icon: Globe, color: 'text-error' },
  ];
  const levelClassMap: Record<string, string> = {
    INFO: 'text-emerald-400',
    WARN: 'text-warning',
    WARNING: 'text-warning',
    ERROR: 'text-error',
    CRIT: 'text-error',
    DEBUG: 'text-sky-400',
  };

  const formatLogTime = (value: any): string => {
    if (!value) return '-';
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return normalizeValue(value);
    return parsed.toLocaleString('zh-CN', { hour12: false });
  };

  const formatTime = (value: any): string => {
    if (!value) return '-';
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return normalizeValue(value);
    return parsed.toLocaleString('zh-CN', { hour12: false });
  };

  const renderUsageBar = (title: string, percent: number, detail: string) => (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-[10px] font-black text-content-muted uppercase tracking-widest">
        <span>{title}</span>
        <span className="text-white">{formatPercent(percent)}</span>
      </div>
      <div className="h-1.5 bg-base-100 rounded-full overflow-hidden border border-base-300">
        <div className="h-full bg-brand-accent rounded-full transition-all duration-300" style={{ width: `${Math.min(100, Math.max(0, percent))}%` }} />
      </div>
      <p className="text-[10px] text-content-muted">{detail}</p>
    </div>
  );

  return (
    <div className="p-8 space-y-10">
      <PageHeader
        title="我的仪表盘"
        description="互联网资产自动化收集系统 · 实时监控中"
        actions={
          <div className="text-right space-y-2">
          <p className="text-xs font-black text-accent uppercase tracking-widest">最后更新</p>
          <p className="text-sm font-mono">{lastUpdatedAt || '-'}</p>
          <div className="flex gap-2 justify-end">
            <button
              onClick={onQuickCreateTask}
              className="px-5 py-2.5 rounded-xl bg-brand-accent text-white text-sm font-black uppercase tracking-wider hover:opacity-90 transition flex items-center gap-2"
            >
              <Plus className="w-[18px] h-[18px]" />
              新建任务
            </button>
            <button
              onClick={() => void load()}
              className="px-5 py-2.5 border border-base-300 rounded-xl text-sm font-semibold hover:bg-base-200/60 transition flex items-center gap-2"
            >
              <RefreshCw className={`w-[18px] h-[18px] ${loading ? 'animate-spin' : ''}`} />
              刷新
            </button>
          </div>
          </div>
        }
      />

      {error ? <div className="text-sm text-error border border-error/30 bg-error/10 rounded-xl px-4 py-3">{error}</div> : null}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {cards.map((card) => (
          <div key={card.title} className="bg-base-200/30 backdrop-blur-md border border-base-300 p-6 rounded-3xl hover:border-accent/50 transition-all group shadow-xl shadow-black/20">
            <div className="flex justify-between items-start mb-4">
              <div className={`p-3 rounded-2xl bg-base-100 border border-base-300 group-hover:scale-110 transition-transform ${card.color}`}>
                <card.icon className="w-6 h-6" />
              </div>
              <div className={`flex items-center gap-1 text-xs font-bold px-2 py-1 rounded-full ${card.isUp ? 'text-emerald-400 bg-emerald-400/10' : 'text-error bg-error/10'}`}>
                {card.isUp ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                {card.change}
              </div>
            </div>
            <h3 className="text-content-muted text-xs font-black uppercase tracking-widest mb-1">{card.title}</h3>
            <p className="text-3xl font-black tracking-tighter">{card.value.toLocaleString()}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-base-200/30 backdrop-blur-md border border-base-300 p-8 rounded-3xl shadow-xl shadow-black/20">
          <h3 className="text-xl font-black tracking-tight mb-8">资产增长趋势 (7日)</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="colorAssetsTrend" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--brand-accent)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--brand-accent)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" vertical={false} />
                <XAxis dataKey="name" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} dy={10} />
                <YAxis stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} />
                <Area type="monotone" dataKey="assets" stroke="var(--brand-accent)" strokeWidth={3} fillOpacity={1} fill="url(#colorAssetsTrend)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-base-200/30 backdrop-blur-md border border-base-300 p-8 rounded-3xl shadow-xl shadow-black/20">
          <h3 className="text-xl font-black tracking-tight mb-8">资产分布概览</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={assetOverviewData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" horizontal={false} />
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} />
                <Bar
                  dataKey="value"
                  radius={[8, 8, 8, 8]}
                  barSize={30}
                  background={{ fill: 'rgba(148,163,184,0.12)', radius: 8 }}
                >
                  {assetOverviewData.map((entry, index) => (
                    <Cell key={`asset-overview-${index}`} fill={entry?.color || '#64748b'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-base-200/30 backdrop-blur-md border border-base-300 p-6 rounded-3xl flex flex-col shadow-xl shadow-black/20">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-secondary/10 rounded-xl">
              <Activity className="w-5 h-5 text-secondary" />
            </div>
            <h3 className="text-xl font-black tracking-tight">系统监控</h3>
          </div>
          <div className="space-y-6 flex-1">
            {renderUsageBar('CPU 负载', cpuPercent, formatCpuSummary(deviceInfo))}
            {renderUsageBar('内存占用', memoryPercent, formatUsageSummary(memoryInfo))}
            {renderUsageBar('磁盘占用', diskPercent, formatUsageSummary(diskInfo))}
            <div className="h-28 mt-4">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={netData}>
                  <Area type="monotone" dataKey="in" stroke="var(--brand-accent)" fill="var(--brand-accent)" fillOpacity={0.1} strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="bg-base-200/30 backdrop-blur-md border border-base-300 p-6 rounded-3xl flex flex-col shadow-xl shadow-black/20">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-accent/10 rounded-xl">
                <Terminal className="w-5 h-5 text-accent" />
              </div>
              <h3 className="text-xl font-black tracking-tight">实时扫描日志</h3>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setIsLogPaused((prev) => !prev)}
                className={`text-xs font-black uppercase tracking-wider px-2 hover:underline ${isLogPaused ? 'text-warning' : 'text-secondary'}`}
              >
                {isLogPaused ? '继续' : '暂停'}
              </button>
              <button
                onClick={() => void loadRecentLogs(true)}
                className="text-xs font-black text-accent uppercase tracking-wider hover:underline px-2"
              >
                刷新日志
              </button>
            </div>
          </div>
          <div className="flex-1 bg-black/20 rounded-2xl p-4 font-mono text-[11px] overflow-y-auto max-h-[520px] min-h-[460px]">
            {isLogPaused ? (
              <div className="mb-2 text-warning border border-warning/30 bg-warning/10 rounded-lg px-2 py-1">扫描日志已暂停自动刷新</div>
            ) : null}
            {logsData.map((log, index) => {
              const level = String(log?.level || 'INFO').toUpperCase();
              const source = String(log?.source || 'SYSTEM').toUpperCase();
              return (
                <div key={`${source}-${level}-${index}`} className="py-2 border-b border-white/5 last:border-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`font-black shrink-0 w-12 ${levelClassMap[level] || 'text-content-muted'}`}>{level}</span>
                    <span className="text-content-muted">{source}</span>
                    <span className="ml-auto text-content-muted">{formatLogTime(log?.time)}</span>
                  </div>
                  <p className="text-white/80 break-all whitespace-pre-wrap leading-relaxed">{normalizeValueNoTruncate(log?.msg)}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <div className="xl:col-span-2 bg-base-200/35 border border-base-300 rounded-3xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xl font-black tracking-tight">最近任务</h3>
            <button
              onClick={() => onOpenModule('task')}
              className="text-sm font-black text-accent border border-accent/30 px-4 py-2 rounded-xl hover:bg-accent/10 transition"
            >
              查看全部
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-base-300">
                  <th className="py-2 pr-4 uppercase tracking-widest text-content-muted">名称</th>
                  <th className="py-2 pr-4 uppercase tracking-widest text-content-muted">状态</th>
                  <th className="py-2 pr-4 uppercase tracking-widest text-content-muted">目标</th>
                  <th className="py-2 uppercase tracking-widest text-content-muted">时间</th>
                </tr>
              </thead>
              <tbody>
                {recentTasks.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-6 text-center text-content-muted">
                      暂无任务数据
                    </td>
                  </tr>
                ) : (
                  recentTasks.map((task) => {
                    const statusInfo = resolveTaskStatus(task?.status);
                    const taskId = String(task?._id || task?.task_id || task?.id || '').trim();
                    return (
                      <tr key={String(task?._id || task?.task_id || task?.id || Math.random())} className="border-b border-base-300/60 last:border-b-0">
                        <td className="py-3 pr-4 font-semibold">
                          {taskId ? (
                            <button
                              onClick={() => onOpenModule('site', { task_id: taskId })}
                              className="text-accent hover:underline text-left"
                              title="点击查看该任务详情"
                            >
                              {normalizeValue(task?.name)}
                            </button>
                          ) : (
                            normalizeValue(task?.name)
                          )}
                        </td>
                        <td className="py-3 pr-4">
                          <StatusPill text={statusInfo.text} type={statusInfo.type} />
                        </td>
                        <td className="py-3 pr-4 font-mono">{normalizeValue(task?.target)}</td>
                        <td className="py-3 text-content-muted">{formatTime(task?.create_time || task?.update_time || task?.start_time)}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-base-200/35 border border-base-300 rounded-3xl p-6">
          <h3 className="text-lg font-black mb-4">快捷入口</h3>
          <div className="grid grid-cols-1 gap-3">
            {quickModules.map((entry) => (
              <button
                key={entry.id}
                onClick={() => onOpenModule(entry.id)}
                className="text-left bg-base-100/40 border border-base-300 rounded-2xl p-4 hover:border-accent/45 hover:bg-base-200/55 transition"
              >
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded-lg bg-base-200/60 border border-base-300 ${entry.color}`}>
                    <entry.icon className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="font-black text-sm">{entry.label}</p>
                    <p className="text-xs text-content-muted mt-1">{entry.desc}</p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
