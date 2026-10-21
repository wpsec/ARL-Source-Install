import { useCallback, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
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
import { HoverCellValue } from '../components/ui/HoverCellValue';
import { StatusPill } from '../components/ui/StatusPill';
import {
  formatDurationSecondsLabel,
  formatPercent,
  normalizeValue,
  normalizeValueNoTruncate,
  parseNumericValue,
} from '../domain/format';
import { formatTokenListText } from '../domain/finger';
import { formatCpuSummary, formatUsageSummary } from '../domain/system';
import {
  buildTaskExecutionAccountingSummary,
  getTaskProgressPercent,
  getTaskQueueStatusInfo,
  normalizeTaskStatus,
} from '../domain/task';
import type {OpenModuleHandler} from '../domain/types';
import { PageHeader } from '../layout/PageHeader';
import {
  CONSOLE_ALERT_ERROR_CLASS,
  CONSOLE_ALERT_WARNING_CLASS,
  CONSOLE_CARD_ACTION_CLASS,
  CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS,
  CONSOLE_PAGE_CLASS,
  CONSOLE_PRIMARY_BUTTON_CLASS,
  CONSOLE_SECONDARY_BUTTON_CLASS,
  CONSOLE_PANEL_CLASS,
  CONSOLE_TEXT_BUTTON_CLASS,
} from '../ui/classes';

const EMPTY_STATS = {
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
};

const CHART_TOOLTIP_CONTENT_STYLE = {
  backgroundColor: 'var(--color-base-200)',
  border: '1px solid var(--color-base-300)',
  borderRadius: 'var(--radius-box)',
  color: 'var(--brand-text)',
};

export function DashboardView({
  token,
  onOpenModule,
  onQuickCreateTask,
}: {
  token: string;
  onOpenModule: OpenModuleHandler;
  onQuickCreateTask: () => void;
}) {
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

  // 回退快照：主聚合接口不可用时并行拉明细（原 loadFallback 的纯数据版，setState 移到水合 effect）。
  const fetchFallbackSnapshot = useCallback(async () => {
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

    return {
      source: 'fallback' as const,
      stats: {
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
        // 回退模式没有权威 running 计数；水合时保留现值、仅在无值时用近期任务估算。
        runningTaskFallback: activeRecentTaskCount,
      },
      deviceInfo: consoleInfo?.data?.device_info || {},
      recentTasks: recentTaskItems,
      lastUpdatedAt: new Date().toLocaleString('zh-CN', { hour12: false }),
    };
  }, [token, loadAssetOverviewCounts]);

  // 数据层迁移（计划 4 工作台批次）：
  // - 聚合快照 = dashboardQuery（主接口失败时 queryFn 内回退明细聚合，双败才报错）；
  // - 扫描日志 = logsQuery 10s refetchInterval，暂停即 interval=false、继续时立即 refetch
  //   （对齐原 loadRecentLogs(force) 语义）；日志失败不打断聚合（原静默 catch 语义）。
  const dashboardQuery = useQuery({
    queryKey: ['dashboard-console', token],
    queryFn: async () => {
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
        const recentTaskResponse = await requestApi(token, '/task/', { method: 'GET', query: { page: 1, size: 6, order: '-_id' } });
        return {
          source: 'primary' as const,
          stats: {
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
          },
          deviceInfo: dashboardData.device_info || {},
          assetTrend: Array.isArray(dashboardData.asset_trend_7d) ? dashboardData.asset_trend_7d : [],
          riskDistribution: Array.isArray(dashboardData.risk_distribution) ? dashboardData.risk_distribution : [],
          networkTrend: Array.isArray(dashboardData.network_trend) ? dashboardData.network_trend : [],
          recentLogs: Array.isArray(dashboardData.recent_logs) ? dashboardData.recent_logs : [],
          recentTasks: normalizeListData(recentTaskResponse).items.slice(0, 6),
          lastUpdatedAt: dashboardData.last_updated
            ? normalizeValue(dashboardData.last_updated)
            : new Date().toLocaleString('zh-CN', { hour12: false }),
        };
      } catch (err: any) {
        // 主接口失败：回退明细聚合；回退也失败则带上原始消息抛出（双败才呈现错误）。
        try {
          return await fetchFallbackSnapshot();
        } catch (fallbackErr: any) {
          throw new Error(fallbackErr?.message || err?.message || '加载仪表盘失败');
        }
      }
    },
    retry: 0,
  });

  const logsQuery = useQuery({
    queryKey: ['dashboard-recent-logs', token],
    queryFn: async () => {
      const response = await requestApi(token, '/console/recent_logs', { method: 'GET', query: { limit: 120 } });
      return Array.isArray(response?.data?.recent_logs) ? response.data.recent_logs : [];
    },
    refetchInterval: isLogPaused ? false : 10000,
    retry: 0,
  });
  const queueMetricsQuery = useQuery({
    queryKey: ['dashboard-queue-metrics', token],
    queryFn: async () => {
      const response = await requestApi(token, '/console/queue_metrics', { method: 'GET' });
      const data = response?.data || {};
      return {
        brokerOk: Boolean(data.broker_ok),
        inspectOk: Boolean(data.inspect_ok),
        queues: Array.isArray(data.queues) ? data.queues : [],
      };
    },
    refetchInterval: 10000,
    retry: 0,
  });

  const loading = dashboardQuery.isFetching;

  const dashboardSnapshot = dashboardQuery.data;
  const stats = dashboardSnapshot?.source === 'fallback'
    ? {
        ...EMPTY_STATS,
        ...dashboardSnapshot.stats,
        running_task: Number(dashboardSnapshot.stats.runningTaskFallback || 0),
      }
    : dashboardSnapshot?.stats || EMPTY_STATS;
  const deviceInfo = dashboardSnapshot?.deviceInfo || {};
  const recentTasks = dashboardSnapshot?.recentTasks || [];
  const activeTasks = recentTasks
    .filter((task: any) => ['running', 'waiting'].includes(normalizeTaskStatus(task?.status)))
    .slice(0, 5);
  const assetTrend = dashboardSnapshot?.source === 'primary' ? dashboardSnapshot.assetTrend : [];
  const riskDistribution = dashboardSnapshot?.source === 'primary' ? dashboardSnapshot.riskDistribution : [];
  const networkTrend = dashboardSnapshot?.source === 'primary' ? dashboardSnapshot.networkTrend : [];
  const fallbackLogs = [{ level: 'INFO', source: 'SCAN', msg: '当前为兼容模式，扫描日志接口不可用', time: '' }];
  const recentLogs = logsQuery.data?.length
    ? logsQuery.data
    : dashboardSnapshot?.source === 'primary'
      ? dashboardSnapshot.recentLogs
      : dashboardSnapshot?.source === 'fallback'
        ? fallbackLogs
        : [];
  const lastUpdatedAt = dashboardSnapshot?.lastUpdatedAt || '';
  const error = dashboardQuery.isError
    ? (dashboardQuery.error as Error)?.message || '加载仪表盘失败'
    : '';

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
    { name: '子域名', value: Number(stats.domain_total || 0), color: 'var(--color-secondary)' },
    { name: 'IP', value: Number(stats.ip_total || 0), color: 'var(--color-info)' },
    { name: '服务', value: Number(stats.service_total || 0), color: 'var(--color-success)' },
    { name: 'URL', value: Number(stats.url_total || 0), color: 'var(--color-warning)' },
  ];
  const hasNetworkTrend = networkTrend.length > 0;
  const logsData = recentLogs.length > 0 ? recentLogs : [{ level: 'INFO', source: 'SCAN', msg: '暂无扫描日志数据', time: '' }];
  const quickModules = [
    { id: 'task', label: '任务管理', desc: '下发、停止、导出扫描任务', icon: Activity, color: 'text-accent' },
    { id: 'policy', label: '策略配置', desc: '维护标准化扫描策略模板', icon: FileCode, color: 'text-secondary' },
    { id: 'scheduler', label: '资产监控', desc: '周期监控资产组与站点变化', icon: Monitor, color: 'text-warning' },
    { id: 'asset_scope', label: '资产分组', desc: '维护范围并执行批量导出', icon: Globe, color: 'text-error' },
  ];
  const levelClassMap: Record<string, string> = {
    INFO: 'text-success',
    WARN: 'text-warning',
    WARNING: 'text-warning',
    ERROR: 'text-error',
    CRIT: 'text-error',
    DEBUG: 'text-info',
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

  const formatQueueWait = (queue: any): string => {
    const queuedAt = String(queue?.earliest_queued_at || '').trim();
    if (!queuedAt) return '-';
    const elapsed = Number(queue?.earliest_wait_seconds);
    const age = Number.isFinite(elapsed) ? formatDurationSecondsLabel(Math.max(0, elapsed)) : '时长未知';
    return `${age} · ${queuedAt}`;
  };

  const queueLabelMap: Record<string, string> = {
    arltask: '普通任务',
    arlheavy: '域名深扫',
    arlip: '重 IP 扫描',
    arlweb: 'Web 重任务',
    arlgithub: 'GitHub 任务',
  };
  const queueMetrics = queueMetricsQuery.data;

  const renderUsageBar = (title: string, percent: number, detail: string) => (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs font-medium text-content-muted">
        <span>{title}</span>
        <span className="text-base-content">{formatPercent(percent)}</span>
      </div>
      <progress
        className="progress progress-primary w-full"
        value={Math.min(100, Math.max(0, percent))}
        max="100"
        aria-label={`${title} ${formatPercent(percent)}`}
      />
      <p className="text-[10px] text-content-muted">{detail}</p>
    </div>
  );

  return (
    <div className={`${CONSOLE_PAGE_CLASS} xl:space-y-6`}>
      <PageHeader
        title="我的仪表盘"
        description="互联网资产自动化收集系统 · 实时监控中"
        actions={
          <div className="min-w-0 w-full space-y-2 text-right xl:w-auto">
          <p className="text-[11px] font-medium text-content-muted tracking-wide">最后更新</p>
          <p className="text-sm font-mono">{lastUpdatedAt || '-'}</p>
          <div className="flex gap-2 justify-end">
            <button
              onClick={onQuickCreateTask}
              className={CONSOLE_PRIMARY_BUTTON_CLASS}
            >
              <Plus className="w-[18px] h-[18px]" />
              新建任务
            </button>
            <button
              onClick={() => {
                void dashboardQuery.refetch();
              }}
              className={CONSOLE_SECONDARY_BUTTON_CLASS}
            >
              <RefreshCw className={`w-[18px] h-[18px] ${loading ? 'animate-spin' : ''}`} />
              刷新
            </button>
          </div>
          </div>
        }
      />

      {error ? <div role="alert" className={CONSOLE_ALERT_ERROR_CLASS}>{error}</div> : null}

      <section className={CONSOLE_PANEL_CLASS} aria-label="运行中的任务">
        <div className="card-body gap-4 p-4 sm:p-6">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="card-title text-lg font-semibold sm:text-xl">运行中的任务</h2>
              <p className="mt-1 text-sm text-content-muted">优先显示近期仍在执行或等待的任务及其当前阶段。</p>
            </div>
            <button
              type="button"
              onClick={() => onOpenModule('task')}
              className={CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS}
            >
              全部任务
            </button>
          </div>
          {activeTasks.length === 0 ? (
            <div className="rounded-box border border-dashed border-base-300 bg-base-200/50 px-4 py-8 text-center text-sm text-content-muted">
              当前没有正在执行或等待的近期任务。
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
              {activeTasks.map((task: any, index: number) => {
                const taskId = String(task?._id || task?.task_id || task?.id || '').trim();
                const queueInfo = getTaskQueueStatusInfo(task);
                const accounting = buildTaskExecutionAccountingSummary(task, Date.now());
                const stageName = accounting.currentStageVisible
                  ? accounting.currentStageName
                  : queueInfo?.label || '任务执行中';
                const stageDuration = queueInfo?.detail || (
                  accounting.hasUncountedDuration
                    ? `${accounting.uncountedStageName} · ${accounting.uncountedDurationLabel}`
                    : '阶段耗时暂不可用'
                );
                const taskName = normalizeValueNoTruncate(task?.name);
                const target = normalizeValueNoTruncate(task?.target);
                const progress = getTaskProgressPercent(task);

                return (
                  <article key={taskId || `active-task-${index}`} className="min-w-0 rounded-box border border-base-300 bg-base-100 p-4">
                    <div className="flex min-w-0 items-start justify-between gap-3">
                      <div className="min-w-0">
                        {taskId ? (
                          <button
                            type="button"
                            onClick={() => onOpenModule('site', { task_id: taskId })}
                            className={`${CONSOLE_TEXT_BUTTON_CLASS} block max-w-full truncate text-left font-semibold text-accent hover:underline`}
                            title="查看任务详情"
                          >
                            {taskName}
                          </button>
                        ) : <h3 className="truncate font-semibold">{taskName}</h3>}
                        <p className="mt-1 truncate font-mono text-xs text-content-muted" title={target}>{target}</p>
                      </div>
                      <StatusPill text={resolveTaskStatus(task?.status).text} type="info" compact />
                    </div>
                    <div className="mt-4 flex min-w-0 items-center justify-between gap-3 text-xs">
                      <span className="truncate font-medium text-base-content">{stageName}</span>
                      <span className="shrink-0 tabular-nums text-content-muted">{progress}%</span>
                    </div>
                    <progress
                      className="progress progress-primary mt-2 h-1.5 w-full"
                      value={progress}
                      max="100"
                      aria-label={`${taskName}扫描进度 ${progress}%`}
                    />
                    <p className="mt-2 truncate text-xs text-content-muted" title={stageDuration}>{stageDuration}</p>
                  </article>
                );
              })}
            </div>
          )}
        </div>
      </section>

      <section className={CONSOLE_PANEL_CLASS} aria-label="Celery 队列状态">
        <div className="card-body p-4 sm:p-6">
          <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
            <div>
              <h2 className="card-title text-lg font-semibold sm:text-xl">扫描队列</h2>
              <p className="mt-1 max-w-4xl text-sm leading-6 text-content-muted">每 10 秒更新；ready 为待消费，reserved 为已预取，active 为正在执行。等待时长来自任务账本，只用于观察当前状态。</p>
            </div>
            <button
              type="button"
              onClick={() => void queueMetricsQuery.refetch()}
              className={CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS}
              aria-label="刷新队列状态"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${queueMetricsQuery.isFetching ? 'animate-spin' : ''}`} />
              刷新
            </button>
          </div>
          {queueMetricsQuery.isError || (!queueMetrics?.brokerOk && !queueMetrics?.inspectOk) ? (
            <p role="status" className="text-sm text-content-muted">队列指标暂不可用。</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="table table-sm min-w-[760px]">
                <thead>
                  <tr>
                    <th>队列</th>
                    <th className="text-right">Ready</th>
                    <th className="text-right">Reserved</th>
                    <th className="text-right">Active</th>
                    <th>最早可观测等待</th>
                  </tr>
                </thead>
                <tbody>
                  {(queueMetrics?.queues || []).map((queue: any) => (
                    <tr key={queue.name}>
                      <td className="font-semibold">{queueLabelMap[String(queue.name)] || queue.name}</td>
                      <td className="text-right tabular-nums">{queue.ready ?? '-'}</td>
                      <td className="text-right tabular-nums">{queue.reserved ?? '-'}</td>
                      <td className="text-right tabular-nums">{queue.active ?? '-'}</td>
                      <td className="text-xs text-content-muted">{formatQueueWait(queue)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {queueMetrics && (!queueMetrics.brokerOk || !queueMetrics.inspectOk) ? (
                <p className="mt-2 text-xs text-warning">部分数据源暂不可用；“-”表示本次无法统计。</p>
              ) : null}
            </div>
          )}
        </div>
      </section>

      <div className="grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-4">
        {cards.map((card) => (
          <div key={card.title} className={`${CONSOLE_PANEL_CLASS} group transition-colors hover:border-primary/50`}>
            <div className="card-body p-5">
              <div className="flex justify-between items-start mb-4">
                <div className={`p-2.5 rounded-box bg-base-100 border border-base-300 group-hover:scale-105 transition-transform ${card.color}`}>
                  <card.icon className="h-5 w-5" />
                </div>
                <div className={`badge badge-soft gap-1 text-xs font-medium ${card.isUp ? 'badge-success' : 'badge-error'}`}>
                  {card.isUp ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                  {card.change}
                </div>
              </div>
              <h3 className="mb-1 text-sm font-medium text-content-muted">{card.title}</h3>
              <p className="text-3xl font-semibold tabular-nums tracking-tight">{card.value.toLocaleString()}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className={`lg:col-span-2 ${CONSOLE_PANEL_CLASS}`}>
          <div className="card-body p-6">
            <h3 className="card-title mb-2 text-lg font-semibold tracking-tight">资产增长趋势 (7日)</h3>
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
                <Tooltip contentStyle={CHART_TOOLTIP_CONTENT_STYLE} labelStyle={{ color: 'var(--brand-text)' }} itemStyle={{ color: 'var(--brand-text)' }} />
                <Area type="monotone" dataKey="assets" stroke="var(--brand-accent)" strokeWidth={3} fillOpacity={1} fill="url(#colorAssetsTrend)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className={CONSOLE_PANEL_CLASS}>
          <div className="card-body p-6">
            <h3 className="card-title mb-2 text-lg font-semibold tracking-tight">资产分布概览</h3>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={assetOverviewData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" horizontal={false} />
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip cursor={{ fill: 'transparent' }} contentStyle={CHART_TOOLTIP_CONTENT_STYLE} labelStyle={{ color: 'var(--brand-text)' }} itemStyle={{ color: 'var(--brand-text)' }} />
                <Bar
                  dataKey="value"
                  radius={[8, 8, 8, 8]}
                  barSize={30}
                  background={{ fill: 'var(--color-base-300)', radius: 8 }}
                >
                  {assetOverviewData.map((entry, index) => (
                    <Cell key={`asset-overview-${index}`} fill={entry?.color || 'var(--color-base-content)'} />
                  ))}
                </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <div className={`${CONSOLE_PANEL_CLASS} flex flex-col`}>
          <div className="card-body p-6 flex-1">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 rounded-box bg-secondary/10">
                <Activity className="w-5 h-5 text-secondary" />
              </div>
              <h3 className="card-title text-lg font-semibold tracking-tight">系统监控</h3>
            </div>
            <div className="space-y-6">
              {renderUsageBar('CPU 负载', cpuPercent, formatCpuSummary(deviceInfo))}
              {renderUsageBar('内存占用', memoryPercent, formatUsageSummary(memoryInfo))}
              {renderUsageBar('磁盘占用', diskPercent, formatUsageSummary(diskInfo))}
              <div className="mt-4 flex h-28 items-center justify-center rounded-box border border-dashed border-base-300 bg-base-100/60 px-4 text-xs text-content-muted">
                {hasNetworkTrend ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={networkTrend}>
                      <Area type="monotone" dataKey="in" stroke="var(--brand-accent)" fill="var(--brand-accent)" fillOpacity={0.1} strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <span role="status" aria-label="暂无网络趋势数据">暂无网络趋势数据</span>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className={`${CONSOLE_PANEL_CLASS} flex flex-col`}>
          <div className="card-body p-6 flex-1">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-box bg-accent/10">
                  <Terminal className="w-5 h-5 text-accent" />
                </div>
                <h3 className="card-title text-lg font-semibold tracking-tight">实时扫描日志</h3>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    const next = !isLogPaused;
                    setIsLogPaused(next);
                    // 继续时立即补一帧（对齐原 loadRecentLogs(force) 语义）。
                    if (!next) {
                      void logsQuery.refetch();
                    }
                  }}
                  className={`${CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} ${isLogPaused ? '!border-warning/50 !bg-warning/10 !text-warning hover:!border-warning/70 hover:!bg-warning/15' : '!border-secondary/50 !bg-secondary/10 !text-secondary hover:!border-secondary/70 hover:!bg-secondary/15'}`}
                >
                  {isLogPaused ? '继续' : '暂停'}
                </button>
                <button
                  onClick={() => void logsQuery.refetch()}
                  disabled={logsQuery.isFetching}
                  className={`${CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} !border-accent/50 !bg-accent/10 !text-accent hover:!border-accent/70 hover:!bg-accent/15`}
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${logsQuery.isFetching ? 'animate-spin' : ''}`} />
                  {logsQuery.isFetching ? '正在刷新...' : '刷新日志'}
                </button>
              </div>
            </div>
            <div className="flex-1 bg-base-100 border border-base-300 rounded-box p-4 font-mono text-[11px] overflow-y-auto max-h-[520px] min-h-[460px]">
              {isLogPaused ? (
                <div role="status" className={`${CONSOLE_ALERT_WARNING_CLASS} mb-2 py-2`}>扫描日志已暂停自动刷新</div>
              ) : null}
              {logsData.map((log, index) => {
                const level = String(log?.level || 'INFO').toUpperCase();
                const source = String(log?.source || 'SYSTEM').toUpperCase();
                return (
                  <div key={`${source}-${level}-${index}`} className="py-2 border-b border-base-300 last:border-0">
                    <div className="flex min-w-0 items-center gap-2 mb-1">
                      <span className={`font-black shrink-0 w-12 ${levelClassMap[level] || 'text-content-muted'}`}>{level}</span>
                      <span className="min-w-0 flex-1 truncate text-content-muted" title={source}>{source}</span>
                      <span className="shrink-0 whitespace-nowrap text-content-muted">{formatLogTime(log?.time)}</span>
                    </div>
                    <p className="text-base-content break-all whitespace-pre-wrap leading-relaxed">{normalizeValueNoTruncate(log?.msg)}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className={`xl:col-span-2 ${CONSOLE_PANEL_CLASS}`}>
          <div className="card-body p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold tracking-tight">最近任务</h3>
            <button
              onClick={() => onOpenModule('task')}
              className={`${CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} !h-9 !min-h-9 !px-3 !text-accent`}
            >
              查看全部
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="arl-fixed-table w-full text-left text-xs">
              <colgroup>
                <col style={{ width: '28%' }} />
                <col style={{ width: '16%' }} />
                <col style={{ width: '40%' }} />
                <col style={{ width: '16%' }} />
              </colgroup>
              <thead>
                <tr className="border-b border-base-300">
                  <th className="py-2 pr-4 text-xs font-semibold text-content-muted">名称</th>
                  <th className="py-2 pr-4 text-xs font-semibold text-content-muted">状态</th>
                  <th className="py-2 pr-4 text-xs font-semibold text-content-muted">目标</th>
                  <th className="py-2 text-xs font-semibold text-content-muted">时间</th>
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
                  recentTasks.map((task, taskIndex) => {
                    const statusInfo = resolveTaskStatus(task?.status);
                    const taskId = String(task?._id || task?.task_id || task?.id || '').trim();
                    const taskNameText = normalizeValueNoTruncate(task?.name);
                    const taskTargetText = normalizeValueNoTruncate(task?.target);
                    return (
                      <tr key={taskId || `recent-task-${taskIndex}`} className="border-b border-base-300/60 last:border-b-0">
                        <td className="min-w-0 max-w-full overflow-hidden py-3 pr-4 font-semibold">
                          <HoverCellValue
                            display={taskId ? (
                              <button
                                onClick={() => onOpenModule('site', { task_id: taskId })}
                                className={`${CONSOLE_TEXT_BUTTON_CLASS} block min-w-0 max-w-full truncate text-left text-accent hover:underline`}
                                title="点击查看该任务详情"
                              >
                                {taskNameText}
                              </button>
                            ) : (
                              <span className="block min-w-0 max-w-full truncate">{taskNameText}</span>
                            )}
                            fullText={taskNameText}
                            label="任务名称"
                            showHover={taskNameText !== '-'}
                            displayClassName="block min-w-0 max-w-full"
                          />
                        </td>
                        <td className="min-w-0 max-w-full overflow-hidden py-3 pr-4">
                          <StatusPill text={statusInfo.text} type={statusInfo.type} compact />
                        </td>
                        <td className="min-w-0 max-w-full overflow-hidden py-3 pr-4 font-mono leading-relaxed">
                          <HoverCellValue
                            display={<div className="max-h-24 overflow-hidden whitespace-pre-wrap break-all">{formatTokenListText(task?.target)}</div>}
                            fullText={taskTargetText}
                            label="任务目标"
                            showHover={taskTargetText !== '-'}
                          />
                        </td>
                        <td className="min-w-0 max-w-full overflow-hidden py-3 text-content-muted">
                          <span className="block min-w-0 max-w-full truncate">{formatTime(task?.create_time || task?.update_time || task?.start_time)}</span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          </div>
        </div>

        <div className={CONSOLE_PANEL_CLASS}>
          <div className="card-body p-6">
          <h3 className="mb-4 text-lg font-semibold">快捷入口</h3>
          <div className="grid grid-cols-1 gap-3">
            {quickModules.map((entry) => (
              <button
                key={entry.id}
                onClick={() => onOpenModule(entry.id)}
                className={`${CONSOLE_CARD_ACTION_CLASS} p-4`}
              >
                <div className="flex min-w-0 w-full items-start gap-3">
                  <div className={`p-2 rounded-box bg-base-200 border border-base-300 ${entry.color}`}>
                    <entry.icon className="w-4 h-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="break-words text-sm font-semibold">{entry.label}</p>
                    <p className="mt-1 break-words text-xs text-content-muted">{entry.desc}</p>
                  </div>
                </div>
              </button>
            ))}
          </div>
          </div>
        </div>
      </div>
    </div>
  );
}
