import React from 'react';
import {
  Cpu,
  Database,
  Network,
  RefreshCw,
  Server,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { requestApi } from '../api/client';
import { formatPercent, normalizeValue, parseNumericValue } from '../domain/format';
import { PageHeader } from '../layout/PageHeader';
import {
  CONSOLE_ALERT_ERROR_CLASS,
  CONSOLE_PAGE_CLASS,
  CONSOLE_PANEL_CLASS,
  CONSOLE_SECONDARY_BUTTON_CLASS,
} from '../ui/classes';

const MONITOR_POLL_INTERVAL_MS = 3000;

function fallbackTimestamp() {
  return new Date().toLocaleString('zh-CN', { hour12: false });
}

export function SystemMonitorView({ token }: { token: string }) {
  // 数据层迁移（计划 4 监控批次）：主查询 3s 轮询替代手写 setInterval；
  // 主查询失败时启用 dashboard 回退查询（与原 loadFallback 同语义）。
  // 本视图纯读取无 mutation，展示数据全部由 query 派生，无本地快照状态。
  const monitorQuery = useQuery({
    queryKey: ['system-monitor', token],
    queryFn: async () => {
      const monitorInfo = await requestApi(token, '/console/system_monitor/', { method: 'GET' });
      const data = monitorInfo?.data || {};
      if (!data?.resource || typeof data.resource !== 'object') {
        throw new Error('系统监控数据为空');
      }
      return data;
    },
    refetchInterval: MONITOR_POLL_INTERVAL_MS,
    refetchIntervalInBackground: false,
    retry: 0,
  });

  const fallbackQuery = useQuery({
    queryKey: ['system-monitor-fallback', token],
    queryFn: async () => {
      const dashboardInfo = await requestApi(token, '/console/dashboard', { method: 'GET' });
      const data = dashboardInfo?.data || {};
      const deviceInfo = data?.device_info || {};
      const memory = deviceInfo?.memory || deviceInfo?.virtual_memory || {};
      const disk = deviceInfo?.disk || deviceInfo?.disk_usage || {};
      const cpuPercent = parseNumericValue(deviceInfo?.cpu?.percent) || 0;
      const memoryPercent = parseNumericValue(memory?.percent) || 0;
      const diskPercent = parseNumericValue(disk?.percent) || 0;

      const fallbackHistory = Array.isArray(data?.network_trend)
        ? data.network_trend.map((item: any) => {
            const netIn = Number(item?.in || 0);
            const netOut = Number(item?.out || 0);
            return {
              time: normalizeValue(item?.time),
              cpu: cpuPercent,
              ram: memoryPercent,
              disk: diskPercent,
              net_in: netIn,
              net_out: netOut,
              net: netIn + netOut,
            };
          })
        : [];

      return {
        resource: {
          cpu_percent: cpuPercent,
          cpu_count: Number(deviceInfo?.cpu?.count || 0),
          memory_percent: memoryPercent,
          memory_used: normalizeValue(memory?.used),
          memory_total: normalizeValue(memory?.total),
          disk_percent: diskPercent,
          disk_used: normalizeValue(disk?.used),
          disk_total: normalizeValue(disk?.total),
          network_total_sent: '-',
          network_total_recv: '-',
          network_rate_in_kbps: Number((fallbackHistory[fallbackHistory.length - 1] || {}).net_in || 0),
          network_rate_out_kbps: Number((fallbackHistory[fallbackHistory.length - 1] || {}).net_out || 0),
          network_rate_total_kbps: Number((fallbackHistory[fallbackHistory.length - 1] || {}).net || 0),
          process_count: '-',
          boot_time: '-',
        },
        history: fallbackHistory,
        updatedAt: data?.last_updated ? normalizeValue(data.last_updated) : fallbackTimestamp(),
      };
    },
    enabled: monitorQuery.isError,
    retry: 0,
  });

  // 主查询错误时旧 data 仍会被 react-query 保留——必须显式让位给回退快照。
  const primarySnapshot = monitorQuery.isError
    ? null
    : monitorQuery.data
      ? {
          resource: monitorQuery.data.resource || {},
          history: Array.isArray(monitorQuery.data.history_24h) ? monitorQuery.data.history_24h : [],
          updatedAt: monitorQuery.data.updated_at ? normalizeValue(monitorQuery.data.updated_at) : fallbackTimestamp(),
        }
      : null;
  const snapshot = primarySnapshot ?? fallbackQuery.data ?? { resource: {}, history: [], updatedAt: '' };
  const resource = snapshot.resource;
  const history = snapshot.history;
  const updatedAt = snapshot.updatedAt;
  const loading = monitorQuery.isFetching;
  const error =
    monitorQuery.isError && fallbackQuery.isError
      ? (fallbackQuery.error as Error)?.message || (monitorQuery.error as Error)?.message || '加载系统监控失败'
      : '';

  const cpuPercent = parseNumericValue(resource?.cpu_percent) || 0;
  const memoryPercent = parseNumericValue(resource?.memory_percent) || 0;
  const diskPercent = parseNumericValue(resource?.disk_percent) || 0;
  const netIn = parseNumericValue(resource?.network_rate_in_kbps) || 0;
  const netOut = parseNumericValue(resource?.network_rate_out_kbps) || 0;
  const netTotal = parseNumericValue(resource?.network_rate_total_kbps) || 0;
  const chartData =
    history.length > 0
      ? history
      : [
          {
            time: '当前',
            cpu: cpuPercent,
            ram: memoryPercent,
            disk: diskPercent,
            net_in: netIn,
            net_out: netOut,
            net: netTotal,
          },
        ];

  const resourceCards: Array<{
    title: string;
    value: string;
    detail: string;
    percent: number;
    icon: React.ComponentType<{ className?: string }>;
    color: string;
  }> = [
    {
      title: 'CPU 使用率',
      value: formatPercent(cpuPercent),
      detail: `${normalizeValue(resource?.cpu_count)} 核`,
      percent: cpuPercent,
      icon: Cpu,
      color: 'text-accent',
    },
    {
      title: '内存占用',
      value: `${normalizeValue(resource?.memory_used)} / ${normalizeValue(resource?.memory_total)}`,
      detail: formatPercent(memoryPercent),
      percent: memoryPercent,
      icon: Database,
      color: 'text-secondary',
    },
    {
      title: '磁盘占用',
      value: `${normalizeValue(resource?.disk_used)} / ${normalizeValue(resource?.disk_total)}`,
      detail: formatPercent(diskPercent),
      percent: diskPercent,
      icon: Server,
      color: 'text-warning',
    },
    {
      title: '网络速率',
      value: `${netTotal.toFixed(1)} KB/s`,
      detail: `入 ${netIn.toFixed(1)} / 出 ${netOut.toFixed(1)} KB/s`,
      percent: Math.min(100, Math.max(0, netTotal > 1000 ? 100 : netTotal / 10)),
      icon: Network,
      color: 'text-success',
    },
  ];

  return (
    <div className={`${CONSOLE_PAGE_CLASS} xl:space-y-8`}>
      <PageHeader
        title="系统监控"
        description="实时监控主机资源、CPU、内存、磁盘与网络流量趋势"
        actions={
          <div className="text-right space-y-2">
          <p className="text-xs font-black text-accent uppercase tracking-widest">最后更新</p>
          <p className="text-sm font-mono">{updatedAt || '-'}</p>
          <button
            onClick={() => void monitorQuery.refetch()}
            className={CONSOLE_SECONDARY_BUTTON_CLASS}
            disabled={loading}
          >
            <RefreshCw className={`w-[18px] h-[18px] ${loading ? 'animate-spin' : ''}`} />
            刷新
          </button>
        </div>
        }
      />

      {error ? <div role="alert" className={CONSOLE_ALERT_ERROR_CLASS}>{error}</div> : null}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        {resourceCards.map((item) => (
          <div key={item.title} className={CONSOLE_PANEL_CLASS}>
            <div className="card-body p-5">
              <div className="flex items-center justify-between mb-5">
                <div className={`p-2.5 rounded-box bg-base-100 border border-base-300 ${item.color}`}>
                  <item.icon className="w-5 h-5" />
                </div>
                <span className="text-xs font-black text-base-content/60">{item.detail}</span>
              </div>
              <h3 className="text-xs font-medium tracking-wide text-base-content/60 mb-1">{item.title}</h3>
              <p className="text-2xl font-semibold tracking-tight">{item.value}</p>
              <progress
                className="progress progress-primary w-full mt-4"
                value={Math.min(100, Math.max(0, item.percent))}
                max="100"
                aria-label={`${item.title} ${item.detail}`}
              />
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className={CONSOLE_PANEL_CLASS}>
          <div className="card-body p-6">
            <h3 className="card-title text-lg font-semibold tracking-tight mb-2">资源使用趋势</h3>
            <div className="h-[320px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} />
                <Line type="monotone" dataKey="cpu" stroke="var(--brand-accent)" strokeWidth={2.5} dot={false} />
                <Line type="monotone" dataKey="ram" stroke="var(--brand-secondary)" strokeWidth={2.5} dot={false} />
                <Line type="monotone" dataKey="disk" stroke="var(--brand-warning)" strokeWidth={2.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className={CONSOLE_PANEL_CLASS}>
          <div className="card-body p-6">
            <h3 className="card-title text-lg font-semibold tracking-tight mb-2">网络流量趋势</h3>
            <div className="h-[320px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="systemMonitorNetIn" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--brand-secondary)" stopOpacity={0.28} />
                    <stop offset="95%" stopColor="var(--brand-secondary)" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="systemMonitorNetOut" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--brand-accent)" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="var(--brand-accent)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} />
                <Area type="monotone" dataKey="net_in" stroke="var(--brand-secondary)" fillOpacity={1} fill="url(#systemMonitorNetIn)" strokeWidth={2.5} />
                <Area type="monotone" dataKey="net_out" stroke="var(--brand-accent)" fillOpacity={1} fill="url(#systemMonitorNetOut)" strokeWidth={2.5} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      <div className="stats stats-vertical md:stats-horizontal w-full bg-base-200 border border-base-300 shadow-sm">
        <div className="stat px-5 py-4">
          <div className="stat-title text-base-content/60">累计发送流量</div>
          <div className="stat-value text-2xl">{normalizeValue(resource?.network_total_sent)}</div>
        </div>
        <div className="stat px-5 py-4">
          <div className="stat-title text-base-content/60">累计接收流量</div>
          <div className="stat-value text-2xl">{normalizeValue(resource?.network_total_recv)}</div>
        </div>
        <div className="stat px-5 py-4">
          <div className="stat-title text-base-content/60">进程数量 / 启动时间</div>
          <div className="stat-value text-lg">{normalizeValue(resource?.process_count)} / {normalizeValue(resource?.boot_time)}</div>
        </div>
      </div>
    </div>
  );
}
