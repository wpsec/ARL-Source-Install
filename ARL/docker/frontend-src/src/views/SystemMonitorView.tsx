import React, { useCallback, useEffect, useState } from 'react';
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
import { requestApi } from '../api/client';
import { formatPercent, normalizeValue, parseNumericValue } from '../domain/format';
import { PageHeader } from '../layout/PageHeader';

export function SystemMonitorView({ token }: { token: string }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [resource, setResource] = useState<any>({});
  const [history, setHistory] = useState<any[]>([]);
  const [updatedAt, setUpdatedAt] = useState('');

  const loadFallback = useCallback(async () => {
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

    setResource({
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
    });
    setHistory(fallbackHistory);
    setUpdatedAt(data?.last_updated ? normalizeValue(data.last_updated) : new Date().toLocaleString('zh-CN', { hour12: false }));
  }, [token]);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const monitorInfo = await requestApi(token, '/console/system_monitor/', { method: 'GET' });
      const data = monitorInfo?.data || {};
      if (!data?.resource || typeof data.resource !== 'object') {
        throw new Error('系统监控数据为空');
      }
      setResource(data.resource || {});
      setHistory(Array.isArray(data.history_24h) ? data.history_24h : []);
      setUpdatedAt(data?.updated_at ? normalizeValue(data.updated_at) : new Date().toLocaleString('zh-CN', { hour12: false }));
    } catch (err: any) {
      try {
        await loadFallback();
      } catch (fallbackErr: any) {
        setError(fallbackErr?.message || err?.message || '加载系统监控失败');
      }
    } finally {
      setLoading(false);
    }
  }, [token, loadFallback]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => {
      void load();
    }, 15000);
    return () => window.clearInterval(timer);
  }, [load]);

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
      color: 'text-emerald-400',
    },
  ];

  return (
    <div className="p-8 space-y-8">
      <PageHeader
        title="系统监控"
        description="实时监控主机资源、CPU、内存、磁盘与网络流量趋势"
        actions={
          <div className="text-right space-y-2">
          <p className="text-xs font-black text-accent uppercase tracking-widest">最后更新</p>
          <p className="text-sm font-mono">{updatedAt || '-'}</p>
          <button
            onClick={() => void load()}
            className="px-5 py-2.5 border border-base-300 rounded-xl text-sm font-semibold hover:bg-base-200/60 transition flex items-center gap-2"
            disabled={loading}
          >
            <RefreshCw className={`w-[18px] h-[18px] ${loading ? 'animate-spin' : ''}`} />
            刷新
          </button>
        </div>
        }
      />

      {error ? <div className="text-sm text-error border border-error/30 bg-error/10 rounded-xl px-4 py-3">{error}</div> : null}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        {resourceCards.map((item) => (
          <div key={item.title} className="bg-base-200/30 backdrop-blur-md border border-base-300 p-6 rounded-3xl shadow-xl shadow-black/20">
            <div className="flex items-center justify-between mb-5">
              <div className={`p-2.5 rounded-xl bg-base-100 border border-base-300 ${item.color}`}>
                <item.icon className="w-5 h-5" />
              </div>
              <span className="text-xs font-black text-content-muted">{item.detail}</span>
            </div>
            <h3 className="text-xs font-black uppercase tracking-wider text-content-muted mb-1">{item.title}</h3>
            <p className="text-2xl font-black tracking-tight">{item.value}</p>
            <div className="h-2 mt-4 rounded-full bg-base-100 border border-base-300 overflow-hidden">
              <div className="h-full bg-brand-accent transition-all duration-300" style={{ width: `${Math.min(100, Math.max(0, item.percent))}%` }} />
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-base-200/30 backdrop-blur-md border border-base-300 p-8 rounded-3xl shadow-xl shadow-black/20">
          <h3 className="text-xl font-black tracking-tight mb-6">资源使用趋势</h3>
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

        <div className="bg-base-200/30 backdrop-blur-md border border-base-300 p-8 rounded-3xl shadow-xl shadow-black/20">
          <h3 className="text-xl font-black tracking-tight mb-6">网络流量趋势</h3>
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

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="bg-base-200/35 border border-base-300 rounded-2xl p-4">
          <p className="text-xs text-content-muted uppercase tracking-wider">累计发送流量</p>
          <p className="text-2xl font-black mt-1">{normalizeValue(resource?.network_total_sent)}</p>
        </div>
        <div className="bg-base-200/35 border border-base-300 rounded-2xl p-4">
          <p className="text-xs text-content-muted uppercase tracking-wider">累计接收流量</p>
          <p className="text-2xl font-black mt-1">{normalizeValue(resource?.network_total_recv)}</p>
        </div>
        <div className="bg-base-200/35 border border-base-300 rounded-2xl p-4">
          <p className="text-xs text-content-muted uppercase tracking-wider">进程数量 / 启动时间</p>
          <p className="text-lg font-black mt-1">{normalizeValue(resource?.process_count)} / {normalizeValue(resource?.boot_time)}</p>
        </div>
      </div>
    </div>
  );
}
