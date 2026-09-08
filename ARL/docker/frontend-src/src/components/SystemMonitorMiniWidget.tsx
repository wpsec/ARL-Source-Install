import { useQuery } from '@tanstack/react-query';
import { Activity, ArrowDown, ArrowUp, Cpu, Database, Network, ExternalLink } from 'lucide-react';
import { requestApi } from '../api/client';
import { formatPercent, normalizeValue, parseNumericValue } from '../domain/format';

const MONITOR_POLL_INTERVAL_MS = 3000;

type MonitorPoint = {
  time?: string;
  cpu?: number;
  ram?: number;
  net?: number;
};

type SystemMonitorMiniWidgetProps = {
  token: string;
  onOpen: () => void;
};

function clampPercent(value: any): number {
  const parsed = parseNumericValue(value);
  return Math.min(100, Math.max(0, parsed ?? 0));
}

function formatNetworkRate(value: any): string {
  const rate = Math.max(0, parseNumericValue(value) ?? 0);
  if (rate >= 1024) return `${(rate / 1024).toFixed(1)} MB/s`;
  return `${rate.toFixed(1)} KB/s`;
}

function buildSparklinePoints(data: MonitorPoint[], dataKey: 'cpu' | 'ram' | 'net'): string {
  const values = data.map((point) => Math.max(0, parseNumericValue(point[dataKey]) ?? 0));
  if (values.length === 0) return '';

  const width = 76;
  const height = 28;
  const padding = 2;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min;

  return values.map((value, index) => {
    const x = values.length === 1
      ? width / 2
      : padding + (index / (values.length - 1)) * (width - padding * 2);
    const normalized = range === 0 ? 0.5 : (value - min) / range;
    const y = height - padding - normalized * (height - padding * 2);
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  }).join(' ');
}

function Sparkline({ data, dataKey, color }: { data: MonitorPoint[]; dataKey: 'cpu' | 'ram' | 'net'; color: string }) {
  const points = buildSparklinePoints(data, dataKey);
  const lastPoint = points.split(' ').at(-1)?.split(',') || [];

  return (
    <div className="h-6 min-w-0 w-full" aria-hidden="true">
      <svg viewBox="0 0 76 28" className="h-full w-full overflow-visible" focusable="false">
        <polyline points={points} fill="none" stroke={color} strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" />
        {lastPoint.length === 2 ? <circle cx={lastPoint[0]} cy={lastPoint[1]} r="2" fill={color} /> : null}
      </svg>
    </div>
  );
}

function MetricRow({
  icon: Icon,
  label,
  value,
  data,
  dataKey,
  color,
}: {
  icon: typeof Cpu;
  label: string;
  value: string;
  data: MonitorPoint[];
  dataKey: 'cpu' | 'ram' | 'net';
  color: string;
}) {
  return (
    <div className="flex h-10 w-[104px] shrink-0 items-center gap-1.5 rounded-xl border border-base-300/70 bg-base-100/60 px-2">
      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color }} />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-1">
          <span className="truncate text-[9px] font-semibold text-content-muted">{label}</span>
          <span className="shrink-0 text-[10px] font-bold tabular-nums" style={{ color }}>{value}</span>
        </div>
        <Sparkline data={data} dataKey={dataKey} color={color} />
      </div>
    </div>
  );
}

export function SystemMonitorMiniWidget({ token, onOpen }: SystemMonitorMiniWidgetProps) {
  const monitorQuery = useQuery({
    queryKey: ['system-monitor', token],
    queryFn: async () => {
      const response = await requestApi(token, '/console/system_monitor/', { method: 'GET' });
      const data = response?.data || {};
      if (!data?.resource || typeof data.resource !== 'object') {
        throw new Error('系统监控数据为空');
      }
      return data;
    },
    enabled: Boolean(token),
    refetchInterval: MONITOR_POLL_INTERVAL_MS,
    refetchIntervalInBackground: false,
    retry: 0,
  });

  const resource = monitorQuery.data?.resource || {};
  const cpuPercent = clampPercent(resource.cpu_percent);
  const memoryPercent = clampPercent(resource.memory_percent);
  const networkRate = Math.max(0, parseNumericValue(resource.network_rate_total_kbps) ?? 0);
  const history = Array.isArray(monitorQuery.data?.history_24h)
    ? monitorQuery.data.history_24h.slice(-20)
    : [];
  const chartData: MonitorPoint[] = history.length > 0
    ? history
    : [{ cpu: cpuPercent, ram: memoryPercent, net: networkRate }];
  const unavailable = monitorQuery.isError;
  const statusLabel = unavailable ? '暂不可用' : monitorQuery.isFetching && !monitorQuery.data ? '正在同步' : '实时运行';
  const isInitialLoading = monitorQuery.isFetching && !monitorQuery.data;
  const statusColor = unavailable ? 'bg-error' : isInitialLoading ? 'bg-warning' : 'bg-success';
  const statusTextColor = unavailable ? 'text-error' : isInitialLoading ? 'text-warning' : 'text-success';

  return (
    <section className="hidden min-w-0 items-center gap-1.5 lg:flex" aria-label="系统监控摘要">
      <div className="flex h-10 shrink-0 items-center gap-1.5 rounded-xl border border-base-300/80 bg-base-200/45 px-2.5" title={statusLabel}>
        <div className="flex h-6 w-6 items-center justify-center rounded-lg bg-accent/10 text-accent">
          <Activity className="h-3.5 w-3.5" />
        </div>
        <span className="hidden text-[10px] font-black 2xl:inline">系统监控</span>
        <span className={`h-1.5 w-1.5 rounded-full ${statusColor}`} />
        <span className={`hidden text-[9px] font-semibold 2xl:inline ${statusTextColor}`}>{statusLabel}</span>
      </div>

      <div className="flex items-center gap-1.5">
        <MetricRow icon={Cpu} label="CPU" value={monitorQuery.data ? formatPercent(cpuPercent) : '--'} data={chartData} dataKey="cpu" color="var(--brand-accent)" />
        <MetricRow icon={Database} label="内存" value={monitorQuery.data ? formatPercent(memoryPercent) : '--'} data={chartData} dataKey="ram" color="var(--brand-secondary)" />
        <MetricRow icon={Network} label="网速" value={monitorQuery.data ? formatNetworkRate(networkRate) : '--'} data={chartData} dataKey="net" color="var(--brand-warning)" />
      </div>

      <div className="flex h-10 shrink-0 items-center gap-2 rounded-xl border border-base-300/70 bg-base-100/40 px-2.5">
        <div className="min-w-0 text-center">
          <div className="flex items-center justify-center gap-1 text-content-muted">
            <ArrowUp className="h-3 w-3" />
            <span className="text-[9px] font-semibold">发送</span>
          </div>
          <p className="truncate text-[10px] font-bold tabular-nums">{normalizeValue(resource.network_total_sent)}</p>
        </div>
        <div className="min-w-0 text-center">
          <div className="flex items-center justify-center gap-1 text-content-muted">
            <ArrowDown className="h-3 w-3" />
            <span className="text-[9px] font-semibold">接收</span>
          </div>
          <p className="truncate text-[10px] font-bold tabular-nums">{normalizeValue(resource.network_total_recv)}</p>
        </div>
        <div className="min-w-0 text-center">
          <div className="flex items-center justify-center gap-1 text-content-muted">
            <Activity className="h-3 w-3" />
            <span className="text-[9px] font-semibold">进程</span>
          </div>
          <p className="truncate text-[10px] font-bold tabular-nums">{normalizeValue(resource.process_count)}</p>
        </div>
      </div>

      <button
        type="button"
        onClick={onOpen}
        className="flex h-10 w-8 shrink-0 items-center justify-center rounded-xl border border-base-300 text-content-muted transition hover:bg-base-100/60 hover:text-accent"
        title="打开系统监控"
        aria-label="打开系统监控"
      >
        <ExternalLink className="h-3.5 w-3.5" />
      </button>
    </section>
  );
}

export default SystemMonitorMiniWidget;
